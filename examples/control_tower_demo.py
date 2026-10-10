"""Control Tower web page with live-looking data: an in-memory cluster, Prometheus, an incident
and an approval waiting.

    PYTHONPATH=. python3 examples/control_tower_demo.py [--port 8080]

Open http://127.0.0.1:8080/ui and paste the SRE token it prints.

For a real cluster, build the same objects with your API server, Prometheus and Vault
(see "Control Tower" in the README) instead of the fakes below.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import fake_prometheus  # noqa: E402
from fake_kube import TOKEN, Cluster, start  # noqa: E402

from sovereign_control import (  # noqa: E402
    AutonomyLevel, Decision, OpsGraph, PolicyRule, RiskLevel, SovereignGateway,
)
from sovereign_control.alertmind import parse_alertmanager  # noqa: E402
from sovereign_control.api import ControlAPI, make_server  # noqa: E402
from sovereign_control.auth import TokenAuthenticator  # noqa: E402
from sovereign_control.clusters import ClusterConfig, ClusterViewer, PrometheusTarget  # noqa: E402
from sovereign_control.credentials import CredentialBroker  # noqa: E402
from sovereign_control.models import ActionContext  # noqa: E402
from sovereign_control.tools.kubernetes import KubeTarget, kubernetes_tools  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8080)
args = parser.parse_args()


class TokenBroker(CredentialBroker):
    """Stands in for Vault in this demo."""

    def issue(self, *a, **kw):
        cred = super().issue(*a, **kw)
        cred.secret = {"service_account_token": TOKEN}
        return cred


# A namespace that looks like a real one: mostly healthy, one crash-looping, one evicted.
cluster = Cluster()
for name, replicas in (("api", 2), ("web", 2), ("worker", 3), ("scheduler", 1), ("notifier", 1), ("ui", 1)):
    cluster.add_deployment("ops", name, f"{name}:3.4.1", replicas=replicas,
                           history=[f"{name}:3.4.0"] if name == "worker" else ())
cluster.add_bare_pod("ops", "vault-0")
cluster.evict("ops", "vault-0")
notifier = cluster.pods_of("ops", "notifier")[0]["metadata"]["name"]
cluster.crashloop("ops", notifier, restarts=14)
api_pod = sorted(p["metadata"]["name"] for p in cluster.pods_of("ops", "api"))[0]
cluster.logs[("ops", api_pod)] = "\n".join([
    "2026-10-10T09:08:30Z INFO  api starting, version 3.4.1",
    "2026-10-10T09:08:31Z INFO  connecting to postgres://api:Pa55w0rd-do-not-log@db.ops:5432/main",
    "2026-10-10T09:08:31Z INFO  connected",
    "2026-10-10T09:08:35Z INFO  GET /healthz 200 2ms",
    "2026-10-10T09:08:36Z WARN  upstream notifier unavailable, retrying",
    "2026-10-10T09:08:40Z INFO  POST /v1/orders 201 41ms",
])
cluster.logs[("ops", notifier)] = ("2026-10-10T09:08:50Z ERROR missing SMTP_PASSWORD; set it in the secret\n"
                                   "2026-10-10T09:08:50Z FATAL exiting")
cluster.add_event("ops", "e1", "Pod", "vault-0", "Evicted", "The node was low on resource: memory.")
cluster.add_event("ops", "e2", "Pod", notifier, "BackOff", "Back-off restarting failed container notifier", count=14)
kube_server, kube_url = start(cluster)
all_pods = [p["metadata"]["name"] for (ns, _), p in cluster.pods.items() if ns == "ops" and p["metadata"]["name"] != "vault-0"]
prom_server, prom_url, _ = fake_prometheus.start(all_pods)

gw = SovereignGateway(credentials=TokenBroker(), graph=OpsGraph.from_dict({
    "nodes": [{"id": "web", "customer_facing": True}, {"id": "api"}, {"id": "worker"}, {"id": "notifier"}],
    "edges": [{"from": "web", "kind": "depends_on", "to": "api"}, {"from": "api", "kind": "depends_on", "to": "worker"},
              {"from": "api", "kind": "depends_on", "to": "notifier"}]}))
for tool in kubernetes_tools({"production": KubeTarget(kube_url)}, allowed_namespaces={"ops"},
                             verify_timeout=5, poll_interval=0.1):
    gw.tools.register(tool)
gw.agents.issue("remediation-agent", role="sre", tenant="acme", environments={"production"},
                permissions={"k8s:pods:read", "k8s:pods:delete", "k8s:deployments:write"},
                tool_scopes={t.tool_id for t in gw.tools.all()},
                autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS, max_risk=RiskLevel.HIGH)
gw.policy.add_rule(PolicyRule("prod-changes-need-approval", Decision.ALLOW_WITH_APPROVAL,
                              match={"environment": "production", "mutating": True}))

auth = TokenAuthenticator()
sre_token = auth.add_user("alice", {"sre"})
viewer = ClusterViewer(gw, {"production": ClusterConfig(KubeTarget(kube_url), {"ops"}, PrometheusTarget(prom_url))})
api = ControlAPI(gw, auth, clusters=viewer)

# An incident from Alertmanager, and the agent's proposal waiting for approval.
results = api.alertmind.ingest(parse_alertmanager({"alerts": [
    {"status": "firing", "labels": {"alertname": "PodCrashLooping", "service": "notifier", "env": "production",
                                    "severity": "critical"},
     "annotations": {"summary": "notifier is crash-looping (14 restarts)"}},
    {"status": "firing", "labels": {"alertname": "APIUpstreamErrors", "service": "api", "env": "production",
                                    "severity": "warning"}},
]}), actor="alertmanager")
incident_id = results[0].incident_id
ex = gw.request("remediation-agent", "k8s.restart_pod", "production", {"namespace": "ops", "pod": notifier},
                ActionContext(service="notifier", severity="critical", confidence=0.6,
                              hypothesis="notifier exits at start-up; a restart may clear a stale config mount",
                              evidence=["14 restarts in CrashLoopBackOff", "log: missing SMTP_PASSWORD"]))
api.incidents.link_execution(incident_id, ex.execution_id, actor="remediation-agent")

server = make_server(api, "127.0.0.1", args.port)
print(f"""AEGIS Control Tower: http://127.0.0.1:{args.port}/ui
  sign in with this SRE token: {sre_token}
""", flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    for s in (server, kube_server, prom_server):
        s.shutdown() if s is not server else None
        s.server_close()
