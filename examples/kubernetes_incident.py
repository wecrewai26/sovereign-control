"""The spec §24 incident, end to end through the HTTP API, against an in-memory Kubernetes cluster.

    PYTHONPATH=. python3 examples/kubernetes_incident.py

1. Alertmanager reports checkout errors after a bad deploy → AlertMind opens an incident.
2. The agent looks at the pods, then asks to roll the Deployment back, linked to the incident.
3. Production changes need approval; an SRE approves.
4. AEGIS issues a short-lived cluster credential, rolls back, and verifies the rollout.
5. The SRE resolves the incident and exports a verified evidence bundle.

To run against a real cluster instead, swap the fake cluster for a KubeTarget pointing at your
API server, and TokenBroker for VaultCredentialBroker (see README).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from fake_kube import TOKEN, Cluster, start  # noqa: E402

from sovereign_control import AutonomyLevel, Decision, OpsGraph, PolicyRule, RiskLevel, SovereignGateway  # noqa: E402
from sovereign_control.api import ControlAPI  # noqa: E402
from sovereign_control.auth import TokenAuthenticator  # noqa: E402
from sovereign_control.credentials import CredentialBroker  # noqa: E402
from sovereign_control.evidence import verify_bundle  # noqa: E402
from sovereign_control.tools.kubernetes import KubeTarget, kubernetes_tools  # noqa: E402


class TokenBroker(CredentialBroker):
    """Stands in for Vault's Kubernetes secrets engine in this example."""

    def issue(self, *args, **kwargs):
        cred = super().issue(*args, **kwargs)
        cred.secret = {"service_account_token": TOKEN}
        return cred


cluster = Cluster()
cluster.bad_images.add("checkout:2.4.0")
cluster.add_deployment("shop", "checkout", "checkout:2.4.0", replicas=3, history=["checkout:2.3.1"])
server, url = start(cluster)

gw = SovereignGateway(credentials=TokenBroker(), graph=OpsGraph.from_dict({
    "nodes": [{"id": "web", "customer_facing": True}, {"id": "checkout"}],
    "edges": [{"from": "web", "kind": "depends_on", "to": "checkout"}]}))
for tool in kubernetes_tools({"production": KubeTarget(url)}, allowed_namespaces={"shop"},
                             verify_timeout=5, poll_interval=0.1):
    gw.tools.register(tool)
gw.agents.issue("remediation-agent", role="sre", tenant="acme", environments={"production"},
                permissions={"k8s:pods:read", "k8s:deployments:write"},
                tool_scopes={"k8s.get_pods", "k8s.rollout_undo"},
                autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS, max_risk=RiskLevel.HIGH)
gw.policy.add_rule(PolicyRule("prod-changes-need-approval", Decision.ALLOW_WITH_APPROVAL,
                              match={"environment": "production", "mutating": True}))

auth = TokenAuthenticator()
t = {"agent": auth.add_agent("remediation-agent"), "sre": auth.add_user("alice", {"sre"}),
     "alerts": auth.add_integration("alertmanager")}
api = ControlAPI(gw, auth)


def call(method, path, who, body=None):
    status, payload = api.handle(method, path, {"Authorization": f"Bearer {t[who]}"},
                                 json.dumps(body).encode() if body is not None else b"")
    if status != 200:
        raise SystemExit(f"{method} {path} → {status} {payload}")
    return payload


def step(text):
    print(f"\n▶ {text}")


step("Alertmanager: checkout 5xx after deploy 2.4.0")
results = call("POST", "/v1/ingest/alertmanager", "alerts", {"alerts": [{"status": "firing", "labels": {
    "alertname": "CheckoutErrorRate", "service": "checkout", "env": "production", "severity": "critical"},
    "annotations": {"summary": "Checkout error rate 31% since deploy 2.4.0"}}]})["results"]
incident_id = results[0]["incident_id"]
print(f"  {results[0]['action']} {incident_id}")

step("Agent investigates")
pods = call("POST", "/v1/agent/actions", "agent", {"tool_id": "k8s.get_pods", "environment": "production",
                                                   "params": {"namespace": "shop"}})["result"]["pods"]
print(f"  {sum(p['ready'] for p in pods)}/{len(pods)} checkout pods ready")

step("Agent proposes a rollback, linked to the incident")
ex = call("POST", "/v1/agent/actions", "agent", {
    "tool_id": "k8s.rollout_undo", "environment": "production", "incident_id": incident_id,
    "params": {"namespace": "shop", "deployment": "checkout"},
    "context": {"service": "checkout", "severity": "critical", "confidence": 0.92,
                "hypothesis": "Release 2.4.0 is failing readiness; 2.3.1 was healthy",
                "evidence": [f"{sum(p['ready'] for p in pods)}/{len(pods)} pods ready", "error rate 31%"]}})
print(f"  risk {ex['risk']['score']} {ex['risk']['level']} → {ex['status']}")
for note in ex["risk"]["notes"]:
    print(f"    · {note}")

step("SRE approves")
ex = call("POST", f"/v1/executions/{ex['execution_id']}/approve", "sre", {"role": "sre"})
print(f"  {ex['status']}, verified={ex['verified']}, revision {ex['result']['from_revision']} → "
      f"{ex['result']['to_revision']}")
d = cluster.deployments[("shop", "checkout")]
print(f"  cluster: image {d['spec']['template']['spec']['containers'][0]['image']}, "
      f"{d['status']['availableReplicas']}/{d['spec']['replicas']} available")

step("SRE resolves the incident and exports evidence")
call("POST", f"/v1/incidents/{incident_id}/status", "sre",
     {"status": "resolved", "resolution": "Rolled checkout back from 2.4.0 to 2.3.1"})
status, bundle = api.handle("GET", f"/v1/incidents/{incident_id}/evidence", {"Authorization": f"Bearer {t['sre']}"})
problems = verify_bundle(bundle.content)
print(f"  {bundle.filename}: {'verified' if not problems else problems}")

step("Timeline")
for event in call("GET", f"/v1/incidents/{incident_id}", "sre")["timeline"]:
    print(f"  {event['time'][11:19]}  {event['event']:<26} {event['actor']}")

server.shutdown()
server.server_close()
