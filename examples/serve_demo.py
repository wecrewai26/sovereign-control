"""Run the Sovereign Control API locally with demo tools, agents and users.

    PYTHONPATH=. python3 examples/serve_demo.py [--port 8080] [--db aegis.db] [--evidence-key-file KEY]

Prints bearer tokens and example curl commands. Binds to 127.0.0.1 only.
With --db, agents, executions, approvals, tokens and the audit trail survive restarts.
"""

import argparse

from sovereign_control import (
    AutonomyLevel,
    Decision,
    OpsGraph,
    PolicyRule,
    RiskLevel,
    SovereignGateway,
    SQLiteStore,
    ToolDefinition,
)
from sovereign_control.alertmind import AlertMind, CorrelationConfig
from sovereign_control.api import ControlAPI, make_server
from sovereign_control.auth import TokenAuthenticator
from sovereign_control.incidents import IncidentManager

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8080)
parser.add_argument("--db", help="SQLite file for durable state (default: in memory)")
parser.add_argument("--evidence-key-file", help="file holding the key used to sign evidence bundles")
args = parser.parse_args()
evidence_key = open(args.evidence_key_file, "rb").read().strip() if args.evidence_key_file else None
store = SQLiteStore(args.db) if args.db else None

pods = {"api-7f9": "CrashLoopBackOff", "api-2c1": "Running"}

graph = OpsGraph.from_dict({
    "nodes": [{"id": "web", "customer_facing": True}, {"id": "api"}, {"id": "postgres", "kind": "database"},
              {"id": "rabbitmq", "kind": "queue"}, {"id": "node-7", "kind": "node"}],
    "edges": [{"from": "web", "kind": "depends_on", "to": "api"},
              {"from": "api", "kind": "depends_on", "to": "postgres"},
              {"from": "api", "kind": "depends_on", "to": "rabbitmq"},
              {"from": "postgres", "kind": "deployed_on", "to": "node-7"}],
})
gw = SovereignGateway(store=store, graph=graph)
gw.tools.register(ToolDefinition(
    tool_id="k8s.get_pods", name="List pods", version="1.0", owner="platform-team",
    description="List pods and their phase", handler=lambda params, cred: dict(pods),
))
gw.tools.register(ToolDefinition(
    tool_id="k8s.restart_pod", name="Restart pod", version="1.0", owner="platform-team",
    description="Delete a pod so its controller recreates it",
    handler=lambda params, cred: pods.__setitem__(params["pod"], "Running") or {"pod": params["pod"]},
    mutating=True, risk_level=RiskLevel.LOW,
    required_permissions=frozenset({"k8s:pods:delete"}),
    verifier=lambda params, result: pods.get(params["pod"]) == "Running",
    rollback=None,
))
if "k8s-agent" not in {a.agent_id for a in gw.agents.all()}:  # already stored on a restart
    gw.agents.issue(
        "k8s-agent", role="sre", tenant="acme", environments={"production"},
        permissions={"k8s:pods:delete"}, tool_scopes={"k8s.get_pods", "k8s.restart_pod"},
        autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS, max_risk=RiskLevel.HIGH,
    )
gw.policy.add_rule(PolicyRule("prod-changes-need-approval", Decision.ALLOW_WITH_APPROVAL,
                              match={"environment": "production"}))

auth = TokenAuthenticator(store)
agent_token = auth.add_agent("k8s-agent")
sre_token = auth.add_user("alice", {"sre"})
admin_token = auth.add_user("root", {"admin"})
alerts_token = auth.add_integration("alertmanager")
discovery_token = auth.add_integration("k8s-discovery")

incidents = IncidentManager(gw)
alertmind = AlertMind(incidents, CorrelationConfig(graph=gw.graph))

port = args.port
server = make_server(
    ControlAPI(gw, auth, evidence_signing_key=evidence_key, incidents=incidents, alertmind=alertmind,
               graph_sources={"k8s-discovery"}),
    "127.0.0.1", port,
)
base = f"http://127.0.0.1:{port}"
print(f"""Sovereign Control API on {base}

  AGENT={agent_token}
  SRE={sre_token}
  ADMIN={admin_token}
  ALERTS={alerts_token}
  DISCOVERY={discovery_token}

  # report a Kubernetes cluster into the OpsGraph (here from a JSON dump; use --in-cluster in a real cluster)
  echo $DISCOVERY > discovery.token
  python3 -m sovereign_control.discovery.kubernetes --from-file cluster.json --environment production \
    --push {base} --token-file discovery.token

  # Alertmanager-style webhook: related alerts are grouped into one incident
  curl -s -X POST {base}/v1/ingest/alertmanager -H "Authorization: Bearer $ALERTS" \
    -d '{{"status":"firing","commonLabels":{{"env":"production"}},"alerts":[
         {{"labels":{{"alertname":"PostgresConnectionsExhausted","service":"postgres","severity":"critical"}},
          "annotations":{{"summary":"Database connection exhaustion"}}}},
         {{"labels":{{"alertname":"APITimeout","service":"api","severity":"error"}}}},
         {{"labels":{{"alertname":"QueueBacklog","service":"rabbitmq","severity":"warning"}}}}]}}'

  # what breaks if node-7 goes down? (also feeds the risk score of any action on these services)
  curl -s {base}/v1/opsgraph/node-7/impact -H "Authorization: Bearer $SRE"

  # agent asks to restart a crash-looping pod (production → needs approval)
  curl -s -X POST {base}/v1/agent/actions -H "Authorization: Bearer $AGENT" \\
    -d '{{"tool_id":"k8s.restart_pod","environment":"production","params":{{"pod":"api-7f9"}},
         "context":{{"severity":"critical","confidence":0.94,"evidence":["CrashLoopBackOff x12"]}}}}'

  curl -s {base}/v1/approvals -H "Authorization: Bearer $SRE"
  curl -s -X POST {base}/v1/executions/<execution_id>/approve -H "Authorization: Bearer $SRE" -d '{{"role":"sre"}}'
  curl -s {base}/v1/control-tower -H "Authorization: Bearer $SRE"

  # open an incident, then link actions to it by adding "incident_id":"INC-0001" to the request above
  curl -s -X POST {base}/v1/agent/incidents -H "Authorization: Bearer $AGENT" \
    -d '{{"title":"api pods crash-looping","severity":"critical","service":"api","environment":"production"}}'
  curl -s {base}/v1/incidents/INC-0001 -H "Authorization: Bearer $SRE"
  curl -s -X POST {base}/v1/incidents/INC-0001/status -H "Authorization: Bearer $SRE" \
    -d '{{"status":"resolved","resolution":"Restarted crash-looping pod"}}'
  curl -s -o incident.zip {base}/v1/incidents/INC-0001/evidence -H "Authorization: Bearer $SRE"

  # download an evidence bundle and verify it offline
  curl -s -o bundle.zip "{base}/v1/evidence?execution_id=<execution_id>&title=INC-1" -H "Authorization: Bearer $SRE"
  python3 -m sovereign_control.evidence verify bundle.zip
""")
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
