"""Run the Sovereign Control API locally with demo tools, agents and users.

    PYTHONPATH=. python3 examples/serve_demo.py [--port 8080] [--db aegis.db]

Prints bearer tokens and example curl commands. Binds to 127.0.0.1 only.
With --db, agents, executions, approvals, tokens and the audit trail survive restarts.
"""

import argparse

from sovereign_control import (
    AutonomyLevel,
    Decision,
    PolicyRule,
    RiskLevel,
    SovereignGateway,
    SQLiteStore,
    ToolDefinition,
)
from sovereign_control.api import ControlAPI, make_server
from sovereign_control.auth import TokenAuthenticator

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8080)
parser.add_argument("--db", help="SQLite file for durable state (default: in memory)")
args = parser.parse_args()
store = SQLiteStore(args.db) if args.db else None

pods = {"api-7f9": "CrashLoopBackOff", "api-2c1": "Running"}

gw = SovereignGateway(store=store)
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

port = args.port
server = make_server(ControlAPI(gw, auth), "127.0.0.1", port)
base = f"http://127.0.0.1:{port}"
print(f"""Sovereign Control API on {base}

  AGENT={agent_token}
  SRE={sre_token}
  ADMIN={admin_token}

  # agent asks to restart a crash-looping pod (production → needs approval)
  curl -s -X POST {base}/v1/agent/actions -H "Authorization: Bearer $AGENT" \\
    -d '{{"tool_id":"k8s.restart_pod","environment":"production","params":{{"pod":"api-7f9"}},
         "context":{{"severity":"critical","confidence":0.94,"evidence":["CrashLoopBackOff x12"]}}}}'

  curl -s {base}/v1/approvals -H "Authorization: Bearer $SRE"
  curl -s -X POST {base}/v1/executions/<execution_id>/approve -H "Authorization: Bearer $SRE" -d '{{"role":"sre"}}'
  curl -s {base}/v1/control-tower -H "Authorization: Bearer $SRE"
""")
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
