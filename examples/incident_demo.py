"""Walk through spec §24's incident: a bad deployment, an agent proposes a rollback,
a human approves, the gateway executes, verifies and seals the evidence trail.

Run: python3 examples/incident_demo.py
"""

from sovereign_control import (
    ActionContext,
    AutonomyLevel,
    Decision,
    PolicyRule,
    RiskLevel,
    SovereignGateway,
    ToolDefinition,
)

cluster = {"checkout": {"revision": 42, "error_rate": 0.31}}


def rollout_undo(params, cred):
    svc = cluster[params["deployment"]]
    previous = svc["revision"]
    svc["revision"] -= 1
    svc["error_rate"] = 0.002
    return {"from_revision": previous, "to_revision": svc["revision"]}


def error_rate_normal(params, result):
    return cluster[params["deployment"]]["error_rate"] < 0.01


def redeploy(params, result, cred):
    cluster[params["deployment"]]["revision"] = result["from_revision"]


gw = SovereignGateway()
gw.tools.register(
    ToolDefinition(
        tool_id="k8s.rollout_undo",
        name="Rollback deployment",
        version="1.0",
        owner="platform-team",
        description="kubectl rollout undo",
        handler=rollout_undo,
        mutating=True,
        risk_level=RiskLevel.MEDIUM,
        required_permissions=frozenset({"k8s:deployments:write"}),
        verifier=error_rate_normal,
        rollback=redeploy,
    )
)
gw.agents.issue(
    "remediation-agent",
    role="sre",
    tenant="acme",
    environments={"production"},
    permissions={"k8s:deployments:write"},
    tool_scopes={"k8s.rollout_undo"},
    autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS,
    max_risk=RiskLevel.HIGH,
)
gw.policy.add_rule(
    PolicyRule("prod-changes-need-approval", Decision.ALLOW_WITH_APPROVAL,
               match={"environment": "production", "mutating": True})
)

execution = gw.request(
    "remediation-agent",
    "k8s.rollout_undo",
    "production",
    {"deployment": "checkout"},
    ActionContext(
        service="checkout",
        severity="critical",
        customer_impact=True,
        confidence=0.92,
        hypothesis="Deployment rev 42 exhausted the DB connection pool",
        evidence=["error rate 31% since 18:04", "deploy rev 42 at 18:01", "pg pool saturation 100%"],
    ),
)
print(f"risk:     {execution.risk.score} ({execution.risk.level.name}) {execution.risk.factors}")
print(f"policy:   {execution.policy.decision.name} {list(execution.policy.reasons)}")
print(f"status:   {execution.status.value}")

gw.approve(execution.execution_id, "alice", "sre")
print(f"approved: {execution.status.value}, verified={execution.verified}, result={execution.result}")
print(f"audit chain intact: {gw.audit.verify()}")
for event in gw.audit.events(execution.execution_id):
    print(f"  {event.seq:>2} {event.event_type:<24} {event.actor}")
