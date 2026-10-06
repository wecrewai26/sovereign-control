# WeCrew AEGIS™ — Sovereign Control

**Observe · Understand · Decide · Govern · Remediate · Verify · Prove · Learn**

Sovereign Control is the governance plane of the AEGIS Sovereign Autonomous Operations OS
(see [`docs/aegis-product-spec.md`](docs/aegis-product-spec.md), §46). It sits between AI agents and
infrastructure: agents never call a tool directly. Every call goes through the governed flow from spec §19:

```
Agent → Tool Registry → Risk Engine → Policy Engine → Approval Engine
      → Credential Broker → Execution → Verification → Rollback → Audit Evidence
```

## What's implemented

| Module | Spec | What it does |
|---|---|---|
| `registry.ToolRegistry` | §18 | Central tool catalog: owner, version, permissions, risk level, environment scope, approval mode, verifier, rollback |
| `registry.AgentRegistry` | §47 | Scoped, expiring agent identities (role, tenant, environments, permissions, tool scopes, autonomy level, risk ceiling) |
| `risk.RiskEngine` | §52 | Explainable 0–100 score from environment, action type, blast radius, data sensitivity, irreversibility, customer impact, confidence |
| `policy.PolicyEngine` | §4.4, §4.5, §49 | Default-deny guardrails + L0–L5 autonomy baseline + declarative rules. Rules can only tighten, never loosen |
| `approval.ApprovalEngine` | §53 | Single / dual / manager / service-owner / security / CAB modes; no self-approval; distinct approvers; expiry |
| `credentials.CredentialBroker` | §51 | Short-lived credential per execution, scoped to agent + tool + environment, revoked afterwards |
| `gateway.SovereignGateway` | §19, §28, §29 | Orchestrates the flow; verifies after action, rolls back on failure, escalates to a human |
| `audit.AuditLog` | §26, §27 | Append-only SHA-256 hash chain; `verify()` detects edits, insertions and deletions |

### Autonomy levels (§4.5)

| Level | Mutating tools |
|---|---|
| L0 Observe / L1 Investigate | Denied (read-only tools allowed) |
| L2 Recommend | Recorded as a recommendation, not executed |
| L3 Approved Execution | Always requires approval |
| L4 Policy-Autonomous | Auto-executes LOW risk; otherwise requires approval |
| L5 Closed Loop | Auto-executes within the agent's risk ceiling |

Above all levels: a risk above the agent's `max_risk` is denied, and a tool marked `approval_required` always needs approval.

## Quick start

No dependencies beyond Python 3.10+.

```bash
python3 -m unittest discover -s tests      # run the tests
PYTHONPATH=. python3 examples/incident_demo.py
```

```python
from sovereign_control import *

gw = SovereignGateway()
gw.tools.register(ToolDefinition(
    tool_id="k8s.restart_pod", name="Restart pod", version="1.0", owner="platform",
    description="Delete a pod so its controller recreates it",
    handler=restart_pod, mutating=True, risk_level=RiskLevel.LOW,
    required_permissions=frozenset({"k8s:pods:delete"}),
    verifier=pod_is_ready, rollback=None,
))
gw.agents.issue("k8s-agent", role="sre", tenant="acme",
                environments={"production"}, permissions={"k8s:pods:delete"},
                tool_scopes={"k8s.restart_pod"},
                autonomy=AutonomyLevel.L3_APPROVED_EXECUTION, max_risk=RiskLevel.HIGH)

ex = gw.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "api-7f9"},
                ActionContext(severity="critical", confidence=0.94,
                              hypothesis="OOM crash loop", evidence=["OOMKilled x5"]))
ex.status          # pending_approval
gw.approve(ex.execution_id, "alice", "sre")
ex.status          # succeeded / rolled_back / ...
gw.audit.verify()  # True
```

## Not yet built

This is the in-process core. Next steps toward the spec:
- HTTP API and Agent Gateway (§10)
- Keycloak/OIDC for human identity (§48) and OPA/Rego as a policy backend (§49)
- Vault dynamic secrets behind `CredentialBroker` (§51)
- Persistent evidence store and incident evidence bundle export (§27)
- MCP server adapters that register into the Tool Registry (§17)
- Control Tower view (§54)
