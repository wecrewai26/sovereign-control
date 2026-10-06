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

| `api.ControlAPI` | §10, §54 | HTTP API Gateway (humans) and Agent Gateway (agents), plus the Control Tower summary |
| `persistence.SQLiteStore` | §26, §27 | Durable audit trail, agent identities, executions, approvals and token hashes (standard-library SQLite) |
| `auth.TokenAuthenticator` | §48 | Bearer tokens for users and agents, stored hashed; swappable for Keycloak/OIDC |

### HTTP API

Standard library only, so it runs air-gapped. Every endpoint except `/healthz` needs `Authorization: Bearer <token>`.
User tokens and agent tokens are kept apart: an agent can't call human endpoints, and a human can't submit as an agent.

| Method | Path | Caller | Purpose |
|---|---|---|---|
| POST | `/v1/agent/actions` | agent | Submit a tool call `{tool_id, environment, params, context}`. The agent's identity comes from its token, never the body |
| GET | `/v1/agent/actions/{id}` | agent | Track one of its own executions (other agents' are not visible) |
| GET | `/v1/agent/me` | agent | Its own identity and scopes |
| GET | `/v1/tools`, `/v1/agents` | user | Registry contents |
| POST | `/v1/agents/{id}/disable` | user with `admin` | Kill switch for an agent |
| GET | `/v1/executions[?status=&agent_id=&environment=&tool_id=]` | user | List and filter executions |
| GET | `/v1/executions/{id}` | user | Full execution: risk factors, policy reasons, approval, result |
| POST | `/v1/executions/{id}/approve` | user | `{role}`. The role must be one the caller holds |
| POST | `/v1/executions/{id}/reject` | user | `{reason}` |
| GET | `/v1/approvals` | user | Pending approvals |
| GET | `/v1/audit[?execution_id=]`, `/v1/audit/verify` | user | Audit trail and hash-chain check |
| GET | `/v1/control-tower` | user | §54 summary: agents, execution states, approvals, blocked/risky actions, credentials, audit health |

Errors are JSON `{"error": ...}`: 400 bad input, 401 no/invalid token, 403 wrong caller or role, 404, 405, 409 approval already decided.

```bash
PYTHONPATH=. python3 examples/serve_demo.py   # prints tokens and curl examples
```

### Persistence

```python
gw = SovereignGateway(store=SQLiteStore("aegis.db"))
auth = TokenAuthenticator(store=gw.store)
```

What a restart keeps: agent identities (including disabled ones), every execution with its risk, policy decision and
approval state, pending approvals (still approvable), token hashes, and the audit trail. Tools and policy rules are
code, so they are registered again at startup.

Safety rules:
- **Audit first.** Each audit event is written to disk before it counts, and the audit table is insert-only.
- **Tamper check on startup.** If the stored hash chain doesn't verify (an edited, inserted or deleted row), startup
  fails with `AuditIntegrityError` rather than appending to a broken record.
- **No silent re-runs.** An execution is saved as `executing` before the tool runs. If the process dies mid-action,
  the next start marks it `interrupted` and escalates it to a human; it is never re-run automatically, because the
  outcome is unknown.

```bash
PYTHONPATH=. python3 examples/serve_demo.py --db aegis.db
```

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
- Keycloak/OIDC authenticator for human identity (§48) and OPA/Rego as a policy backend (§49)
- TLS termination (put the API behind a reverse proxy until then)
- Signing or external anchoring of the audit chain: the hash chain catches partial edits, but someone with write
  access to the database could rebuild the whole chain
- Vault dynamic secrets behind `CredentialBroker` (§51)
- Incident evidence bundle export (§27)
- MCP server adapters that register into the Tool Registry (§17)
- Control Tower web UI (§54; the API summary exists)
