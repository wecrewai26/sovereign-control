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
| `credentials.CredentialBroker` | §51 | Short-lived credential per execution, scoped to agent + tool + environment, revoked afterwards (local placeholder tokens, for development) |
| `vault.VaultCredentialBroker` | §51 | Real dynamic credentials from HashiCorp Vault (Kubernetes, database, cloud secrets engines), revoked after each action |
| `gateway.SovereignGateway` | §19, §28, §29 | Orchestrates the flow; verifies after action, rolls back on failure, escalates to a human |
| `audit.AuditLog` | §26, §27 | Append-only SHA-256 hash chain; `verify()` detects edits, insertions and deletions |

| `api.ControlAPI` | §10, §54 | HTTP API Gateway (humans) and Agent Gateway (agents), plus the Control Tower summary |
| `persistence.SQLiteStore` | §26, §27 | Durable audit trail, agent identities, executions, approvals and token hashes (standard-library SQLite) |
| `evidence` | §26, §27 | Evidence bundle export (zip with manifest of SHA-256 hashes, optional HMAC signature) and an offline verifier |
| `incidents.IncidentManager` | §21, §23, §24 | Incidents that group alerts (de-duplicated by fingerprint) and governed executions, with a status lifecycle and a timeline read from the audit trail |
| `alertmind.AlertMind` | §21, §22 | Alert ingestion (Alertmanager webhook, generic JSON), severity normalization, de-duplication, silences, noise threshold, and dependency-aware correlation into incidents |
| `opsgraph.OpsGraph` | §33 | Service and infrastructure graph: what depends on what and what runs where. Feeds blast radius into risk and dependency chains into alert correlation |
| `discovery.kubernetes` | §39 | Read-only Kubernetes discovery: workloads, nodes and placement, plus declared dependencies, reported into the OpsGraph |
| `tools.kubernetes` | §31 | Real Kubernetes actions (list pods, restart pod, rolling restart, scale, roll back) with post-action verification and rollback |
| `auth.TokenAuthenticator` | §48 | Bearer tokens for users and agents, stored hashed; swappable for Keycloak/OIDC |

### HTTP API

Standard library only, so it runs air-gapped. Every endpoint except `/healthz` needs `Authorization: Bearer <token>`.
User, agent and integration tokens are kept apart: an agent can't call human endpoints, a human can't submit as an
agent, and an integration token (for Alertmanager and similar) can only push alerts, so it can never approve an action.

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
| GET | `/v1/evidence?execution_id=…[&execution_id=…][&title=…]` | user | Download an evidence bundle (zip). The export is itself written to the audit trail with the file's SHA-256 |
| POST | `/v1/ingest/alertmanager` | integration | Prometheus Alertmanager webhook (v4 payload) |
| POST | `/v1/ingest/alerts` | integration | Generic alert JSON: one alert or `{"alerts": [...]}` |
| GET | `/v1/opsgraph` | user | The whole graph and its fingerprint |
| PUT | `/v1/opsgraph` | user with `admin` | Replace the graph (validated first; audited with its fingerprint; persisted) |
| POST | `/v1/ingest/opsgraph` | integration (approved sources only) | Discovery report, merged under the source's name |
| GET | `/v1/opsgraph/{id}/impact`, `/v1/agent/opsgraph/{id}/impact` | user, agent | What fails if this fails, what it depends on, which customer-facing services are reached |
| GET, POST | `/v1/silences` | user | List or add a silence `{name, match: {label: value}, duration_minutes}` |
| POST | `/v1/agent/incidents` | agent | Open an incident (`detection_source` is recorded as the agent) |
| GET | `/v1/agent/incidents/{id}` | agent | Incident with timeline |
| POST | `/v1/agent/incidents/{id}/alerts` | agent | Attach an alert `{name, source, severity, summary, labels, fingerprint}` |
| POST | `/v1/agent/incidents/{id}/status` | agent | `investigating` or `mitigating` only |
| GET, POST | `/v1/incidents` | user | List (`?status=&severity=`) or open incidents |
| GET | `/v1/incidents/{id}` | user | Incident with its full timeline |
| POST | `/v1/incidents/{id}/alerts`, `/links` | user | Attach an alert; link an execution `{execution_id}` |
| POST | `/v1/incidents/{id}/status` | user | `{status, note, resolution}`; resolving requires a resolution |
| POST | `/v1/incidents/{id}/update` | user | `{owner, severity, impact, root_cause, affected_services}` |
| GET | `/v1/incidents/{id}/evidence` | user | Evidence bundle for the whole incident |
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

### OpsGraph (§33)

```json
{"nodes": [{"id": "web", "customer_facing": true}, {"id": "postgres", "kind": "database"}, {"id": "node-7", "kind": "node"}],
 "edges": [{"from": "web", "kind": "depends_on", "to": "api"},
           {"from": "api", "kind": "depends_on", "to": "postgres"},
           {"from": "postgres", "kind": "deployed_on", "to": "node-7"}]}
```

`depends_on`, `deployed_on` and `runs_on` carry impact (if the target fails, the source is affected). Other spec
relationships (`owns`, `monitors`, `managed_by`, …) are recorded without propagating impact.

One graph is shared by:
- **Risk (§52).** When an agent names a `service`, its blast radius is the larger of the agent's claim and the graph's
  count of affected services, and customer impact is set if a customer-facing service is reached. An agent can
  overstate risk but never understate it. The reasons appear in the risk `notes` (audit trail, API, evidence bundles),
  including a note when the service is missing from the graph.
- **AlertMind (§22).** Alerts are related when one is in the other's dependency chain, including placement, so a
  `NodeNotReady` on `node-7` joins the incident for the services running there.

`PUT /v1/opsgraph` replaces it for everyone at once and is saved; after that the saved graph wins over the one
passed at startup. Ids containing `/` (such as `node/ip-10-0-1-7`) are URL-encoded in paths: `node%2Fip-10-0-1-7`.

### Kubernetes discovery (§39)

A job in the cluster reads nodes, pods, services and workloads (Deployments, StatefulSets, DaemonSets) with a
read-only service account and reports them to AEGIS:

- **Placement:** each workload is `deployed_on` the nodes its pods are scheduled on, so a node failure reaches the
  services on it.
- **Ids line up with alerts:** a workload's id is its `app.kubernetes.io/name` label, else `app`, else its name;
  the same id in two namespaces becomes `<namespace>/<id>`.
- **Dependencies are declared**, since Kubernetes doesn't know who calls whom, with annotations on the workload:
  `aegis.wecrew.ai/depends-on: "postgres, payments-rds"` (Service names resolve to the workloads behind them;
  other names, such as a managed database, are used as-is), `aegis.wecrew.ai/customer-facing: "true"`, and
  `aegis.wecrew.ai/owner`.

[`deploy/kubernetes/opsgraph-discovery.yaml`](deploy/kubernetes/opsgraph-discovery.yaml) has the read-only RBAC
and a CronJob. To try it without a cluster: `python3 -m sovereign_control.discovery.kubernetes --from-file dump.json`.

Because the graph raises risk scores, discovery is governed too:
- Only integrations listed in `ControlAPI(graph_sources={...})` may report; alert senders can't.
- Each source's entries are tagged with its name and replaced as a set on every report. Entries people wrote, and
  other sources' entries, are never touched, and a person's description of a node wins over the discovered one.
  A source can't mark its entries as hand-written.
- A report that would remove more than half of that source's edges is refused (409) and recorded in the audit
  trail, so a broken or compromised job can't quietly strip out dependencies and lower risk scores. An admin can
  apply it with `PUT /v1/opsgraph` after review.

### AlertMind (§21, §22)

Point Alertmanager (or anything that can POST JSON) at AlertMind with an integration token:

```yaml
# alertmanager.yml
receivers:
  - name: aegis
    webhook_configs:
      - url: https://aegis.example.internal/v1/ingest/alertmanager
        http_config:
          authorization: { credentials_file: /etc/alertmanager/aegis-token }
```

For each alert, in order:

1. **Same alert already on an open incident:** counted as a repeat; a `resolved` alert marks it cleared.
2. **Silenced** (maintenance window): recorded in the audit trail and dropped.
3. **Related to an open incident:** same environment, recent activity (default 30 minutes), and the same service or
   one linked to it in the OpsGraph (or a simple dependency map), directly or via a chain. The alert is attached, the service is added
   to `affected_services`, and the incident's severity is raised if the alert is more severe.
4. **Otherwise** a new incident is opened, unless the alert is below the noise threshold (default `medium`).

```python
AlertMind(incidents, CorrelationConfig(
    dependencies={"web": ["api"], "api": ["postgres", "rabbitmq"]},
    window=timedelta(minutes=30),
    min_severity_to_open="medium",
))
```

So the spec's §22 example (database exhaustion, CPU, API timeout, queue backlog, pod restart) becomes a single incident.
Severities from different tools (`P1`, `error`, `warning`, `info`, …) are mapped to low/medium/high/critical.

### Incidents (§23, §24)

An incident (`INC-0001`, …) groups the alerts and governed executions for one problem. Agents add
`"incident_id"` to `POST /v1/agent/actions` to link an action as they take it; the incident is checked before the
action runs, so an action is never taken against an unknown or closed incident.

```
open → investigating ⇄ mitigating → resolved → closed
                 ↑__________________________|  (reopen)
```

- Agents may open incidents, attach alerts, link their own actions and set `investigating` / `mitigating`.
  Resolving and closing are left to people, and resolving requires a written resolution.
- Repeated alerts with the same fingerprint (default `source:name`) increase a count instead of adding rows.
- The timeline isn't stored separately: it's every audit event about the incident or its linked executions, so it
  has the same tamper evidence as the rest of the audit trail.
- `GET /v1/incidents/{id}/evidence` exports the whole incident, adding `incident.json` and the root cause, impact
  and resolution to `RCA.md`.

### Evidence bundles (§27)

One zip per incident, covering one or more executions:

```
evb-<id>.zip
├── manifest.json       contents, SHA-256 of every file, audit chain state at export
├── manifest.sig        HMAC-SHA256 of the manifest (when a signing key is configured)
├── timeline.json       every audit event for these executions, in order
├── RCA.md              agent hypothesis, evidence, confidence, risk, policy decision, outcome
├── remediation.json    tool, parameters, risk factors, policy reasons, result
├── approvals.json      approvers and roles, rejections, expiry
├── verification.json   verified?, rolled back?, escalated to a human?
└── audit.json          the raw hash-chained audit events
```

An auditor can check a bundle without access to the system:

```bash
python3 -m sovereign_control.evidence verify evb-1234.zip --key-file evidence.key
```

This confirms no file was changed, added or removed since export, every audit event still matches its own hash, and,
when signed, that the manifest came from a holder of the key. Each export is recorded in the audit trail with the
bundle's SHA-256, so a bundle can be matched to the system's own record of producing it. Metrics, logs and traces
will be added to bundles once telemetry sources are connected.

### Vault credentials (§51)

```python
from sovereign_control.vault import AppRoleAuth, VaultClient, VaultCredentialBroker, VaultCredentialSpec

vault = VaultClient("https://vault.example.internal:8200", AppRoleAuth(role_id, secret_id))
gw = SovereignGateway(store=store, credentials=VaultCredentialBroker(vault, {
    "k8s.restart_pod": VaultCredentialSpec("kubernetes/creds/{environment}-pod-restarter",
                                           data={"kubernetes_namespace": "{param:namespace}"},
                                           ttl=timedelta(minutes=5)),
    "db.kill_query": VaultCredentialSpec("database/creds/{environment}-dba", method="GET"),
}))
```

Only after policy and approval does AEGIS ask Vault for a credential. The tool reads it from `cred.secret` (for
example `cred.secret["service_account_token"]`), and the lease is revoked as soon as the action, its check and any
rollback finish. AEGIS logs in with a token, AppRole or Kubernetes auth, and logs in again if its session expires.

- **Fails closed.** If a tool has no Vault mapping, Vault is down or sealed, or AEGIS's login is refused, there is no
  credential and the action doesn't run; it's marked failed and escalated.
- **Dynamic secrets only.** A response with no lease or TTL (a static KV secret) is refused.
- **Agents can't redirect requests.** Placeholders are filled only from the environment, agent, tool and named
  parameters, and parameter values must be plain names, so `"../../sys/raw"` is refused before anything is sent.
- **Secrets stay out of records.** The audit trail gets the credential's source path and a fingerprint of the lease,
  not the secret. If a tool echoes a secret in its result or error, it's replaced with `[REDACTED]` before being
  recorded or stored.
- **Revocation failures are recorded,** with the lease's expiry, rather than failing an action that already happened.

The Vault role behind each path is the real permission boundary (which namespaces, which verbs, the max TTL).
[`deploy/vault/aegis-broker.hcl`](deploy/vault/aegis-broker.hcl) is a least-privilege policy for AEGIS's own Vault
identity: it can generate those credentials and revoke leases, nothing else.

### Kubernetes actions (§31)

```python
from sovereign_control.tools.kubernetes import KubeTarget, kubernetes_tools

for tool in kubernetes_tools({"production": KubeTarget("https://k8s.prod:6443", ca_file="/etc/aegis/prod-ca.crt")},
                             allowed_namespaces={"shop", "payments"}):
    gw.tools.register(tool)
```

| Tool | Does | Verified by | Undo if verification fails |
|---|---|---|---|
| `k8s.get_pods` | List pods: phase, readiness, restarts, node | n/a (read-only) | n/a |
| `k8s.restart_pod` | Delete a controller-managed pod so it's recreated | Old pod gone, controller fully ready | None; escalates to a person |
| `k8s.rollout_restart` | Rolling restart of a Deployment | Rollout completes | None; escalates |
| `k8s.scale` | Set a Deployment's replicas | That many replicas available | Scale back to the previous count |
| `k8s.rollout_undo` | Go back to the previous (or a named) revision | Rollout completes | Return to the revision it replaced |

Each call uses the short-lived token from the execution's credential (`cred.secret["service_account_token"]`, as
Vault's Kubernetes secrets engine issues it), so the tools hold no standing cluster access. Map them in Vault with
`VaultCredentialSpec("kubernetes/creds/{environment}-remediation", data={"kubernetes_namespace": "{param:namespace}"})`;
[`deploy/vault/aegis-broker.hcl`](deploy/vault/aegis-broker.hcl) lists the exact Kubernetes permissions they need.

Built-in guards, on top of policy, approval and the Vault role:
- Only namespaces in `allowed_namespaces`; names must be valid Kubernetes names.
- A pod with no controller is never deleted, since nothing would bring it back.
- Scaling to zero is refused unless `allow_scale_to_zero`; replicas are capped by `max_replicas`.
- Updates carry the object's `resourceVersion`, so if someone else changed it in the meantime the action fails with
  a conflict instead of overwriting their change. Pod deletion is pinned to the pod's UID.
- Pod templates, which can hold secrets in environment variables, are never copied into results or the audit trail;
  rollbacks refer to revision numbers.

`PYTHONPATH=. python3 examples/kubernetes_incident.py` runs the spec's §24 incident end to end through the API
against an in-memory cluster: alert → incident → investigation → rollback proposal → approval → credential →
rollback → verification → resolution → verified evidence bundle.

Policy rules can match `"mutating": True` so that, for example, "production changes need approval" doesn't also
gate read-only lookups.

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
- Running executions off the request path: verification can wait minutes for a rollout, and today the API
  handles one governance operation at a time, so other requests wait meanwhile
- Signing or external anchoring of the audit chain: the hash chain catches partial edits, but someone with write
  access to the database could rebuild the whole chain
- Metrics, logs, traces and topology in evidence bundles, once telemetry sources exist (§27, §42)
- Alert sources beyond Alertmanager and generic JSON (Grafana, Zabbix, Datadog, cloud alerts) as adapters (§21)
- Discovery beyond Kubernetes (VMware, Proxmox, cloud APIs, SNMP/LLDP, Redfish) and ChangeGraph (§34, §39);
  service-mesh or tracing data to find dependencies without annotations. Silences are in memory only
- MCP server adapters that register into the Tool Registry (§17)
- Control Tower web UI (§54; the API summary exists)
