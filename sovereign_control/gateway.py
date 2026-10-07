"""Sovereign gateway: the governed tool-calling flow (spec §19, §28, §29).

    Agent → Tool Registry → Risk → Policy → Approval → Credential broker
          → Execution → Verification → (Rollback) → Evidence

Every step is written to the audit log. An agent never calls a tool directly.
"""

from __future__ import annotations

import enum
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .approval import ApprovalEngine, ApprovalError, ApprovalRequest, ApprovalState
from .audit import AuditLog
from .credentials import CredentialBroker
from .models import ActionContext, Decision
from .policy import PolicyEngine, PolicyResult
from .registry import AgentRegistry, ToolRegistry
from .opsgraph import GraphConflict, OpsGraph
from .risk import RiskAssessment, RiskEngine

if TYPE_CHECKING:
    from .persistence import Store


OPSGRAPH_KEY = "opsgraph"
REDACTED = "[REDACTED]"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _redact(value: Any, secrets: list[str]) -> Any:
    """Replace any secret string a tool echoed back, so it never reaches the audit trail or storage."""
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, REDACTED)
        return value
    if isinstance(value, dict):
        return {k: _redact(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, secrets) for v in value]
    return value


class ExecutionStatus(str, enum.Enum):
    DENIED = "denied"
    RECOMMENDED = "recommended"
    PENDING_APPROVAL = "pending_approval"
    REJECTED = "rejected"
    EXECUTING = "executing"
    # The process stopped while the tool was running; the outcome is unknown and needs a human.
    INTERRUPTED = "interrupted"
    SUCCEEDED = "succeeded"
    EXECUTION_FAILED = "execution_failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


@dataclass
class Execution:
    execution_id: str
    agent_id: str
    tool_id: str
    environment: str
    params: dict[str, Any]
    context: ActionContext
    risk: RiskAssessment
    policy: PolicyResult
    status: ExecutionStatus
    approval: ApprovalRequest | None = None
    result: Any = None
    error: str | None = None
    verified: bool | None = None
    escalated: bool = False
    notes: list[str] = field(default_factory=list)


class SovereignGateway:
    def __init__(
        self,
        tools: ToolRegistry | None = None,
        agents: AgentRegistry | None = None,
        policy: PolicyEngine | None = None,
        risk: RiskEngine | None = None,
        approvals: ApprovalEngine | None = None,
        credentials: CredentialBroker | None = None,
        audit: AuditLog | None = None,
        store: "Store | None" = None,
        graph: OpsGraph | None = None,
    ) -> None:
        self.store = store
        # One shared graph: the risk engine reads it, and replacing it updates everyone.
        self.graph = graph if graph is not None else OpsGraph()
        if store and (saved := store.load_document(OPSGRAPH_KEY)) is not None:
            self.graph.replace_with(OpsGraph.from_dict(saved))  # an admin's saved graph wins over config
        self.tools = tools or ToolRegistry()
        self.agents = agents or AgentRegistry(store)
        self.policy = policy or PolicyEngine()
        self.risk = risk or RiskEngine(self.graph)
        self.approvals = approvals or ApprovalEngine()
        self.credentials = credentials or CredentialBroker()
        self.audit = audit or AuditLog(store)
        self._executions: dict[str, Execution] = {}
        if store:
            self._recover(store)

    def _recover(self, store: "Store") -> None:
        """Reload executions after a restart, reopening pending approvals.

        Anything that was mid-execution is never re-run automatically: its outcome
        is unknown, so it is marked interrupted and escalated to a human.
        """
        for execution in store.load_executions():
            self._executions[execution.execution_id] = execution
            if execution.status is ExecutionStatus.PENDING_APPROVAL and execution.approval:
                self.approvals.restore(execution.approval)
            elif execution.status is ExecutionStatus.EXECUTING:
                execution.status = ExecutionStatus.INTERRUPTED
                execution.error = "process stopped during execution; outcome unknown"
                self.audit.record("execution.interrupted", "gateway", execution.execution_id)
                self._escalate(execution, execution.error)
                self._save(execution)

    def request(
        self,
        agent_id: str,
        tool_id: str,
        environment: str,
        params: dict[str, Any] | None = None,
        context: ActionContext | None = None,
    ) -> Execution:
        """Submit a tool call. Returns the execution in its resulting state."""
        execution = self._submit(agent_id, tool_id, environment, params or {}, context or ActionContext())
        self._save(execution)
        return execution

    def _submit(
        self, agent_id: str, tool_id: str, environment: str, params: dict[str, Any], ctx: ActionContext
    ) -> Execution:
        agent = self.agents.get(agent_id)
        tool = self.tools.get(tool_id)
        execution_id = f"exe-{uuid.uuid4().hex[:12]}"

        self.audit.record(
            "tool.requested",
            agent_id,
            execution_id,
            tool_id=tool_id,
            environment=environment,
            params=params,
            hypothesis=ctx.hypothesis,
            evidence=ctx.evidence,
            confidence=ctx.confidence,
        )
        risk = self.risk.assess(tool, environment, ctx)
        self.audit.record("risk.assessed", "risk-engine", execution_id, score=risk.score, level=risk.level.name,
                          factors=risk.factors, notes=list(risk.notes))
        result = self.policy.evaluate(agent, tool, environment, ctx, risk)
        self.audit.record(
            "policy.evaluated",
            "policy-engine",
            execution_id,
            decision=result.decision.name,
            reasons=list(result.reasons),
            approval_mode=result.approval_mode.value if result.approval_mode else None,
        )

        execution = Execution(
            execution_id=execution_id,
            agent_id=agent_id,
            tool_id=tool_id,
            environment=environment,
            params=params,
            context=ctx,
            risk=risk,
            policy=result,
            status=ExecutionStatus.DENIED,
        )
        self._executions[execution_id] = execution

        if result.decision is Decision.DENY:
            return execution
        if result.decision is Decision.RECOMMEND_ONLY:
            execution.status = ExecutionStatus.RECOMMENDED
            self.audit.record("action.recommended", agent_id, execution_id)
            return execution
        if result.decision is Decision.ALLOW_WITH_APPROVAL:
            assert result.approval_mode is not None
            execution.approval = self.approvals.open(
                execution_id, agent_id, result.approval_mode, f"{tool_id} in {environment} ({risk.level.name} risk)"
            )
            execution.status = ExecutionStatus.PENDING_APPROVAL
            self.audit.record(
                "approval.requested", agent_id, execution_id,
                approval_id=execution.approval.approval_id, mode=result.approval_mode.value,
            )
            return execution

        self._execute(execution)
        return execution

    def approve(self, execution_id: str, user: str, role: str) -> Execution:
        execution = self._pending(execution_id)
        assert execution.approval is not None
        approval = self.approvals.approve(execution.approval.approval_id, user, role)
        self.audit.record("approval.granted", user, execution_id, role=role, state=approval.state.value)
        if approval.state is ApprovalState.APPROVED:
            self._execute(execution)
        self._save(execution)
        return execution

    def reject(self, execution_id: str, user: str, reason: str = "") -> Execution:
        execution = self._pending(execution_id)
        assert execution.approval is not None
        self.approvals.reject(execution.approval.approval_id, user, reason)
        execution.status = ExecutionStatus.REJECTED
        self.audit.record("approval.rejected", user, execution_id, reason=reason)
        self._save(execution)
        return execution

    def get(self, execution_id: str) -> Execution:
        return self._executions[execution_id]

    def executions(self) -> list[Execution]:
        return list(self._executions.values())

    def _pending(self, execution_id: str) -> Execution:
        execution = self.get(execution_id)
        if execution.status is not ExecutionStatus.PENDING_APPROVAL or execution.approval is None:
            raise ApprovalError(f"execution {execution_id} is not awaiting approval")
        return execution

    def _execute(self, execution: Execution) -> None:
        tool = self.tools.get(execution.tool_id)
        eid = execution.execution_id
        # Re-check identity at execution time: approval may arrive after the agent was disabled.
        if not self.agents.get(execution.agent_id).is_active():
            execution.status = ExecutionStatus.DENIED
            execution.error = "agent identity disabled or expired before execution"
            self.audit.record("tool.blocked", "gateway", eid, reason=execution.error)
            return

        # Persist before touching infrastructure so a crash mid-action is visible on restart.
        execution.status = ExecutionStatus.EXECUTING
        self._save(execution)
        try:
            cred = self.credentials.issue(execution.agent_id, tool.tool_id, execution.environment,
                                          params=execution.params)
        except Exception as exc:  # noqa: BLE001 - no credential means the action must not run
            execution.status = ExecutionStatus.EXECUTION_FAILED
            execution.error = f"credential could not be issued: {type(exc).__name__}: {exc}"
            self.audit.record("credential.failed", "credential-broker", eid, error=execution.error)
            self._escalate(execution, "no credential; action not taken")
            return
        self.audit.record("credential.issued", "credential-broker", eid, source=cred.source,
                          expires_at=cred.expires_at.isoformat(),
                          lease=_fingerprint(cred.lease_id) if cred.lease_id else None)
        secrets_in_use = cred.secret_values()
        try:
            try:
                execution.result = _redact(tool.handler(execution.params, cred), secrets_in_use)
            except Exception as exc:  # noqa: BLE001 - tool failures are data, not crashes
                execution.status = ExecutionStatus.EXECUTION_FAILED
                execution.error = _redact(f"{type(exc).__name__}: {exc}", secrets_in_use)
                self.audit.record("tool.failed", execution.agent_id, eid, error=execution.error)
                self._escalate(execution, "execution failed")
                return
            self.audit.record("tool.executed", execution.agent_id, eid, result=execution.result)

            if tool.verifier is None:
                execution.status = ExecutionStatus.SUCCEEDED
                execution.notes.append("no verifier registered; success is unverified")
                self.audit.record("verification.skipped", "verification-engine", eid)
                return

            execution.verified = self._verify(execution, tool.verifier)
            if execution.verified:
                execution.status = ExecutionStatus.SUCCEEDED
                return
            self._rollback(execution, cred)
        finally:
            try:
                self.credentials.revoke(cred)
                self.audit.record("credential.revoked", "credential-broker", eid)
            except Exception as exc:  # noqa: BLE001 - the lease still expires at its TTL
                self.audit.record("credential.revoke_failed", "credential-broker", eid,
                                  error=f"{type(exc).__name__}: {exc}", expires_at=cred.expires_at.isoformat())

    def _verify(self, execution: Execution, verifier) -> bool:
        try:
            ok = bool(verifier(execution.params, execution.result))
        except Exception as exc:  # noqa: BLE001
            execution.notes.append(f"verifier raised {type(exc).__name__}: {exc}")
            ok = False
        self.audit.record("verification.completed", "verification-engine", execution.execution_id, passed=ok)
        return ok

    def _rollback(self, execution: Execution, cred) -> None:
        tool = self.tools.get(execution.tool_id)
        eid = execution.execution_id
        if tool.rollback is None:
            execution.status = ExecutionStatus.ROLLBACK_FAILED
            execution.error = "verification failed and tool has no rollback"
            self.audit.record("rollback.unavailable", "rollback-engine", eid)
            self._escalate(execution, execution.error)
            return
        try:
            tool.rollback(execution.params, execution.result, cred)
        except Exception as exc:  # noqa: BLE001
            execution.status = ExecutionStatus.ROLLBACK_FAILED
            execution.error = f"rollback raised {type(exc).__name__}: {exc}"
            self.audit.record("rollback.failed", "rollback-engine", eid, error=execution.error)
        else:
            execution.status = ExecutionStatus.ROLLED_BACK
            self.audit.record("rollback.completed", "rollback-engine", eid)
        self._escalate(execution, "verification failed")

    def replace_graph(self, graph: OpsGraph, *, actor: str) -> str:
        """Replace the OpsGraph everywhere, persist it, and record the change."""
        self.graph.replace_with(graph)
        if self.store:
            self.store.save_document(OPSGRAPH_KEY, self.graph.to_dict())
        fingerprint = self.graph.fingerprint()
        self.audit.record("opsgraph.replaced", actor, None, fingerprint=fingerprint,
                          nodes=len(self.graph.nodes()), edges=len(self.graph.edges()))
        return fingerprint

    def merge_discovered_graph(
        self, origin: str, discovered: OpsGraph, *, max_edge_removal: float = 0.5
    ) -> dict[str, Any]:
        """Replace what `origin` previously reported with `discovered`, keeping everything else.

        Removing edges lowers blast radius and so lowers risk scores. A submission that would
        remove more than `max_edge_removal` of this source's edges is refused; an admin can
        apply it with a full replace instead.
        """
        before = {(e.source, e.kind, e.target) for e in self.graph.edges() if e.origin == origin}
        after = {(e.source, e.kind, e.target) for e in discovered.edges()}
        removed, added = before - after, after - before
        if before and len(removed) / len(before) > max_edge_removal:
            self.audit.record("opsgraph.discovery_refused", origin, None, removed_edges=len(removed),
                              previous_edges=len(before), reason="too many edges removed at once")
            raise GraphConflict(
                f"refused: this would remove {len(removed)} of {len(before)} edges from {origin}; "
                "an admin must review and apply it with PUT /v1/opsgraph")
        self.graph.replace_with(self.graph.merged_with_origin(origin, discovered))
        if self.store:
            self.store.save_document(OPSGRAPH_KEY, self.graph.to_dict())
        stats = {"origin": origin, "fingerprint": self.graph.fingerprint(), "edges_added": len(added),
                 "edges_removed": len(removed), "nodes": len(self.graph.nodes()), "edges": len(self.graph.edges())}
        self.audit.record("opsgraph.discovered", origin, None, **stats,
                          removed=sorted(f"{s} {k} {t}" for s, k, t in removed)[:50])
        return stats

    def _save(self, execution: Execution) -> None:
        if self.store:
            self.store.save_execution(execution)

    def _escalate(self, execution: Execution, reason: str) -> None:
        execution.escalated = True
        self.audit.record("escalated.to_human", "gateway", execution.execution_id, reason=reason)
