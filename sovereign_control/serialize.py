"""JSON views of governance objects for the HTTP API."""

from __future__ import annotations

from dataclasses import asdict, fields
from typing import Any

from .approval import ApprovalRequest
from .audit import AuditEvent
from .gateway import Execution
from .incidents import Incident
from .models import ActionContext, AgentIdentity, ToolDefinition


def tool(t: ToolDefinition) -> dict[str, Any]:
    return {
        "tool_id": t.tool_id,
        "name": t.name,
        "version": t.version,
        "owner": t.owner,
        "description": t.description,
        "mutating": t.mutating,
        "risk_level": t.risk_level.name,
        "required_permissions": sorted(t.required_permissions),
        "environment_scope": sorted(t.environment_scope),
        "timeout_seconds": t.timeout_seconds,
        "approval_required": t.approval_required,
        "approval_mode": t.approval_mode.value,
        "rollback_supported": t.rollback_supported,
        "verification": t.verifier is not None,
        "input_schema": t.input_schema,
        "output_schema": t.output_schema,
    }


def agent(a: AgentIdentity) -> dict[str, Any]:
    return {
        "agent_id": a.agent_id,
        "service_account": a.service_account,
        "role": a.role,
        "tenant": a.tenant,
        "environments": sorted(a.environments),
        "permissions": sorted(a.permissions),
        "tool_scopes": sorted(a.tool_scopes),
        "autonomy": a.autonomy.name,
        "max_risk": a.max_risk.name,
        "expires_at": a.expires_at.isoformat(),
        "enabled": a.enabled,
        "active": a.is_active(),
    }


def approval(r: ApprovalRequest | None) -> dict[str, Any] | None:
    if r is None:
        return None
    return {
        "approval_id": r.approval_id,
        "execution_id": r.execution_id,
        "requested_by": r.requested_by,
        "mode": r.mode.value,
        "required_approvals": r.mode.required_approvals,
        "required_role": r.mode.required_role,
        "summary": r.summary,
        "state": r.state.value,
        "approvers": [{"user": u, "role": role} for u, role in r.approvers],
        "rejected_by": r.rejected_by,
        "reason": r.reason,
        "expires_at": r.expires_at.isoformat(),
    }


def execution(e: Execution) -> dict[str, Any]:
    return {
        "execution_id": e.execution_id,
        "agent_id": e.agent_id,
        "tool_id": e.tool_id,
        "environment": e.environment,
        "params": e.params,
        "context": asdict(e.context),
        "status": e.status.value,
        "risk": {"score": e.risk.score, "level": e.risk.level.name, "factors": e.risk.factors},
        "policy": {
            "decision": e.policy.decision.name,
            "reasons": list(e.policy.reasons),
            "approval_mode": e.policy.approval_mode.value if e.policy.approval_mode else None,
        },
        "approval": approval(e.approval),
        "result": e.result,
        "error": e.error,
        "verified": e.verified,
        "escalated": e.escalated,
        "notes": list(e.notes),
    }


def audit_event(ev: AuditEvent) -> dict[str, Any]:
    return asdict(ev)


def incident(i: Incident, timeline: list[AuditEvent] | None = None) -> dict[str, Any]:
    data = asdict(i)
    data["status"] = i.status.value
    data["alert_count"] = sum(a["count"] for a in i.alerts)
    if timeline is not None:
        data["timeline"] = [
            {"time": e.timestamp, "event": e.event_type, "actor": e.actor, "execution_id": e.execution_id,
             "details": e.data}
            for e in timeline
        ]
    return data


_CONTEXT_FIELDS = {f.name: f for f in fields(ActionContext)}
_CONTEXT_TYPES: dict[str, tuple[type, ...]] = {
    "service": (str,),
    "severity": (str,),
    "affected_services": (int,),
    "data_sensitive": (bool,),
    "customer_impact": (bool,),
    "confidence": (int, float),
    "hypothesis": (str,),
    "evidence": (list,),
}


def parse_context(raw: Any) -> ActionContext:
    """Build an ActionContext from untrusted JSON, rejecting unknown or mistyped fields."""
    if raw is None:
        return ActionContext()
    if not isinstance(raw, dict):
        raise ValueError("context must be an object")
    unknown = set(raw) - set(_CONTEXT_FIELDS)
    if unknown:
        raise ValueError(f"unknown context fields: {', '.join(sorted(unknown))}")
    for key, value in raw.items():
        expected = _CONTEXT_TYPES[key]
        # bool is a subclass of int; don't let true/false pass as a number.
        if not isinstance(value, expected) or (isinstance(value, bool) and bool not in expected):
            raise ValueError(f"context.{key} has the wrong type")
    if "evidence" in raw and not all(isinstance(x, str) for x in raw["evidence"]):
        raise ValueError("context.evidence must be a list of strings")
    if "confidence" in raw and not 0.0 <= raw["confidence"] <= 1.0:
        raise ValueError("context.confidence must be between 0 and 1")
    if "affected_services" in raw and raw["affected_services"] < 0:
        raise ValueError("context.affected_services must be >= 0")
    return ActionContext(**raw)
