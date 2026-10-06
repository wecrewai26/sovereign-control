"""Approval engine (spec §53)."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import ApprovalMode, utcnow


class ApprovalState(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalError(ValueError):
    pass


@dataclass
class ApprovalRequest:
    approval_id: str
    execution_id: str
    requested_by: str
    mode: ApprovalMode
    summary: str
    expires_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    approvers: list[tuple[str, str]] = field(default_factory=list)  # (user, role)
    rejected_by: str | None = None
    reason: str = ""


class ApprovalEngine:
    def __init__(self, ttl: timedelta = timedelta(hours=1)) -> None:
        self.ttl = ttl
        self._requests: dict[str, ApprovalRequest] = {}

    def open(self, execution_id: str, requested_by: str, mode: ApprovalMode, summary: str) -> ApprovalRequest:
        req = ApprovalRequest(
            approval_id=f"apr-{uuid.uuid4().hex[:12]}",
            execution_id=execution_id,
            requested_by=requested_by,
            mode=mode,
            summary=summary,
            expires_at=utcnow() + self.ttl,
        )
        self._requests[req.approval_id] = req
        return req

    def get(self, approval_id: str) -> ApprovalRequest:
        try:
            req = self._requests[approval_id]
        except KeyError:
            raise ApprovalError(f"unknown approval: {approval_id}") from None
        if req.state is ApprovalState.PENDING and utcnow() >= req.expires_at:
            req.state = ApprovalState.EXPIRED
        return req

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in (self.get(a) for a in list(self._requests)) if r.state is ApprovalState.PENDING]

    def approve(self, approval_id: str, user: str, role: str) -> ApprovalRequest:
        req = self._require_pending(approval_id)
        if user == req.requested_by:
            raise ApprovalError("requester cannot approve their own action")
        if any(u == user for u, _ in req.approvers):
            raise ApprovalError(f"{user} has already approved")
        required_role = req.mode.required_role
        if required_role and role != required_role:
            raise ApprovalError(f"{req.mode.value} approval requires role {required_role}")
        req.approvers.append((user, role))
        if len(req.approvers) >= req.mode.required_approvals:
            req.state = ApprovalState.APPROVED
        return req

    def reject(self, approval_id: str, user: str, reason: str = "") -> ApprovalRequest:
        req = self._require_pending(approval_id)
        req.state = ApprovalState.REJECTED
        req.rejected_by = user
        req.reason = reason
        return req

    def _require_pending(self, approval_id: str) -> ApprovalRequest:
        req = self.get(approval_id)
        if req.state is not ApprovalState.PENDING:
            raise ApprovalError(f"approval {approval_id} is {req.state.value}")
        return req
