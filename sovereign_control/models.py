"""Core data types for the Sovereign Control governance plane."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AutonomyLevel(enum.IntEnum):
    """Spec §4.5 — configurable, human-controlled autonomy."""

    L0_OBSERVE = 0
    L1_INVESTIGATE = 1
    L2_RECOMMEND = 2
    L3_APPROVED_EXECUTION = 3
    L4_POLICY_AUTONOMOUS = 4
    L5_CLOSED_LOOP = 5


class RiskLevel(enum.IntEnum):
    """Spec §52 score bands."""

    LOW = 1  # 0–20
    MEDIUM = 2  # 21–50
    HIGH = 3  # 51–80
    CRITICAL = 4  # 81–100

    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        if score <= 20:
            return cls.LOW
        if score <= 50:
            return cls.MEDIUM
        if score <= 80:
            return cls.HIGH
        return cls.CRITICAL


class Decision(enum.IntEnum):
    """Policy outcomes, ordered from least to most restrictive."""

    ALLOW = 0
    ALLOW_WITH_APPROVAL = 1
    RECOMMEND_ONLY = 2
    DENY = 3


class ApprovalMode(str, enum.Enum):
    """Spec §53 approval modes."""

    SINGLE = "single"
    DUAL = "dual"
    MANAGER = "manager"
    SERVICE_OWNER = "service_owner"
    SECURITY = "security"
    CAB = "cab"

    @property
    def required_approvals(self) -> int:
        return 2 if self is ApprovalMode.DUAL else 1

    @property
    def required_role(self) -> str | None:
        return {
            ApprovalMode.MANAGER: "manager",
            ApprovalMode.SERVICE_OWNER: "service_owner",
            ApprovalMode.SECURITY: "security",
            ApprovalMode.CAB: "cab",
        }.get(self)


ToolHandler = Callable[[dict[str, Any], "Credential"], Any]
Verifier = Callable[[dict[str, Any], Any], bool]
RollbackHandler = Callable[[dict[str, Any], Any, "Credential"], Any]


@dataclass
class ToolDefinition:
    """Spec §18 — every tool is registered centrally with its governance metadata."""

    tool_id: str
    name: str
    version: str
    owner: str
    description: str
    handler: ToolHandler
    mutating: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    required_permissions: frozenset[str] = frozenset()
    environment_scope: frozenset[str] = frozenset()  # empty = any environment
    timeout_seconds: int = 60
    approval_required: bool = False
    approval_mode: ApprovalMode = ApprovalMode.SINGLE
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    verifier: Verifier | None = None
    rollback: RollbackHandler | None = None

    @property
    def rollback_supported(self) -> bool:
        return self.rollback is not None


@dataclass
class AgentIdentity:
    """Spec §47 — every agent has its own scoped, expiring identity."""

    agent_id: str
    service_account: str
    role: str
    tenant: str
    environments: frozenset[str]
    permissions: frozenset[str]
    tool_scopes: frozenset[str]
    autonomy: AutonomyLevel
    max_risk: RiskLevel
    expires_at: datetime
    enabled: bool = True

    def is_active(self, now: datetime | None = None) -> bool:
        return self.enabled and (now or utcnow()) < self.expires_at


@dataclass
class ActionContext:
    """Facts about the target of an action, used for risk and policy (spec §49, §52)."""

    service: str = ""
    severity: str = "low"
    affected_services: int = 1
    data_sensitive: bool = False
    customer_impact: bool = False
    confidence: float = 1.0
    hypothesis: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class Credential:
    """Short-lived, scoped credential handed to a tool for one execution (spec §51)."""

    token: str
    agent_id: str
    tool_id: str
    environment: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False

    def is_valid(self, now: datetime | None = None) -> bool:
        return not self.revoked and (now or utcnow()) < self.expires_at
