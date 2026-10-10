"""Policy engine (spec §4.4, §4.5, §46, §49).

Evaluation is default-deny and strictest-wins: built-in guardrails (identity,
scope, permissions, risk ceiling, autonomy level) produce a baseline decision,
then declarative rules can only make it stricter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import (
    ActionContext,
    AgentIdentity,
    ApprovalMode,
    AutonomyLevel,
    Decision,
    RiskLevel,
    ToolDefinition,
)
from .risk import RiskAssessment


@dataclass(frozen=True)
class PolicyRule:
    """Declarative rule. Each `match` key must equal (or be contained in) the request attribute.

    Supported keys: role, environment, tool_id, mutating, severity, service, risk_level, min_risk_level.
    Use {"mutating": True} to target only tools that change something (e.g. "production changes
    need approval" without also gating read-only lookups).
    """

    name: str
    effect: Decision
    match: dict[str, Any] = field(default_factory=dict)
    approval_mode: ApprovalMode = ApprovalMode.SINGLE

    def matches(self, attrs: dict[str, Any]) -> bool:
        for key, expected in self.match.items():
            if key == "min_risk_level":
                if attrs["risk_level"] < expected:
                    return False
                continue
            actual = attrs.get(key)
            if isinstance(expected, (set, frozenset, list, tuple)):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reasons: tuple[str, ...]
    approval_mode: ApprovalMode | None = None


class PolicyEngine:
    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self.rules: list[PolicyRule] = list(rules or [])

    def add_rule(self, rule: PolicyRule) -> None:
        self.rules.append(rule)

    def evaluate(
        self,
        agent: AgentIdentity,
        tool: ToolDefinition,
        environment: str,
        ctx: ActionContext,
        risk: RiskAssessment,
    ) -> PolicyResult:
        denials = self._guardrail_denials(agent, tool, environment, risk)
        if denials:
            return PolicyResult(Decision.DENY, tuple(denials))

        decision, reasons, mode = self._autonomy_baseline(agent, tool, risk)

        attrs = {
            "role": agent.role,
            "environment": environment,
            "tool_id": tool.tool_id,
            "mutating": tool.mutating,
            "severity": ctx.severity,
            "service": ctx.service,
            "risk_level": risk.level,
        }
        for rule in self.rules:
            if not rule.matches(attrs) or rule.effect < decision:
                continue
            if rule.effect > decision:
                reasons = []
                mode = None
            decision = rule.effect
            reasons.append(f"rule:{rule.name}")
            if decision is Decision.ALLOW_WITH_APPROVAL:
                mode = _stricter_mode(mode, rule.approval_mode)

        if decision is Decision.ALLOW_WITH_APPROVAL and mode is None:
            mode = tool.approval_mode
        if decision is not Decision.ALLOW_WITH_APPROVAL:
            mode = None
        return PolicyResult(decision, tuple(reasons), mode)

    @staticmethod
    def _guardrail_denials(
        agent: AgentIdentity, tool: ToolDefinition, environment: str, risk: RiskAssessment
    ) -> list[str]:
        denials = []
        if not agent.is_active():
            denials.append("agent identity disabled or expired")
        if tool.tool_id not in agent.tool_scopes:
            denials.append(f"tool {tool.tool_id} not in agent tool scope")
        if environment not in agent.environments:
            denials.append(f"environment {environment} not in agent scope")
        if tool.environment_scope and environment not in tool.environment_scope:
            denials.append(f"tool {tool.tool_id} not permitted in {environment}")
        missing = tool.required_permissions - agent.permissions
        if missing:
            denials.append(f"missing permissions: {', '.join(sorted(missing))}")
        if risk.level > agent.max_risk:
            denials.append(f"risk {risk.level.name} exceeds agent ceiling {agent.max_risk.name}")
        return denials

    @staticmethod
    def _autonomy_baseline(
        agent: AgentIdentity, tool: ToolDefinition, risk: RiskAssessment
    ) -> tuple[Decision, list[str], ApprovalMode | None]:
        level = agent.autonomy
        if not tool.mutating:
            return Decision.ALLOW, ["read-only tool"], None
        if level <= AutonomyLevel.L1_INVESTIGATE:
            return Decision.DENY, [f"autonomy {level.name} cannot change state"], None
        if level == AutonomyLevel.L2_RECOMMEND:
            return Decision.RECOMMEND_ONLY, [f"autonomy {level.name} may only recommend"], None
        if tool.approval_required:
            return Decision.ALLOW_WITH_APPROVAL, ["tool requires approval"], tool.approval_mode
        if level == AutonomyLevel.L3_APPROVED_EXECUTION:
            return Decision.ALLOW_WITH_APPROVAL, [f"autonomy {level.name} requires approval"], None
        if level == AutonomyLevel.L4_POLICY_AUTONOMOUS and risk.level > RiskLevel.LOW:
            return (
                Decision.ALLOW_WITH_APPROVAL,
                [f"autonomy {level.name} auto-executes LOW risk only"],
                None,
            )
        return Decision.ALLOW, [f"autonomy {level.name} within policy boundary"], None


_MODE_STRICTNESS = [
    ApprovalMode.SINGLE,
    ApprovalMode.SERVICE_OWNER,
    ApprovalMode.MANAGER,
    ApprovalMode.DUAL,
    ApprovalMode.SECURITY,
    ApprovalMode.CAB,
]


def _stricter_mode(a: ApprovalMode | None, b: ApprovalMode) -> ApprovalMode:
    if a is None:
        return b
    return max(a, b, key=_MODE_STRICTNESS.index)
