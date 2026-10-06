"""Risk engine (spec §52): explainable 0–100 score from weighted factors."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ActionContext, RiskLevel, ToolDefinition

ENVIRONMENT_WEIGHT = {"production": 30, "prod": 30, "staging": 10, "stage": 10}
ACTION_WEIGHT = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 15, RiskLevel.HIGH: 30, RiskLevel.CRITICAL: 45}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: RiskLevel
    factors: dict[str, int]


class RiskEngine:
    def assess(self, tool: ToolDefinition, environment: str, ctx: ActionContext) -> RiskAssessment:
        factors: dict[str, int] = {}
        if not tool.mutating:
            # Read-only tools only carry data-sensitivity risk.
            if ctx.data_sensitive:
                factors["data_sensitivity"] = 10
            return self._result(factors)

        factors["environment"] = ENVIRONMENT_WEIGHT.get(environment.lower(), 0)
        factors["action_type"] = ACTION_WEIGHT[tool.risk_level]
        factors["blast_radius"] = min(max(ctx.affected_services - 1, 0) * 5, 20)
        if ctx.data_sensitive:
            factors["data_sensitivity"] = 10
        if not tool.rollback_supported:
            factors["irreversible"] = 15
        if ctx.customer_impact:
            factors["customer_impact"] = 10
        confidence = min(max(ctx.confidence, 0.0), 1.0)
        factors["low_confidence"] = round((1.0 - confidence) * 20)
        return self._result(factors)

    @staticmethod
    def _result(factors: dict[str, int]) -> RiskAssessment:
        score = max(0, min(100, sum(factors.values())))
        return RiskAssessment(score=score, level=RiskLevel.from_score(score), factors=factors)
