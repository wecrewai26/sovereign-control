"""Risk engine (spec §52): explainable 0–100 score from weighted factors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import ActionContext, RiskLevel, ToolDefinition

if TYPE_CHECKING:
    from .opsgraph import OpsGraph

ENVIRONMENT_WEIGHT = {"production": 30, "prod": 30, "staging": 10, "stage": 10}
ACTION_WEIGHT = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 15, RiskLevel.HIGH: 30, RiskLevel.CRITICAL: 45}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: RiskLevel
    factors: dict[str, int]
    notes: tuple[str, ...] = ()


class RiskEngine:
    """With an OpsGraph, blast radius and customer impact come from the graph as well as the
    agent's own claims, and the larger of the two is used: an agent can raise its risk, never
    understate it."""

    def __init__(self, graph: "OpsGraph | None" = None) -> None:
        self.graph = graph

    def assess(self, tool: ToolDefinition, environment: str, ctx: ActionContext) -> RiskAssessment:
        factors: dict[str, int] = {}
        notes: list[str] = []
        if not tool.mutating:
            # Read-only tools only carry data-sensitivity risk.
            if ctx.data_sensitive:
                factors["data_sensitivity"] = 10
            return self._result(factors, notes)

        affected, customer_impact = ctx.affected_services, ctx.customer_impact
        if self.graph is not None and self.graph.nodes() and ctx.service:
            if ctx.service in self.graph:
                impact = self.graph.impact(ctx.service)
                graph_affected = 1 + len(impact["impacted"])
                if graph_affected > affected:
                    notes.append(f"blast radius from OpsGraph: {ctx.service} affects {len(impact['impacted'])} "
                                 f"other service(s) ({', '.join(impact['impacted'][:10])})")
                    affected = graph_affected
                if impact["customer_facing_impacted"] and not customer_impact:
                    notes.append("customer impact from OpsGraph: reaches "
                                 + ", ".join(impact["customer_facing_impacted"][:10]))
                    customer_impact = True
            else:
                notes.append(f"{ctx.service} is not in the OpsGraph; blast radius is the agent's claim only")

        factors["environment"] = ENVIRONMENT_WEIGHT.get(environment.lower(), 0)
        factors["action_type"] = ACTION_WEIGHT[tool.risk_level]
        factors["blast_radius"] = min(max(affected - 1, 0) * 5, 20)
        if ctx.data_sensitive:
            factors["data_sensitivity"] = 10
        if not tool.rollback_supported:
            factors["irreversible"] = 15
        if customer_impact:
            factors["customer_impact"] = 10
        confidence = min(max(ctx.confidence, 0.0), 1.0)
        factors["low_confidence"] = round((1.0 - confidence) * 20)
        return self._result(factors, notes)

    @staticmethod
    def _result(factors: dict[str, int], notes: list[str]) -> RiskAssessment:
        score = max(0, min(100, sum(factors.values())))
        return RiskAssessment(score=score, level=RiskLevel.from_score(score), factors=factors, notes=tuple(notes))
