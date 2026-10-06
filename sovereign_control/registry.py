"""Central tool registry (spec §18) and agent identity registry (spec §47)."""

from __future__ import annotations

from datetime import timedelta

from .models import AgentIdentity, AutonomyLevel, RiskLevel, ToolDefinition, utcnow


class RegistryError(KeyError):
    pass


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> ToolDefinition:
        if tool.tool_id in self._tools:
            raise ValueError(f"tool already registered: {tool.tool_id}")
        self._tools[tool.tool_id] = tool
        return tool

    def get(self, tool_id: str) -> ToolDefinition:
        try:
            return self._tools[tool_id]
        except KeyError:
            raise RegistryError(f"unknown tool: {tool_id}") from None

    def all(self) -> list[ToolDefinition]:
        return list(self._tools.values())


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}

    def issue(
        self,
        agent_id: str,
        *,
        role: str,
        tenant: str,
        environments: set[str],
        permissions: set[str],
        tool_scopes: set[str],
        autonomy: AutonomyLevel = AutonomyLevel.L0_OBSERVE,
        max_risk: RiskLevel = RiskLevel.LOW,
        ttl: timedelta = timedelta(hours=8),
    ) -> AgentIdentity:
        if agent_id in self._agents:
            raise ValueError(f"agent already exists: {agent_id}")
        identity = AgentIdentity(
            agent_id=agent_id,
            service_account=f"sa-agent-{agent_id}",
            role=role,
            tenant=tenant,
            environments=frozenset(environments),
            permissions=frozenset(permissions),
            tool_scopes=frozenset(tool_scopes),
            autonomy=autonomy,
            max_risk=max_risk,
            expires_at=utcnow() + ttl,
        )
        self._agents[agent_id] = identity
        return identity

    def get(self, agent_id: str) -> AgentIdentity:
        try:
            return self._agents[agent_id]
        except KeyError:
            raise RegistryError(f"unknown agent: {agent_id}") from None

    def disable(self, agent_id: str) -> None:
        self.get(agent_id).enabled = False

    def all(self) -> list[AgentIdentity]:
        return list(self._agents.values())
