"""Durable state (spec §26, §27): audit trail, agent identities, executions, tokens.

`SQLiteStore` uses only the standard library, so it works air-gapped. Tools and
policy rules are code/configuration and are re-registered at startup; everything
that records what happened is persisted here.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, Iterator, Protocol

from .models import (
    ActionContext,
    AgentIdentity,
    ApprovalMode,
    AutonomyLevel,
    Decision,
    RiskLevel,
)

if TYPE_CHECKING:
    from .approval import ApprovalRequest
    from .audit import AuditEvent
    from .gateway import Execution
    from .incidents import Incident


class Store(Protocol):
    def save_agent(self, agent: AgentIdentity) -> None: ...
    def load_agents(self) -> list[AgentIdentity]: ...
    def append_audit(self, event: "AuditEvent") -> None: ...
    def load_audit(self) -> list["AuditEvent"]: ...
    def save_execution(self, execution: "Execution") -> None: ...
    def load_executions(self) -> list["Execution"]: ...
    def save_token(self, token_hash: str, kind: str, principal_id: str, roles: list[str]) -> None: ...
    def delete_token(self, token_hash: str) -> None: ...
    def load_tokens(self) -> list[tuple[str, str, str, list[str]]]: ...
    def save_incident(self, incident: "Incident") -> None: ...
    def load_incidents(self) -> list["Incident"]: ...
    def save_document(self, key: str, data: Any) -> None: ...
    def load_document(self, key: str) -> Any: ...


_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS executions (execution_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents (incident_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents (key TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, principal_id TEXT NOT NULL, roles TEXT NOT NULL
);
"""


class SQLiteStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    def _write(self, sql: str, args: tuple[Any, ...]) -> None:
        with self._lock:
            self._db.execute(sql, args)

    def _rows_args(self, sql: str, args: tuple[Any, ...]) -> list[tuple[Any, ...]]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _rows(self, sql: str) -> Iterator[tuple[Any, ...]]:
        with self._lock:
            rows = self._db.execute(sql).fetchall()
        return iter(rows)

    # agents
    def save_agent(self, agent: AgentIdentity) -> None:
        self._write(
            "INSERT INTO agents (agent_id, data) VALUES (?, ?) "
            "ON CONFLICT(agent_id) DO UPDATE SET data = excluded.data",
            (agent.agent_id, _dumps(agent_to_dict(agent))),
        )

    def load_agents(self) -> list[AgentIdentity]:
        return [agent_from_dict(json.loads(d)) for (d,) in self._rows("SELECT data FROM agents ORDER BY rowid")]

    # audit — append-only: INSERT without upsert, so a duplicate seq fails loudly.
    def append_audit(self, event: "AuditEvent") -> None:
        self._write("INSERT INTO audit (seq, data) VALUES (?, ?)", (event.seq, _dumps(asdict(event))))

    def load_audit(self) -> list["AuditEvent"]:
        from .audit import AuditEvent

        return [AuditEvent(**json.loads(d)) for (d,) in self._rows("SELECT data FROM audit ORDER BY seq")]

    # executions
    def save_execution(self, execution: "Execution") -> None:
        self._write(
            "INSERT INTO executions (execution_id, data) VALUES (?, ?) "
            "ON CONFLICT(execution_id) DO UPDATE SET data = excluded.data",
            (execution.execution_id, _dumps(execution_to_dict(execution))),
        )

    def load_executions(self) -> list["Execution"]:
        rows = self._rows("SELECT data FROM executions ORDER BY rowid")
        return [execution_from_dict(json.loads(d)) for (d,) in rows]

    # tokens (hashes only)
    def save_token(self, token_hash: str, kind: str, principal_id: str, roles: list[str]) -> None:
        self._write(
            "INSERT OR REPLACE INTO tokens (token_hash, kind, principal_id, roles) VALUES (?, ?, ?, ?)",
            (token_hash, kind, principal_id, _dumps(sorted(roles))),
        )

    def delete_token(self, token_hash: str) -> None:
        self._write("DELETE FROM tokens WHERE token_hash = ?", (token_hash,))

    def load_tokens(self) -> list[tuple[str, str, str, list[str]]]:
        rows = self._rows("SELECT token_hash, kind, principal_id, roles FROM tokens")
        return [(h, k, p, json.loads(r)) for h, k, p, r in rows]

    # named documents (configuration such as the OpsGraph)
    def save_document(self, key: str, data: Any) -> None:
        self._write(
            "INSERT INTO documents (key, data) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET data = excluded.data",
            (key, _dumps(data)),
        )

    def load_document(self, key: str) -> Any:
        rows = list(self._rows_args("SELECT data FROM documents WHERE key = ?", (key,)))
        return json.loads(rows[0][0]) if rows else None

    # incidents
    def save_incident(self, incident: "Incident") -> None:
        data = asdict(incident)
        data["status"] = incident.status.value
        self._write(
            "INSERT INTO incidents (incident_id, data) VALUES (?, ?) "
            "ON CONFLICT(incident_id) DO UPDATE SET data = excluded.data",
            (incident.incident_id, _dumps(data)),
        )

    def load_incidents(self) -> list["Incident"]:
        from .incidents import Incident, IncidentStatus

        incidents = []
        for (raw,) in self._rows("SELECT data FROM incidents ORDER BY rowid"):
            data = json.loads(raw)
            data["status"] = IncidentStatus(data["status"])
            incidents.append(Incident(**data))
        return incidents


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


# ---- codecs -----------------------------------------------------------------


def agent_to_dict(a: AgentIdentity) -> dict[str, Any]:
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
    }


def agent_from_dict(d: dict[str, Any]) -> AgentIdentity:
    return AgentIdentity(
        agent_id=d["agent_id"],
        service_account=d["service_account"],
        role=d["role"],
        tenant=d["tenant"],
        environments=frozenset(d["environments"]),
        permissions=frozenset(d["permissions"]),
        tool_scopes=frozenset(d["tool_scopes"]),
        autonomy=AutonomyLevel[d["autonomy"]],
        max_risk=RiskLevel[d["max_risk"]],
        expires_at=datetime.fromisoformat(d["expires_at"]),
        enabled=d["enabled"],
    )


def approval_to_dict(r: "ApprovalRequest") -> dict[str, Any]:
    return {
        "approval_id": r.approval_id,
        "execution_id": r.execution_id,
        "requested_by": r.requested_by,
        "mode": r.mode.value,
        "summary": r.summary,
        "expires_at": r.expires_at.isoformat(),
        "state": r.state.value,
        "approvers": [list(a) for a in r.approvers],
        "rejected_by": r.rejected_by,
        "reason": r.reason,
    }


def approval_from_dict(d: dict[str, Any]) -> "ApprovalRequest":
    from .approval import ApprovalRequest, ApprovalState

    return ApprovalRequest(
        approval_id=d["approval_id"],
        execution_id=d["execution_id"],
        requested_by=d["requested_by"],
        mode=ApprovalMode(d["mode"]),
        summary=d["summary"],
        expires_at=datetime.fromisoformat(d["expires_at"]),
        state=ApprovalState(d["state"]),
        approvers=[(u, role) for u, role in d["approvers"]],
        rejected_by=d["rejected_by"],
        reason=d["reason"],
    )


def execution_to_dict(e: "Execution") -> dict[str, Any]:
    return {
        "execution_id": e.execution_id,
        "agent_id": e.agent_id,
        "tool_id": e.tool_id,
        "environment": e.environment,
        "params": e.params,
        "context": asdict(e.context),
        "risk": {"score": e.risk.score, "level": e.risk.level.name, "factors": e.risk.factors,
                 "notes": list(e.risk.notes)},
        "policy": {
            "decision": e.policy.decision.name,
            "reasons": list(e.policy.reasons),
            "approval_mode": e.policy.approval_mode.value if e.policy.approval_mode else None,
        },
        "status": e.status.value,
        "approval": approval_to_dict(e.approval) if e.approval else None,
        "result": e.result,
        "error": e.error,
        "verified": e.verified,
        "escalated": e.escalated,
        "notes": list(e.notes),
    }


def execution_from_dict(d: dict[str, Any]) -> "Execution":
    from .gateway import Execution, ExecutionStatus
    from .policy import PolicyResult
    from .risk import RiskAssessment

    policy = d["policy"]
    return Execution(
        execution_id=d["execution_id"],
        agent_id=d["agent_id"],
        tool_id=d["tool_id"],
        environment=d["environment"],
        params=d["params"],
        context=ActionContext(**d["context"]),
        risk=RiskAssessment(score=d["risk"]["score"], level=RiskLevel[d["risk"]["level"]], factors=d["risk"]["factors"],
                            notes=tuple(d["risk"].get("notes", ()))),
        policy=PolicyResult(
            decision=Decision[policy["decision"]],
            reasons=tuple(policy["reasons"]),
            approval_mode=ApprovalMode(policy["approval_mode"]) if policy["approval_mode"] else None,
        ),
        status=ExecutionStatus(d["status"]),
        approval=approval_from_dict(d["approval"]) if d["approval"] else None,
        result=d["result"],
        error=d["error"],
        verified=d["verified"],
        escalated=d["escalated"],
        notes=list(d["notes"]),
    )
