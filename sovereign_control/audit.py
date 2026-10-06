"""Audit engine (spec §4.4, §26, §27).

Append-only, hash-chained log: each event commits to the previous event's hash,
so any edit, insertion or deletion is detectable by `verify()`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from .models import utcnow

if TYPE_CHECKING:
    from .persistence import Store

GENESIS_HASH = "0" * 64


class AuditIntegrityError(RuntimeError):
    """The stored audit chain does not verify; refuse to append to it."""


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    timestamp: str
    event_type: str
    actor: str
    execution_id: str | None
    data: dict[str, Any]
    prev_hash: str
    hash: str


def _digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


class AuditLog:
    def __init__(self, store: "Store | None" = None) -> None:
        self._store = store
        self._events: list[AuditEvent] = store.load_audit() if store else []
        if not self.verify():
            raise AuditIntegrityError("stored audit chain failed verification; it may have been tampered with")

    def record(self, event_type: str, actor: str, execution_id: str | None = None, **data: Any) -> AuditEvent:
        prev_hash = self._events[-1].hash if self._events else GENESIS_HASH
        payload = {
            "seq": len(self._events),
            "timestamp": utcnow().isoformat(),
            "event_type": event_type,
            "actor": actor,
            "execution_id": execution_id,
            "data": json.loads(json.dumps(data, default=str)),
            "prev_hash": prev_hash,
        }
        event = AuditEvent(**payload, hash=_digest(payload))
        if self._store:
            self._store.append_audit(event)  # durable first: an action is never recorded only in memory
        self._events.append(event)
        return event

    def events(self, execution_id: str | None = None) -> list[AuditEvent]:
        if execution_id is None:
            return list(self._events)
        return [e for e in self._events if e.execution_id == execution_id]

    def verify(self) -> bool:
        prev_hash = GENESIS_HASH
        for seq, event in enumerate(self._events):
            payload = asdict(event)
            claimed = payload.pop("hash")
            if event.seq != seq or event.prev_hash != prev_hash or _digest(payload) != claimed:
                return False
            prev_hash = claimed
        return True

    def export(self, execution_id: str | None = None) -> str:
        return json.dumps([asdict(e) for e in self.events(execution_id)], indent=2)
