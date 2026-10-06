"""Credential broker (spec §51).

Agents never hold standing credentials. A short-lived token scoped to one
agent, tool and environment is minted per execution and revoked afterwards.
A production deployment would back this with Vault dynamic secrets; the
interface stays the same.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from .models import Credential, utcnow


class CredentialBroker:
    def __init__(self, ttl: timedelta = timedelta(minutes=5)) -> None:
        self.ttl = ttl
        self._issued: dict[str, Credential] = {}

    def issue(self, agent_id: str, tool_id: str, environment: str, ttl: timedelta | None = None) -> Credential:
        now = utcnow()
        cred = Credential(
            token=secrets.token_urlsafe(24),
            agent_id=agent_id,
            tool_id=tool_id,
            environment=environment,
            issued_at=now,
            expires_at=now + (ttl or self.ttl),
        )
        self._issued[cred.token] = cred
        return cred

    def revoke(self, cred: Credential) -> None:
        cred.revoked = True

    def active(self) -> list[Credential]:
        return [c for c in self._issued.values() if c.is_valid()]
