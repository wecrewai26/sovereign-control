"""Caller authentication for the HTTP API.

Two kinds of principal reach the API (spec §10, §48):
- humans (operators, approvers, admins) through the API Gateway;
- agents through the Agent Gateway, each with a token bound to its agent identity.

`TokenAuthenticator` is the built-in bearer-token implementation. Tokens are
stored only as SHA-256 hashes. A Keycloak/OIDC authenticator can replace it by
implementing the same `authenticate(token)` method.
"""

from __future__ import annotations

import enum
import hashlib
import secrets
from dataclasses import dataclass
from typing import Protocol


class PrincipalKind(str, enum.Enum):
    USER = "user"
    AGENT = "agent"


@dataclass(frozen=True)
class Principal:
    kind: PrincipalKind
    id: str
    roles: frozenset[str] = frozenset()


class Authenticator(Protocol):
    def authenticate(self, token: str) -> Principal | None: ...


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenAuthenticator:
    def __init__(self) -> None:
        self._principals: dict[str, Principal] = {}

    def add_user(self, user_id: str, roles: set[str], token: str | None = None) -> str:
        return self._add(Principal(PrincipalKind.USER, user_id, frozenset(roles)), token)

    def add_agent(self, agent_id: str, token: str | None = None) -> str:
        return self._add(Principal(PrincipalKind.AGENT, agent_id), token)

    def revoke(self, token: str) -> None:
        self._principals.pop(_hash(token), None)

    def authenticate(self, token: str) -> Principal | None:
        return self._principals.get(_hash(token))

    def _add(self, principal: Principal, token: str | None) -> str:
        token = token or secrets.token_urlsafe(32)
        self._principals[_hash(token)] = principal
        return token
