"""HashiCorp Vault dynamic credentials (spec §51).

    Agent → Policy approval → Vault → Short-lived credential → Tool execution → Credential revoked

Each tool is mapped to a Vault path that *generates* a credential on request, such as
the Kubernetes, database or AWS secrets engines:

    VaultCredentialBroker(client, {
        "k8s.restart_pod": VaultCredentialSpec(
            "kubernetes/creds/{environment}-pod-restarter",
            data={"kubernetes_namespace": "{param:namespace}"},
            ttl=timedelta(minutes=5)),
        "db.kill_query": VaultCredentialSpec("database/creds/{environment}-dba", method="GET"),
    })

The Vault role behind each path is the real permission boundary: it decides what the
credential can do. AEGIS decides whether this agent may use it for this action, asks
for it only after policy and approval, hands it to the tool for one execution, and
revokes the lease straight afterwards.

Rules this module enforces:
- Fail closed: a tool with no mapping, or any Vault error, means no credential and the
  action does not run.
- Only dynamic secrets: a response without a lease or TTL (a static KV secret) is refused.
- Placeholders are filled only from the environment, agent, tool and execution
  parameters, and parameter values must be plain names, so an agent cannot steer a
  request to another Vault path.
"""

from __future__ import annotations

import json
import re
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .credentials import CredentialBroker, CredentialError
from .models import Credential, utcnow

_PLACEHOLDER = re.compile(r"\{(environment|agent_id|tool_id|param:[A-Za-z0-9_]+)\}")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")


class VaultError(CredentialError):
    pass


# ---- authentication -----------------------------------------------------------------


@dataclass(frozen=True)
class TokenAuth:
    token: str


@dataclass(frozen=True)
class AppRoleAuth:
    role_id: str
    secret_id: str
    mount: str = "approle"


@dataclass(frozen=True)
class KubernetesAuth:
    role: str
    jwt_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    mount: str = "kubernetes"


VaultAuth = TokenAuth | AppRoleAuth | KubernetesAuth


class VaultClient:
    """Minimal Vault HTTP client (standard library only)."""

    def __init__(
        self,
        addr: str,
        auth: VaultAuth,
        *,
        namespace: str | None = None,
        ca_file: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.addr = addr.rstrip("/")
        self.auth = auth
        self.namespace = namespace
        self.timeout = timeout
        self._ssl = ssl.create_default_context(cafile=ca_file) if addr.startswith("https") else None
        self._token: str | None = auth.token if isinstance(auth, TokenAuth) else None

    def request(self, method: str, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._token is None:
            self._login()
        try:
            return self._send(method, path, data, self._token)
        except _Forbidden:
            if isinstance(self.auth, TokenAuth):
                raise VaultError(f"{method} {path}: permission denied") from None
            self._login()  # the login token may have expired; try once more with a fresh one
            try:
                return self._send(method, path, data, self._token)
            except _Forbidden:
                raise VaultError(f"{method} {path}: permission denied") from None

    def _login(self) -> None:
        if isinstance(self.auth, AppRoleAuth):
            path, body = f"auth/{self.auth.mount}/login", {"role_id": self.auth.role_id,
                                                           "secret_id": self.auth.secret_id}
        elif isinstance(self.auth, KubernetesAuth):
            try:
                with open(self.auth.jwt_path) as fh:
                    jwt = fh.read().strip()
            except OSError as exc:
                raise VaultError(f"cannot read service account token: {exc}") from None
            path, body = f"auth/{self.auth.mount}/login", {"role": self.auth.role, "jwt": jwt}
        else:
            raise VaultError("token auth has no login")
        try:
            response = self._send("POST", path, body, None)
        except _Forbidden:
            raise VaultError("Vault login was refused") from None
        token = (response.get("auth") or {}).get("client_token")
        if not token:
            raise VaultError("Vault login returned no token")
        self._token = token

    def _send(self, method: str, path: str, data: dict[str, Any] | None, token: str | None) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"{self.addr}/v1/{path}", data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self._ssl) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise _Forbidden() from None
            detail = _vault_errors(exc.read())
            raise VaultError(f"{method} {path}: HTTP {exc.code}{': ' + detail if detail else ''}") from None
        except urllib.error.URLError as exc:
            raise VaultError(f"Vault unreachable: {exc.reason}") from None
        return json.loads(raw) if raw else {}


class _Forbidden(Exception):
    pass


def _vault_errors(raw: bytes) -> str:
    try:
        return "; ".join(str(e) for e in json.loads(raw).get("errors", []))[:300]
    except (ValueError, AttributeError):
        return ""


# ---- broker -----------------------------------------------------------------------


@dataclass(frozen=True)
class VaultCredentialSpec:
    path: str
    method: str = "POST"
    data: dict[str, str] = field(default_factory=dict)
    ttl: timedelta | None = None  # requested TTL, sent as "ttl" unless send_ttl is False
    send_ttl: bool = True


class VaultCredentialBroker(CredentialBroker):
    def __init__(
        self,
        client: VaultClient,
        specs: dict[str, VaultCredentialSpec],
        *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        super().__init__(ttl)
        self.client = client
        self.specs = dict(specs)

    def issue(
        self,
        agent_id: str,
        tool_id: str,
        environment: str,
        ttl: timedelta | None = None,
        params: dict[str, Any] | None = None,
    ) -> Credential:
        spec = self.specs.get(tool_id)
        if spec is None:
            raise VaultError(f"no Vault credential is configured for tool {tool_id}")
        values = {"environment": environment, "agent_id": agent_id, "tool_id": tool_id}
        path = _fill(spec.path, values, params or {})
        data = {k: _fill(v, values, params or {}) for k, v in spec.data.items()}
        requested = ttl or spec.ttl or self.ttl
        if spec.send_ttl and spec.method.upper() != "GET":
            data.setdefault("ttl", f"{int(requested.total_seconds())}s")

        response = self.client.request(spec.method.upper(), path, data if spec.method.upper() != "GET" else None)
        lease_id = response.get("lease_id") or ""
        lease_seconds = int(response.get("lease_duration") or 0)
        if not lease_id and lease_seconds <= 0:
            raise VaultError(f"{path} returned a static secret (no lease); only dynamic credentials are allowed")
        secret = response.get("data") or {}
        if not isinstance(secret, dict) or not secret:
            raise VaultError(f"{path} returned no credential data")

        now = utcnow()
        lifetime = timedelta(seconds=lease_seconds) if lease_seconds > 0 else requested
        cred = Credential(
            token=secrets.token_urlsafe(24),  # an opaque handle; the secret itself is in `secret`
            agent_id=agent_id,
            tool_id=tool_id,
            environment=environment,
            issued_at=now,
            expires_at=now + lifetime,
            source=f"vault:{path}",
            secret=secret,
            lease_id=lease_id,
        )
        self._issued[cred.token] = cred
        return cred

    def revoke(self, cred: Credential) -> None:
        cred.revoked = True
        cred.secret = {}  # drop the material from memory whether or not Vault answers
        if cred.lease_id:
            self.client.request("PUT", "sys/leases/revoke", {"lease_id": cred.lease_id})


def _fill(template: str, values: dict[str, str], params: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key.startswith("param:"):
            name = key.split(":", 1)[1]
            value = params.get(name)
            if not isinstance(value, str) or not _SAFE_VALUE.match(value):
                raise VaultError(f"parameter {name!r} must be a plain name to be used in a Vault request")
            return value
        value = values[key]
        if not _SAFE_VALUE.match(value):
            raise VaultError(f"{key} {value!r} is not a plain name")
        return value

    result = _PLACEHOLDER.sub(replace, template)
    if "{" in result or "}" in result:
        raise VaultError(f"unknown placeholder in {template!r}")
    return result
