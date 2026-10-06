"""HTTP API and Agent Gateway (spec §10).

    /v1/agent/...   Agent Gateway: agents submit and track their own tool calls
    /v1/...         API Gateway: humans review, approve, audit and administer

`ControlAPI.handle()` is transport-independent (method, path, headers, body in;
status and JSON out) so it can be tested directly and mounted behind any server.
`serve()` runs it on the standard-library threaded HTTP server.
"""

from __future__ import annotations

import json
import re
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from . import serialize
from .approval import ApprovalError
from .evidence import EvidenceError, build_bundle
from .auth import Authenticator, Principal, PrincipalKind
from .gateway import ExecutionStatus, SovereignGateway
from .models import RiskLevel
from .registry import RegistryError

MAX_BODY_BYTES = 1_000_000
ADMIN_ROLE = "admin"


class HTTPError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class FileResponse:
    """A non-JSON response body, sent as a download."""

    def __init__(self, content: bytes, content_type: str, filename: str, headers: dict[str, str] | None = None):
        self.content = content
        self.content_type = content_type
        self.filename = filename
        self.headers = headers or {}


Response = tuple[int, Any]
Handler = Callable[["Request"], Any]


class Request:
    def __init__(self, principal: Principal, params: dict[str, str], query: dict[str, list[str]], body: bytes):
        self.principal = principal
        self.params = params
        self.query = query
        self._body = body

    def json(self) -> dict[str, Any]:
        if not self._body:
            return {}
        try:
            data = json.loads(self._body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPError(400, f"invalid JSON: {exc}") from None
        if not isinstance(data, dict):
            raise HTTPError(400, "request body must be a JSON object")
        return data

    def q(self, name: str) -> str | None:
        values = self.query.get(name)
        return values[0] if values else None


class ControlAPI:
    def __init__(
        self, gateway: SovereignGateway, authenticator: Authenticator, evidence_signing_key: bytes | None = None
    ) -> None:
        self.gateway = gateway
        self.auth = authenticator
        self.evidence_signing_key = evidence_signing_key
        # The governance core is not thread-safe; serialize access to it.
        self._lock = threading.Lock()
        self._routes: list[tuple[str, re.Pattern[str], PrincipalKind, Handler]] = []

        agent, user = PrincipalKind.AGENT, PrincipalKind.USER
        self._route("POST", "/v1/agent/actions", agent, self.agent_submit)
        self._route("GET", "/v1/agent/actions/{id}", agent, self.agent_get)
        self._route("GET", "/v1/agent/me", agent, self.agent_me)

        self._route("GET", "/v1/tools", user, self.list_tools)
        self._route("GET", "/v1/agents", user, self.list_agents)
        self._route("POST", "/v1/agents/{id}/disable", user, self.disable_agent)
        self._route("GET", "/v1/executions", user, self.list_executions)
        self._route("GET", "/v1/executions/{id}", user, self.get_execution)
        self._route("POST", "/v1/executions/{id}/approve", user, self.approve)
        self._route("POST", "/v1/executions/{id}/reject", user, self.reject)
        self._route("GET", "/v1/approvals", user, self.list_approvals)
        self._route("GET", "/v1/audit", user, self.list_audit)
        self._route("GET", "/v1/audit/verify", user, self.verify_audit)
        self._route("GET", "/v1/control-tower", user, self.control_tower)
        self._route("GET", "/v1/evidence", user, self.export_evidence)

    def _route(self, method: str, template: str, kind: PrincipalKind, handler: Handler) -> None:
        pattern = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[A-Za-z0-9_.:-]+)", template) + "$")
        self._routes.append((method, pattern, kind, handler))

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes = b"") -> Response:
        try:
            return 200, self._dispatch(method.upper(), target, headers, body)
        except HTTPError as exc:
            return exc.status, {"error": exc.message}
        except Exception:  # noqa: BLE001 - never leak internals to callers
            return 500, {"error": "internal error"}

    def _dispatch(self, method: str, target: str, headers: dict[str, str], body: bytes) -> Any:
        url = urlsplit(target)
        if url.path == "/healthz" and method == "GET":
            return {"status": "ok"}

        matched_path = False
        for route_method, pattern, kind, handler in self._routes:
            m = pattern.match(url.path)
            if not m:
                continue
            matched_path = True
            if route_method != method:
                continue
            principal = self._authenticate(headers)
            if principal.kind is not kind:
                raise HTTPError(403, f"endpoint requires a {kind.value} credential")
            request = Request(principal, m.groupdict(), parse_qs(url.query), body)
            with self._lock:
                try:
                    return handler(request)
                except RegistryError as exc:
                    raise HTTPError(404, str(exc.args[0])) from None
                except ApprovalError as exc:
                    raise HTTPError(409, str(exc)) from None
        raise HTTPError(405 if matched_path else 404, "method not allowed" if matched_path else "not found")

    def _authenticate(self, headers: dict[str, str]) -> Principal:
        value = {k.lower(): v for k, v in headers.items()}.get("authorization", "")
        scheme, _, token = value.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPError(401, "missing bearer token")
        principal = self.auth.authenticate(token.strip())
        if principal is None:
            raise HTTPError(401, "invalid token")
        return principal

    # ---- Agent Gateway ------------------------------------------------------

    def agent_submit(self, req: Request) -> Any:
        data = req.json()
        tool_id, environment = data.get("tool_id"), data.get("environment")
        if not isinstance(tool_id, str) or not isinstance(environment, str):
            raise HTTPError(400, "tool_id and environment are required strings")
        params = data.get("params", {})
        if not isinstance(params, dict):
            raise HTTPError(400, "params must be an object")
        try:
            ctx = serialize.parse_context(data.get("context"))
        except ValueError as exc:
            raise HTTPError(400, str(exc)) from None
        # The agent identity comes from the credential, never from the request body.
        execution = self.gateway.request(req.principal.id, tool_id, environment, params, ctx)
        return serialize.execution(execution)

    def agent_get(self, req: Request) -> Any:
        execution = self._execution(req.params["id"])
        if execution.agent_id != req.principal.id:
            raise HTTPError(404, "execution not found")
        return serialize.execution(execution)

    def agent_me(self, req: Request) -> Any:
        return serialize.agent(self.gateway.agents.get(req.principal.id))

    # ---- Human API ----------------------------------------------------------

    def list_tools(self, req: Request) -> Any:
        return {"tools": [serialize.tool(t) for t in self.gateway.tools.all()]}

    def list_agents(self, req: Request) -> Any:
        return {"agents": [serialize.agent(a) for a in self.gateway.agents.all()]}

    def disable_agent(self, req: Request) -> Any:
        if ADMIN_ROLE not in req.principal.roles:
            raise HTTPError(403, f"requires role {ADMIN_ROLE}")
        agent_id = req.params["id"]
        self.gateway.agents.disable(agent_id)
        self.gateway.audit.record("agent.disabled", req.principal.id, None, agent_id=agent_id)
        return serialize.agent(self.gateway.agents.get(agent_id))

    def list_executions(self, req: Request) -> Any:
        executions = self.gateway.executions()
        status = req.q("status")
        if status:
            try:
                wanted = ExecutionStatus(status)
            except ValueError:
                raise HTTPError(400, f"unknown status: {status}") from None
            executions = [e for e in executions if e.status is wanted]
        for key in ("agent_id", "environment", "tool_id"):
            value = req.q(key)
            if value:
                executions = [e for e in executions if getattr(e, key) == value]
        return {"executions": [serialize.execution(e) for e in executions]}

    def get_execution(self, req: Request) -> Any:
        return serialize.execution(self._execution(req.params["id"]))

    def approve(self, req: Request) -> Any:
        role = req.json().get("role")
        if not isinstance(role, str) or role not in req.principal.roles:
            raise HTTPError(403, "role must be one of the caller's roles")
        self._execution(req.params["id"])
        return serialize.execution(self.gateway.approve(req.params["id"], req.principal.id, role))

    def reject(self, req: Request) -> Any:
        reason = req.json().get("reason", "")
        if not isinstance(reason, str):
            raise HTTPError(400, "reason must be a string")
        self._execution(req.params["id"])
        return serialize.execution(self.gateway.reject(req.params["id"], req.principal.id, reason))

    def list_approvals(self, req: Request) -> Any:
        return {"approvals": [serialize.approval(a) for a in self.gateway.approvals.pending()]}

    def list_audit(self, req: Request) -> Any:
        events = self.gateway.audit.events(req.q("execution_id"))
        return {"events": [serialize.audit_event(e) for e in events]}

    def verify_audit(self, req: Request) -> Any:
        return {"valid": self.gateway.audit.verify(), "events": len(self.gateway.audit.events())}

    def control_tower(self, req: Request) -> Any:
        """Spec §54: an enterprise-wide summary of agents, actions and governance state."""
        agents = self.gateway.agents.all()
        executions = self.gateway.executions()
        risky = [e for e in executions if e.risk.level >= RiskLevel.HIGH]
        return {
            "agents": {"total": len(agents), "active": sum(a.is_active() for a in agents)},
            "executions": dict(Counter(e.status.value for e in executions)),
            "pending_approvals": len(self.gateway.approvals.pending()),
            "blocked_actions": sum(e.status is ExecutionStatus.DENIED for e in executions),
            "escalations": sum(e.escalated for e in executions),
            "risky_actions": [
                {"execution_id": e.execution_id, "agent_id": e.agent_id, "tool_id": e.tool_id,
                 "risk": e.risk.level.name, "status": e.status.value}
                for e in risky[-20:]
            ],
            "policies": len(self.gateway.policy.rules),
            "active_credentials": len(self.gateway.credentials.active()),
            "audit": {"events": len(self.gateway.audit.events()), "chain_valid": self.gateway.audit.verify()},
        }

    def export_evidence(self, req: Request) -> Any:
        """Spec §27: download an evidence bundle for one or more executions (?execution_id=… repeatable)."""
        title = req.q("title") or ""
        try:
            bundle = build_bundle(
                self.gateway, req.query.get("execution_id", []), exported_by=req.principal.id,
                title=title, signing_key=self.evidence_signing_key,
            )
        except EvidenceError as exc:
            raise HTTPError(404 if str(exc).startswith("unknown") else 400, str(exc)) from None
        return FileResponse(bundle.content, "application/zip", bundle.filename,
                            {"X-Evidence-SHA256": bundle.sha256, "X-Evidence-Bundle-Id": bundle.bundle_id})

    def _execution(self, execution_id: str):
        try:
            return self.gateway.get(execution_id)
        except KeyError:
            raise HTTPError(404, "execution not found") from None


def _make_handler(api: ControlAPI) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SovereignControl/0.1"

        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                status, payload = 413, {"error": "request body too large"}
            else:
                body = self.rfile.read(length) if length else b""
                status, payload = api.handle(self.command, self.path, dict(self.headers), body)
            extra: dict[str, str] = {}
            if isinstance(payload, FileResponse):
                data, content_type = payload.content, payload.content_type
                extra = {"Content-Disposition": f'attachment; filename="{payload.filename}"', **payload.headers}
            else:
                data, content_type = json.dumps(payload, default=str).encode(), "application/json"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _serve

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            pass

    return Handler


def make_server(api: ControlAPI, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), _make_handler(api))


def serve(api: ControlAPI, host: str = "127.0.0.1", port: int = 8080) -> None:
    server = make_server(api, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
