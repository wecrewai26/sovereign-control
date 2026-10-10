"""Live, read-only cluster views for people (spec §42, §43, §54) - the Lens-style page in AEGIS.

    viewer = ClusterViewer(gateway, {
        "production": ClusterConfig(
            KubeTarget("https://k8s.prod:6443", ca_file="/etc/aegis/prod-ca.crt"),
            namespaces={"shop", "payments"},
            prometheus=PrometheusTarget("http://prometheus.monitoring:9090")),
    })

Viewing is governed like acting, at L0 (Observe):
- Every read uses a fresh short-lived credential from the credential broker, requested for the
  pseudo-tool `k8s.read` (map it in Vault to a role with get/list/log only), revoked right after.
- Only the configured namespaces can be viewed.
- Who looked at which pods, deployments, events and logs is written to the audit trail.
  Metrics (aggregate CPU/memory numbers) are not, to keep the trail readable.
- Logs and event messages pass through secret redaction before they reach the screen.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from .redaction import redact_text
from .tools.kubernetes import KubeAPI, KubeError, KubeTarget

if TYPE_CHECKING:
    from .gateway import SovereignGateway

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
READ_TOOL = "k8s.read"


class ClusterViewError(RuntimeError):
    status = 502


class NotAllowed(ClusterViewError):
    status = 403


class NotFound(ClusterViewError):
    status = 404


class BadRequest(ClusterViewError):
    status = 400


@dataclass(frozen=True)
class PrometheusTarget:
    url: str
    bearer_token: str | None = None  # read-only Prometheus access; prefer a proxy that adds auth
    ca_file: str | None = None
    timeout: float = 15.0


@dataclass(frozen=True)
class ClusterConfig:
    target: KubeTarget
    namespaces: frozenset[str] | set[str]
    prometheus: PrometheusTarget | None = None


class ClusterViewer:
    def __init__(self, gateway: "SovereignGateway", clusters: dict[str, ClusterConfig],
                 guard: Callable[[], Any] | None = None) -> None:
        self.gateway = gateway
        self.clusters = {env: ClusterConfig(c.target, frozenset(c.namespaces), c.prometheus)
                         for env, c in clusters.items()}
        # Serializes access to shared governance state (credential broker, audit log) while the
        # slow cluster calls themselves run without holding it.
        self._guard = guard

    # ---- plumbing ------------------------------------------------------------------

    def list_clusters(self) -> list[dict[str, Any]]:
        return [{"environment": env, "namespaces": sorted(c.namespaces), "metrics": c.prometheus is not None}
                for env, c in sorted(self.clusters.items())]

    def _config(self, env: str, namespace: str) -> ClusterConfig:
        config = self.clusters.get(env)
        if config is None:
            raise NotFound(f"no cluster is configured for environment {env!r}")
        if not _NAME.match(namespace or ""):
            raise BadRequest("namespace must be a valid Kubernetes name")
        if namespace not in config.namespaces:
            raise NotAllowed(f"namespace {namespace!r} is not viewable in {env}")
        return config

    def _locked(self, fn: Callable[[], Any]) -> Any:
        if self._guard is None:
            return fn()
        with self._guard():
            return fn()

    def _read(self, actor: str, env: str, namespace: str, fn: Callable[[KubeAPI], Any]) -> Any:
        config = self._config(env, namespace)
        cred = self._locked(lambda: self.gateway.credentials.issue(actor, READ_TOOL, env,
                                                                   params={"namespace": namespace}))
        try:
            token = cred.secret.get("service_account_token")
            if not token:
                raise ClusterViewError("the read credential has no Kubernetes service account token")
            try:
                return fn(KubeAPI(config.target, token))
            except KubeError as exc:
                if "HTTP 404" in str(exc):
                    raise NotFound(str(exc)) from None
                raise ClusterViewError(str(exc)) from None
        finally:
            try:
                self._locked(lambda: self.gateway.credentials.revoke(cred))
            except Exception:  # noqa: BLE001 - the lease expires on its own; nothing to show the viewer
                pass

    def _audit(self, event: str, actor: str, **data: Any) -> None:
        self._locked(lambda: self.gateway.audit.record(event, actor, None, **data))

    # ---- views ---------------------------------------------------------------------

    def pods(self, actor: str, env: str, namespace: str) -> dict[str, Any]:
        def read(k: KubeAPI) -> list[dict[str, Any]]:
            pods = k.get(f"/api/v1/namespaces/{namespace}/pods").get("items", [])
            rs_owner = {}
            for rs in k.get(f"/apis/apps/v1/namespaces/{namespace}/replicasets").get("items", []):
                owner = _controller(rs)
                if owner:
                    rs_owner[rs["metadata"]["name"]] = owner
            return [_pod_row(p, rs_owner) for p in pods]

        rows = self._read(actor, env, namespace, read)
        usage = self._pod_usage(env, namespace)
        for row in rows:
            row["cpu_cores"], row["memory_bytes"] = usage.get(row["name"], (None, None))
        rows.sort(key=lambda r: r["name"])
        self._audit("cluster.viewed", actor, environment=env, namespace=namespace, resource="pods")
        return {"environment": env, "namespace": namespace,
                "metrics": self.clusters[env].prometheus is not None, "pods": rows}

    def deployments(self, actor: str, env: str, namespace: str) -> dict[str, Any]:
        def read(k: KubeAPI) -> list[dict[str, Any]]:
            out = []
            for d in k.get(f"/apis/apps/v1/namespaces/{namespace}/deployments").get("items", []):
                spec, status = d.get("spec") or {}, d.get("status") or {}
                out.append({
                    "name": d["metadata"]["name"],
                    "replicas": spec.get("replicas", 1),
                    "ready": status.get("readyReplicas", 0),
                    "updated": status.get("updatedReplicas", 0),
                    "available": status.get("availableReplicas", 0),
                    "revision": (d["metadata"].get("annotations") or {}).get("deployment.kubernetes.io/revision"),
                    "age_seconds": _age(d["metadata"].get("creationTimestamp")),
                })
            return sorted(out, key=lambda r: r["name"])

        rows = self._read(actor, env, namespace, read)
        self._audit("cluster.viewed", actor, environment=env, namespace=namespace, resource="deployments")
        return {"environment": env, "namespace": namespace, "deployments": rows}

    def events(self, actor: str, env: str, namespace: str, limit: int = 200) -> dict[str, Any]:
        def read(k: KubeAPI) -> list[dict[str, Any]]:
            out = []
            for e in k.get(f"/api/v1/namespaces/{namespace}/events").get("items", []):
                obj = e.get("involvedObject") or {}
                last = e.get("lastTimestamp") or e.get("eventTime") or e["metadata"].get("creationTimestamp")
                message, _ = redact_text(e.get("message", ""))
                out.append({"type": e.get("type"), "reason": e.get("reason"),
                            "object": f"{obj.get('kind', '')}/{obj.get('name', '')}", "message": message,
                            "count": e.get("count", 1), "last_seen": last, "age_seconds": _age(last)})
            out.sort(key=lambda r: r["last_seen"] or "", reverse=True)
            return out[:limit]

        rows = self._read(actor, env, namespace, read)
        self._audit("cluster.viewed", actor, environment=env, namespace=namespace, resource="events")
        return {"environment": env, "namespace": namespace, "events": rows}

    def logs(self, actor: str, env: str, namespace: str, pod: str, container: str | None = None,
             tail: int = 200) -> dict[str, Any]:
        if not _NAME.match(pod or "") or (container is not None and not _NAME.match(container)):
            raise BadRequest("pod and container must be valid Kubernetes names")
        if not 1 <= tail <= 2000:
            raise BadRequest("tail must be between 1 and 2000 lines")
        query = {"tailLines": tail, "timestamps": "true", "limitBytes": 1_000_000}
        if container:
            query["container"] = container
        path = f"/api/v1/namespaces/{namespace}/pods/{pod}/log?{urllib.parse.urlencode(query)}"
        text = self._read(actor, env, namespace, lambda k: k.get_text(path))
        text, redactions = redact_text(text)
        self._audit("cluster.logs_viewed", actor, environment=env, namespace=namespace, pod=pod,
                    container=container, lines=tail, redactions=redactions)
        return {"environment": env, "namespace": namespace, "pod": pod, "container": container,
                "redactions": redactions, "lines": text.splitlines()}

    # ---- metrics (Prometheus) ---------------------------------------------------------

    def pod_metrics(self, env: str, namespace: str, pod: str, minutes: int = 60) -> dict[str, Any]:
        config = self._config(env, namespace)
        if config.prometheus is None:
            raise NotFound(f"no Prometheus is configured for {env}")
        if not _NAME.match(pod or ""):
            raise BadRequest("pod must be a valid Kubernetes name")
        if not 5 <= minutes <= 7 * 24 * 60:
            raise BadRequest("minutes must be between 5 and 10080")
        selector = f'namespace="{namespace}",pod="{pod}",container!="",image!=""'
        now = datetime.now(timezone.utc).timestamp()
        start, step = now - minutes * 60, max(15, minutes * 60 // 120)
        prom = _Prometheus(config.prometheus)
        cpu = prom.range(f"sum(rate(container_cpu_usage_seconds_total{{{selector}}}[5m]))", start, now, step)
        memory = prom.range(f"sum(container_memory_working_set_bytes{{{selector}}})", start, now, step)
        return {"environment": env, "namespace": namespace, "pod": pod, "minutes": minutes, "step_seconds": step,
                "cpu_cores": cpu, "memory_bytes": memory}

    def _pod_usage(self, env: str, namespace: str) -> dict[str, tuple[float | None, float | None]]:
        config = self.clusters[env]
        if config.prometheus is None:
            return {}
        prom = _Prometheus(config.prometheus)
        selector = f'namespace="{namespace}",container!="",image!=""'
        try:
            cpu = prom.instant(f"sum by (pod) (rate(container_cpu_usage_seconds_total{{{selector}}}[5m]))")
            memory = prom.instant(f"sum by (pod) (container_memory_working_set_bytes{{{selector}}})")
        except ClusterViewError:
            return {}  # the pod list is still useful without usage numbers
        names = set(cpu) | set(memory)
        return {name: (cpu.get(name), memory.get(name)) for name in names}


class _Prometheus:
    def __init__(self, target: PrometheusTarget) -> None:
        self.target = target
        self._ssl = ssl.create_default_context(cafile=target.ca_file) if target.url.startswith("https") else None

    def _query(self, path: str, params: dict[str, Any]) -> Any:
        url = f"{self.target.url.rstrip('/')}{path}?{urllib.parse.urlencode(params)}"
        headers = {"Accept": "application/json"}
        if self.target.bearer_token:
            headers["Authorization"] = f"Bearer {self.target.bearer_token}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=self.target.timeout,
                                        context=self._ssl) as resp:
                body = json.load(resp)
        except urllib.error.HTTPError as exc:
            raise ClusterViewError(f"Prometheus returned HTTP {exc.code}") from None
        except (urllib.error.URLError, ValueError) as exc:
            raise ClusterViewError(f"Prometheus unreachable: {getattr(exc, 'reason', exc)}") from None
        if body.get("status") != "success":
            raise ClusterViewError(f"Prometheus query failed: {body.get('error', 'unknown error')}")
        return body["data"]["result"]

    def instant(self, query: str) -> dict[str, float]:
        return {r["metric"].get("pod", ""): float(r["value"][1]) for r in self._query("/api/v1/query", {"query": query})}

    def range(self, query: str, start: float, end: float, step: int) -> list[list[float]]:
        result = self._query("/api/v1/query_range", {"query": query, "start": start, "end": end, "step": step})
        if not result:
            return []
        return [[float(t), float(v)] for t, v in result[0]["values"]]


# ---- shaping, like Lens ------------------------------------------------------------------


def _controller(obj: dict[str, Any]) -> dict[str, str] | None:
    for ref in obj["metadata"].get("ownerReferences") or []:
        if ref.get("controller"):
            return {"kind": ref.get("kind", ""), "name": ref.get("name", "")}
    return None


def _age(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        then = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((datetime.now(timezone.utc) - then).total_seconds()))


def _pod_row(pod: dict[str, Any], rs_owner: dict[str, dict[str, str]]) -> dict[str, Any]:
    meta, spec, status = pod["metadata"], pod.get("spec") or {}, pod.get("status") or {}
    containers = []
    statuses = {s["name"]: s for s in status.get("containerStatuses") or []}
    for c in spec.get("containers") or []:
        s = statuses.get(c["name"], {})
        state = s.get("state") or {}
        if "running" in state:
            st = "running"
        elif "waiting" in state:
            st = state["waiting"].get("reason") or "waiting"
        elif "terminated" in state:
            st = state["terminated"].get("reason") or "terminated"
        else:
            st = "unknown"
        containers.append({"name": c["name"], "ready": bool(s.get("ready")), "state": st,
                           "restarts": s.get("restartCount", 0)})

    # Status as Lens shows it: deletion, then a pod-level reason (Evicted), then the first
    # problem a container reports (CrashLoopBackOff), then the phase.
    if meta.get("deletionTimestamp"):
        display = "Terminating"
    elif status.get("reason"):
        display = status["reason"]
    else:
        problem = next((c["state"] for c in containers if c["state"] not in ("running", "Completed", "unknown")),
                       None)
        display = problem or status.get("phase") or "Unknown"

    owner = _controller(pod)
    if owner and owner["kind"] == "ReplicaSet" and owner["name"] in rs_owner:
        owner = rs_owner[owner["name"]]
    return {
        "name": meta["name"],
        "namespace": meta.get("namespace"),
        "status": display,
        "phase": status.get("phase"),
        "containers": containers,
        "restarts": sum(c["restarts"] for c in containers),
        "controlled_by": owner,
        "node": spec.get("nodeName"),
        "qos": status.get("qosClass"),
        "age_seconds": _age(meta.get("creationTimestamp")),
        "message": redact_text(status.get("message", ""))[0] or None,
    }
