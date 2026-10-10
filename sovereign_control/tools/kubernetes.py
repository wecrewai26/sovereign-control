"""Kubernetes remediation pack (spec §31): real cluster actions with verification and rollback.

    tools = kubernetes_tools({"production": KubeTarget("https://k8s.prod:6443", ca_file="/etc/aegis/prod-ca.crt")},
                             allowed_namespaces={"shop", "payments"})
    for tool in tools:
        gw.tools.register(tool)

| tool                  | does                                   | verified by                         | rollback            |
|-----------------------|----------------------------------------|-------------------------------------|---------------------|
| k8s.get_pods          | list pods, phase, readiness, restarts  | –                                   | – (read-only)       |
| k8s.restart_pod       | delete a controller-managed pod        | its controller is fully ready again | none (recreated)    |
| k8s.rollout_restart   | rolling restart of a Deployment        | the rollout completes               | none                |
| k8s.scale             | set a Deployment's replicas            | that many replicas are available    | scale back          |
| k8s.rollout_undo      | go back to the previous revision       | the rollout completes               | redo the revision   |

Every call authenticates with the short-lived token in the execution's credential
(`cred.secret["service_account_token"]`, as issued by Vault's Kubernetes secrets engine),
so these tools hold no standing access to the cluster.

Guards, on top of policy, approval and the Vault role:
- namespaces are limited to `allowed_namespaces`; names must be valid Kubernetes names;
- a pod without a controller is never deleted (nothing would bring it back);
- scaling to zero is refused unless `allow_scale_to_zero`, and replicas are capped by `max_replicas`;
- updates use the object's resourceVersion, so a concurrent change makes the action fail
  instead of silently overwriting it;
- nothing that could hold secrets (such as pod templates and their environment) is
  copied into the result, which is what reaches the audit trail.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from ..models import Credential, RiskLevel, ToolDefinition

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
REVISION = "deployment.kubernetes.io/revision"


class KubeError(RuntimeError):
    pass


@dataclass(frozen=True)
class KubeTarget:
    server: str
    ca_file: str | None = None
    timeout: float = 15.0


class KubeAPI:
    """Minimal Kubernetes REST client bound to one execution's credential."""

    def __init__(self, target: KubeTarget, token: str) -> None:
        self.target = target
        self._token = token
        self._ssl = ssl.create_default_context(cafile=target.ca_file) if target.server.startswith("https") else None

    def request(self, method: str, path: str, body: Any = None, content_type: str = "application/json",
                *, text: bool = False) -> Any:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "text/plain" if text else "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.target.server.rstrip("/") + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.target.timeout, context=self._ssl) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            message = ""
            try:
                message = json.loads(exc.read()).get("message", "")
            except (ValueError, AttributeError):
                pass
            raise KubeError(f"{method} {path}: HTTP {exc.code}{' ' + message if message else ''}") from None
        except urllib.error.URLError as exc:
            raise KubeError(f"Kubernetes API unreachable: {exc.reason}") from None
        if text:
            return raw.decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def get_text(self, path: str) -> str:
        return self.request("GET", path, text=True)


def kubernetes_tools(
    targets: dict[str, KubeTarget],
    *,
    allowed_namespaces: set[str],
    max_replicas: int = 50,
    allow_scale_to_zero: bool = False,
    verify_timeout: float = 180.0,
    poll_interval: float = 3.0,
    sleep: Callable[[float], None] = time.sleep,
) -> list[ToolDefinition]:
    """Build the pack. `targets` maps an AEGIS environment (e.g. "production") to a cluster."""
    namespaces = frozenset(allowed_namespaces)
    if not namespaces:
        raise ValueError("allowed_namespaces must name at least one namespace")

    def api(cred: Credential) -> KubeAPI:
        target = targets.get(cred.environment)
        if target is None:
            raise KubeError(f"no cluster is configured for environment {cred.environment!r}")
        token = cred.secret.get("service_account_token")
        if not token:
            raise KubeError("the credential has no Kubernetes service account token")
        return KubeAPI(target, token)

    def name(params: dict[str, Any], key: str) -> str:
        value = params.get(key)
        if not isinstance(value, str) or not _NAME.match(value):
            raise KubeError(f"{key} must be a valid Kubernetes name")
        return value

    def namespace(params: dict[str, Any]) -> str:
        ns = name(params, "namespace")
        if ns not in namespaces:
            raise KubeError(f"namespace {ns!r} is not one AEGIS may act in")
        return ns

    def wait(check: Callable[[], tuple[bool, str]]) -> bool:
        deadline = time.monotonic() + verify_timeout
        while True:
            done, _ = check()
            if done:
                return True
            if time.monotonic() >= deadline:
                return False
            sleep(poll_interval)

    def deployment_path(ns: str, deployment: str) -> str:
        return f"/apis/apps/v1/namespaces/{ns}/deployments/{deployment}"

    def rollout_complete(k: KubeAPI, ns: str, deployment: str) -> tuple[bool, str]:
        d = k.get(deployment_path(ns, deployment))
        spec, status = d.get("spec") or {}, d.get("status") or {}
        want = spec.get("replicas", 1)
        done = (status.get("observedGeneration", 0) >= d["metadata"].get("generation", 0)
                and status.get("updatedReplicas", 0) == want
                and status.get("availableReplicas", 0) == want
                and status.get("replicas", 0) == want)
        return done, f"{status.get('availableReplicas', 0)}/{want} available"

    # ---- k8s.get_pods ---------------------------------------------------------------

    def get_pods(params: dict[str, Any], cred: Credential) -> Any:
        ns = namespace(params)
        query = ""
        if params.get("label_selector"):
            selector = params["label_selector"]
            if not isinstance(selector, str) or len(selector) > 256:
                raise KubeError("label_selector must be a short string")
            query = "?" + urllib.parse.urlencode({"labelSelector": selector})
        pods = api(cred).get(f"/api/v1/namespaces/{ns}/pods{query}").get("items", [])
        out = []
        for pod in pods:
            statuses = (pod.get("status") or {}).get("containerStatuses") or []
            out.append({
                "name": pod["metadata"]["name"],
                "phase": (pod.get("status") or {}).get("phase"),
                "ready": bool(statuses) and all(s.get("ready") for s in statuses),
                "restarts": sum(s.get("restartCount", 0) for s in statuses),
                "node": (pod.get("spec") or {}).get("nodeName"),
            })
        return {"namespace": ns, "pods": out}

    # ---- k8s.restart_pod --------------------------------------------------------------

    def owner_workload(k: KubeAPI, ns: str, pod: dict[str, Any]) -> tuple[str, str]:
        refs = [r for r in pod["metadata"].get("ownerReferences") or [] if r.get("controller")]
        if not refs:
            raise KubeError("pod has no controller; deleting it would not bring it back")
        kind, owner = refs[0]["kind"], refs[0]["name"]
        if kind == "ReplicaSet":
            rs = k.get(f"/apis/apps/v1/namespaces/{ns}/replicasets/{owner}")
            parents = [r for r in rs["metadata"].get("ownerReferences") or [] if r.get("controller")]
            if parents and parents[0]["kind"] == "Deployment":
                return "Deployment", parents[0]["name"]
            return "ReplicaSet", owner
        if kind in ("StatefulSet", "DaemonSet"):
            return kind, owner
        raise KubeError(f"pods owned by a {kind} are not restarted by AEGIS")

    def restart_pod(params: dict[str, Any], cred: Credential) -> Any:
        ns, pod_name = namespace(params), name(params, "pod")
        k = api(cred)
        pod = k.get(f"/api/v1/namespaces/{ns}/pods/{pod_name}")
        kind, owner = owner_workload(k, ns, pod)
        k.request("DELETE", f"/api/v1/namespaces/{ns}/pods/{pod_name}",
                  {"kind": "DeleteOptions", "apiVersion": "v1",
                   "preconditions": {"uid": pod["metadata"]["uid"]}})
        return {"namespace": ns, "pod": pod_name, "pod_uid": pod["metadata"]["uid"],
                "controller": f"{kind}/{owner}"}

    def workload_ready(k: KubeAPI, ns: str, controller: str) -> bool:
        kind, owner = controller.split("/", 1)
        plural = {"Deployment": "deployments", "ReplicaSet": "replicasets", "StatefulSet": "statefulsets",
                  "DaemonSet": "daemonsets"}[kind]
        obj = k.get(f"/apis/apps/v1/namespaces/{ns}/{plural}/{owner}")
        status = obj.get("status") or {}
        if kind == "DaemonSet":
            want = status.get("desiredNumberScheduled", 0)
            return status.get("numberReady", 0) == want and status.get("updatedNumberScheduled", want) == want
        want = (obj.get("spec") or {}).get("replicas", 1)
        return status.get("readyReplicas", 0) == want and status.get("replicas", 0) == want

    def verify_restart_pod(params: dict[str, Any], result: Any, cred: Credential) -> bool:
        k, ns = api(cred), result["namespace"]

        def check() -> tuple[bool, str]:
            try:
                current = k.get(f"/api/v1/namespaces/{ns}/pods/{result['pod']}")
                if current["metadata"].get("uid") == result["pod_uid"]:
                    return False, "old pod still terminating"
            except KubeError as exc:
                if "HTTP 404" not in str(exc):
                    raise
            return workload_ready(k, ns, result["controller"]), "waiting for controller"

        return wait(check)

    # ---- k8s.rollout_restart ---------------------------------------------------------

    def rollout_restart(params: dict[str, Any], cred: Credential) -> Any:
        ns, deployment = namespace(params), name(params, "deployment")
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        k = api(cred)
        current = k.get(deployment_path(ns, deployment))
        patch = {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]},
                 "spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": stamp}}}}}
        k.request("PATCH", deployment_path(ns, deployment), patch, "application/merge-patch+json")
        return {"namespace": ns, "deployment": deployment, "restarted_at": stamp}

    def verify_rollout(params: dict[str, Any], result: Any, cred: Credential) -> bool:
        k = api(cred)
        return wait(lambda: rollout_complete(k, result["namespace"], result["deployment"]))

    # ---- k8s.scale ---------------------------------------------------------------------

    def scale(params: dict[str, Any], cred: Credential) -> Any:
        ns, deployment = namespace(params), name(params, "deployment")
        replicas = params.get("replicas")
        if not isinstance(replicas, int) or isinstance(replicas, bool) or not 0 <= replicas <= max_replicas:
            raise KubeError(f"replicas must be a whole number from 0 to {max_replicas}")
        if replicas == 0 and not allow_scale_to_zero:
            raise KubeError("scaling to zero is not allowed")
        k = api(cred)
        current = k.get(deployment_path(ns, deployment))
        previous = (current.get("spec") or {}).get("replicas", 1)
        patch = {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]},
                 "spec": {"replicas": replicas}}
        k.request("PATCH", deployment_path(ns, deployment), patch, "application/merge-patch+json")
        return {"namespace": ns, "deployment": deployment, "previous_replicas": previous, "replicas": replicas}

    def rollback_scale(params: dict[str, Any], result: Any, cred: Credential) -> Any:
        api(cred).request("PATCH", deployment_path(result["namespace"], result["deployment"]),
                          {"spec": {"replicas": result["previous_replicas"]}}, "application/merge-patch+json")

    # ---- k8s.rollout_undo ---------------------------------------------------------------

    def revisions(k: KubeAPI, ns: str, deployment: dict[str, Any]) -> dict[int, dict[str, Any]]:
        uid = deployment["metadata"]["uid"]
        out = {}
        for rs in k.get(f"/apis/apps/v1/namespaces/{ns}/replicasets").get("items", []):
            owned = any(r.get("uid") == uid for r in rs["metadata"].get("ownerReferences") or [])
            revision = (rs["metadata"].get("annotations") or {}).get(REVISION)
            if owned and revision and revision.isdigit():
                out[int(revision)] = rs
        return out

    def set_template_from(k: KubeAPI, ns: str, deployment_name: str, revision: int) -> int:
        deployment = k.get(deployment_path(ns, deployment_name))
        found = revisions(k, ns, deployment)
        if revision not in found:
            raise KubeError(f"revision {revision} no longer exists")
        template = json.loads(json.dumps(found[revision]["spec"]["template"]))
        (template.get("metadata") or {}).get("labels", {}).pop("pod-template-hash", None)
        deployment["spec"]["template"] = template
        k.request("PUT", deployment_path(ns, deployment_name), deployment)  # resourceVersion guards concurrency
        return revision

    def rollout_undo(params: dict[str, Any], cred: Credential) -> Any:
        ns, deployment_name = namespace(params), name(params, "deployment")
        k = api(cred)
        deployment = k.get(deployment_path(ns, deployment_name))
        current = int((deployment["metadata"].get("annotations") or {}).get(REVISION, "0") or 0)
        older = sorted(r for r in revisions(k, ns, deployment) if r < current)
        if "to_revision" in params:
            target = params["to_revision"]
            if not isinstance(target, int) or isinstance(target, bool) or target not in older:
                raise KubeError(f"to_revision must be one of the earlier revisions {older}")
        elif older:
            target = older[-1]
        else:
            raise KubeError("there is no earlier revision to go back to")
        set_template_from(k, ns, deployment_name, target)
        return {"namespace": ns, "deployment": deployment_name, "from_revision": current, "to_revision": target}

    def rollback_undo(params: dict[str, Any], result: Any, cred: Credential) -> Any:
        set_template_from(api(cred), result["namespace"], result["deployment"], result["from_revision"])

    common = {"version": "1.0", "owner": "platform"}
    return [
        ToolDefinition(tool_id="k8s.get_pods", name="List pods", description="List pods with phase, readiness "
                       "and restarts", handler=get_pods, mutating=False,
                       required_permissions=frozenset({"k8s:pods:read"}), **common),
        ToolDefinition(tool_id="k8s.restart_pod", name="Restart pod", description="Delete a controller-managed "
                       "pod so it is recreated", handler=restart_pod, mutating=True, risk_level=RiskLevel.LOW,
                       required_permissions=frozenset({"k8s:pods:delete"}), verifier=verify_restart_pod,
                       **common),
        ToolDefinition(tool_id="k8s.rollout_restart", name="Rolling restart", description="Restart every pod of "
                       "a Deployment, a few at a time", handler=rollout_restart, mutating=True,
                       risk_level=RiskLevel.MEDIUM, required_permissions=frozenset({"k8s:deployments:write"}),
                       verifier=verify_rollout, **common),
        ToolDefinition(tool_id="k8s.scale", name="Scale deployment", description="Set a Deployment's replica count",
                       handler=scale, mutating=True, risk_level=RiskLevel.MEDIUM,
                       required_permissions=frozenset({"k8s:deployments:write"}),
                       verifier=lambda params, result, cred: wait(
                           lambda: rollout_complete(api(cred), result["namespace"], result["deployment"])),
                       rollback=rollback_scale, **common),
        ToolDefinition(tool_id="k8s.rollout_undo", name="Roll back deployment", description="Return a Deployment "
                       "to its previous revision", handler=rollout_undo, mutating=True, risk_level=RiskLevel.MEDIUM,
                       required_permissions=frozenset({"k8s:deployments:write"}), verifier=verify_rollout,
                       rollback=rollback_undo, **common),
    ]
