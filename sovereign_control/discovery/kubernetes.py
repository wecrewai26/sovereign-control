"""Kubernetes discovery for the OpsGraph (spec §39).

Reads (never writes) nodes, pods, services and workloads from the Kubernetes API and
turns them into graph entries:

    workload  ──deployed_on──▶  node/<name>       (from where its pods are scheduled)
    workload  ──depends_on───▶  other workload    (from the aegis.wecrew.ai/depends-on annotation)

Workloads are Deployments, StatefulSets and DaemonSets. A workload's graph id is its
`app.kubernetes.io/name` label, else its `app` label, else its name, so it lines up with
the `service` label alerts usually carry. If two namespaces produce the same id, both are
qualified as `<namespace>/<id>`.

Kubernetes doesn't know which service calls which, so dependencies come from annotations
on the workload:

    aegis.wecrew.ai/depends-on: "postgres, payments-api"   # Service names or graph ids
    aegis.wecrew.ai/customer-facing: "true"
    aegis.wecrew.ai/owner: "team-orders"                   # or a `team` label

A name that matches a Service in the same namespace resolves to the workloads behind it;
anything else is used as a graph id as-is (for example a database outside the cluster
that is described by hand).

Run it as a job inside the cluster with a read-only service account, posting to AEGIS
with an integration token:

    python3 -m sovereign_control.discovery.kubernetes --in-cluster --environment production \\
        --push https://aegis.example.internal --token-file /var/run/secrets/aegis/token
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any

from ..opsgraph import OpsGraph

ANNOTATION_PREFIX = "aegis.wecrew.ai/"
DEFAULT_EXCLUDED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
RESOURCES = {
    "nodes": "/api/v1/nodes",
    "pods": "/api/v1/pods",
    "services": "/api/v1/services",
    "deployments": "/apis/apps/v1/deployments",
    "replicasets": "/apis/apps/v1/replicasets",
    "statefulsets": "/apis/apps/v1/statefulsets",
    "daemonsets": "/apis/apps/v1/daemonsets",
}
_WORKLOAD_KINDS = {"deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet"}
_IN_CLUSTER_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class DiscoveryError(RuntimeError):
    pass


# ---- reading the cluster ----------------------------------------------------------


class KubernetesClient:
    """Minimal read-only Kubernetes API client (standard library only)."""

    def __init__(self, server: str, token: str, ca_file: str | None = None, timeout: float = 30.0) -> None:
        self.server = server.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._ssl = ssl.create_default_context(cafile=ca_file) if server.startswith("https") else None

    @classmethod
    def in_cluster(cls) -> "KubernetesClient":
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise DiscoveryError("not running inside a cluster (KUBERNETES_SERVICE_HOST is unset)")
        with open(f"{_IN_CLUSTER_DIR}/token") as fh:
            token = fh.read().strip()
        return cls(f"https://{host}:{port}", token, f"{_IN_CLUSTER_DIR}/ca.crt")

    def list(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        token = ""
        while True:
            query = urllib.parse.urlencode({"limit": 500, **({"continue": token} if token else {})})
            request = urllib.request.Request(f"{self.server}{path}?{query}", headers={
                "Authorization": f"Bearer {self.token}", "Accept": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=self.timeout, context=self._ssl) as resp:
                    body = json.load(resp)
            except urllib.error.HTTPError as exc:
                raise DiscoveryError(f"GET {path} failed: HTTP {exc.code}") from None
            except urllib.error.URLError as exc:
                raise DiscoveryError(f"GET {path} failed: {exc.reason}") from None
            items.extend(body.get("items") or [])
            token = (body.get("metadata") or {}).get("continue") or ""
            if not token:
                return items

    def fetch(self) -> dict[str, list[dict[str, Any]]]:
        return {name: self.list(path) for name, path in RESOURCES.items()}


# ---- building the graph -------------------------------------------------------------


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    return obj.get("metadata") or {}


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    return _meta(obj).get("labels") or {}


def _annotation(obj: dict[str, Any], key: str) -> str:
    return (_meta(obj).get("annotations") or {}).get(ANNOTATION_PREFIX + key, "")


def _owner(obj: dict[str, Any]) -> tuple[str, str] | None:
    for ref in _meta(obj).get("ownerReferences") or []:
        if ref.get("controller", True):
            return ref.get("kind", ""), ref.get("name", "")
    return None


def build_graph(
    objects: dict[str, list[dict[str, Any]]],
    *,
    environment: str = "",
    cluster: str = "",
    excluded_namespaces: frozenset[str] = DEFAULT_EXCLUDED_NAMESPACES,
) -> OpsGraph:
    """Turn lists of Kubernetes API objects into an OpsGraph."""
    graph = OpsGraph()

    def included(obj: dict[str, Any]) -> bool:
        return _meta(obj).get("namespace", "") not in excluded_namespaces

    # Machines.
    for node in objects.get("nodes", []):
        name = _meta(node).get("name", "")
        if not name:
            continue
        labels = _labels(node)
        ready = next((c.get("status") for c in (node.get("status") or {}).get("conditions") or []
                      if c.get("type") == "Ready"), "Unknown")
        attributes = {k: v for k, v in {
            "zone": labels.get("topology.kubernetes.io/zone", ""),
            "instance_type": labels.get("node.kubernetes.io/instance-type", ""),
            "ready": ready,
            "cluster": cluster,
        }.items() if v}
        graph.add_node(f"node/{name}", kind="node", name=name, environment=environment, attributes=attributes)

    # Workloads, with ids that match alert `service` labels where possible.
    workloads: dict[tuple[str, str, str], dict[str, Any]] = {}  # (kind, namespace, name) -> object
    for resource, kind in _WORKLOAD_KINDS.items():
        for obj in objects.get(resource, []):
            if included(obj):
                workloads[(kind, _meta(obj).get("namespace", ""), _meta(obj).get("name", ""))] = obj

    def short_id(obj: dict[str, Any]) -> str:
        template = ((obj.get("spec") or {}).get("template") or {})
        labels = {**(template.get("metadata") or {}).get("labels", {}), **_labels(obj)}
        return labels.get("app.kubernetes.io/name") or labels.get("app") or _meta(obj).get("name", "")

    namespaces_by_id: dict[str, set[str]] = defaultdict(set)
    for (_, namespace, _), obj in workloads.items():
        namespaces_by_id[short_id(obj)].add(namespace)
    ids: dict[tuple[str, str, str], str] = {}
    for key, obj in workloads.items():
        base = short_id(obj)
        ids[key] = base if len(namespaces_by_id[base]) == 1 else f"{key[1]}/{base}"

    for key, obj in workloads.items():
        kind, namespace, name = key
        node_id = ids[key]
        if node_id in graph:
            continue  # several workloads share one app id (e.g. app + its worker); first one describes it
        graph.add_node(
            node_id,
            kind="service",
            name=name,
            environment=environment,
            owner=_annotation(obj, "owner") or _labels(obj).get("team", ""),
            customer_facing=_annotation(obj, "customer-facing").strip().lower() == "true",
            attributes={k: v for k, v in {"namespace": namespace, "workload": f"{kind}/{name}",
                                          "cluster": cluster}.items() if v},
        )

    # Placement: pod → (ReplicaSet →) workload, and the node it is scheduled on.
    replicaset_owner = {
        (_meta(rs).get("namespace", ""), _meta(rs).get("name", "")): _owner(rs)
        for rs in objects.get("replicasets", [])
    }
    for pod in objects.get("pods", []):
        node_name = (pod.get("spec") or {}).get("nodeName")
        owner = _owner(pod)
        if not node_name or not owner or not included(pod):
            continue
        namespace = _meta(pod).get("namespace", "")
        kind, name = owner
        if kind == "ReplicaSet":
            owner = replicaset_owner.get((namespace, name))
            if not owner:
                continue
            kind, name = owner
        node_id = ids.get((kind, namespace, name))
        if node_id and f"node/{node_name}" in graph:
            graph.add_edge(node_id, "deployed_on", f"node/{node_name}")

    # Declared dependencies; Service names resolve to the workloads they select.
    services: dict[tuple[str, str], dict[str, str]] = {
        (_meta(s).get("namespace", ""), _meta(s).get("name", "")): (s.get("spec") or {}).get("selector") or {}
        for s in objects.get("services", [])
    }

    def selected(namespace: str, selector: dict[str, str]) -> list[str]:
        found = []
        for (kind, ns, name), obj in workloads.items():
            template_labels = (((obj.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels", {})
            if ns == namespace and selector and all(template_labels.get(k) == v for k, v in selector.items()):
                found.append(ids[(kind, ns, name)])
        return found

    for key, obj in workloads.items():
        namespace = key[1]
        for target in (t.strip() for t in _annotation(obj, "depends-on").split(",")):
            if not target:
                continue
            resolved = selected(namespace, services.get((namespace, target), {})) or [target]
            for target_id in resolved:
                if target_id != ids[key]:
                    graph.add_edge(ids[key], "depends_on", target_id)
    return graph


# ---- CLI --------------------------------------------------------------------------


def push(graph: OpsGraph, base_url: str, token: str, ca_file: str | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/ingest/opsgraph", method="POST", data=json.dumps(graph.to_dict()).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=ca_file) if base_url.startswith("https") else None
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise DiscoveryError(f"AEGIS rejected the graph: HTTP {exc.code} {detail}") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m sovereign_control.discovery.kubernetes")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--in-cluster", action="store_true", help="use the pod's service account")
    source.add_argument("--server", help="Kubernetes API URL (with --kube-token-file)")
    source.add_argument("--from-file", help="read a JSON dump {nodes:[…], pods:[…], …} instead of a cluster")
    parser.add_argument("--kube-token-file")
    parser.add_argument("--kube-ca-file")
    parser.add_argument("--environment", default="")
    parser.add_argument("--cluster", default="")
    parser.add_argument("--exclude-namespace", action="append", default=None,
                        help="namespace to skip (repeatable; default: kube-system, kube-public, kube-node-lease)")
    parser.add_argument("--push", metavar="AEGIS_URL", help="POST the graph to AEGIS instead of printing it")
    parser.add_argument("--token-file", help="AEGIS integration token (with --push)")
    parser.add_argument("--aegis-ca-file")
    args = parser.parse_args(argv)

    try:
        if args.from_file:
            with open(args.from_file) as fh:
                objects = json.load(fh)
        elif args.in_cluster:
            objects = KubernetesClient.in_cluster().fetch()
        else:
            if not args.kube_token_file:
                parser.error("--server needs --kube-token-file")
            with open(args.kube_token_file) as fh:
                objects = KubernetesClient(args.server, fh.read().strip(), args.kube_ca_file).fetch()
        excluded = frozenset(args.exclude_namespace) if args.exclude_namespace is not None \
            else DEFAULT_EXCLUDED_NAMESPACES
        graph = build_graph(objects, environment=args.environment, cluster=args.cluster,
                            excluded_namespaces=excluded)
        if args.push:
            if not args.token_file:
                parser.error("--push needs --token-file")
            with open(args.token_file) as fh:
                result = push(graph, args.push, fh.read().strip(), args.aegis_ca_file)
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(graph.to_dict(), indent=2))
    except (DiscoveryError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR  {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
