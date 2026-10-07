"""OpsGraph: a live map of services and infrastructure (spec §33).

Nodes are things that can fail (services, databases, queues, deployments, nodes,
VMs, hypervisors, racks...). Edges say how they relate. Three edge kinds carry
impact — if B fails, A is affected:

    A depends_on B      A calls or needs B
    A deployed_on B     A runs on B (deployment on a cluster, pod on a node)
    A runs_on B         A runs on B (VM on a hypervisor, node in a rack)

Other spec relationships (owns, monitors, managed_by, changed_by,
communicates_with, connected_to, consumes) are recorded but don't propagate impact.

The graph answers two governance questions:
- impact:  if this fails or is changed, what else is affected? (risk blast radius)
- related: are these two things connected by a chain of impact? (alert correlation)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from typing import Any

IMPACT_EDGES = frozenset({"depends_on", "deployed_on", "runs_on"})
EDGE_KINDS = IMPACT_EDGES | frozenset({
    "owns", "monitors", "managed_by", "changed_by", "communicates_with", "connected_to", "consumes",
})


class GraphError(ValueError):
    pass


class GraphConflict(GraphError):
    """The change is refused as unsafe without a person's review."""


@dataclass
class Node:
    node_id: str
    kind: str = "service"
    name: str = ""
    environment: str = ""
    owner: str = ""
    customer_facing: bool = False
    attributes: dict[str, str] = field(default_factory=dict)
    origin: str = ""  # "" = written by people; otherwise the discovery source that reported it


@dataclass(frozen=True)
class Edge:
    source: str
    kind: str
    target: str
    origin: str = ""


class OpsGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: set[Edge] = set()

    # ---- building -------------------------------------------------------------

    def add_node(self, node_id: str, **fields: Any) -> Node:
        if not isinstance(node_id, str) or not node_id:
            raise GraphError("node id must be a non-empty string")
        node = Node(node_id=node_id, **fields)
        self._nodes[node_id] = node
        return node

    def add_edge(self, source: str, kind: str, target: str, origin: str = "") -> Edge:
        if kind not in EDGE_KINDS:
            raise GraphError(f"unknown edge kind {kind!r}; expected one of {', '.join(sorted(EDGE_KINDS))}")
        for end in (source, target):
            if end not in self._nodes:
                self.add_node(end, origin=origin)  # implicit nodes keep config short; describe them later
        edge = Edge(source, kind, target, origin)
        self._edges.add(edge)
        return edge

    @classmethod
    def from_dependencies(cls, dependencies: dict[str, list[str]]) -> "OpsGraph":
        """Build a graph from a simple {service: [services it depends on]} map."""
        graph = cls()
        for service, deps in dependencies.items():
            if service not in graph:
                graph.add_node(service)
            for dep in deps:
                graph.add_edge(service, "depends_on", dep)
        return graph

    @classmethod
    def from_dict(cls, data: Any) -> "OpsGraph":
        """{"nodes": [{"id", "kind", "name", "environment", "owner", "customer_facing", "attributes", "origin"}],
            "edges": [{"from", "kind", "to", "origin"}]}"""
        if not isinstance(data, dict):
            raise GraphError("graph must be an object with 'nodes' and 'edges'")
        nodes, edges = data.get("nodes", []), data.get("edges", [])
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise GraphError("'nodes' and 'edges' must be lists")
        graph = cls()
        allowed = {"id", "kind", "name", "environment", "owner", "customer_facing", "attributes", "origin"}
        for raw in nodes:
            if not isinstance(raw, dict):
                raise GraphError("each node must be an object")
            unknown = set(raw) - allowed
            if unknown:
                raise GraphError(f"unknown node fields: {', '.join(sorted(unknown))}")
            for key in ("kind", "name", "environment", "owner", "origin"):
                if key in raw and not isinstance(raw[key], str):
                    raise GraphError(f"node.{key} must be a string")
            if "customer_facing" in raw and not isinstance(raw["customer_facing"], bool):
                raise GraphError("node.customer_facing must be true or false")
            attributes = raw.get("attributes", {})
            if not isinstance(attributes, dict):
                raise GraphError("node.attributes must be an object")
            fields = {k: v for k, v in raw.items() if k not in ("id", "attributes")}
            graph.add_node(raw.get("id"), attributes={str(k): str(v) for k, v in attributes.items()}, **fields)
        for raw in edges:
            if not isinstance(raw, dict) or not all(isinstance(raw.get(k), str) for k in ("from", "kind", "to")):
                raise GraphError("each edge needs string 'from', 'kind' and 'to'")
            if not isinstance(raw.get("origin", ""), str):
                raise GraphError("edge.origin must be a string")
            graph.add_edge(raw["from"], raw["kind"], raw["to"], raw.get("origin", ""))
        return graph

    def to_dict(self) -> dict[str, Any]:
        nodes = []
        for node in sorted(self._nodes.values(), key=lambda n: n.node_id):
            data = asdict(node)
            data["id"] = data.pop("node_id")
            nodes.append(data)
        edges = [{"from": e.source, "kind": e.kind, "to": e.target, **({"origin": e.origin} if e.origin else {})}
                 for e in sorted(self._edges, key=lambda e: (e.source, e.kind, e.target, e.origin))]
        return {"nodes": nodes, "edges": edges}

    def merged_with_origin(self, origin: str, discovered: "OpsGraph") -> "OpsGraph":
        """A copy of this graph where everything previously reported by `origin` is replaced by `discovered`.

        Entries written by people (origin "") and by other sources are kept. Where a person has
        described a node, their description wins over the discovered one.
        """
        if not origin:
            raise GraphError("a discovery origin is required")
        nodes = {nid: n for nid, n in self._nodes.items() if n.origin != origin}
        for node in discovered.nodes():
            if node.node_id not in nodes:
                nodes[node.node_id] = replace(node, origin=origin)
        edges = {e for e in self._edges if e.origin != origin}
        edges |= {replace(e, origin=origin) for e in discovered.edges()}
        merged = OpsGraph()
        merged._nodes = nodes
        merged._edges = edges
        for edge in edges:  # keep every edge's endpoints described
            for end in (edge.source, edge.target):
                if end not in merged._nodes:
                    merged._nodes[end] = Node(node_id=end, origin=edge.origin)
        return merged

    def replace_with(self, other: "OpsGraph") -> None:
        """Swap in another graph's contents, so every component holding this graph sees the change."""
        self._nodes, self._edges = dict(other._nodes), set(other._edges)

    def fingerprint(self) -> str:
        """SHA-256 of the canonical graph, so changes can be recorded and compared."""
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()

    # ---- queries ----------------------------------------------------------------

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._nodes

    def node(self, node_id: str) -> Node:
        try:
            return self._nodes[node_id]
        except KeyError:
            raise GraphError(f"unknown node: {node_id}") from None

    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    def edges(self) -> list[Edge]:
        return list(self._edges)

    def dependencies(self, node_id: str) -> set[str]:
        """Everything this node needs, directly or through a chain (what could break it)."""
        return self._walk(node_id, forward=True)

    def impacted_by(self, node_id: str) -> set[str]:
        """Everything affected if this node fails or is changed (its blast radius)."""
        return self._walk(node_id, forward=False)

    def related(self, a: str, b: str) -> bool:
        if not a or not b:
            return False
        return a == b or b in self.dependencies(a) or a in self.dependencies(b)

    def impact(self, node_id: str) -> dict[str, Any]:
        impacted = self.impacted_by(node_id)
        customer_facing = sorted(n for n in impacted | {node_id}
                                 if n in self._nodes and self._nodes[n].customer_facing)
        return {
            "node": node_id,
            "known": node_id in self._nodes,
            "impacted": sorted(impacted),
            "dependencies": sorted(self.dependencies(node_id)),
            "customer_facing_impacted": customer_facing,
        }

    def _walk(self, start: str, *, forward: bool) -> set[str]:
        adjacency: dict[str, set[str]] = {}
        for e in self._edges:
            if e.kind in IMPACT_EDGES:
                a, b = (e.source, e.target) if forward else (e.target, e.source)
                adjacency.setdefault(a, set()).add(b)
        seen: set[str] = set()
        stack = list(adjacency.get(start, ()))
        while stack:
            current = stack.pop()
            if current in seen or current == start:
                continue
            seen.add(current)
            stack.extend(adjacency.get(current, ()))
        return seen
