import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from sovereign_control import ActionContext, OpsGraph, RiskLevel, SovereignGateway, SQLiteStore, ToolDefinition
from sovereign_control.api import ControlAPI
from sovereign_control.auth import TokenAuthenticator
from sovereign_control.discovery.kubernetes import DiscoveryError, KubernetesClient, build_graph, main


def workload(kind, name, ns="shop", app=None, annotations=None, labels=None):
    tpl = {"app": app or name}
    return {"kind": kind, "metadata": {"name": name, "namespace": ns, "labels": labels or {},
                                       "annotations": {f"aegis.wecrew.ai/{k}": v for k, v in (annotations or {}).items()}},
            "spec": {"template": {"metadata": {"labels": tpl}}}}


def pod(name, owner_kind, owner, node, ns="shop"):
    return {"metadata": {"name": name, "namespace": ns,
                         "ownerReferences": [{"kind": owner_kind, "name": owner, "controller": True}]},
            "spec": {"nodeName": node}}


def cluster():
    return {
        "nodes": [
            {"metadata": {"name": "ip-10-0-1-7", "labels": {"topology.kubernetes.io/zone": "eu-west-1a"}},
             "status": {"conditions": [{"type": "Ready", "status": "True"}]}},
            {"metadata": {"name": "ip-10-0-2-9"}, "status": {"conditions": [{"type": "Ready", "status": "False"}]}},
        ],
        "deployments": [
            workload("Deployment", "web", annotations={"customer-facing": "true", "depends-on": "checkout-svc"}),
            workload("Deployment", "checkout", annotations={"depends-on": "postgres, payments-rds", "owner": "orders"}),
            workload("Deployment", "checkout", ns="staging"),           # same id in another namespace
            workload("Deployment", "coredns", ns="kube-system"),        # excluded by default
        ],
        "statefulsets": [workload("StatefulSet", "postgres-primary", app="postgres")],
        "daemonsets": [workload("DaemonSet", "log-agent")],
        "replicasets": [
            {"metadata": {"name": "web-5d8", "namespace": "shop", "ownerReferences": [{"kind": "Deployment", "name": "web"}]}},
            {"metadata": {"name": "checkout-7f1", "namespace": "shop",
                          "ownerReferences": [{"kind": "Deployment", "name": "checkout"}]}},
        ],
        "pods": [
            pod("web-5d8-a", "ReplicaSet", "web-5d8", "ip-10-0-1-7"),
            pod("web-5d8-b", "ReplicaSet", "web-5d8", "ip-10-0-2-9"),
            pod("checkout-7f1-a", "ReplicaSet", "checkout-7f1", "ip-10-0-1-7"),
            pod("postgres-primary-0", "StatefulSet", "postgres-primary", "ip-10-0-2-9"),
            pod("log-agent-x", "DaemonSet", "log-agent", "ip-10-0-1-7"),
            {"metadata": {"name": "pending", "namespace": "shop",
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d8"}]}, "spec": {}},
        ],
        "services": [
            {"metadata": {"name": "checkout-svc", "namespace": "shop"}, "spec": {"selector": {"app": "checkout"}}},
            {"metadata": {"name": "postgres", "namespace": "shop"}, "spec": {"selector": {"app": "postgres"}}},
        ],
    }


class BuildGraphTests(unittest.TestCase):
    def setUp(self):
        self.g = build_graph(cluster(), environment="production", cluster="prod-eu-1")
        self.edges = {(e.source, e.kind, e.target) for e in self.g.edges()}

    def test_nodes(self):
        node = self.g.node("node/ip-10-0-1-7")
        self.assertEqual((node.kind, node.attributes["zone"], node.attributes["ready"]), ("node", "eu-west-1a", "True"))
        self.assertEqual(self.g.node("node/ip-10-0-2-9").attributes["ready"], "False")

    def test_workload_ids_and_collisions(self):
        ids = {n.node_id for n in self.g.nodes() if "workload" in n.attributes}
        self.assertEqual(ids, {"web", "shop/checkout", "staging/checkout", "postgres", "log-agent"})
        self.assertIn("payments-rds", self.g)  # named in an annotation, lives outside the cluster
        self.assertNotIn("coredns", self.g)
        web = self.g.node("web")
        self.assertTrue(web.customer_facing)
        self.assertEqual(web.attributes, {"namespace": "shop", "workload": "Deployment/web", "cluster": "prod-eu-1"})
        self.assertEqual(self.g.node("shop/checkout").owner, "orders")

    def test_placement(self):
        self.assertTrue({("web", "deployed_on", "node/ip-10-0-1-7"), ("web", "deployed_on", "node/ip-10-0-2-9"),
                         ("shop/checkout", "deployed_on", "node/ip-10-0-1-7"),
                         ("postgres", "deployed_on", "node/ip-10-0-2-9"),
                         ("log-agent", "deployed_on", "node/ip-10-0-1-7")} <= self.edges)

    def test_dependencies_resolve_services_and_keep_external_names(self):
        self.assertIn(("web", "depends_on", "shop/checkout"), self.edges)    # via Service checkout-svc
        self.assertIn(("shop/checkout", "depends_on", "postgres"), self.edges)  # via Service postgres
        self.assertIn(("shop/checkout", "depends_on", "payments-rds"), self.edges)  # outside the cluster

    def test_impact_of_a_node_reaches_customers(self):
        impact = self.g.impact("node/ip-10-0-2-9")
        self.assertEqual(impact["impacted"], ["postgres", "shop/checkout", "web"])
        self.assertEqual(impact["customer_facing_impacted"], ["web"])


class FakeKubeAPI(BaseHTTPRequestHandler):
    objects = cluster()
    seen_auth = []

    def do_GET(self):
        url = urlsplit(self.path)
        FakeKubeAPI.seen_auth.append(self.headers.get("Authorization"))
        resource = url.path.rsplit("/", 1)[-1]
        if self.headers.get("Authorization") != "Bearer kube-token":
            self.send_response(401); self.end_headers(); return
        items = self.objects.get(resource, [])
        start = int(parse_qs(url.query).get("continue", ["0"])[0])
        page = items[start:start + 2]  # tiny pages to exercise pagination
        cont = str(start + 2) if start + 2 < len(items) else ""
        body = json.dumps({"items": page, "metadata": {"continue": cont}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeKubeAPI)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_fetch_pages_through_everything(self):
        objects = KubernetesClient(self.url, "kube-token").fetch()
        self.assertEqual(len(objects["pods"]), 6)
        self.assertEqual(build_graph(objects).to_dict(), build_graph(cluster()).to_dict())

    def test_bad_token(self):
        with self.assertRaises(DiscoveryError):
            KubernetesClient(self.url, "wrong").fetch()


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(str(Path(self.tmp.name) / "aegis.db"))
        # Hand-written: a database outside the cluster, and a curated description of web.
        manual = OpsGraph.from_dict({"nodes": [{"id": "payments-rds", "kind": "database"},
                                               {"id": "web", "customer_facing": True, "owner": "frontend-team"}],
                                     "edges": [{"from": "payments-rds", "kind": "runs_on", "to": "aws-eu-west-1"}]})
        self.gw = SovereignGateway(store=self.store, graph=manual)
        auth = TokenAuthenticator()
        self.t = {"disc": auth.add_integration("k8s-prod"), "alerts": auth.add_integration("alertmanager"),
                  "admin": auth.add_user("root", {"admin"})}
        self.api = ControlAPI(self.gw, auth, graph_sources={"k8s-prod"})

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def post(self, who, graph):
        return self.api.handle("POST", "/v1/ingest/opsgraph", {"Authorization": f"Bearer {self.t[who]}"},
                               json.dumps(graph.to_dict()).encode())

    def test_merge_keeps_manual_entries_and_tags_origin(self):
        status, stats = self.post("disc", build_graph(cluster(), environment="production"))
        self.assertEqual(status, 200)
        self.assertEqual(stats["edges_removed"], 0)
        g = self.gw.graph
        self.assertEqual(g.node("web").owner, "frontend-team")  # a person's description wins
        self.assertEqual(g.node("node/ip-10-0-1-7").origin, "k8s-prod")
        # The chain now runs from the cloud region through the cluster to the website.
        self.assertIn("web", g.impacted_by("aws-eu-west-1"))
        event = self.gw.audit.events()[-1]
        self.assertEqual((event.event_type, event.actor), ("opsgraph.discovered", "k8s-prod"))

    def test_discovery_cannot_pose_as_manual_or_touch_manual_edges(self):
        spoof = OpsGraph.from_dict({"nodes": [{"id": "x", "origin": ""}], "edges": []})
        self.post("disc", spoof)
        self.assertEqual(self.gw.graph.node("x").origin, "k8s-prod")
        self.post("disc", OpsGraph())  # report an empty cluster
        self.assertIn(("payments-rds", "runs_on", "aws-eu-west-1"),
                      {(e.source, e.kind, e.target) for e in self.gw.graph.edges()})

    def test_mass_removal_is_refused_and_audited(self):
        self.post("disc", build_graph(cluster()))
        before = self.gw.graph.fingerprint()
        status, body = self.post("disc", OpsGraph.from_dependencies({"web": ["shop/checkout"]}))
        self.assertEqual(status, 409)
        self.assertIn("admin must review", body["error"])
        self.assertEqual(self.gw.graph.fingerprint(), before)
        self.assertEqual(self.gw.audit.events()[-1].event_type, "opsgraph.discovery_refused")

    def test_small_change_is_applied(self):
        objects = cluster()
        self.post("disc", build_graph(objects))
        objects["pods"].append(pod("web-5d8-c", "ReplicaSet", "web-5d8", "ip-10-0-2-9"))
        objects["pods"] = [p for p in objects["pods"] if p["metadata"]["name"] != "log-agent-x"]
        status, stats = self.post("disc", build_graph(objects))
        self.assertEqual((status, stats["edges_removed"]), (200, 1))

    def test_ids_with_slashes_can_be_queried(self):
        self.post("disc", build_graph(cluster()))
        token = self.api.auth.add_user("alice", {"sre"})
        status, impact = self.api.handle("GET", "/v1/opsgraph/node%2Fip-10-0-2-9/impact",
                                         {"Authorization": f"Bearer {token}"})
        self.assertEqual((status, impact["node"], impact["known"]), (200, "node/ip-10-0-2-9", True))
        self.assertIn("web", impact["impacted"])
        status, _ = self.api.handle("GET", "/v1/opsgraph/node/ip-10-0-2-9/impact",
                                    {"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 404)  # an unencoded slash is a different path

    def test_only_approved_sources(self):
        self.assertEqual(self.post("alerts", build_graph(cluster()))[0], 403)
        status, _ = self.api.handle("POST", "/v1/ingest/opsgraph", {"Authorization": f"Bearer {self.t['admin']}"},
                                    b"{}")
        self.assertEqual(status, 403)

    def test_discovered_graph_drives_risk_and_survives_restart(self):
        self.post("disc", build_graph(cluster()))
        tool = ToolDefinition(tool_id="t", name="t", version="1", owner="o", description="", mutating=True,
                              handler=lambda p, c: None, risk_level=RiskLevel.LOW, rollback=lambda p, r, c: None)
        risk = self.gw.risk.assess(tool, "production", ActionContext(service="postgres"))
        self.assertEqual((risk.factors["blast_radius"], risk.factors["customer_impact"]), (10, 10))
        again = SovereignGateway(store=self.store)
        self.assertEqual(again.graph.fingerprint(), self.gw.graph.fingerprint())


class CLITests(unittest.TestCase):
    def test_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dump.json"
            path.write_text(json.dumps(cluster()))
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["--from-file", str(path), "--environment", "production"]), 0)
            graph = OpsGraph.from_dict(json.loads(out.getvalue()))
            self.assertIn("web", graph)


if __name__ == "__main__":
    unittest.main()
