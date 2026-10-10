import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

import fake_prometheus
from fake_kube import TOKEN, Cluster, start

from sovereign_control import SovereignGateway
from sovereign_control.api import ControlAPI, FileResponse, make_server
from sovereign_control.auth import TokenAuthenticator
from sovereign_control.clusters import ClusterConfig, ClusterViewer, PrometheusTarget
from sovereign_control.credentials import CredentialBroker
from sovereign_control.redaction import redact_text
from sovereign_control.tools.kubernetes import KubeTarget


class ReadBroker(CredentialBroker):
    """Stands in for Vault's `k8s.read` role. Records what was asked for."""

    def __init__(self):
        super().__init__()
        self.requests, self.revoked = [], 0

    def issue(self, agent_id, tool_id, environment, ttl=None, params=None):
        self.requests.append((agent_id, tool_id, environment, params))
        cred = super().issue(agent_id, tool_id, environment, ttl, params)
        cred.secret = {"service_account_token": TOKEN}
        return cred

    def revoke(self, cred):
        self.revoked += 1
        super().revoke(cred)


SECRET_LOG = """2026-10-10T09:00:01Z starting checkout v2.3.1
2026-10-10T09:00:02Z connecting to postgres://checkout:S3cr3tPassw0rd@db.internal:5432/orders
2026-10-10T09:00:03Z calling payments with Authorization: Bearer abc123def456ghi789
2026-10-10T09:00:04Z config loaded {"api_key": "sk_live_51HxYz", "region": "eu-west-1"}
2026-10-10T09:00:05Z ready"""


class ClusterTest(unittest.TestCase):
    def setUp(self):
        self.cluster = Cluster()
        self.cluster.add_deployment("shop", "checkout", "checkout:1", replicas=2)
        self.cluster.add_deployment("shop", "web", "web:1", replicas=1)
        self.cluster.add_bare_pod("shop", "debug")
        self.cluster.evict("shop", "debug")
        self.checkout_pods = sorted(p["metadata"]["name"] for p in self.cluster.pods_of("shop", "checkout"))
        self.cluster.crashloop("shop", self.checkout_pods[1])
        self.cluster.logs[("shop", self.checkout_pods[0])] = SECRET_LOG
        self.cluster.add_event("shop", "ev1", "Pod", "debug", "Evicted", "The node was low on memory. token=abcd1234efgh")
        self.kube, kube_url = start(self.cluster)
        self.prom, prom_url, self.prom_handler = fake_prometheus.start(self.checkout_pods)
        self.broker = ReadBroker()
        self.gw = SovereignGateway(credentials=self.broker)
        auth = TokenAuthenticator()
        self.t = {"alice": auth.add_user("alice", {"sre"}), "agent": auth.add_agent("agent")}
        self.viewer = ClusterViewer(self.gw, {
            "production": ClusterConfig(KubeTarget(kube_url), {"shop"}, PrometheusTarget(prom_url)),
            "staging": ClusterConfig(KubeTarget(kube_url), {"shop"}),
        })
        self.api = ControlAPI(self.gw, auth, clusters=self.viewer)

    def tearDown(self):
        for server in (self.kube, self.prom):
            server.shutdown()
            server.server_close()

    def get(self, path, who="alice"):
        return self.api.handle("GET", path, {"Authorization": f"Bearer {self.t[who]}"})


class ViewTests(ClusterTest):
    def test_pods_like_lens(self):
        status, body = self.get("/v1/clusters/production/namespaces/shop/pods")
        self.assertEqual(status, 200)
        rows = {p["name"]: p for p in body["pods"]}
        healthy, crashing = rows[self.checkout_pods[0]], rows[self.checkout_pods[1]]
        self.assertEqual((healthy["status"], healthy["controlled_by"]),
                         ("Running", {"kind": "Deployment", "name": "checkout"}))
        self.assertEqual((crashing["status"], crashing["restarts"]), ("CrashLoopBackOff", 7))
        self.assertEqual(rows["debug"]["status"], "Evicted")
        self.assertIn("low on resource", rows["debug"]["message"])
        self.assertEqual((healthy["qos"], healthy["node"]), ("Burstable", "node-1"))
        self.assertGreater(healthy["age_seconds"], 0)
        self.assertTrue(body["metrics"])
        self.assertAlmostEqual(healthy["memory_bytes"] / 2**20, 180 + 20 * __import__("math").sin(len(healthy["name"])), 3)
        self.assertIsNone(rows["debug"]["cpu_cores"])

    def test_without_prometheus(self):
        _, body = self.get("/v1/clusters/staging/namespaces/shop/pods")
        self.assertFalse(body["metrics"])
        self.assertEqual(self.get("/v1/clusters/staging/namespaces/shop/pods/x/metrics")[0], 404)

    def test_deployments_and_events(self):
        _, body = self.get("/v1/clusters/production/namespaces/shop/deployments")
        self.assertEqual([(d["name"], d["ready"], d["replicas"]) for d in body["deployments"]],
                         [("checkout", 2, 2), ("web", 1, 1)])
        _, body = self.get("/v1/clusters/production/namespaces/shop/events")
        self.assertEqual(body["events"][0]["object"], "Pod/debug")
        self.assertIn("token=[REDACTED]", body["events"][0]["message"])

    def test_logs_are_redacted_and_audited(self):
        pod = self.checkout_pods[0]
        _, body = self.get(f"/v1/clusters/production/namespaces/shop/pods/{pod}/logs?tail=50")
        text = "\n".join(body["lines"])
        for secret in ("S3cr3tPassw0rd", "abc123def456ghi789", "sk_live_51HxYz"):
            self.assertNotIn(secret, text)
        self.assertIn("starting checkout v2.3.1", text)
        self.assertEqual(body["redactions"], 3)
        event = self.gw.audit.events()[-1]
        self.assertEqual((event.event_type, event.actor, event.data["pod"]), ("cluster.logs_viewed", "alice", pod))
        self.assertNotIn("S3cr3tPassw0rd", json.dumps([e.data for e in self.gw.audit.events()]))

    def test_metrics(self):
        pod = self.checkout_pods[0]
        status, body = self.get(f"/v1/clusters/production/namespaces/shop/pods/{pod}/metrics?minutes=60")
        self.assertEqual(status, 200)
        self.assertGreater(len(body["cpu_cores"]), 100)
        self.assertEqual(len(body["cpu_cores"]), len(body["memory_bytes"]))
        self.assertTrue(all(f'pod="{pod}"' in q for q in self.prom_handler.queries[-2:]))

    def test_every_read_uses_a_short_lived_read_credential(self):
        self.get("/v1/clusters/production/namespaces/shop/pods")
        self.get("/v1/clusters/production/namespaces/shop/events")
        self.assertEqual([r[:3] for r in self.broker.requests], [("alice", "k8s.read", "production")] * 2)
        self.assertEqual(self.broker.requests[0][3], {"namespace": "shop"})
        self.assertEqual(self.broker.revoked, 2)
        self.assertEqual(self.broker.active(), [])
        self.assertEqual([e.data["resource"] for e in self.gw.audit.events()], ["pods", "events"])

    def test_guards(self):
        self.assertEqual(self.get("/v1/clusters/production/namespaces/kube-system/pods")[0], 403)
        self.assertEqual(self.get("/v1/clusters/nowhere/namespaces/shop/pods")[0], 404)
        self.assertEqual(self.get("/v1/clusters/production/namespaces/shop/pods/nope/logs")[0], 404)
        self.assertEqual(self.get("/v1/clusters/production/namespaces/shop/pods/x/logs?tail=99999")[0], 400)
        self.assertEqual(self.get("/v1/clusters/production/namespaces/shop/pods/x/logs?tail=lots")[0], 400)
        bad = urllib.parse.quote('x"} or vector(1) #', safe="")  # PromQL injection attempt
        self.assertEqual(self.get(f"/v1/clusters/production/namespaces/shop/pods/{bad}/metrics")[0], 400)
        self.assertEqual(self.get("/v1/clusters/production/namespaces/shop/pods", who="agent")[0], 403)
        # Only the well-formed lookup of a missing pod reached the cluster; every rejected request
        # was refused before any credential was issued.
        self.assertEqual(len(self.broker.requests), 1)
        self.assertEqual(self.broker.revoked, 1)

    def test_cluster_down(self):
        self.kube.shutdown()
        self.kube.server_close()
        status, body = self.get("/v1/clusters/production/namespaces/shop/pods")
        self.assertEqual(status, 502)
        self.assertEqual(self.broker.revoked, 1)  # credential still revoked
        self.kube, _ = start(self.cluster)  # for tearDown

    def test_list_clusters(self):
        _, body = self.get("/v1/clusters")
        self.assertEqual(body["clusters"], [
            {"environment": "production", "namespaces": ["shop"], "metrics": True},
            {"environment": "staging", "namespaces": ["shop"], "metrics": False}])


class RedactionTests(unittest.TestCase):
    def test_shapes(self):
        cases = {
            "password=hunter2xyz": "password=[REDACTED]",
            '"client_secret": "abc"': '"client_secret": "[REDACTED]"',
            "url https://u:p4ss@host/x": "url https://u:[REDACTED]@host/x",
            "key AKIAABCDEFGHIJKLMNOP": "key [REDACTED]",
            "jwt eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl": "jwt [REDACTED]",
        }
        for raw, expected in cases.items():
            self.assertEqual(redact_text(raw)[0], expected, raw)
        pem = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\nxyz\n-----END RSA PRIVATE KEY-----\nb"
        self.assertEqual(redact_text(pem)[0], "a\n[REDACTED]\nb")
        self.assertEqual(redact_text("GET /healthz 200 in 3ms"), ("GET /healthz 200 in 3ms", 0))


class WebTests(unittest.TestCase):
    def test_page_and_assets_are_served_with_strict_headers(self):
        api = ControlAPI(SovereignGateway(), TokenAuthenticator())
        for path, kind in (("/ui", "text/html"), ("/ui/app.js", "text/javascript"), ("/ui/app.css", "text/css")):
            status, body = api.handle("GET", path, {})
            self.assertEqual(status, 200)
            self.assertIsInstance(body, FileResponse)
            self.assertTrue(body.content_type.startswith(kind))
            self.assertIsNone(body.filename)
            self.assertIn("script-src 'self'", body.headers["Content-Security-Policy"])
            self.assertIn("frame-ancestors 'none'", body.headers["Content-Security-Policy"])

    def test_script_never_uses_innerhtml(self):
        status, body = ControlAPI(SovereignGateway(), TokenAuthenticator()).handle("GET", "/ui/app.js", {})
        source = body.content.decode()
        self.assertNotIn("innerHTML", source)
        self.assertNotIn("insertAdjacentHTML", source)
        self.assertNotIn("eval(", source)

    def test_served_over_http_inline(self):
        api = ControlAPI(SovereignGateway(), TokenAuthenticator())
        server = make_server(api, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(f"http://127.0.0.1:{server.server_address[1]}/ui") as resp:
                self.assertIsNone(resp.headers.get("Content-Disposition"))
                self.assertIn(b"AEGIS Control Tower", resp.read())
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                opener.open(f"http://127.0.0.1:{server.server_address[1]}/v1/control-tower")
            self.assertEqual(ctx.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()

    def test_me(self):
        auth = TokenAuthenticator()
        token = auth.add_user("alice", {"sre", "admin"})
        status, body = ControlAPI(SovereignGateway(), auth).handle("GET", "/v1/me", {"Authorization": f"Bearer {token}"})
        self.assertEqual(body, {"id": "alice", "roles": ["admin", "sre"]})


if __name__ == "__main__":
    unittest.main()
