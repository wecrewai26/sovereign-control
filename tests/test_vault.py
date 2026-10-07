import json
import threading
import unittest
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sovereign_control import AutonomyLevel, ExecutionStatus, RiskLevel, SovereignGateway, ToolDefinition
from sovereign_control.vault import (
    AppRoleAuth,
    TokenAuth,
    VaultClient,
    VaultCredentialBroker,
    VaultCredentialSpec,
    VaultError,
)

SA_TOKEN = "eyJhbGciOiJSUzI1NiJ9.service-account-token-abc123"


class FakeVault(BaseHTTPRequestHandler):
    """Just enough of the Vault HTTP API: AppRole login, dynamic creds, a static KV secret, lease revocation."""

    state: dict = {}

    @classmethod
    def reset(cls):
        cls.state = {"tokens": {"root-token"}, "leases": {}, "requests": [], "logins": 0, "down": False}

    def _reply(self, code, body=None):
        raw = json.dumps(body or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        s = FakeVault.state
        if s["down"]:
            return self._reply(503, {"errors": ["Vault is sealed"]})
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        path = self.path.removeprefix("/v1/")
        s["requests"].append((self.command, path, body))
        if path == "auth/approle/login":
            if body.get("secret_id") != "good-secret":
                return self._reply(403, {"errors": ["permission denied"]})
            s["logins"] += 1
            token = f"login-token-{s['logins']}"
            s["tokens"].add(token)
            return self._reply(200, {"auth": {"client_token": token}})
        if self.headers.get("X-Vault-Token") not in s["tokens"]:
            return self._reply(403, {"errors": ["permission denied"]})
        if path.startswith("kubernetes/creds/") and self.command == "POST":
            if path != "kubernetes/creds/production-pod-restarter":
                return self._reply(400, {"errors": ["unknown role"]})
            lease = f"kubernetes/creds/production-pod-restarter/{len(s['leases']) + 1}"
            s["leases"][lease] = "active"
            return self._reply(200, {"lease_id": lease, "lease_duration": 300,
                                     "data": {"service_account_token": SA_TOKEN,
                                              "service_account_namespace": body.get("kubernetes_namespace")}})
        if path == "database/creds/production-dba" and self.command == "GET":
            s["leases"]["database/creds/production-dba/1"] = "active"
            return self._reply(200, {"lease_id": "database/creds/production-dba/1", "lease_duration": 120,
                                     "data": {"username": "v-dba-x1", "password": "A1b2C3d4E5f6G7h8"}})
        if path == "secret/data/static":
            return self._reply(200, {"lease_id": "", "lease_duration": 0, "data": {"password": "long-lived-secret"}})
        if path == "sys/leases/revoke" and self.command == "PUT":
            s["leases"][body["lease_id"]] = "revoked"
            return self._reply(204)
        return self._reply(404, {"errors": ["no handler"]})

    do_GET = do_POST = do_PUT = _handle

    def log_message(self, *args):
        pass


K8S_SPEC = VaultCredentialSpec("kubernetes/creds/{environment}-pod-restarter",
                               data={"kubernetes_namespace": "{param:namespace}"}, ttl=timedelta(minutes=5))


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        FakeVault.reset()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeVault)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addr = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def broker(self, auth=None, specs=None):
        client = VaultClient(self.addr, auth or AppRoleAuth("role", "good-secret"))
        return VaultCredentialBroker(client, specs or {"k8s.restart_pod": K8S_SPEC,
                                                       "db.kill_query": VaultCredentialSpec(
                                                           "database/creds/{environment}-dba", method="GET"),
                                                       "static.tool": VaultCredentialSpec("secret/data/static",
                                                                                          method="GET")})


class BrokerTests(VaultTestCase):
    def test_issue_and_revoke_dynamic_kubernetes_credential(self):
        b = self.broker()
        cred = b.issue("agent", "k8s.restart_pod", "production", params={"namespace": "shop"})
        self.assertEqual(cred.secret["service_account_token"], SA_TOKEN)
        self.assertEqual(cred.source, "vault:kubernetes/creds/production-pod-restarter")
        method, path, body = FakeVault.state["requests"][-1]
        self.assertEqual((method, body), ("POST", {"kubernetes_namespace": "shop", "ttl": "300s"}))
        self.assertAlmostEqual((cred.expires_at - cred.issued_at).total_seconds(), 300)
        self.assertNotIn(SA_TOKEN, repr(cred))
        b.revoke(cred)
        self.assertEqual(FakeVault.state["leases"][cred.lease_id], "revoked")
        self.assertEqual(cred.secret, {})

    def test_get_style_engine(self):
        cred = self.broker().issue("agent", "db.kill_query", "production")
        self.assertEqual(cred.secret["username"], "v-dba-x1")
        self.assertEqual(FakeVault.state["requests"][-1][2], {})

    def test_fail_closed(self):
        b = self.broker()
        with self.assertRaisesRegex(VaultError, "no Vault credential is configured"):
            b.issue("agent", "unmapped", "production")
        with self.assertRaisesRegex(VaultError, "static secret"):
            b.issue("agent", "static.tool", "production")
        FakeVault.state["down"] = True
        with self.assertRaisesRegex(VaultError, "HTTP 503: Vault is sealed"):
            b.issue("agent", "k8s.restart_pod", "production", params={"namespace": "shop"})

    def test_agent_params_cannot_steer_the_vault_path(self):
        b = self.broker(specs={"t": VaultCredentialSpec("kubernetes/creds/{param:role}")})
        for evil in ("../../sys/raw", "a/b", "", "x" * 300, 5, None):
            with self.assertRaises(VaultError):
                b.issue("agent", "t", "production", params={"role": evil})
        self.assertEqual(FakeVault.state["requests"], [])  # nothing reached Vault, not even a login

    def test_unknown_placeholder_rejected(self):
        b = self.broker(specs={"t": VaultCredentialSpec("kubernetes/creds/{secret_sauce}")})
        with self.assertRaisesRegex(VaultError, "unknown placeholder"):
            b.issue("agent", "t", "production")


class ClientAuthTests(VaultTestCase):
    def test_relogin_when_token_expires(self):
        b = self.broker()
        b.issue("agent", "k8s.restart_pod", "production", params={"namespace": "shop"})
        FakeVault.state["tokens"] = {"root-token"}  # Vault expired the login token
        b.issue("agent", "k8s.restart_pod", "production", params={"namespace": "shop"})
        self.assertEqual(FakeVault.state["logins"], 2)

    def test_bad_approle_secret(self):
        with self.assertRaisesRegex(VaultError, "login was refused"):
            self.broker(auth=AppRoleAuth("role", "wrong")).issue("a", "k8s.restart_pod", "production",
                                                                 params={"namespace": "shop"})

    def test_static_token(self):
        cred = self.broker(auth=TokenAuth("root-token")).issue("a", "db.kill_query", "production")
        self.assertTrue(cred.lease_id)
        with self.assertRaisesRegex(VaultError, "permission denied"):
            self.broker(auth=TokenAuth("nope")).issue("a", "db.kill_query", "production")


class GatewayVaultTests(VaultTestCase):
    def make(self, handler, **tool_kw):
        gw = SovereignGateway(credentials=self.broker())
        gw.tools.register(ToolDefinition(
            tool_id="k8s.restart_pod", name="Restart pod", version="1", owner="platform", description="",
            handler=handler, mutating=True, risk_level=RiskLevel.LOW, verifier=lambda p, r: True,
            rollback=lambda p, r, c: None, **tool_kw))
        gw.agents.issue("agent", role="sre", tenant="acme", environments={"production"}, permissions=set(),
                        tool_scopes={"k8s.restart_pod"}, autonomy=AutonomyLevel.L5_CLOSED_LOOP,
                        max_risk=RiskLevel.HIGH)
        return gw

    def test_tool_gets_the_secret_and_lease_is_revoked(self):
        seen = {}

        def handler(params, cred):
            seen["token"] = cred.secret["service_account_token"]
            return {"restarted": params["pod"]}

        gw = self.make(handler)
        ex = gw.request("agent", "k8s.restart_pod", "production", {"pod": "api-1", "namespace": "shop"})
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(seen["token"], SA_TOKEN)
        self.assertEqual(set(FakeVault.state["leases"].values()), {"revoked"})
        issued = next(e for e in gw.audit.events(ex.execution_id) if e.event_type == "credential.issued")
        self.assertEqual(issued.data["source"], "vault:kubernetes/creds/production-pod-restarter")
        self.assertEqual(len(issued.data["lease"]), 16)  # fingerprint, not the lease id itself
        self.assertNotIn(SA_TOKEN, json.dumps([e.data for e in gw.audit.events()]))

    def test_secret_echoed_by_tool_is_redacted(self):
        def leaky(params, cred):
            return {"debug": f"used token {cred.secret['service_account_token']}"}

        def leaky_error(params, cred):
            raise RuntimeError(f"auth failed with {cred.secret['service_account_token']}")

        gw = self.make(leaky)
        ex = gw.request("agent", "k8s.restart_pod", "production", {"pod": "a", "namespace": "shop"})
        self.assertEqual(ex.result, {"debug": "used token [REDACTED]"})
        gw = self.make(leaky_error)
        ex = gw.request("agent", "k8s.restart_pod", "production", {"pod": "a", "namespace": "shop"})
        self.assertEqual(ex.error, "RuntimeError: auth failed with [REDACTED]")
        self.assertNotIn(SA_TOKEN, json.dumps([e.data for e in gw.audit.events()]))

    def test_vault_down_means_action_not_taken(self):
        ran = []
        gw = self.make(lambda p, c: ran.append(1))
        FakeVault.state["down"] = True
        ex = gw.request("agent", "k8s.restart_pod", "production", {"pod": "a", "namespace": "shop"})
        self.assertEqual((ex.status, ran, ex.escalated), (ExecutionStatus.EXECUTION_FAILED, [], True))
        self.assertIn("credential could not be issued", ex.error)
        types = [e.event_type for e in gw.audit.events(ex.execution_id)]
        self.assertIn("credential.failed", types)
        self.assertNotIn("tool.executed", types)

    def test_revoke_failure_is_recorded_not_fatal(self):
        def handler(params, cred):
            FakeVault.state["down"] = True  # Vault goes away mid-action
            return "ok"

        gw = self.make(handler)
        ex = gw.request("agent", "k8s.restart_pod", "production", {"pod": "a", "namespace": "shop"})
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED)
        failed = [e for e in gw.audit.events(ex.execution_id) if e.event_type == "credential.revoke_failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("expires_at", failed[0].data)


if __name__ == "__main__":
    unittest.main()
