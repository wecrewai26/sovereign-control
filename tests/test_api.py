import json
import threading
import unittest
import urllib.error
import urllib.request

from sovereign_control import ApprovalMode, AutonomyLevel, RiskLevel, SovereignGateway, ToolDefinition
from sovereign_control.api import ControlAPI, make_server
from sovereign_control.auth import TokenAuthenticator


def build():
    gw = SovereignGateway()
    gw.tools.register(ToolDefinition(
        tool_id="k8s.restart_pod", name="Restart pod", version="1", owner="platform", description="",
        handler=lambda p, c: {"restarted": p.get("pod")}, mutating=True, risk_level=RiskLevel.LOW,
        required_permissions=frozenset({"k8s:write"}), verifier=lambda p, r: True,
        rollback=lambda p, r, c: None, approval_required=True, approval_mode=ApprovalMode.SINGLE,
    ))
    gw.tools.register(ToolDefinition(
        tool_id="k8s.get_pods", name="Get pods", version="1", owner="platform", description="",
        handler=lambda p, c: ["api-1"],
    ))
    for agent_id in ("k8s-agent", "other-agent"):
        gw.agents.issue(agent_id, role="sre", tenant="acme", environments={"production"},
                        permissions={"k8s:write"}, tool_scopes={"k8s.restart_pod", "k8s.get_pods"},
                        autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS, max_risk=RiskLevel.HIGH)
    auth = TokenAuthenticator()
    tokens = {
        "agent": auth.add_agent("k8s-agent"),
        "other": auth.add_agent("other-agent"),
        "alice": auth.add_user("alice", {"sre"}),
        "admin": auth.add_user("root", {"admin"}),
    }
    return ControlAPI(gw, auth), tokens


class APITests(unittest.TestCase):
    def setUp(self):
        self.api, self.t = build()

    def call(self, method, path, who=None, body=None):
        headers = {"Authorization": f"Bearer {self.t[who]}"} if who else {}
        raw = json.dumps(body).encode() if body is not None else b""
        return self.api.handle(method, path, headers, raw)

    def submit(self, **body):
        body.setdefault("tool_id", "k8s.restart_pod")
        body.setdefault("environment", "production")
        return self.call("POST", "/v1/agent/actions", "agent", body)

    def test_health_needs_no_auth(self):
        self.assertEqual(self.call("GET", "/healthz"), (200, {"status": "ok"}))

    def test_auth_required(self):
        self.assertEqual(self.call("GET", "/v1/tools")[0], 401)
        status, _ = self.api.handle("GET", "/v1/tools", {"Authorization": "Bearer nope"})
        self.assertEqual(status, 401)

    def test_principal_kinds_are_separated(self):
        self.assertEqual(self.call("GET", "/v1/tools", "agent")[0], 403)
        self.assertEqual(self.call("POST", "/v1/agent/actions", "alice", {})[0], 403)

    def test_unknown_route_and_method(self):
        self.assertEqual(self.call("GET", "/nope", "alice")[0], 404)
        self.assertEqual(self.call("DELETE", "/v1/tools", "alice")[0], 405)

    def test_read_only_tool_executes_immediately(self):
        status, ex = self.submit(tool_id="k8s.get_pods")
        self.assertEqual(status, 200)
        self.assertEqual(ex["status"], "succeeded")
        self.assertEqual(ex["result"], ["api-1"])

    def test_full_approval_flow(self):
        status, ex = self.submit(params={"pod": "api-1"},
                                 context={"severity": "critical", "confidence": 0.9, "evidence": ["OOMKilled"]})
        self.assertEqual((status, ex["status"]), (200, "pending_approval"))
        eid = ex["execution_id"]

        status, pending = self.call("GET", "/v1/approvals", "alice")
        self.assertEqual([a["execution_id"] for a in pending["approvals"]], [eid])

        status, ex = self.call("POST", f"/v1/executions/{eid}/approve", "alice", {"role": "sre"})
        self.assertEqual((status, ex["status"]), (200, "succeeded"))
        self.assertEqual(ex["approval"]["approvers"], [{"user": "alice", "role": "sre"}])

        status, agent_view = self.call("GET", f"/v1/agent/actions/{eid}", "agent")
        self.assertEqual(agent_view["status"], "succeeded")

        status, audit = self.call("GET", f"/v1/audit?execution_id={eid}", "alice")
        self.assertIn("approval.granted", [e["event_type"] for e in audit["events"]])
        self.assertEqual(self.call("GET", "/v1/audit/verify", "alice")[1]["valid"], True)

    def test_cannot_approve_with_role_you_do_not_hold(self):
        eid = self.submit()[1]["execution_id"]
        self.assertEqual(self.call("POST", f"/v1/executions/{eid}/approve", "alice", {"role": "security"})[0], 403)

    def test_double_decision_conflicts(self):
        eid = self.submit()[1]["execution_id"]
        self.assertEqual(self.call("POST", f"/v1/executions/{eid}/reject", "alice", {"reason": "no"})[1]["status"],
                         "rejected")
        self.assertEqual(self.call("POST", f"/v1/executions/{eid}/approve", "alice", {"role": "sre"})[0], 409)

    def test_agents_cannot_see_each_others_executions(self):
        eid = self.submit()[1]["execution_id"]
        self.assertEqual(self.call("GET", f"/v1/agent/actions/{eid}", "other")[0], 404)

    def test_agent_identity_comes_from_token_not_body(self):
        status, ex = self.submit(agent_id="other-agent")
        self.assertEqual(ex["agent_id"], "k8s-agent")

    def test_input_validation(self):
        self.assertEqual(self.submit(tool_id=5)[0], 400)
        self.assertEqual(self.submit(params=[1])[0], 400)
        self.assertEqual(self.submit(context={"confidence": 3})[0], 400)
        self.assertEqual(self.submit(context={"confidence": True})[0], 400)
        self.assertEqual(self.submit(context={"rogue": 1})[0], 400)
        status, _ = self.api.handle("POST", "/v1/agent/actions", {"Authorization": f"Bearer {self.t['agent']}"},
                                    b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(self.submit(tool_id="missing.tool")[0], 404)

    def test_execution_filters(self):
        self.submit(tool_id="k8s.get_pods")
        self.submit()
        _, data = self.call("GET", "/v1/executions?status=pending_approval", "alice")
        self.assertEqual([e["tool_id"] for e in data["executions"]], ["k8s.restart_pod"])
        self.assertEqual(self.call("GET", "/v1/executions?status=bogus", "alice")[0], 400)

    def test_disable_agent_requires_admin_and_blocks_agent(self):
        self.assertEqual(self.call("POST", "/v1/agents/k8s-agent/disable", "alice")[0], 403)
        status, agent = self.call("POST", "/v1/agents/k8s-agent/disable", "admin")
        self.assertEqual((status, agent["active"]), (200, False))
        self.assertEqual(self.submit(tool_id="k8s.get_pods")[1]["status"], "denied")

    def test_control_tower(self):
        self.submit()
        self.submit(tool_id="k8s.get_pods")
        _, tower = self.call("GET", "/v1/control-tower", "alice")
        self.assertEqual(tower["agents"], {"total": 2, "active": 2})
        self.assertEqual(tower["pending_approvals"], 1)
        self.assertEqual(tower["executions"], {"pending_approval": 1, "succeeded": 1})
        self.assertTrue(tower["audit"]["chain_valid"])

    def test_handler_bug_returns_500_without_details(self):
        self.api.gateway.request = None  # simulate a bug inside the gateway
        status, body = self.submit(tool_id="k8s.get_pods")
        self.assertEqual((status, body), (500, {"error": "internal error"}))


class ServerTests(unittest.TestCase):
    def test_over_real_socket(self):
        api, tokens = build()
        server = make_server(api, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # ignore host proxy settings
        try:
            req = urllib.request.Request(
                f"{base}/v1/agent/actions", method="POST",
                data=json.dumps({"tool_id": "k8s.get_pods", "environment": "production"}).encode(),
                headers={"Authorization": f"Bearer {tokens['agent']}", "Content-Type": "application/json"},
            )
            with opener.open(req) as resp:
                self.assertEqual(json.load(resp)["status"], "succeeded")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                opener.open(f"{base}/v1/tools")
            self.assertEqual(ctx.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
