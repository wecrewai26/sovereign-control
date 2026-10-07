import json
import tempfile
import unittest
from pathlib import Path

from sovereign_control import (
    ActionContext,
    AutonomyLevel,
    IncidentManager,
    OpsGraph,
    RiskLevel,
    SovereignGateway,
    SQLiteStore,
    ToolDefinition,
)
from sovereign_control.alertmind import AlertMind, CorrelationConfig, parse_generic
from sovereign_control.api import ControlAPI
from sovereign_control.auth import TokenAuthenticator
from sovereign_control.opsgraph import GraphError

# Spec §33/§41 shape: web → api-gateway → order-service → {postgres, redis, rabbitmq}; pods on nodes.
GRAPH = {
    "nodes": [
        {"id": "web", "customer_facing": True, "owner": "frontend"},
        {"id": "api-gateway"},
        {"id": "order-service", "owner": "orders"},
        {"id": "postgres", "kind": "database"},
        {"id": "redis", "kind": "cache"},
        {"id": "rabbitmq", "kind": "queue"},
        {"id": "node-7", "kind": "node"},
        {"id": "rack-2", "kind": "rack"},
    ],
    "edges": [
        {"from": "web", "kind": "depends_on", "to": "api-gateway"},
        {"from": "api-gateway", "kind": "depends_on", "to": "order-service"},
        {"from": "order-service", "kind": "depends_on", "to": "postgres"},
        {"from": "order-service", "kind": "depends_on", "to": "redis"},
        {"from": "order-service", "kind": "depends_on", "to": "rabbitmq"},
        {"from": "postgres", "kind": "deployed_on", "to": "node-7"},
        {"from": "node-7", "kind": "runs_on", "to": "rack-2"},
        {"from": "orders-team", "kind": "owns", "to": "order-service"},
    ],
}


def build_graph():
    return OpsGraph.from_dict(GRAPH)


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.g = build_graph()

    def test_impact_follows_dependencies_and_placement(self):
        impact = self.g.impact("rack-2")
        self.assertEqual(impact["impacted"], ["api-gateway", "node-7", "order-service", "postgres", "web"])
        self.assertEqual(impact["customer_facing_impacted"], ["web"])
        self.assertEqual(self.g.impact("web")["impacted"], [])
        self.assertEqual(self.g.dependencies("web"), {"api-gateway", "order-service", "postgres", "redis",
                                                      "rabbitmq", "node-7", "rack-2"})

    def test_ownership_does_not_carry_impact(self):
        self.assertEqual(self.g.impacted_by("orders-team"), set())
        self.assertNotIn("orders-team", self.g.impacted_by("order-service"))

    def test_related(self):
        self.assertTrue(self.g.related("web", "postgres"))
        self.assertTrue(self.g.related("rack-2", "web"))
        self.assertFalse(self.g.related("redis", "rabbitmq"))  # siblings
        self.assertFalse(self.g.related("web", "unknown"))

    def test_cycles_terminate(self):
        g = OpsGraph.from_dependencies({"a": ["b"], "b": ["c"], "c": ["a"]})
        self.assertEqual(g.impacted_by("a"), {"b", "c"})

    def test_round_trip_and_fingerprint(self):
        again = OpsGraph.from_dict(self.g.to_dict())
        self.assertEqual(again.fingerprint(), self.g.fingerprint())
        again.add_edge("web", "depends_on", "redis")
        self.assertNotEqual(again.fingerprint(), self.g.fingerprint())

    def test_validation(self):
        for bad in ([], {"nodes": "x"}, {"nodes": [{"id": ""}]}, {"nodes": [{"id": "a", "bogus": 1}]},
                    {"nodes": [{"id": "a", "customer_facing": "yes"}]},
                    {"edges": [{"from": "a", "kind": "likes", "to": "b"}]}, {"edges": [{"from": "a"}]}):
            with self.assertRaises(GraphError):
                OpsGraph.from_dict(bad)


def restart_tool(**kw):
    return ToolDefinition(tool_id="svc.restart", name="Restart", version="1", owner="platform", description="",
                          handler=lambda p, c: "ok", mutating=True, risk_level=RiskLevel.LOW,
                          verifier=lambda p, r: True, rollback=lambda p, r, c: None, **kw)


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.gw = SovereignGateway(graph=build_graph())
        self.tool = restart_tool()

    def test_graph_raises_blast_radius_and_customer_impact(self):
        risk = self.gw.risk.assess(self.tool, "production", ActionContext(service="postgres", affected_services=1))
        self.assertEqual(risk.factors["blast_radius"], 15)  # postgres → order-service, api-gateway, web
        self.assertEqual(risk.factors["customer_impact"], 10)  # web is customer-facing
        self.assertTrue(any("OpsGraph" in n for n in risk.notes))

    def test_agent_cannot_understate_but_can_overstate(self):
        low = self.gw.risk.assess(self.tool, "production", ActionContext(service="redis", affected_services=0))
        self.assertEqual(low.factors["blast_radius"], 15)
        high = self.gw.risk.assess(self.tool, "production", ActionContext(service="web", affected_services=6))
        self.assertEqual(high.factors["blast_radius"], 20)

    def test_unknown_service_is_flagged(self):
        risk = self.gw.risk.assess(self.tool, "production", ActionContext(service="mystery"))
        self.assertEqual(risk.notes, ("mystery is not in the OpsGraph; blast radius is the agent's claim only",))

    def test_no_graph_no_notes(self):
        risk = SovereignGateway().risk.assess(self.tool, "production", ActionContext(service="postgres"))
        self.assertEqual((risk.notes, risk.factors["blast_radius"]), ((), 0))

    def test_graph_can_change_the_policy_outcome(self):
        """A restart of a LOW-risk-looking cache becomes MEDIUM once the graph shows what depends on it."""
        self.gw.tools.register(self.tool)
        self.gw.agents.issue("agent", role="sre", tenant="acme", environments={"staging"}, permissions=set(),
                             tool_scopes={"svc.restart"}, autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS,
                             max_risk=RiskLevel.HIGH)
        plain = SovereignGateway()
        plain.tools.register(restart_tool())
        plain.agents.issue("agent", role="sre", tenant="acme", environments={"staging"}, permissions=set(),
                           tool_scopes={"svc.restart"}, autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS,
                           max_risk=RiskLevel.HIGH)
        ctx = ActionContext(service="postgres")
        self.assertEqual(plain.request("agent", "svc.restart", "staging", context=ctx).status.value, "succeeded")
        ex = self.gw.request("agent", "svc.restart", "staging", context=ctx)
        self.assertEqual(ex.status.value, "pending_approval")
        notes = self.gw.audit.events(ex.execution_id)[1].data["notes"]
        self.assertTrue(notes and "OpsGraph" in notes[0])


class AlertMindGraphTests(unittest.TestCase):
    def test_node_failure_correlates_with_service_alerts(self):
        gw = SovereignGateway(graph=build_graph())
        mind = AlertMind(IncidentManager(gw), CorrelationConfig(graph=gw.graph))
        results = mind.ingest(parse_generic({"alerts": [
            {"name": "NodeNotReady", "service": "node-7", "severity": "critical"},
            {"name": "CheckoutErrors", "service": "web", "severity": "high"},
        ]}), actor="am")
        self.assertEqual([r.action for r in results], ["opened", "attached"])


class GraphAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "aegis.db")
        self.store = SQLiteStore(self.path)
        self.gw = SovereignGateway(store=self.store)
        auth = TokenAuthenticator()
        self.t = {"admin": auth.add_user("root", {"admin"}), "alice": auth.add_user("alice", {"sre"}),
                  "agent": auth.add_agent("agent")}
        self.api = ControlAPI(self.gw, auth)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def call(self, method, path, who, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.api.handle(method, path, {"Authorization": f"Bearer {self.t[who]}"}, raw)

    def test_replace_requires_admin_and_is_audited_and_persisted(self):
        self.assertEqual(self.call("PUT", "/v1/opsgraph", "alice", GRAPH)[0], 403)
        self.assertEqual(self.call("PUT", "/v1/opsgraph", "admin", {"edges": [{"from": "a"}]})[0], 400)
        status, body = self.call("PUT", "/v1/opsgraph", "admin", GRAPH)
        self.assertEqual((status, body["nodes"]), (200, 9))
        event = self.gw.audit.events()[-1]
        self.assertEqual((event.event_type, event.data["fingerprint"]), ("opsgraph.replaced", body["fingerprint"]))

        # The same graph object is used by the risk engine and AlertMind.
        self.assertIs(self.gw.risk.graph, self.gw.graph)
        self.assertIs(self.api.alertmind.config.graph, self.gw.graph)
        self.assertTrue(self.gw.graph.related("web", "postgres"))

        # Survives a restart, and wins over a graph passed in code.
        restarted = SovereignGateway(store=self.store, graph=OpsGraph.from_dependencies({"x": ["y"]}))
        self.assertEqual(restarted.graph.fingerprint(), body["fingerprint"])

    def test_impact_endpoints(self):
        self.call("PUT", "/v1/opsgraph", "admin", GRAPH)
        _, impact = self.call("GET", "/v1/opsgraph/postgres/impact", "alice")
        self.assertEqual(impact["impacted"], ["api-gateway", "order-service", "web"])
        _, agent_view = self.call("GET", "/v1/agent/opsgraph/postgres/impact", "agent")
        self.assertEqual(agent_view, impact)
        _, unknown = self.call("GET", "/v1/opsgraph/nope/impact", "alice")
        self.assertFalse(unknown["known"])
        _, whole = self.call("GET", "/v1/opsgraph", "alice")
        self.assertEqual(len(whole["edges"]), 8)
        self.assertEqual(self.call("PUT", "/v1/opsgraph", "agent", GRAPH)[0], 403)


if __name__ == "__main__":
    unittest.main()
