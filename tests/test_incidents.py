import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from sovereign_control import (
    ActionContext,
    AutonomyLevel,
    IncidentError,
    IncidentManager,
    IncidentStatus,
    RiskLevel,
    SovereignGateway,
    SQLiteStore,
    ToolDefinition,
)
from sovereign_control.api import ControlAPI, FileResponse
from sovereign_control.auth import TokenAuthenticator
from sovereign_control.evidence import build_bundle, verify_bundle
from sovereign_control.incidents import IncidentConflict, IncidentNotFound


def make_gateway(store=None):
    gw = SovereignGateway(store=store)
    gw.tools.register(ToolDefinition(
        tool_id="k8s.rollout_undo", name="Rollback", version="1", owner="platform", description="",
        handler=lambda p, c: {"to_revision": 41}, mutating=True, risk_level=RiskLevel.LOW,
        verifier=lambda p, r: True, rollback=lambda p, r, c: None,
    ))
    if not gw.agents.all():
        gw.agents.issue("agent", role="sre", tenant="acme", environments={"production"}, permissions=set(),
                        tool_scopes={"k8s.rollout_undo"}, autonomy=AutonomyLevel.L5_CLOSED_LOOP,
                        max_risk=RiskLevel.HIGH)
        gw.agents.issue("other", role="sre", tenant="acme", environments={"production"}, permissions=set(),
                        tool_scopes={"k8s.rollout_undo"}, autonomy=AutonomyLevel.L5_CLOSED_LOOP,
                        max_risk=RiskLevel.HIGH)
    return gw


class IncidentManagerTests(unittest.TestCase):
    def setUp(self):
        self.gw = make_gateway()
        self.im = IncidentManager(self.gw)
        self.inc = self.im.open("Checkout error rate spike", actor="alertmind", severity="critical",
                                service="checkout", environment="production")

    def test_ids_are_sequential(self):
        self.assertEqual(self.inc.incident_id, "INC-0001")
        self.assertEqual(self.im.open("Second", actor="x").incident_id, "INC-0002")

    def test_alerts_are_deduplicated(self):
        alert = {"name": "HighErrorRate", "source": "prometheus", "severity": "critical"}
        self.im.attach_alert(self.inc.incident_id, alert, actor="alertmind")
        self.im.attach_alert(self.inc.incident_id, alert, actor="alertmind")
        self.im.attach_alert(self.inc.incident_id, {"name": "DBPoolSaturated", "source": "prometheus"},
                             actor="alertmind")
        self.assertEqual([(a["name"], a["count"]) for a in self.inc.alerts],
                         [("HighErrorRate", 2), ("DBPoolSaturated", 1)])

    def test_status_lifecycle(self):
        iid = self.inc.incident_id
        self.im.set_status(iid, IncidentStatus.INVESTIGATING, actor="agent")
        with self.assertRaises(IncidentError):  # resolution required
            self.im.set_status(iid, IncidentStatus.RESOLVED, actor="alice")
        self.im.set_status(iid, IncidentStatus.RESOLVED, actor="alice", resolution="Rolled back rev 42")
        self.assertIsNotNone(self.inc.resolved_at)
        self.im.set_status(iid, IncidentStatus.INVESTIGATING, actor="alice", note="recurred")  # reopen
        self.assertIsNone(self.inc.resolved_at)
        self.im.set_status(iid, IncidentStatus.RESOLVED, actor="alice")  # earlier resolution kept
        self.im.set_status(iid, IncidentStatus.CLOSED, actor="alice")
        with self.assertRaises(IncidentConflict):
            self.im.set_status(iid, IncidentStatus.INVESTIGATING, actor="alice")
        with self.assertRaises(IncidentConflict):
            self.im.attach_alert(iid, {"name": "x"}, actor="alice")

    def test_invalid_transition(self):
        with self.assertRaises(IncidentConflict):
            self.im.set_status(self.inc.incident_id, IncidentStatus.CLOSED, actor="alice")

    def test_update_validates_and_records_changes(self):
        self.im.update(self.inc.incident_id, actor="alice", owner="alice", root_cause="DB pool exhaustion")
        self.assertEqual(self.inc.owner, "alice")
        with self.assertRaises(IncidentError):
            self.im.update(self.inc.incident_id, actor="alice", severity="apocalyptic")
        with self.assertRaises(IncidentError):
            self.im.update(self.inc.incident_id, actor="alice", status="closed")
        last = self.im.timeline(self.inc.incident_id)[-1]
        self.assertEqual(last.event_type, "incident.updated")
        self.assertEqual(last.data["changes"]["owner"], {"from": None, "to": "alice"})

    def test_timeline_merges_incident_and_execution_events(self):
        ex = self.gw.request("agent", "k8s.rollout_undo", "production", {"deployment": "checkout"})
        self.gw.request("agent", "k8s.rollout_undo", "production", {"deployment": "unrelated"})
        self.im.link_execution(self.inc.incident_id, ex.execution_id, actor="agent")
        types = [e.event_type for e in self.im.timeline(self.inc.incident_id)]
        self.assertEqual(types[0], "incident.opened")
        self.assertIn("tool.executed", types)
        self.assertEqual(types.count("tool.executed"), 1)  # the unrelated execution is excluded
        with self.assertRaises(IncidentNotFound):
            self.im.link_execution(self.inc.incident_id, "exe-nope", actor="agent")

    def test_incident_evidence_bundle(self):
        ex = self.gw.request("agent", "k8s.rollout_undo", "production", {"deployment": "checkout"},
                             ActionContext(hypothesis="bad deploy"))
        self.im.link_execution(self.inc.incident_id, ex.execution_id, actor="agent")
        self.im.attach_alert(self.inc.incident_id, {"name": "HighErrorRate"}, actor="alertmind")
        self.im.update(self.inc.incident_id, actor="alice", root_cause="Deploy rev 42 leaked DB connections")
        bundle = build_bundle(self.gw, [], exported_by="auditor", incidents=self.im,
                              incident_id=self.inc.incident_id)
        self.assertEqual(verify_bundle(bundle.content), [])
        zf = zipfile.ZipFile(io.BytesIO(bundle.content))
        self.assertIn("incident.json", zf.namelist())
        manifest = json.loads(zf.read("manifest.json"))
        self.assertEqual((manifest["incident_id"], manifest["execution_ids"]),
                         (self.inc.incident_id, [ex.execution_id]))
        events = [e["event"] for e in json.loads(zf.read("timeline.json"))]
        self.assertIn("incident.alert_attached", events)
        self.assertIn("tool.executed", events)
        rca = zf.read("RCA.md").decode()
        self.assertIn("# INC-0001: Checkout error rate spike", rca)
        self.assertIn("Deploy rev 42 leaked DB connections", rca)
        self.assertEqual(self.gw.audit.events()[-1].data["incident_id"], self.inc.incident_id)


class IncidentPersistenceTests(unittest.TestCase):
    def test_incidents_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "aegis.db")
            store = SQLiteStore(path)
            gw = make_gateway(store)
            im = IncidentManager(gw)
            inc = im.open("Disk filling", actor="agent", severity="high")
            im.attach_alert(inc.incident_id, {"name": "DiskPressure"}, actor="agent")
            im.set_status(inc.incident_id, IncidentStatus.INVESTIGATING, actor="agent")
            store.close()

            store2 = SQLiteStore(path)
            gw2 = make_gateway(store2)
            im2 = IncidentManager(gw2)
            restored = im2.get(inc.incident_id)
            self.assertEqual(restored.status, IncidentStatus.INVESTIGATING)
            self.assertEqual(restored.alerts[0]["name"], "DiskPressure")
            self.assertEqual(len(im2.timeline(inc.incident_id)), 3)
            self.assertEqual(im2.open("Next", actor="x").incident_id, "INC-0002")
            store2.close()


class IncidentAPITests(unittest.TestCase):
    def setUp(self):
        self.gw = make_gateway()
        auth = TokenAuthenticator()
        self.t = {"agent": auth.add_agent("agent"), "other": auth.add_agent("other"),
                  "alice": auth.add_user("alice", {"sre"})}
        self.api = ControlAPI(self.gw, auth)

    def call(self, method, path, who, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.api.handle(method, path, {"Authorization": f"Bearer {self.t[who]}"}, raw)

    def test_agent_driven_incident_flow(self):
        status, inc = self.call("POST", "/v1/agent/incidents", "agent",
                                {"title": "Checkout 5xx", "severity": "critical", "service": "checkout"})
        self.assertEqual((status, inc["detection_source"]), (200, "agent:agent"))
        iid = inc["incident_id"]
        self.call("POST", f"/v1/agent/incidents/{iid}/alerts", "agent", {"name": "HighErrorRate"})
        self.assertEqual(self.call("POST", f"/v1/agent/incidents/{iid}/status", "agent",
                                   {"status": "mitigating"})[1]["status"], "mitigating")

        status, ex = self.call("POST", "/v1/agent/actions", "agent", {
            "tool_id": "k8s.rollout_undo", "environment": "production", "incident_id": iid})
        self.assertEqual(ex["status"], "succeeded")

        # Agents can't resolve.
        self.assertEqual(self.call("POST", f"/v1/agent/incidents/{iid}/status", "agent",
                                   {"status": "resolved", "resolution": "x"})[0], 403)

        status, inc = self.call("POST", f"/v1/incidents/{iid}/status", "alice",
                                {"status": "resolved", "resolution": "Rolled back"})
        self.assertEqual(inc["status"], "resolved")

        _, full = self.call("GET", f"/v1/incidents/{iid}", "alice")
        self.assertEqual(full["execution_ids"], [ex["execution_id"]])
        events = [e["event"] for e in full["timeline"]]
        self.assertEqual(events[0], "incident.opened")
        self.assertIn("incident.execution_linked", events)
        self.assertEqual(events[-1], "incident.status_changed")

        status, body = self.call("GET", f"/v1/incidents/{iid}/evidence", "alice")
        self.assertIsInstance(body, FileResponse)
        self.assertEqual(verify_bundle(body.content), [])

    def test_action_against_unknown_or_closed_incident_is_refused_before_running(self):
        status, _ = self.call("POST", "/v1/agent/actions", "agent",
                              {"tool_id": "k8s.rollout_undo", "environment": "production", "incident_id": "INC-9999"})
        self.assertEqual(status, 404)
        self.assertEqual(self.gw.executions(), [])

    def test_errors_and_filters(self):
        iid = self.call("POST", "/v1/incidents", "alice", {"title": "A", "severity": "low"})[1]["incident_id"]
        self.call("POST", "/v1/incidents", "alice", {"title": "B", "severity": "critical"})
        self.assertEqual(self.call("POST", "/v1/incidents", "alice", {"title": ""})[0], 400)
        self.assertEqual(self.call("POST", "/v1/incidents", "alice", {"title": "x", "bogus": 1})[0], 400)
        self.assertEqual(self.call("POST", "/v1/incidents", "alice", {"title": "x", "severity": "huge"})[0], 400)
        self.assertEqual(self.call("GET", "/v1/incidents/INC-9999", "alice")[0], 404)
        self.assertEqual(self.call("POST", f"/v1/incidents/{iid}/status", "alice", {"status": "closed"})[0], 409)
        self.assertEqual(self.call("POST", f"/v1/incidents/{iid}/status", "alice", {"status": "nope"})[0], 400)
        self.assertEqual(self.call("POST", f"/v1/incidents/{iid}/links", "alice", {"execution_id": "exe-x"})[0], 404)
        self.assertEqual(self.call("POST", f"/v1/incidents/{iid}/alerts", "alice", {"name": "x", "labels": [1]})[0],
                         400)
        _, crit = self.call("GET", "/v1/incidents?severity=critical", "alice")
        self.assertEqual([i["title"] for i in crit["incidents"]], ["B"])
        _, tower = self.call("GET", "/v1/control-tower", "alice")
        self.assertEqual(tower["open_incidents"], {"low": 1, "critical": 1})
        self.assertEqual(self.call("GET", "/v1/incidents", "agent")[0], 403)

    def test_update_endpoint(self):
        iid = self.call("POST", "/v1/incidents", "alice", {"title": "A"})[1]["incident_id"]
        status, inc = self.call("POST", f"/v1/incidents/{iid}/update", "alice",
                                {"owner": "alice", "root_cause": "cert expired"})
        self.assertEqual((status, inc["owner"], inc["root_cause"]), (200, "alice", "cert expired"))
        self.assertEqual(self.call("POST", f"/v1/incidents/{iid}/update", "alice", {"owner": 5})[0], 400)


if __name__ == "__main__":
    unittest.main()
