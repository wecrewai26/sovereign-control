import json
import unittest
from datetime import timedelta

from sovereign_control import IncidentManager, IncidentStatus, SovereignGateway
from sovereign_control.alertmind import (
    AlertError,
    AlertMind,
    CorrelationConfig,
    Silence,
    normalize_severity,
    parse_alertmanager,
    parse_generic,
)
from sovereign_control.api import ControlAPI
from sovereign_control.auth import TokenAuthenticator
from sovereign_control.models import utcnow

DEPS = {
    "web": ["api-gateway"],
    "api-gateway": ["order-service"],
    "order-service": ["postgres", "rabbitmq", "redis"],
}


def am_payload(*alerts, status="firing"):
    return {"version": "4", "status": status, "commonLabels": {"env": "production"}, "alerts": [
        {"status": a.get("status", status), "labels": {"alertname": a["name"], "service": a["service"],
                                                       "severity": a.get("severity", "warning")},
         "annotations": {"summary": a.get("summary", "")}, "fingerprint": a.get("fp", a["name"])}
        for a in alerts
    ]}


class ParsingTests(unittest.TestCase):
    def test_alertmanager(self):
        [a] = parse_alertmanager(am_payload({"name": "PostgresSlow", "service": "postgres", "severity": "critical",
                                             "summary": "p99 latency 2s"}))
        self.assertEqual((a.name, a.service, a.environment, a.severity, a.summary, a.source),
                         ("PostgresSlow", "postgres", "production", "critical", "p99 latency 2s", "alertmanager"))

    def test_generic_single_and_batch(self):
        self.assertEqual(len(parse_generic({"name": "x"})), 1)
        self.assertEqual(len(parse_generic({"alerts": [{"name": "x"}, {"name": "y"}]})), 2)

    def test_bad_payloads(self):
        for bad in ({}, {"alerts": "x"}, {"alerts": [{"labels": {}}]}, {"alerts": [{"labels": [1]}]}):
            with self.assertRaises(AlertError):
                parse_alertmanager(bad)
        for bad in ({"name": ""}, {"name": "x", "status": "maybe"}, {"alerts": [5]}):
            with self.assertRaises(AlertError):
                parse_generic(bad)

    def test_severity_normalization(self):
        self.assertEqual([normalize_severity(s) for s in ("P1", "error", "warning", "info", None, "weird")],
                         ["critical", "high", "medium", "low", "medium", "medium"])


class DependencyTests(unittest.TestCase):
    def test_related_follows_chains_both_ways_but_not_siblings(self):
        config = CorrelationConfig(dependencies={**DEPS, "postgres": ["order-service"]})  # includes a cycle
        self.assertTrue(config.related("web", "postgres"))
        self.assertTrue(config.related("postgres", "web"))
        self.assertTrue(config.related("redis", "redis"))
        self.assertFalse(config.related("redis", "rabbitmq"))  # siblings share a parent, nothing more
        self.assertFalse(config.related("web", "logging"))
        self.assertFalse(config.related("", "web"))


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.gw = SovereignGateway()
        self.im = IncidentManager(self.gw)
        self.mind = AlertMind(self.im, CorrelationConfig(dependencies=DEPS))

    def ingest(self, *alerts, **kw):
        return self.mind.ingest(parse_alertmanager(am_payload(*alerts, **kw)), actor="alertmanager")

    def test_spec_example_five_alerts_become_one_incident(self):
        """Spec §22: CPU, DB latency, API timeout, queue increase and pod restart → one incident."""
        results = self.ingest(
            {"name": "PostgresConnectionsExhausted", "service": "postgres", "severity": "critical",
             "summary": "Database connection exhaustion"},
            {"name": "HighCPU", "service": "order-service"},
            {"name": "APITimeout", "service": "api-gateway", "severity": "error"},
            {"name": "QueueBacklog", "service": "rabbitmq"},
            {"name": "PodRestarting", "service": "order-service"},
        )
        self.assertEqual([r.action for r in results], ["opened", "attached", "attached", "attached", "attached"])
        self.assertEqual(len(self.im.all()), 1)
        inc = self.im.all()[0]
        self.assertEqual(inc.title, "Database connection exhaustion")
        self.assertEqual(inc.severity, "critical")
        self.assertEqual(set(inc.affected_services), {"postgres", "order-service", "api-gateway", "rabbitmq"})
        self.assertEqual(len(inc.alerts), 5)

    def test_unrelated_service_opens_its_own_incident(self):
        self.ingest({"name": "PostgresSlow", "service": "postgres"})
        [r] = self.ingest({"name": "DiskFull", "service": "logging"})
        self.assertEqual(r.action, "opened")
        self.assertEqual(len(self.im.all()), 2)

    def test_other_environment_is_not_correlated(self):
        self.ingest({"name": "PostgresSlow", "service": "postgres"})
        [r] = self.mind.ingest(parse_generic({"name": "PostgresSlow2", "service": "postgres",
                                              "environment": "staging"}), actor="x")
        self.assertEqual(r.action, "opened")

    def test_repeat_and_resolve(self):
        self.ingest({"name": "PostgresSlow", "service": "postgres"})
        [r] = self.ingest({"name": "PostgresSlow", "service": "postgres"})
        self.assertEqual(r.action, "deduplicated")
        [r] = self.ingest({"name": "PostgresSlow", "service": "postgres"}, status="resolved")
        self.assertEqual(r.action, "resolved")
        alert = self.im.all()[0].alerts[0]
        self.assertEqual((alert["count"], alert["status"]), (2, "resolved"))
        [r] = self.ingest({"name": "Unknown", "service": "x"}, status="resolved")
        self.assertEqual(r.action, "ignored")

    def test_low_severity_alone_is_noise_but_joins_existing_incident(self):
        [r] = self.ingest({"name": "CacheMissRate", "service": "redis", "severity": "info"})
        self.assertEqual((r.action, self.im.all()), ("ignored", []))
        self.ingest({"name": "PostgresSlow", "service": "postgres"})
        [r] = self.ingest({"name": "CacheMissRate", "service": "order-service", "severity": "info"})
        self.assertEqual(r.action, "attached")

    def test_silence(self):
        self.mind.config.silences.append(Silence("pg-maintenance", {"service": "postgres"},
                                                 utcnow() + timedelta(hours=1)))
        [r] = self.ingest({"name": "PostgresDown", "service": "postgres", "severity": "critical"})
        self.assertEqual((r.action, self.im.all()), ("suppressed", []))
        self.assertEqual(self.gw.audit.events()[-1].event_type, "alert.suppressed")
        self.mind.config.silences[0] = Silence("old", {"service": "postgres"}, utcnow() - timedelta(minutes=1))
        [r] = self.ingest({"name": "PostgresDown", "service": "postgres", "severity": "critical"})
        self.assertEqual(r.action, "opened")

    def test_correlation_window(self):
        self.ingest({"name": "PostgresSlow", "service": "postgres"})
        inc = self.im.all()[0]
        old = (utcnow() - timedelta(hours=2)).isoformat()
        inc.created_at = old
        inc.alerts[0]["last_seen"] = old
        [r] = self.ingest({"name": "OrderErrors", "service": "order-service"})
        self.assertEqual(r.action, "opened")

    def test_resolved_incident_is_not_reused(self):
        self.ingest({"name": "PostgresSlow", "service": "postgres"})
        iid = self.im.all()[0].incident_id
        self.im.set_status(iid, IncidentStatus.RESOLVED, actor="alice", resolution="tuned pool")
        [r] = self.ingest({"name": "PostgresSlow", "service": "postgres"})
        self.assertEqual(r.action, "opened")
        self.assertNotEqual(r.incident_id, iid)

    def test_everything_is_audited(self):
        self.ingest({"name": "PostgresSlow", "service": "postgres", "severity": "critical"},
                    {"name": "APITimeout", "service": "api-gateway"})
        types = [e.event_type for e in self.gw.audit.events()]
        self.assertEqual(types, ["incident.opened", "incident.alert_attached", "incident.alert_attached",
                                 "incident.updated"])
        self.assertEqual({e.actor for e in self.gw.audit.events()}, {"alertmanager"})


class IngestAPITests(unittest.TestCase):
    def setUp(self):
        self.gw = SovereignGateway()
        auth = TokenAuthenticator()
        self.t = {"am": auth.add_integration("alertmanager-prod"), "alice": auth.add_user("alice", {"sre"})}
        im = IncidentManager(self.gw)
        self.api = ControlAPI(self.gw, auth, incidents=im,
                              alertmind=AlertMind(im, CorrelationConfig(dependencies=DEPS)))

    def call(self, method, path, who, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.api.handle(method, path, {"Authorization": f"Bearer {self.t[who]}"}, raw)

    def test_alertmanager_webhook(self):
        status, body = self.call("POST", "/v1/ingest/alertmanager", "am", am_payload(
            {"name": "PostgresSlow", "service": "postgres", "severity": "critical"},
            {"name": "APITimeout", "service": "api-gateway"}))
        self.assertEqual(status, 200)
        self.assertEqual([r["action"] for r in body["results"]], ["opened", "attached"])
        iid = body["results"][0]["incident_id"]
        _, inc = self.call("GET", f"/v1/incidents/{iid}", "alice")
        self.assertEqual(inc["detection_source"], "alertmind:alertmanager")
        self.assertEqual(inc["timeline"][0]["actor"], "alertmanager-prod")
        _, tower = self.call("GET", "/v1/control-tower", "alice")
        self.assertEqual(tower["alerts_since_start"], {"opened": 1, "attached": 1})

    def test_credentials_are_separated(self):
        self.assertEqual(self.call("GET", "/v1/incidents", "am")[0], 403)
        self.assertEqual(self.call("GET", "/v1/approvals", "am")[0], 403)
        self.assertEqual(self.call("POST", "/v1/ingest/alerts", "alice", {"name": "x"})[0], 403)

    def test_bad_payload(self):
        self.assertEqual(self.call("POST", "/v1/ingest/alertmanager", "am", {"nope": 1})[0], 400)
        self.assertEqual(self.call("POST", "/v1/ingest/alerts", "am", {"name": ""})[0], 400)

    def test_silences_api(self):
        self.assertEqual(self.call("POST", "/v1/silences", "alice", {"name": "m", "match": {},
                                                                     "duration_minutes": 5})[0], 400)
        self.assertEqual(self.call("POST", "/v1/silences", "alice", {"name": "m", "match": {"service": "postgres"},
                                                                     "duration_minutes": 0})[0], 400)
        status, _ = self.call("POST", "/v1/silences", "alice", {"name": "pg-maint", "match": {"service": "postgres"},
                                                                "duration_minutes": 60})
        self.assertEqual(status, 200)
        self.assertTrue(self.call("GET", "/v1/silences", "alice")[1]["silences"][0]["active"])
        _, body = self.call("POST", "/v1/ingest/alerts", "am", {"name": "PostgresDown", "service": "postgres"})
        self.assertEqual(body["results"][0]["action"], "suppressed")


if __name__ == "__main__":
    unittest.main()
