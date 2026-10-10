"""AlertMind: alert ingestion, normalization and correlation (spec §21, §22).

    raw alert ──normalize──▶ Alert ──suppress?──▶ correlate ──▶ attach to incident / open new incident

Correlation, in order of preference:
1. The same alert (fingerprint) is already on an open incident: de-duplicate into it.
2. An open incident in the same environment covers the alert's service, or a service that
   depends on it or that it depends on, directly or through a chain (from the configured
   dependency map), and has had
   activity within the correlation window: attach, and add the service to affected_services.
3. Otherwise open a new incident, if the alert is severe enough; else drop it as noise.

So "DB latency", "API timeout" and "queue backlog" for services that depend on each other
become one incident (spec §22) instead of three.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .incidents import SEVERITIES, Incident, IncidentManager, IncidentStatus
from .models import utcnow
from .opsgraph import OpsGraph

_SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "page": "critical", "emergency": "critical", "p1": "critical",
    "high": "high", "error": "high", "major": "high", "p2": "high",
    "medium": "medium", "warning": "medium", "warn": "medium", "minor": "medium", "p3": "medium",
    "low": "low", "info": "low", "informational": "low", "none": "low", "p4": "low", "p5": "low",
}
# Labels naming what the alert is about. `job` is deliberately absent: it names the scrape job
# (e.g. "node-exporter"), which many unrelated hosts share. Host alerts fall back to `node`, then
# the host part of `instance` (see _subject).
_SERVICE_LABELS = ("service", "app", "app_kubernetes_io_name", "application")
# Some setups send "back to normal" notifications as firing alerts with severity/state "Ok".
_RECOVERY_WORDS = frozenset({"ok", "normal", "resolved", "recovered", "clear", "cleared"})
_ENV_LABELS = ("environment", "env")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class AlertError(ValueError):
    pass


@dataclass(frozen=True)
class Alert:
    """An alert in AEGIS's common shape, whatever system sent it."""

    name: str
    source: str
    status: str  # firing | resolved
    severity: str  # low | medium | high | critical
    service: str
    environment: str
    summary: str
    fingerprint: str
    labels: dict[str, str]

    def as_incident_alert(self) -> dict[str, Any]:
        return {
            "name": self.name, "source": self.source, "status": self.status, "severity": self.severity,
            "service": self.service, "environment": self.environment, "summary": self.summary,
            "fingerprint": self.fingerprint, "labels": self.labels,
        }


@dataclass(frozen=True)
class Silence:
    """Suppress matching alerts, e.g. during a maintenance window. All `match` labels must be equal."""

    name: str
    match: dict[str, str]
    ends_at: datetime | None = None

    def applies(self, alert: Alert, now: datetime) -> bool:
        if self.ends_at is not None and now >= self.ends_at:
            return False
        fields = {**alert.labels, "service": alert.service, "environment": alert.environment, "alertname": alert.name}
        return all(fields.get(k) == v for k, v in self.match.items())


@dataclass
class CorrelationConfig:
    window: timedelta = timedelta(minutes=30)
    min_severity_to_open: str = "medium"
    # Either an OpsGraph, or a simple map of service -> services it depends on,
    # e.g. {"checkout": ["postgres", "rabbitmq"]}. The graph wins when both are given.
    graph: OpsGraph | None = None
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    silences: list[Silence] = field(default_factory=list)

    def related(self, a: str, b: str) -> bool:
        """True if one service depends on (or runs on) the other, directly or through a chain."""
        graph = self.graph if self.graph is not None else OpsGraph.from_dependencies(self.dependencies)
        return graph.related(a, b)


@dataclass(frozen=True)
class IngestResult:
    fingerprint: str
    name: str
    action: str  # opened | attached | deduplicated | resolved | suppressed | ignored
    incident_id: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"fingerprint": self.fingerprint, "name": self.name, "action": self.action,
                "incident_id": self.incident_id, "reason": self.reason}


# ---- normalization -------------------------------------------------------------


def _subject(labels: dict[str, str]) -> str:
    """The service or host an alert is about."""
    found = _first(labels, _SERVICE_LABELS) or labels.get("node", "")
    if not found and labels.get("instance"):
        host = labels["instance"]
        if host.startswith("["):  # [ipv6]:port
            host = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:  # host:port
            host = host.split(":", 1)[0]
        found = host
    return found


def _is_recovery(status: Any, labels: dict[str, str]) -> bool:
    return status == "resolved" or any(
        labels.get(key, "").strip().lower() in _RECOVERY_WORDS for key in ("severity", "state"))


def normalize_severity(value: Any) -> str:
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), "medium")


def _first(mapping: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        if mapping.get(key):
            return mapping[key]
    return ""


def _str_dict(value: Any, what: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AlertError(f"{what} must be an object")
    return {str(k): str(v) for k, v in value.items()}


def parse_alertmanager(payload: Any) -> list[Alert]:
    """Prometheus Alertmanager webhook payload (version 4)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise AlertError("expected an Alertmanager webhook payload with an 'alerts' list")
    common = _str_dict(payload.get("commonLabels"), "commonLabels")
    alerts = []
    for raw in payload["alerts"]:
        if not isinstance(raw, dict):
            raise AlertError("each alert must be an object")
        labels = {**common, **_str_dict(raw.get("labels"), "labels")}
        annotations = _str_dict(raw.get("annotations"), "annotations")
        name = labels.get("alertname")
        if not name:
            raise AlertError("alert is missing labels.alertname")
        status = raw.get("status", payload.get("status", "firing"))
        subject = _subject(labels)
        alerts.append(Alert(
            name=name,
            source="alertmanager",
            status="resolved" if _is_recovery(status, labels) else "firing",
            severity=normalize_severity(labels.get("severity")),
            service=subject,
            environment=_first(labels, _ENV_LABELS),
            summary=annotations.get("summary") or annotations.get("description", ""),
            fingerprint=str(raw.get("fingerprint") or f"alertmanager:{name}:{subject}"),
            labels=labels,
        ))
    return alerts


def parse_generic(payload: Any) -> list[Alert]:
    """A simple format any tool can send: one alert object, or {"alerts": [...]}.

    {"name", "source", "status", "severity", "service", "environment", "summary", "labels", "fingerprint"}
    """
    items = payload.get("alerts") if isinstance(payload, dict) and "alerts" in payload else [payload]
    if not isinstance(items, list):
        raise AlertError("alerts must be a list")
    alerts = []
    for raw in items:
        if not isinstance(raw, dict):
            raise AlertError("each alert must be an object")
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise AlertError("alert.name is required")
        labels = _str_dict(raw.get("labels"), "labels")
        source = str(raw.get("source") or "generic")
        service = str(raw.get("service") or _subject(labels))
        status = raw.get("status", "firing")
        if status not in ("firing", "resolved"):
            raise AlertError("alert.status must be firing or resolved")
        alerts.append(Alert(
            name=name,
            source=source,
            status="resolved" if _is_recovery(status, {**labels, "severity": str(raw.get("severity") or
                                                                            labels.get("severity", ""))})
            else "firing",
            severity=normalize_severity(raw.get("severity")),
            service=service,
            environment=str(raw.get("environment") or _first(labels, _ENV_LABELS)),
            summary=str(raw.get("summary") or ""),
            fingerprint=str(raw.get("fingerprint") or f"{source}:{name}:{service}"),
            labels=labels,
        ))
    return alerts


# ---- correlation -----------------------------------------------------------------


class AlertMind:
    def __init__(self, incidents: IncidentManager, config: CorrelationConfig | None = None) -> None:
        self.incidents = incidents
        self.config = config or CorrelationConfig()
        self.stats: Counter[str] = Counter()  # actions since process start

    def ingest(self, alerts: list[Alert], *, actor: str) -> list[IngestResult]:
        results = [self._ingest_one(alert, actor) for alert in alerts]
        self.stats.update(r.action for r in results)
        return results

    def _ingest_one(self, alert: Alert, actor: str) -> IngestResult:
        now = utcnow()
        audit = self.incidents.gateway.audit
        open_incidents = [i for i in self.incidents.all()
                          if i.status not in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)]

        # 1. Already known on an open incident: update it in place.
        for incident in open_incidents:
            if any(a["fingerprint"] == alert.fingerprint for a in incident.alerts):
                self.incidents.attach_alert(incident.incident_id, alert.as_incident_alert(), actor=actor)
                action = "resolved" if alert.status == "resolved" else "deduplicated"
                return self._result(alert, action, incident.incident_id, "same alert already on this incident")

        if alert.status == "resolved":
            return self._result(alert, "ignored", None, "resolved alert with no open incident")

        for silence in self.config.silences:
            if silence.applies(alert, now):
                audit.record("alert.suppressed", actor, None, fingerprint=alert.fingerprint, name=alert.name,
                             service=alert.service, silence=silence.name)
                return self._result(alert, "suppressed", None, f"silenced by {silence.name}")

        # 2. Correlate with a related open incident.
        match = self._correlate(alert, open_incidents, now)
        if match is not None:
            incident, reason = match
            self.incidents.attach_alert(incident.incident_id, alert.as_incident_alert(), actor=actor)
            self._widen(incident, alert, actor)
            return self._result(alert, "attached", incident.incident_id, reason)

        # 3. New incident, unless it's below the noise floor.
        if _RANK[alert.severity] < _RANK[self.config.min_severity_to_open]:
            audit.record("alert.ignored", actor, None, fingerprint=alert.fingerprint, name=alert.name,
                         severity=alert.severity, reason="below severity threshold")
            return self._result(alert, "ignored", None,
                                f"{alert.severity} is below the {self.config.min_severity_to_open} threshold")
        title = alert.summary or (f"{alert.name} on {alert.service}" if alert.service else alert.name)
        incident = self.incidents.open(
            title, actor=actor, severity=alert.severity, service=alert.service, environment=alert.environment,
            detection_source=f"alertmind:{alert.source}",
            affected_services=[alert.service] if alert.service else [],
        )
        self.incidents.attach_alert(incident.incident_id, alert.as_incident_alert(), actor=actor)
        return self._result(alert, "opened", incident.incident_id, "no related open incident")

    def _correlate(self, alert: Alert, incidents: list[Incident], now: datetime) -> tuple[Incident, str] | None:
        best: tuple[Incident, str] | None = None
        for incident in incidents:
            if incident.environment and alert.environment and incident.environment != alert.environment:
                continue
            if now - _last_activity(incident) > self.config.window:
                continue
            services = {incident.service, *incident.affected_services} - {""}
            if alert.service in services:
                return incident, f"same service ({alert.service})"
            related = next((s for s in sorted(services) if self.config.related(alert.service, s)), None)
            if related and best is None:
                best = (incident, f"{alert.service} is linked to {related} by a dependency")
        return best

    def _widen(self, incident: Incident, alert: Alert, actor: str) -> None:
        changes: dict[str, Any] = {}
        if alert.service and alert.service != incident.service and alert.service not in incident.affected_services:
            changes["affected_services"] = [*incident.affected_services, alert.service]
        if _RANK[alert.severity] > _RANK[incident.severity]:
            changes["severity"] = alert.severity
        if changes:
            self.incidents.update(incident.incident_id, actor=actor, **changes)

    @staticmethod
    def _result(alert: Alert, action: str, incident_id: str | None, reason: str) -> IngestResult:
        return IngestResult(alert.fingerprint, alert.name, action, incident_id, reason)


def _last_activity(incident: Incident) -> datetime:
    stamps = [incident.created_at, *(a["last_seen"] for a in incident.alerts)]
    return max(datetime.fromisoformat(s) for s in stamps)
