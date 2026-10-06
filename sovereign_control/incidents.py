"""Incident management (spec §23, §24).

An incident groups the alerts and governed executions that belong to one
operational problem. Every change to an incident is written to the audit log,
and the incident timeline is read back from there, so it carries the same
tamper evidence as everything else.

Agents may open incidents, attach alerts, link their own executions and move an
incident to investigating/mitigating. Resolving and closing are human decisions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .audit import AuditEvent
from .models import utcnow

if TYPE_CHECKING:
    from .gateway import SovereignGateway
    from .persistence import Store


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


SEVERITIES = ("low", "medium", "high", "critical")

_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING, IncidentStatus.MITIGATING, IncidentStatus.RESOLVED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.MITIGATING, IncidentStatus.RESOLVED},
    IncidentStatus.MITIGATING: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED},
    IncidentStatus.RESOLVED: {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},  # reopen or close
    IncidentStatus.CLOSED: set(),
}
AGENT_SETTABLE = {IncidentStatus.INVESTIGATING, IncidentStatus.MITIGATING}


class IncidentError(ValueError):
    """Invalid input."""


class IncidentNotFound(IncidentError):
    pass


class IncidentConflict(IncidentError):
    """The change isn't allowed in the incident's current state."""


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    status: IncidentStatus
    service: str
    environment: str
    detection_source: str
    opened_by: str
    created_at: str
    first_observed: str
    owner: str | None = None
    impact: str = ""
    root_cause: str = ""
    resolution: str = ""
    affected_services: list[str] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    execution_ids: list[str] = field(default_factory=list)
    resolved_at: str | None = None


class IncidentManager:
    def __init__(self, gateway: "SovereignGateway", store: "Store | None" = None) -> None:
        self.gateway = gateway
        self.store = store if store is not None else gateway.store
        self._incidents: dict[str, Incident] = {}
        if self.store:
            for incident in self.store.load_incidents():
                self._incidents[incident.incident_id] = incident

    # ---- queries --------------------------------------------------------------

    def get(self, incident_id: str) -> Incident:
        try:
            return self._incidents[incident_id]
        except KeyError:
            raise IncidentNotFound(f"unknown incident: {incident_id}") from None

    def all(self) -> list[Incident]:
        return list(self._incidents.values())

    def timeline(self, incident_id: str) -> list[AuditEvent]:
        """Every audit event about the incident or any execution linked to it, in order."""
        incident = self.get(incident_id)
        linked = set(incident.execution_ids)
        return [
            e for e in self.gateway.audit.events()
            if e.data.get("incident_id") == incident_id or (e.execution_id is not None and e.execution_id in linked)
        ]

    # ---- changes ----------------------------------------------------------------

    def open(
        self,
        title: str,
        *,
        actor: str,
        severity: str = "medium",
        service: str = "",
        environment: str = "",
        detection_source: str = "manual",
        first_observed: str | None = None,
        impact: str = "",
        affected_services: list[str] | None = None,
    ) -> Incident:
        if not title.strip():
            raise IncidentError("title is required")
        _check_severity(severity)
        now = utcnow().isoformat()
        incident = Incident(
            incident_id=f"INC-{len(self._incidents) + 1:04d}",
            title=title.strip(),
            severity=severity,
            status=IncidentStatus.OPEN,
            service=service,
            environment=environment,
            detection_source=detection_source,
            opened_by=actor,
            created_at=now,
            first_observed=first_observed or now,
            impact=impact,
            affected_services=list(affected_services or []),
        )
        self._incidents[incident.incident_id] = incident
        self._record(incident, "incident.opened", actor, title=incident.title, severity=severity,
                     service=service, environment=environment, detection_source=detection_source)
        return incident

    def attach_alert(self, incident_id: str, alert: dict[str, Any], *, actor: str) -> Incident:
        """Attach an alert. Alerts with the same fingerprint are de-duplicated into a count (spec §21)."""
        incident = self.require_open(incident_id)
        name = alert.get("name")
        if not isinstance(name, str) or not name:
            raise IncidentError("alert.name is required")
        fingerprint = str(alert.get("fingerprint") or f"{alert.get('source', '')}:{name}")
        received_at = utcnow().isoformat()
        for existing in incident.alerts:
            if existing["fingerprint"] == fingerprint:
                existing["count"] += 1
                existing["last_seen"] = received_at
                self._record(incident, "incident.alert_repeated", actor, fingerprint=fingerprint,
                             count=existing["count"])
                return incident
        labels = alert.get("labels") or {}
        if not isinstance(labels, dict):
            raise IncidentError("alert.labels must be an object")
        record = {
            "fingerprint": fingerprint,
            "name": name,
            "source": str(alert.get("source", "")),
            "severity": str(alert.get("severity", "")),
            "summary": str(alert.get("summary", "")),
            "labels": {str(k): str(v) for k, v in labels.items()},
            "first_seen": received_at,
            "last_seen": received_at,
            "count": 1,
        }
        incident.alerts.append(record)
        self._record(incident, "incident.alert_attached", actor, fingerprint=fingerprint, name=name,
                     source=record["source"], alert_severity=record["severity"])
        return incident

    def link_execution(self, incident_id: str, execution_id: str, *, actor: str) -> Incident:
        incident = self.require_open(incident_id)
        try:
            self.gateway.get(execution_id)
        except KeyError:
            raise IncidentNotFound(f"unknown execution: {execution_id}") from None
        if execution_id not in incident.execution_ids:
            incident.execution_ids.append(execution_id)
            self._record(incident, "incident.execution_linked", actor, linked_execution_id=execution_id)
        return incident

    def set_status(
        self, incident_id: str, status: IncidentStatus, *, actor: str, note: str = "", resolution: str = ""
    ) -> Incident:
        incident = self.get(incident_id)
        if status not in _TRANSITIONS[incident.status]:
            raise IncidentConflict(f"cannot move incident from {incident.status.value} to {status.value}")
        if status is IncidentStatus.RESOLVED:
            if not (resolution or incident.resolution).strip():
                raise IncidentError("a resolution is required to resolve an incident")
            incident.resolution = resolution or incident.resolution
            incident.resolved_at = utcnow().isoformat()
        if incident.status is IncidentStatus.RESOLVED and status is IncidentStatus.INVESTIGATING:
            incident.resolved_at = None  # reopened
        previous = incident.status
        incident.status = status
        self._record(incident, "incident.status_changed", actor, from_status=previous.value,
                     to_status=status.value, note=note, resolution=resolution)
        return incident

    def update(self, incident_id: str, *, actor: str, **fields: Any) -> Incident:
        """Change owner, severity, impact, root_cause or affected_services."""
        allowed = {"owner", "severity", "impact", "root_cause", "affected_services"}
        unknown = set(fields) - allowed
        if unknown:
            raise IncidentError(f"cannot update: {', '.join(sorted(unknown))}")
        incident = self.require_open(incident_id)
        if "severity" in fields:
            _check_severity(fields["severity"])
        if "affected_services" in fields:
            services = fields["affected_services"]
            if not isinstance(services, list) or not all(isinstance(s, str) for s in services):
                raise IncidentError("affected_services must be a list of strings")
        for key in ("owner", "impact", "root_cause"):
            if key in fields and not isinstance(fields[key], str):
                raise IncidentError(f"{key} must be a string")
        changes = {k: {"from": getattr(incident, k), "to": v} for k, v in fields.items() if getattr(incident, k) != v}
        for key, change in changes.items():
            setattr(incident, key, change["to"])
        if changes:
            self._record(incident, "incident.updated", actor, changes=changes)
        return incident

    # ---- internals --------------------------------------------------------------

    def require_open(self, incident_id: str) -> Incident:
        """Return the incident, or raise if it is unknown or closed."""
        incident = self.get(incident_id)
        if incident.status is IncidentStatus.CLOSED:
            raise IncidentConflict(f"incident {incident_id} is closed")
        return incident

    def _record(self, incident: Incident, event_type: str, actor: str, **data: Any) -> None:
        self.gateway.audit.record(event_type, actor, None, incident_id=incident.incident_id, **data)
        if self.store:
            self.store.save_incident(incident)


def _check_severity(severity: Any) -> None:
    if severity not in SEVERITIES:
        raise IncidentError(f"severity must be one of {', '.join(SEVERITIES)}")
