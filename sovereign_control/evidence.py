"""Evidence bundles (spec §26, §27).

A bundle is a zip file covering one or more executions:

    manifest.json       what's inside, SHA-256 of every file, audit chain state at export
    manifest.sig        HMAC-SHA256 of manifest.json (only when a signing key is configured)
    incident.json       the incident record with its alerts (incident bundles only)
    timeline.json       every audit event for the executions, in order, in plain form
    RCA.md              the agent's hypothesis, evidence and confidence, and what was done
    remediation.json    tool, parameters, risk assessment, policy decision, result
    approvals.json      who approved or rejected, with which role, and when it expired
    verification.json   verification outcome, rollback and escalation
    audit.json          the raw hash-chained audit events

Verify a bundle offline:

    python3 -m sovereign_control.evidence verify bundle.zip [--key-file KEY]

What verification proves: no file changed since export, each audit event still
matches its own hash, and (with a key) the manifest was produced by a holder of
the key. Metrics, logs and traces (§27) will join once telemetry sources exist.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import sys
import uuid
import zipfile
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from .audit import GENESIS_HASH, AuditEvent, _digest
from .gateway import Execution, SovereignGateway
from .models import utcnow

if TYPE_CHECKING:
    from .incidents import IncidentManager

BUNDLE_FORMAT = "aegis-evidence-bundle/1"
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class EvidenceBundle:
    bundle_id: str
    filename: str
    content: bytes
    sha256: str


class EvidenceError(ValueError):
    pass


def build_bundle(
    gateway: SovereignGateway,
    execution_ids: list[str],
    *,
    exported_by: str,
    title: str = "",
    signing_key: bytes | None = None,
    incidents: "IncidentManager | None" = None,
    incident_id: str | None = None,
) -> EvidenceBundle:
    incident = None
    if incident_id is not None:
        if incidents is None:
            raise EvidenceError("incident bundles need an IncidentManager")
        try:
            incident = incidents.get(incident_id)
        except ValueError:
            raise EvidenceError(f"unknown incident: {incident_id}") from None
        execution_ids = [*incident.execution_ids, *execution_ids]
        title = title or f"{incident.incident_id}: {incident.title}"
    if not execution_ids and incident is None:
        raise EvidenceError("at least one execution_id is required")
    ids = list(dict.fromkeys(execution_ids))  # de-duplicate, keep order
    try:
        executions = [gateway.get(eid) for eid in ids]
    except KeyError as exc:
        raise EvidenceError(f"unknown execution: {exc.args[0]}") from None

    id_set = set(ids)
    events = [
        e for e in gateway.audit.events()
        if e.execution_id in id_set or (incident is not None and e.data.get("incident_id") == incident.incident_id)
    ]
    all_events = gateway.audit.events()
    bundle_id = f"evb-{uuid.uuid4().hex[:12]}"

    files: dict[str, bytes] = {
        "timeline.json": _json([_timeline_entry(e) for e in events]),
        "RCA.md": _rca(title, executions, incident).encode(),
        "remediation.json": _json([_remediation(x) for x in executions]),
        "approvals.json": _json([_approvals(x) for x in executions]),
        "verification.json": _json([_verification(x) for x in executions]),
        "audit.json": _json([asdict(e) for e in events]),
    }
    if incident is not None:
        incident_data = asdict(incident)
        incident_data["status"] = incident.status.value
        files["incident.json"] = _json(incident_data)
    manifest = {
        "format": BUNDLE_FORMAT,
        "bundle_id": bundle_id,
        "title": title,
        "created_at": utcnow().isoformat(),
        "exported_by": exported_by,
        "execution_ids": ids,
        "incident_id": incident.incident_id if incident else None,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
        "audit_chain": {
            "valid_at_export": gateway.audit.verify(),
            "length": len(all_events),
            "head_hash": all_events[-1].hash if all_events else GENESIS_HASH,
        },
        "signed": signing_key is not None,
    }
    files["manifest.json"] = _json(manifest)
    if signing_key is not None:
        files["manifest.sig"] = hmac.new(signing_key, files["manifest.json"], hashlib.sha256).hexdigest().encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[name])
    content = buf.getvalue()
    digest = hashlib.sha256(content).hexdigest()

    # The export itself is evidence: tie this exact file to the audit chain.
    gateway.audit.record(
        "evidence.exported", exported_by, None,
        bundle_id=bundle_id, sha256=digest, execution_ids=ids, signed=signing_key is not None,
        **({"incident_id": incident.incident_id} if incident else {}),
    )
    return EvidenceBundle(bundle_id, f"{bundle_id}.zip", content, digest)


def verify_bundle(content: bytes, signing_key: bytes | None = None) -> list[str]:
    """Return a list of problems; an empty list means the bundle verifies."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        return ["not a zip file"]
    with zf:
        names = set(zf.namelist())
        if "manifest.json" not in names:
            return ["manifest.json missing"]
        manifest_raw = zf.read("manifest.json")
        try:
            manifest = json.loads(manifest_raw)
        except json.JSONDecodeError:
            return ["manifest.json is not valid JSON"]
        problems: list[str] = []
        if manifest.get("format") != BUNDLE_FORMAT:
            problems.append(f"unknown bundle format: {manifest.get('format')}")

        expected = manifest.get("files", {})
        allowed = set(expected) | {"manifest.json", "manifest.sig"}
        for extra in sorted(names - allowed):
            problems.append(f"unexpected file: {extra}")
        for name, digest in sorted(expected.items()):
            if name not in names:
                problems.append(f"missing file: {name}")
            elif hashlib.sha256(zf.read(name)).hexdigest() != digest:
                problems.append(f"file changed since export: {name}")

        if manifest.get("signed"):
            if signing_key is None:
                problems.append("bundle is signed but no key was given; signature not checked")
            elif "manifest.sig" not in names:
                problems.append("manifest.sig missing")
            else:
                want = hmac.new(signing_key, manifest_raw, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(want.encode(), zf.read("manifest.sig").strip()):
                    problems.append("signature does not match")

        if "audit.json" in names:
            try:
                for raw in json.loads(zf.read("audit.json")):
                    event = AuditEvent(**raw)
                    payload = asdict(event)
                    claimed = payload.pop("hash")
                    if _digest(payload) != claimed:
                        problems.append(f"audit event {event.seq} does not match its hash")
            except (json.JSONDecodeError, TypeError):
                problems.append("audit.json is malformed")
        return problems


# ---- file builders ------------------------------------------------------------


def _json(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, default=str).encode()


def _timeline_entry(e: AuditEvent) -> dict[str, Any]:
    return {"time": e.timestamp, "event": e.event_type, "actor": e.actor, "execution_id": e.execution_id,
            "details": e.data}


def _remediation(x: Execution) -> dict[str, Any]:
    return {
        "execution_id": x.execution_id,
        "agent_id": x.agent_id,
        "tool_id": x.tool_id,
        "environment": x.environment,
        "params": x.params,
        "status": x.status.value,
        "risk": {"score": x.risk.score, "level": x.risk.level.name, "factors": x.risk.factors},
        "policy": {
            "decision": x.policy.decision.name,
            "reasons": list(x.policy.reasons),
            "approval_mode": x.policy.approval_mode.value if x.policy.approval_mode else None,
        },
        "result": x.result,
        "error": x.error,
    }


def _approvals(x: Execution) -> dict[str, Any]:
    a = x.approval
    if a is None:
        return {"execution_id": x.execution_id, "approval_required": False}
    return {
        "execution_id": x.execution_id,
        "approval_required": True,
        "approval_id": a.approval_id,
        "mode": a.mode.value,
        "state": a.state.value,
        "approvers": [{"user": u, "role": r} for u, r in a.approvers],
        "rejected_by": a.rejected_by,
        "reason": a.reason,
        "expires_at": a.expires_at.isoformat(),
    }


def _verification(x: Execution) -> dict[str, Any]:
    return {
        "execution_id": x.execution_id,
        "status": x.status.value,
        "verified": x.verified,
        "rolled_back": x.status.value == "rolled_back",
        "escalated_to_human": x.escalated,
        "notes": list(x.notes),
    }


def _md_text(text: str) -> str:
    return text.strip()


def _md_cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _rca(title: str, executions: list[Execution], incident=None) -> str:
    lines = [f"# {title or 'Evidence bundle'}", ""]
    if incident is not None:
        lines += [
            "| | |",
            "|---|---|",
            f"| Incident | `{incident.incident_id}` |",
            f"| Status | {incident.status.value} |",
            f"| Severity | {incident.severity} |",
            f"| Service | {_md_cell(incident.service or '—')} |",
            f"| Owner | {_md_cell(incident.owner or '—')} |",
            f"| First observed | {incident.first_observed} |",
            f"| Alerts | {len(incident.alerts)} distinct, {sum(a['count'] for a in incident.alerts)} total |",
            "",
            "## Root cause",
            "",
            _md_text(incident.root_cause) or "_Not yet recorded._",
            "",
            "## Impact",
            "",
            _md_text(incident.impact) or "_Not yet recorded._",
            "",
            "## Resolution",
            "",
            _md_text(incident.resolution) or "_Not yet resolved._",
            "",
            "## Actions taken",
            "",
        ]
        if not executions:
            lines += ["_No governed actions were linked to this incident._", ""]
    for x in executions:
        c = x.context
        lines += [
            f"## {x.tool_id} on {x.environment} — {x.status.value}",
            "",
            "| | |",
            "|---|---|",
            f"| Execution | `{x.execution_id}` |",
            f"| Agent | `{x.agent_id}` |",
            f"| Service | {_md_cell(c.service or '—')} |",
            f"| Severity | {_md_cell(c.severity)} |",
            f"| Risk | {x.risk.score} ({x.risk.level.name}) |",
            f"| Policy | {x.policy.decision.name} |",
            f"| Agent confidence | {c.confidence:.0%} |",
            "",
            "### Hypothesis",
            "",
            c.hypothesis or "_None recorded by the agent._",
            "",
            "### Supporting evidence",
            "",
        ]
        lines += [f"- {item}" for item in c.evidence] or ["_None recorded by the agent._"]
        lines += [
            "",
            "### Outcome",
            "",
            f"- Verified: {x.verified if x.verified is not None else 'not verified'}",
            f"- Escalated to a human: {'yes' if x.escalated else 'no'}",
        ]
        if x.error:
            lines.append(f"- Error: {x.error}")
        lines.append("")
    lines += [
        "---",
        "",
        "Hypothesis and evidence are as recorded by the agent at request time; they are not independently checked.",
        "",
    ]
    return "\n".join(lines)


# ---- CLI ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m sovereign_control.evidence")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify an evidence bundle")
    verify.add_argument("bundle")
    verify.add_argument("--key-file", help="file holding the HMAC signing key")
    args = parser.parse_args(argv)

    try:
        with open(args.bundle, "rb") as fh:
            content = fh.read()
        key = None
        if args.key_file:
            with open(args.key_file, "rb") as fh:
                key = fh.read().strip()
    except OSError as exc:
        print(f"ERROR  {exc}", file=sys.stderr)
        return 2
    problems = verify_bundle(content, key)
    if problems:
        print("FAILED")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK  sha256={hashlib.sha256(content).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
