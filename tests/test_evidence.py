import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from sovereign_control import ActionContext, AutonomyLevel, RiskLevel, SovereignGateway, ToolDefinition
from sovereign_control.api import ControlAPI, FileResponse
from sovereign_control.auth import TokenAuthenticator
from sovereign_control.evidence import EvidenceError, build_bundle, main, verify_bundle

KEY = b"test-signing-key"


def make_gateway():
    gw = SovereignGateway()
    gw.tools.register(ToolDefinition(
        tool_id="k8s.rollout_undo", name="Rollback", version="1", owner="platform", description="",
        handler=lambda p, c: {"to_revision": 41}, mutating=True, risk_level=RiskLevel.MEDIUM,
        verifier=lambda p, r: True, rollback=lambda p, r, c: None, approval_required=True,
    ))
    gw.agents.issue("agent", role="sre", tenant="acme", environments={"production"}, permissions=set(),
                    tool_scopes={"k8s.rollout_undo"}, autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS,
                    max_risk=RiskLevel.HIGH)
    ex = gw.request("agent", "k8s.rollout_undo", "production", {"deployment": "checkout"},
                    ActionContext(service="checkout", severity="critical", confidence=0.92,
                                  hypothesis="Deploy rev 42 exhausted the DB pool | pipes ok",
                                  evidence=["error rate 31%", "pg pool 100%"]))
    gw.approve(ex.execution_id, "alice", "sre")
    return gw, ex


def rewrite(content, changes, drop=()):
    """Return a copy of a bundle with some files replaced, added or removed."""
    src = zipfile.ZipFile(io.BytesIO(content))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name in src.namelist():
            if name not in drop and name not in changes:
                zf.writestr(name, src.read(name))
        for name, data in changes.items():
            zf.writestr(name, data)
    return out.getvalue()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.gw, self.ex = make_gateway()
        self.bundle = build_bundle(self.gw, [self.ex.execution_id], exported_by="auditor", title="INC-1042")
        self.zf = zipfile.ZipFile(io.BytesIO(self.bundle.content))

    def read(self, name):
        return json.loads(self.zf.read(name))

    def test_layout_matches_spec(self):
        self.assertEqual(sorted(self.zf.namelist()), [
            "RCA.md", "approvals.json", "audit.json", "manifest.json", "remediation.json",
            "timeline.json", "verification.json",
        ])

    def test_contents(self):
        manifest = self.read("manifest.json")
        self.assertEqual(manifest["execution_ids"], [self.ex.execution_id])
        self.assertTrue(manifest["audit_chain"]["valid_at_export"])
        self.assertEqual(self.read("approvals.json")[0]["approvers"], [{"user": "alice", "role": "sre"}])
        self.assertEqual(self.read("verification.json")[0]["verified"], True)
        self.assertEqual(self.read("remediation.json")[0]["result"], {"to_revision": 41})
        events = [e["event"] for e in self.read("timeline.json")]
        self.assertEqual(events[0], "tool.requested")
        self.assertIn("approval.granted", events)
        rca = self.zf.read("RCA.md").decode()
        self.assertIn("# INC-1042", rca)
        self.assertIn("- pg pool 100%", rca)
        self.assertIn("92%", rca)

    def test_export_is_recorded_and_tied_to_file_hash(self):
        last = self.gw.audit.events()[-1]
        self.assertEqual(last.event_type, "evidence.exported")
        self.assertEqual(last.actor, "auditor")
        self.assertEqual(last.data["sha256"], hashlib.sha256(self.bundle.content).hexdigest())
        self.assertTrue(self.gw.audit.verify())

    def test_bundle_verifies(self):
        self.assertEqual(verify_bundle(self.bundle.content), [])

    def test_changed_file_detected(self):
        bad = rewrite(self.bundle.content, {"approvals.json": b"[]"})
        self.assertIn("file changed since export: approvals.json", verify_bundle(bad))

    def test_missing_and_extra_files_detected(self):
        bad = rewrite(self.bundle.content, {"extra.txt": b"x"}, drop=("RCA.md",))
        problems = verify_bundle(bad)
        self.assertIn("missing file: RCA.md", problems)
        self.assertIn("unexpected file: extra.txt", problems)

    def test_rewritten_audit_event_detected_even_with_fixed_manifest(self):
        audit = self.read("audit.json")
        audit[0]["actor"] = "mallory"
        new_audit = json.dumps(audit).encode()
        manifest = self.read("manifest.json")
        manifest["files"]["audit.json"] = hashlib.sha256(new_audit).hexdigest()
        bad = rewrite(self.bundle.content, {"audit.json": new_audit, "manifest.json": json.dumps(manifest).encode()})
        self.assertEqual(verify_bundle(bad), [f"audit event {audit[0]['seq']} does not match its hash"])

    def test_signed_bundle(self):
        signed = build_bundle(self.gw, [self.ex.execution_id], exported_by="auditor", signing_key=KEY)
        self.assertEqual(verify_bundle(signed.content, KEY), [])
        self.assertEqual(verify_bundle(signed.content, b"wrong"), ["signature does not match"])
        self.assertEqual(verify_bundle(signed.content),
                         ["bundle is signed but no key was given; signature not checked"])
        # Forging the manifest breaks the signature.
        zf = zipfile.ZipFile(io.BytesIO(signed.content))
        manifest = json.loads(zf.read("manifest.json"))
        manifest["exported_by"] = "someone-else"
        forged = rewrite(signed.content, {"manifest.json": json.dumps(manifest).encode()})
        self.assertIn("signature does not match", verify_bundle(forged, KEY))

    def test_bad_input(self):
        with self.assertRaises(EvidenceError):
            build_bundle(self.gw, [], exported_by="x")
        with self.assertRaises(EvidenceError):
            build_bundle(self.gw, ["exe-nope"], exported_by="x")
        self.assertEqual(verify_bundle(b"not a zip"), ["not a zip file"])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.zip"
            path.write_bytes(self.bundle.content)
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["verify", str(path)]), 0)
            self.assertIn("OK", out.getvalue())
            path.write_bytes(rewrite(self.bundle.content, {"RCA.md": b"edited"}))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["verify", str(path)]), 1)


class EvidenceAPITests(unittest.TestCase):
    def setUp(self):
        self.gw, self.ex = make_gateway()
        auth = TokenAuthenticator()
        self.user = auth.add_user("auditor", {"audit"})
        self.agent = auth.add_agent("agent")
        self.api = ControlAPI(self.gw, auth, evidence_signing_key=KEY)

    def get(self, query, token=None):
        return self.api.handle("GET", f"/v1/evidence{query}", {"Authorization": f"Bearer {token or self.user}"})

    def test_download(self):
        status, body = self.get(f"?execution_id={self.ex.execution_id}&title=INC-1042")
        self.assertEqual(status, 200)
        self.assertIsInstance(body, FileResponse)
        self.assertEqual(body.content_type, "application/zip")
        self.assertEqual(body.headers["X-Evidence-SHA256"], hashlib.sha256(body.content).hexdigest())
        self.assertEqual(verify_bundle(body.content, KEY), [])

    def test_errors(self):
        self.assertEqual(self.get("")[0], 400)
        self.assertEqual(self.get("?execution_id=exe-nope")[0], 404)
        self.assertEqual(self.get(f"?execution_id={self.ex.execution_id}", self.agent)[0], 403)


if __name__ == "__main__":
    unittest.main()
