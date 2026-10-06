import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sovereign_control import (
    ActionContext,
    ApprovalMode,
    AuditIntegrityError,
    AutonomyLevel,
    ExecutionStatus,
    RiskLevel,
    SovereignGateway,
    SQLiteStore,
    ToolDefinition,
)
from sovereign_control.auth import PrincipalKind, TokenAuthenticator


def restart_tool(calls):
    def handler(params, cred):
        calls.append(params["pod"])
        return {"restarted": params["pod"]}

    return ToolDefinition(
        tool_id="k8s.restart_pod", name="Restart pod", version="1", owner="platform", description="",
        handler=handler, mutating=True, risk_level=RiskLevel.LOW,
        required_permissions=frozenset({"k8s:write"}), verifier=lambda p, r: True,
        rollback=lambda p, r, c: None, approval_required=True, approval_mode=ApprovalMode.SINGLE,
    )


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "aegis.db")
        self.calls = []
        self.stores = []

    def tearDown(self):
        for store in self.stores:
            store.close()
        self.tmp.cleanup()

    def boot(self):
        """Simulate a process start: fresh objects over the same database file."""
        store = SQLiteStore(self.path)
        self.stores.append(store)
        gw = SovereignGateway(store=store)
        gw.tools.register(restart_tool(self.calls))  # tools are code, re-registered at startup
        return gw

    def first_boot(self):
        gw = self.boot()
        gw.agents.issue("k8s-agent", role="sre", tenant="acme", environments={"production"},
                        permissions={"k8s:write"}, tool_scopes={"k8s.restart_pod"},
                        autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS, max_risk=RiskLevel.HIGH)
        return gw

    def test_pending_approval_survives_restart_and_executes_once(self):
        gw = self.first_boot()
        ex = gw.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "api-1"},
                        ActionContext(severity="critical", evidence=["OOMKilled"]))
        self.assertEqual(ex.status, ExecutionStatus.PENDING_APPROVAL)

        gw2 = self.boot()
        restored = gw2.get(ex.execution_id)
        self.assertEqual(restored.status, ExecutionStatus.PENDING_APPROVAL)
        self.assertEqual(restored.context.evidence, ["OOMKilled"])
        self.assertEqual(restored.risk.score, ex.risk.score)
        self.assertEqual([a.execution_id for a in gw2.approvals.pending()], [ex.execution_id])

        gw2.approve(ex.execution_id, "alice", "sre")
        self.assertEqual(self.calls, ["api-1"])

        gw3 = self.boot()
        final = gw3.get(ex.execution_id)
        self.assertEqual(final.status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(final.result, {"restarted": "api-1"})
        self.assertEqual(final.approval.approvers, [("alice", "sre")])
        self.assertEqual(gw3.approvals.pending(), [])
        self.assertTrue(gw3.audit.verify())

    def test_audit_chain_continues_across_restarts(self):
        gw = self.first_boot()
        gw.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "a"})
        n = len(gw.audit.events())
        gw2 = self.boot()
        self.assertEqual(len(gw2.audit.events()), n)
        gw2.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "b"})
        self.assertTrue(self.boot().audit.verify())

    def test_disabled_agent_stays_disabled(self):
        gw = self.first_boot()
        gw.agents.disable("k8s-agent")
        gw2 = self.boot()
        self.assertFalse(gw2.agents.get("k8s-agent").is_active())
        self.assertEqual(gw2.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "a"}).status,
                         ExecutionStatus.DENIED)

    def test_crash_during_execution_is_never_rerun(self):
        gw = self.first_boot()
        ex = gw.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "api-1"})

        # Simulate the process dying inside the tool call.
        def crash(params, cred):
            raise SystemExit("power loss")

        gw.tools.get("k8s.restart_pod").handler = crash
        with self.assertRaises(SystemExit):
            gw.approve(ex.execution_id, "alice", "sre")

        gw2 = self.boot()
        recovered = gw2.get(ex.execution_id)
        self.assertEqual(recovered.status, ExecutionStatus.INTERRUPTED)
        self.assertTrue(recovered.escalated)
        self.assertEqual(self.calls, [])
        types = [e.event_type for e in gw2.audit.events(ex.execution_id)]
        self.assertEqual(types[-2:], ["execution.interrupted", "escalated.to_human"])
        # And a later restart doesn't re-escalate it.
        n = len(gw2.audit.events())
        self.assertEqual(len(self.boot().audit.events()), n)

    def test_tampered_database_refuses_to_start(self):
        gw = self.first_boot()
        gw.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "a"})
        db = sqlite3.connect(self.path)
        data = json.loads(db.execute("SELECT data FROM audit WHERE seq = 0").fetchone()[0])
        data["actor"] = "mallory"
        db.execute("UPDATE audit SET data = ? WHERE seq = 0", (json.dumps(data),))
        db.commit()
        db.close()
        with self.assertRaises(AuditIntegrityError):
            self.boot()

    def test_deleted_audit_row_refuses_to_start(self):
        gw = self.first_boot()
        gw.request("k8s-agent", "k8s.restart_pod", "production", {"pod": "a"})
        db = sqlite3.connect(self.path)
        db.execute("DELETE FROM audit WHERE seq = 1")
        db.commit()
        db.close()
        with self.assertRaises(AuditIntegrityError):
            self.boot()

    def test_tokens_persist_as_hashes_and_revoke(self):
        store = SQLiteStore(self.path)
        self.stores.append(store)
        auth = TokenAuthenticator(store)
        agent_token = auth.add_agent("k8s-agent")
        user_token = auth.add_user("alice", {"sre", "admin"})

        auth2 = TokenAuthenticator(store)
        self.assertEqual(auth2.authenticate(agent_token).kind, PrincipalKind.AGENT)
        self.assertEqual(auth2.authenticate(user_token).roles, frozenset({"sre", "admin"}))
        raw = b"".join(f.read_bytes() for f in Path(self.tmp.name).iterdir())
        self.assertNotIn(agent_token.encode(), raw)

        auth2.revoke(agent_token)
        self.assertIsNone(TokenAuthenticator(store).authenticate(agent_token))


if __name__ == "__main__":
    unittest.main()
