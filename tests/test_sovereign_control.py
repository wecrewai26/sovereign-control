import unittest
from dataclasses import replace
from datetime import timedelta

from sovereign_control import (
    ActionContext,
    ApprovalError,
    ApprovalMode,
    AutonomyLevel,
    Decision,
    ExecutionStatus,
    PolicyRule,
    RiskLevel,
    SovereignGateway,
    ToolDefinition,
)
from sovereign_control.audit import AuditLog


def make_tool(tool_id="k8s.restart_pod", **overrides):
    defaults = dict(
        tool_id=tool_id,
        name=tool_id,
        version="1.0",
        owner="platform",
        description="test tool",
        handler=lambda params, cred: {"restarted": params.get("pod"), "token_valid": cred.is_valid()},
        mutating=True,
        risk_level=RiskLevel.LOW,
        required_permissions=frozenset({"k8s:write"}),
        verifier=lambda params, result: True,
        rollback=lambda params, result, cred: None,
    )
    defaults.update(overrides)
    return ToolDefinition(**defaults)


def make_gateway(tool=None, autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS, max_risk=RiskLevel.HIGH, **agent_kw):
    gw = SovereignGateway()
    tool = tool or make_tool()
    gw.tools.register(tool)
    gw.agents.issue(
        "k8s-agent",
        role="sre",
        tenant="acme",
        environments=agent_kw.pop("environments", {"dev", "production"}),
        permissions=agent_kw.pop("permissions", {"k8s:write", "k8s:read"}),
        tool_scopes=agent_kw.pop("tool_scopes", {tool.tool_id}),
        autonomy=autonomy,
        max_risk=max_risk,
        **agent_kw,
    )
    return gw


class RiskEngineTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(RiskLevel.from_score(20), RiskLevel.LOW)
        self.assertEqual(RiskLevel.from_score(21), RiskLevel.MEDIUM)
        self.assertEqual(RiskLevel.from_score(80), RiskLevel.HIGH)
        self.assertEqual(RiskLevel.from_score(81), RiskLevel.CRITICAL)

    def test_production_irreversible_scores_higher_than_dev(self):
        gw = make_gateway()
        tool = make_tool(rollback=None, risk_level=RiskLevel.MEDIUM)
        prod = gw.risk.assess(tool, "production", ActionContext(customer_impact=True, confidence=0.5))
        dev = gw.risk.assess(tool, "dev", ActionContext())
        self.assertGreater(prod.score, dev.score)
        self.assertIn("irreversible", prod.factors)
        self.assertEqual(prod.score, 30 + 15 + 15 + 10 + 10)

    def test_read_only_is_low(self):
        gw = make_gateway()
        risk = gw.risk.assess(make_tool(mutating=False), "production", ActionContext())
        self.assertEqual(risk.level, RiskLevel.LOW)


class GuardrailTests(unittest.TestCase):
    def test_tool_outside_scope_denied(self):
        gw = make_gateway(tool_scopes=set())
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        self.assertEqual(ex.status, ExecutionStatus.DENIED)

    def test_environment_outside_scope_denied(self):
        gw = make_gateway(environments={"dev"})
        ex = gw.request("k8s-agent", "k8s.restart_pod", "production")
        self.assertEqual(ex.status, ExecutionStatus.DENIED)
        self.assertTrue(any("environment" in r for r in ex.policy.reasons))

    def test_missing_permission_denied(self):
        gw = make_gateway(permissions={"k8s:read"})
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        self.assertEqual(ex.status, ExecutionStatus.DENIED)

    def test_expired_identity_denied(self):
        gw = make_gateway(ttl=timedelta(seconds=-1))
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        self.assertEqual(ex.status, ExecutionStatus.DENIED)

    def test_risk_ceiling_denied(self):
        gw = make_gateway(max_risk=RiskLevel.LOW)
        ex = gw.request("k8s-agent", "k8s.restart_pod", "production")
        self.assertEqual(ex.status, ExecutionStatus.DENIED)


class AutonomyTests(unittest.TestCase):
    def test_l1_cannot_mutate_but_can_read(self):
        gw = make_gateway(autonomy=AutonomyLevel.L1_INVESTIGATE)
        gw.tools.register(make_tool("k8s.get_pods", mutating=False, required_permissions=frozenset()))
        gw.agents.get("k8s-agent").tool_scopes |= {"k8s.get_pods"}
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "dev").status, ExecutionStatus.DENIED)
        self.assertEqual(gw.request("k8s-agent", "k8s.get_pods", "production").status, ExecutionStatus.SUCCEEDED)

    def test_l2_recommends_only(self):
        gw = make_gateway(autonomy=AutonomyLevel.L2_RECOMMEND)
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "dev").status, ExecutionStatus.RECOMMENDED)

    def test_l3_always_needs_approval(self):
        gw = make_gateway(autonomy=AutonomyLevel.L3_APPROVED_EXECUTION)
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "dev").status, ExecutionStatus.PENDING_APPROVAL)

    def test_l4_auto_executes_low_risk_only(self):
        gw = make_gateway(autonomy=AutonomyLevel.L4_POLICY_AUTONOMOUS)
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "dev").status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(
            gw.request("k8s-agent", "k8s.restart_pod", "production").status, ExecutionStatus.PENDING_APPROVAL
        )

    def test_l5_executes_within_ceiling(self):
        gw = make_gateway(autonomy=AutonomyLevel.L5_CLOSED_LOOP)
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "production").status, ExecutionStatus.SUCCEEDED)

    def test_tool_approval_flag_overrides_autonomy(self):
        gw = make_gateway(tool=make_tool(approval_required=True), autonomy=AutonomyLevel.L5_CLOSED_LOOP)
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "dev").status, ExecutionStatus.PENDING_APPROVAL)


class PolicyRuleTests(unittest.TestCase):
    def test_spec_example_allow_with_approval(self):
        """Spec §49: SRE / Production / Restart Pod / Critical / Medium → ALLOW WITH APPROVAL."""
        gw = make_gateway(autonomy=AutonomyLevel.L5_CLOSED_LOOP)
        gw.policy.add_rule(
            PolicyRule(
                "prod-restart-needs-approval",
                Decision.ALLOW_WITH_APPROVAL,
                match={"role": "sre", "environment": "production", "tool_id": "k8s.restart_pod"},
            )
        )
        ex = gw.request("k8s-agent", "k8s.restart_pod", "production", context=ActionContext(severity="critical"))
        self.assertEqual(ex.policy.decision, Decision.ALLOW_WITH_APPROVAL)
        self.assertIn("rule:prod-restart-needs-approval", ex.policy.reasons)

    def test_rule_can_target_only_changes(self):
        gw = make_gateway(autonomy=AutonomyLevel.L5_CLOSED_LOOP)
        gw.tools.register(make_tool("k8s.get_pods", mutating=False, required_permissions=frozenset()))
        gw.agents.get("k8s-agent").tool_scopes |= {"k8s.get_pods"}
        gw.policy.add_rule(PolicyRule("prod-changes", Decision.ALLOW_WITH_APPROVAL,
                                      match={"environment": "production", "mutating": True}))
        self.assertEqual(gw.request("k8s-agent", "k8s.get_pods", "production").status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "production").status,
                         ExecutionStatus.PENDING_APPROVAL)

    def test_rules_cannot_loosen(self):
        gw = make_gateway(autonomy=AutonomyLevel.L3_APPROVED_EXECUTION)
        gw.policy.add_rule(PolicyRule("allow-all", Decision.ALLOW))
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "dev").status, ExecutionStatus.PENDING_APPROVAL)

    def test_deny_rule_wins(self):
        gw = make_gateway(autonomy=AutonomyLevel.L5_CLOSED_LOOP)
        gw.policy.add_rule(PolicyRule("freeze", Decision.DENY, match={"environment": "production"}))
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "production").status, ExecutionStatus.DENIED)

    def test_min_risk_rule_escalates_mode(self):
        gw = make_gateway(autonomy=AutonomyLevel.L3_APPROVED_EXECUTION)
        gw.policy.add_rule(
            PolicyRule("medium-plus-dual", Decision.ALLOW_WITH_APPROVAL,
                       match={"min_risk_level": RiskLevel.MEDIUM}, approval_mode=ApprovalMode.DUAL)
        )
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "production").approval.mode, ApprovalMode.DUAL)
        self.assertEqual(gw.request("k8s-agent", "k8s.restart_pod", "dev").approval.mode, ApprovalMode.SINGLE)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.gw = make_gateway(tool=make_tool(approval_required=True, approval_mode=ApprovalMode.DUAL))
        self.ex = self.gw.request("k8s-agent", "k8s.restart_pod", "dev", {"pod": "api-1"})

    def test_dual_approval_needs_two_distinct_people(self):
        self.gw.approve(self.ex.execution_id, "alice", "sre")
        self.assertEqual(self.ex.status, ExecutionStatus.PENDING_APPROVAL)
        with self.assertRaises(ApprovalError):
            self.gw.approve(self.ex.execution_id, "alice", "sre")
        self.gw.approve(self.ex.execution_id, "bob", "sre")
        self.assertEqual(self.ex.status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(self.ex.result["restarted"], "api-1")

    def test_agent_cannot_self_approve(self):
        with self.assertRaises(ApprovalError):
            self.gw.approve(self.ex.execution_id, "k8s-agent", "sre")

    def test_reject(self):
        self.gw.reject(self.ex.execution_id, "alice", "not during peak")
        self.assertEqual(self.ex.status, ExecutionStatus.REJECTED)
        with self.assertRaises(ApprovalError):
            self.gw.approve(self.ex.execution_id, "bob", "sre")

    def test_role_bound_mode(self):
        gw = make_gateway(tool=make_tool(approval_required=True, approval_mode=ApprovalMode.SECURITY))
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        with self.assertRaises(ApprovalError):
            gw.approve(ex.execution_id, "alice", "sre")
        gw.approve(ex.execution_id, "sam", "security")
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED)

    def test_identity_revoked_before_approval_blocks_execution(self):
        self.gw.agents.disable("k8s-agent")
        self.gw.approve(self.ex.execution_id, "alice", "sre")
        self.gw.approve(self.ex.execution_id, "bob", "sre")
        self.assertEqual(self.ex.status, ExecutionStatus.DENIED)
        self.assertIsNone(self.ex.result)


class ExecutionTests(unittest.TestCase):
    def test_credential_is_short_lived_and_revoked(self):
        gw = make_gateway()
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        self.assertTrue(ex.result["token_valid"])
        self.assertEqual(gw.credentials.active(), [])

    def test_failed_verification_rolls_back_and_escalates(self):
        rolled = []
        tool = make_tool(verifier=lambda p, r: False, rollback=lambda p, r, c: rolled.append(c.is_valid()))
        gw = make_gateway(tool=tool)
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        self.assertEqual(ex.status, ExecutionStatus.ROLLED_BACK)
        self.assertEqual(rolled, [True])
        self.assertTrue(ex.escalated)

    def test_failed_verification_without_rollback(self):
        gw = make_gateway(tool=make_tool(verifier=lambda p, r: False, rollback=None),
                          autonomy=AutonomyLevel.L5_CLOSED_LOOP)
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        self.assertEqual(ex.status, ExecutionStatus.ROLLBACK_FAILED)
        self.assertTrue(ex.escalated)

    def test_handler_exception_is_captured(self):
        def boom(params, cred):
            raise RuntimeError("api down")

        gw = make_gateway(tool=make_tool(handler=boom))
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev")
        self.assertEqual(ex.status, ExecutionStatus.EXECUTION_FAILED)
        self.assertIn("api down", ex.error)
        self.assertEqual(gw.credentials.active(), [])


class AuditTests(unittest.TestCase):
    def test_full_trail_recorded_and_chain_valid(self):
        gw = make_gateway()
        ex = gw.request("k8s-agent", "k8s.restart_pod", "dev",
                        context=ActionContext(hypothesis="OOM loop", evidence=["kube event: OOMKilled"]))
        types = [e.event_type for e in gw.audit.events(ex.execution_id)]
        self.assertEqual(types, [
            "tool.requested", "risk.assessed", "policy.evaluated", "credential.issued",
            "tool.executed", "verification.completed", "credential.revoked",
        ])
        self.assertTrue(gw.audit.verify())

    def test_tampering_detected(self):
        log = AuditLog()
        log.record("a", "x")
        log.record("b", "y")
        log._events[0] = replace(log._events[0], actor="mallory")
        self.assertFalse(log.verify())

    def test_deletion_detected(self):
        log = AuditLog()
        for i in range(3):
            log.record("e", str(i))
        del log._events[1]
        self.assertFalse(log.verify())


if __name__ == "__main__":
    unittest.main()
