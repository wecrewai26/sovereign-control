import json
import unittest

from fake_kube import TOKEN, Cluster, start

from sovereign_control import AutonomyLevel, ExecutionStatus, RiskLevel, SovereignGateway
from sovereign_control.credentials import CredentialBroker
from sovereign_control.tools.kubernetes import KubeTarget, kubernetes_tools


class TokenBroker(CredentialBroker):
    """Stands in for Vault's Kubernetes secrets engine: each credential carries a service account token."""

    def __init__(self, token=TOKEN):
        super().__init__()
        self.token = token

    def issue(self, *args, **kwargs):
        cred = super().issue(*args, **kwargs)
        cred.secret = {"service_account_token": self.token}
        return cred


class KubeToolsTest(unittest.TestCase):
    def setUp(self):
        self.cluster = Cluster()
        self.server, url = start(self.cluster)
        self.gw = SovereignGateway(credentials=TokenBroker())
        for tool in kubernetes_tools({"production": KubeTarget(url)}, allowed_namespaces={"shop"},
                                     max_replicas=10, verify_timeout=0.2, poll_interval=0.01, sleep=lambda s: None):
            self.gw.tools.register(tool)
        self.gw.agents.issue(
            "k8s-agent", role="sre", tenant="acme", environments={"production"},
            permissions={"k8s:pods:read", "k8s:pods:delete", "k8s:deployments:write"},
            tool_scopes={t.tool_id for t in self.gw.tools.all()},
            autonomy=AutonomyLevel.L5_CLOSED_LOOP, max_risk=RiskLevel.CRITICAL)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def run_tool(self, tool_id, **params):
        return self.gw.request("k8s-agent", tool_id, "production", params)

    def audit_types(self, ex):
        return [e.event_type for e in self.gw.audit.events(ex.execution_id)]


class ReadTests(KubeToolsTest):
    def test_get_pods(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        ex = self.run_tool("k8s.get_pods", namespace="shop")
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(len(ex.result["pods"]), 2)
        self.assertTrue(all(p["ready"] for p in ex.result["pods"]))


class RestartPodTests(KubeToolsTest):
    def test_restart_controller_pod_and_verify_replacement(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        victim = self.cluster.pods_of("shop", "checkout")[0]["metadata"]["name"]
        ex = self.run_tool("k8s.restart_pod", namespace="shop", pod=victim)
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED, ex.error)
        self.assertTrue(ex.verified)
        self.assertEqual(self.cluster.deleted, [victim])
        self.assertEqual(ex.result["controller"], "Deployment/checkout")
        self.assertEqual(len(self.cluster.pods_of("shop", "checkout")), 2)

    def test_replacement_not_ready_fails_verification_and_escalates(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        self.cluster.bad_images.add("checkout:v1")  # the replacement will not become ready
        victim = self.cluster.pods_of("shop", "checkout")[0]["metadata"]["name"]
        ex = self.run_tool("k8s.restart_pod", namespace="shop", pod=victim)
        self.assertEqual((ex.verified, ex.escalated), (False, True))
        self.assertEqual(ex.status, ExecutionStatus.ROLLBACK_FAILED)  # nothing to undo: a person must look

    def test_bare_pod_is_never_deleted(self):
        self.cluster.add_bare_pod("shop", "debug-shell")
        ex = self.run_tool("k8s.restart_pod", namespace="shop", pod="debug-shell")
        self.assertEqual(ex.status, ExecutionStatus.EXECUTION_FAILED)
        self.assertIn("no controller", ex.error)
        self.assertEqual(self.cluster.deleted, [])

    def test_guards(self):
        self.cluster.add_deployment("kube-system", "coredns", "coredns:1", replicas=1)
        pod = self.cluster.pods_of("kube-system", "coredns")[0]["metadata"]["name"]
        ex = self.run_tool("k8s.restart_pod", namespace="kube-system", pod=pod)
        self.assertIn("not one AEGIS may act in", ex.error)
        ex = self.run_tool("k8s.restart_pod", namespace="shop", pod="../../etc")
        self.assertIn("valid Kubernetes name", ex.error)
        self.assertEqual(self.cluster.deleted, [])


class ScaleTests(KubeToolsTest):
    def test_scale_and_verify(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        ex = self.run_tool("k8s.scale", namespace="shop", deployment="checkout", replicas=5)
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED, ex.error)
        self.assertEqual(ex.result, {"namespace": "shop", "deployment": "checkout", "previous_replicas": 2,
                                     "replicas": 5})
        self.assertEqual(self.cluster.deployments[("shop", "checkout")]["status"]["availableReplicas"], 5)

    def test_scale_that_cannot_become_available_is_rolled_back(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        self.cluster.capacity = 3
        ex = self.run_tool("k8s.scale", namespace="shop", deployment="checkout", replicas=6)
        self.assertEqual(ex.status, ExecutionStatus.ROLLED_BACK)
        self.assertEqual(self.cluster.deployments[("shop", "checkout")]["spec"]["replicas"], 2)
        self.assertEqual(self.audit_types(ex)[-4:], ["verification.completed", "rollback.completed",
                                                     "escalated.to_human", "credential.revoked"])

    def test_scale_limits(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        for bad in (0, 11, -1, "3", True):
            ex = self.run_tool("k8s.scale", namespace="shop", deployment="checkout", replicas=bad)
            self.assertEqual(ex.status, ExecutionStatus.EXECUTION_FAILED, bad)
        self.assertEqual(self.cluster.deployments[("shop", "checkout")]["spec"]["replicas"], 2)

    def test_concurrent_change_is_not_overwritten(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        self.cluster.concurrent_writer = True
        ex = self.run_tool("k8s.scale", namespace="shop", deployment="checkout", replicas=4)
        self.assertEqual(ex.status, ExecutionStatus.EXECUTION_FAILED)
        self.assertIn("HTTP 409", ex.error)


class RolloutTests(KubeToolsTest):
    def test_undo_bad_release(self):
        """The spec §24 scenario: a bad deploy, rolled back to the previous revision and verified."""
        self.cluster.bad_images.add("checkout:v2")
        self.cluster.add_deployment("shop", "checkout", "checkout:v2", replicas=3, history=["checkout:v1"])
        d = self.cluster.deployments[("shop", "checkout")]
        self.assertEqual(d["status"]["availableReplicas"], 0)
        ex = self.run_tool("k8s.rollout_undo", namespace="shop", deployment="checkout")
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED, ex.error)
        self.assertEqual((ex.result["from_revision"], ex.result["to_revision"]), (2, 1))
        self.assertEqual(d["spec"]["template"]["spec"]["containers"][0]["image"], "checkout:v1")
        self.assertNotIn("pod-template-hash", d["spec"]["template"]["metadata"]["labels"])
        self.assertEqual(d["status"]["availableReplicas"], 3)
        # Nothing from the pod template (which can hold env secrets) went into the record.
        self.assertNotIn("checkout:v1", json.dumps([e.data for e in self.gw.audit.events()]))

    def test_undo_to_an_also_broken_revision_is_reverted(self):
        self.cluster.bad_images.update({"checkout:v1", "checkout:v2"})
        self.cluster.add_deployment("shop", "checkout", "checkout:v2", replicas=2, history=["checkout:v1"])
        ex = self.run_tool("k8s.rollout_undo", namespace="shop", deployment="checkout")
        self.assertEqual(ex.status, ExecutionStatus.ROLLED_BACK)
        d = self.cluster.deployments[("shop", "checkout")]
        self.assertEqual(d["spec"]["template"]["spec"]["containers"][0]["image"], "checkout:v2")

    def test_undo_needs_history(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1")
        ex = self.run_tool("k8s.rollout_undo", namespace="shop", deployment="checkout")
        self.assertIn("no earlier revision", ex.error)
        ex = self.run_tool("k8s.rollout_undo", namespace="shop", deployment="checkout", to_revision=7)
        self.assertEqual(ex.status, ExecutionStatus.EXECUTION_FAILED)

    def test_rollout_restart(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1", replicas=2)
        before = {p["metadata"]["uid"] for p in self.cluster.pods_of("shop", "checkout")}
        ex = self.run_tool("k8s.rollout_restart", namespace="shop", deployment="checkout")
        self.assertEqual(ex.status, ExecutionStatus.SUCCEEDED, ex.error)
        after = {p["metadata"]["uid"] for p in self.cluster.pods_of("shop", "checkout")}
        self.assertFalse(before & after)


class CredentialTests(KubeToolsTest):
    def test_wrong_or_missing_token(self):
        self.cluster.add_deployment("shop", "checkout", "checkout:v1")
        self.gw.credentials = TokenBroker(token="stolen")
        ex = self.run_tool("k8s.get_pods", namespace="shop")
        self.assertIn("HTTP 401", ex.error)
        self.gw.credentials = CredentialBroker()  # placeholder credentials carry no cluster token
        ex = self.run_tool("k8s.get_pods", namespace="shop")
        self.assertIn("no Kubernetes service account token", ex.error)

    def test_unknown_environment(self):
        self.gw.agents.get("k8s-agent").environments = frozenset({"production", "staging"})
        ex = self.gw.request("k8s-agent", "k8s.get_pods", "staging", {"namespace": "shop"})
        self.assertIn("no cluster is configured", ex.error)


if __name__ == "__main__":
    unittest.main()
