import unittest
import os
import sys

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardian_swarm.core.policies import is_forbidden_tool, is_allowed_tool, is_high_risk_target
from guardian_swarm.utils.audit import AuditLog
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.core.interceptor import GuardianInterceptor

class TestGuardianPolicies(unittest.TestCase):
    def test_forbidden_tools(self):
        # Coder forbidden tools
        self.assertTrue(is_forbidden_tool("coder", "delete_file"))
        self.assertTrue(is_forbidden_tool("coder", "modify_system"))
        
        # Researcher forbidden tools
        self.assertTrue(is_forbidden_tool("researcher", "delete_file"))
        self.assertTrue(is_forbidden_tool("researcher", "write_file"))
        
        # Allowed tools
        self.assertFalse(is_forbidden_tool("coder", "write_file"))
        self.assertFalse(is_forbidden_tool("researcher", "search_web"))

    def test_allowed_tools(self):
        self.assertTrue(is_allowed_tool("coder", "write_file"))
        self.assertTrue(is_allowed_tool("researcher", "search_web"))
        self.assertFalse(is_allowed_tool("researcher", "delete_file"))

    def test_high_risk_targets(self):
        self.assertTrue(is_high_risk_target("/etc/passwd"))
        self.assertTrue(is_high_risk_target("/system/config"))
        self.assertTrue(is_high_risk_target("transfer_funds"))
        self.assertFalse(is_high_risk_target("research_notes.txt"))


from guardian_swarm.core.user_rbac import UserSession

class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.chain = []  # Fresh chain for unit test assertions

    def test_hash_chain_creation(self):
        # Create block 0
        b0 = self.log.create_entry(
            agent_id="test_agent",
            agent_type="researcher",
            tool="search_web",
            target="google.com",
            params={},
            verdict="APPROVED",
            confidence=1.0,
            reasoning="policy match",
            trace=["tier1"]
        )
        
        self.assertEqual(len(self.log.chain), 1)
        self.assertEqual(b0["prev_hash"], "0" * 64)
        
        # Create block 1
        b1 = self.log.create_entry(
            agent_id="test_agent",
            agent_type="researcher",
            tool="write_file",
            target="test.txt",
            params={},
            verdict="APPROVED",
            confidence=1.0,
            reasoning="policy match",
            trace=["tier1"]
        )
        
        self.assertEqual(len(self.log.chain), 2)
        self.assertEqual(b1["prev_hash"], b0["entry_hash"])
        
        # Verify chain integrity
        verified, msg = self.log.verify_chain()
        self.assertTrue(verified, msg)

    def test_tampering_detection(self):
        # Create two blocks
        self.log.create_entry("agent_1", "researcher", "search", "test", {}, "APPROVED", 1.0, "safe", [])
        self.log.create_entry("agent_2", "coder", "write", "file.txt", {}, "APPROVED", 1.0, "safe", [])
        
        # Confirm valid chain
        verified, _ = self.log.verify_chain()
        self.assertTrue(verified)
        
        # Tamper with block 0 data
        self.log.chain[0]["verdict"] = "BLOCKED"
        
        # Verify chain detects tampering
        tamper_detected, _ = self.log.verify_chain()
        self.assertFalse(tamper_detected)


class TestInterceptorFlows(unittest.TestCase):
    def setUp(self):
        self.audit = AuditLog()
        self.agent = VerificationAgent()
        self.agent.is_heuristic = True # Use fast rules engine for unit tests
        self.interceptor = GuardianInterceptor(self.agent, self.audit)
        self.manager_session = UserSession("manager_user", "MANAGER", "MANAGER", "Engineering")

    def test_auto_block_forbidden_tool(self):
        # Researcher calls delete_file (forbidden)
        approved, log = self.interceptor.intercept_action(
            agent_id="res_01",
            agent_type="researcher",
            tool="delete_file",
            target="/some/path",
            params={"task_group": "RESEARCH"},
            user_session=self.manager_session
        )
        
        self.assertFalse(approved)
        self.assertEqual(log["verdict"], "BLOCKED")

    def test_auto_approve_allowed_tool(self):
        # Researcher calls search_web (allowed)
        approved, log = self.interceptor.intercept_action(
            agent_id="res_01",
            agent_type="researcher",
            tool="search_web",
            target="quantum research",
            params={"task_group": "RESEARCH"},
            user_session=self.manager_session
        )
        
        self.assertTrue(approved)
        self.assertEqual(log["verdict"], "APPROVED")

    def test_escalation_on_high_risk_target(self):
        # Coder calls write_file (allowed) targeting /etc/passwd (high-risk)
        approved, log = self.interceptor.intercept_action(
            agent_id="code_01",
            agent_type="coder",
            tool="write_file",
            target="/etc/passwd",
            params={"task_group": "CODE"},
            user_session=self.manager_session
        )
        
        # Should escalate to AI (heuristics mode in test) and get BLOCKED
        self.assertFalse(approved)
        self.assertEqual(log["verdict"], "BLOCKED")

if __name__ == "__main__":
    unittest.main()
