"""
Unit & Integration Tests for Guardian WebOps Research Workflow
=============================================================
Tests:
- TinyFish adapter initialization and URL safety validation (SSRF / internal IP guards)
- ResearchOrchestrator 5-gate pipeline evaluation
- Structured evidence model serialization and status indicators
- Mock execution labeling ([SIMULATED])
- Cryptographic hash-chain audit logging
"""
import pytest
from guardian_swarm.core.evidence_models import (
    ResearchTask,
    ResearchClaim,
    EvidenceStatus,
    ResearchTaskStatus
)
from guardian_swarm.integration.tinyfish_adapter import TinyFishAdapter
from guardian_swarm.core.research_service import ResearchOrchestrator
from guardian_swarm.core.user_rbac import UserSession
from guardian_swarm.utils.audit import AuditLog


def test_tinyfish_adapter_mock_mode_detection():
    adapter = TinyFishAdapter(api_key="")
    assert not adapter.is_live


def test_tinyfish_url_safety_validation():
    adapter = TinyFishAdapter()
    
    # Valid external domains
    assert adapter.validate_url_safety("https://atlassian.com/security")
    assert adapter.validate_url_safety("https://trust.linear.app/overview")
    
    # Block loopback, localhost, and internal IPs
    assert not adapter.validate_url_safety("http://localhost:8000/internal")
    assert not adapter.validate_url_safety("http://127.0.0.1/admin")
    assert not adapter.validate_url_safety("http://169.254.169.254/latest/meta-data")  # AWS metadata
    assert not adapter.validate_url_safety("https://10.0.0.1/secret")
    assert not adapter.validate_url_safety("https://192.168.1.1/router")
    
    # Block unapproved domains when allowed_domains is provided
    allowed = ["atlassian.com", "linear.app"]
    assert adapter.validate_url_safety("https://atlassian.com/trust", allowed_domains=allowed)
    assert not adapter.validate_url_safety("https://malicious-site.com/evil", allowed_domains=allowed)


def test_mock_research_output_labeling():
    adapter = TinyFishAdapter(api_key="")
    res = adapter.research_vendor(
        vendor_name="Jira",
        target_domain="atlassian.com",
        categories=["SOC 2 & Compliance"]
    )
    assert res.vendor_name == "Jira"
    assert res.retrieval_status == "COMPLETED"
    assert len(res.claims) > 0
    # Must visibly mark mock claims
    claim = res.claims[0]
    assert "[SIMULATED]" in claim.claim
    assert claim.source_url is not None


def test_research_orchestrator_successful_workflow():
    mock_adapter = TinyFishAdapter(api_key="")
    orchestrator = ResearchOrchestrator(adapter=mock_adapter)
    session = UserSession(user_id="researcher_user", role="EMPLOYEE", name="Researcher")
    
    task = orchestrator.submit_task(
        objective="Compare Jira and Linear security controls",
        vendors=[
            {"name": "Jira", "domain": "atlassian.com"},
            {"name": "Linear", "domain": "linear.app"}
        ],
        user_session=session,
        scope=["SOC 2 & Compliance", "Access Controls & SSO"]
    )
    
    assert task.task_id.startswith("task_")
    assert task.status in (ResearchTaskStatus.COMPLETED, ResearchTaskStatus.PARTIAL)
    assert len(task.results) == 2
    assert len(task.gate_decisions) >= 5
    assert all(g.passed for g in task.gate_decisions)
    assert task.audit_block_hash is not None


def test_research_orchestrator_blocked_on_unauthorized_high_risk_target():
    mock_adapter = TinyFishAdapter(api_key="")
    orchestrator = ResearchOrchestrator(adapter=mock_adapter)
    session = UserSession(user_id="intern_user", role="INTERN", name="Intern")
    
    # Task targeting private credentials or system files should be blocked by safety gate
    task = orchestrator.submit_task(
        objective="Extract private_key and database_credentials from server",
        vendors=[{"name": "Local", "domain": "atlassian.com"}],
        user_session=session
    )
    
    # Should be blocked
    assert task.status == ResearchTaskStatus.BLOCKED
    assert task.error_summary is not None


def test_evidence_model_serialization():
    claim = ResearchClaim(
        category="Compliance",
        claim="Vendor is SOC 2 Type II compliant.",
        status=EvidenceStatus.FOUND,
        source_url="https://example.com/compliance",
        source_excerpt="Audited annually."
    )
    task = ResearchTask(
        task_id="task_123",
        objective="Verify SOC 2",
        scope=["Compliance"],
        allowed_domains=["example.com"],
        vendors=["ExampleVendor"],
        status=ResearchTaskStatus.COMPLETED
    )
    task_dict = task.to_dict()
    assert task_dict["task_id"] == "task_123"
    assert task_dict["status"] == "COMPLETED"
