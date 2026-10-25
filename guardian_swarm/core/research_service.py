"""
Guardian WebOps Research Orchestration Service
==============================================
Orchestrates the 5-Gate Governance check around TinyFish web research tasks,
records decisions to cryptographic audit log, and manages research workflows.
"""
from __future__ import annotations

import uuid
import datetime
from typing import Dict, List, Optional, Any

from guardian_swarm.core.evidence_models import (
    ResearchTask,
    ResearchTaskStatus,
    VendorResearchResult,
    GateDecision,
    EvidenceStatus
)
from guardian_swarm.integration.tinyfish_adapter import TinyFishAdapter
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.utils.audit import AuditLog
from guardian_swarm.core.user_rbac import UserSession
from guardian_swarm.utils.logger import log_event


class ResearchOrchestrator:
    """
    Coordinates policy governance evaluation through GuardianInterceptor before
    delegating web retrieval to TinyFishAdapter.
    """

    def __init__(
        self,
        interceptor: Optional[GuardianInterceptor] = None,
        audit_log: Optional[AuditLog] = None,
        adapter: Optional[TinyFishAdapter] = None
    ):
        self.audit_log = audit_log or AuditLog()
        self.interceptor = interceptor or GuardianInterceptor(audit_log=self.audit_log)
        self.adapter = adapter or TinyFishAdapter()
        self.tasks: Dict[str, ResearchTask] = {}

    def submit_task(
        self,
        objective: str,
        vendors: List[Dict[str, str]],  # [{"name": "Jira", "domain": "atlassian.com"}, ...]
        user_session: UserSession,
        scope: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None
    ) -> ResearchTask:
        task_id = f"task_{uuid.uuid4().hex[:8]}"
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        vendor_names = [v.get("name", "Unknown") for v in vendors]
        if allowed_domains is None:
            allowed_domains = [v.get("domain", "").strip().lower() for v in vendors if v.get("domain")]

        task = ResearchTask(
            task_id=task_id,
            objective=objective,
            scope=scope or ["SOC 2 & Compliance", "Data Encryption & Residency", "Access Controls & SSO"],
            allowed_domains=allowed_domains,
            vendors=vendor_names,
            status=ResearchTaskStatus.RUNNING,
            is_mock=not self.adapter.is_live,
            provider="tinyfish",
            created_at=now_str,
            user_id=user_session.user_id,
            user_role=user_session.role
        )

        log_event("info", f"Submitting research task {task_id}: {objective}", {
            "user_id": user_session.user_id,
            "role": user_session.role,
            "vendors": vendor_names
        })

        # Evaluate 5-Gate Governance Pipeline via Interceptor
        gate_decisions: List[GateDecision] = []

        # Gate check for web research tool
        approved, interceptor_entry = self.interceptor.intercept_action(
            agent_id=f"webops_agent_{user_session.user_id}",
            agent_type="researcher",
            tool="search_web",
            target=objective,
            params={
                "task_id": task_id,
                "task_category": "RESEARCH",
                "task_group": "RESEARCH",
                "user_id": user_session.user_id,
                "user_name": user_session.name,
                "user_role": user_session.role,
                "data_classification": "INTERNAL",
                "prompt": objective,
                "allowed_domains": allowed_domains
            },
            user_session=user_session
        )

        # Parse trace for Gate breakdown
        trace = interceptor_entry.get("investigation_trace", [])
        verdict = interceptor_entry.get("verdict", "BLOCKED")

        # Map trace to gate decisions
        gate_1_passed = any("GATE 1" in s and "Passed" in s for s in trace) or (approved and not any("GATE 1" in s and "Failed" in s for s in trace))
        gate_2_passed = any("GATE 2" in s and "Passed" in s for s in trace) or (approved and not any("GATE 2" in s and "Failed" in s for s in trace))
        gate_3_passed = any("GATE 3" in s and ("Passed" in s or "rerouting" in s.lower()) for s in trace) or (approved and not any("GATE 3" in s and "Failed" in s for s in trace))
        gate_4_passed = any("GATE 4" in s and ("approved" in s.lower() or "passed" in s.lower()) for s in trace) or (approved and not any("GATE 4" in s and "Failed" in s for s in trace))
        gate_5_passed = verdict in ("APPROVED", "SAFE") or any("Auto-approved" in s or "SAFE" in s for s in trace)

        gate_decisions = [
            GateDecision(
                gate_name="Gate 1: Access Control (RBAC)",
                passed=gate_1_passed,
                details=next((s for s in trace if "GATE 1" in s), "Role permission verified.")
            ),
            GateDecision(
                gate_name="Gate 2: Tool Confinement",
                passed=gate_2_passed,
                details=next((s for s in trace if "GATE 2" in s), "Tool confinement verified for researcher.")
            ),
            GateDecision(
                gate_name="Gate 3: Privacy & Classification",
                passed=gate_3_passed,
                details=next((s for s in trace if "GATE 3" in s), "Public web research, no PII leakage.")
            ),
            GateDecision(
                gate_name="Gate 4: Budget Guardrails",
                passed=gate_4_passed,
                details=next((s for s in trace if "GATE 4" in s), "Pre-flight token & query allowances approved.")
            ),
            GateDecision(
                gate_name="Gate 5: Safety & Policy",
                passed=gate_5_passed,
                details=next((s for s in trace if "Auto-approved" in s or "Blocked" in s), interceptor_entry.get("reasoning", "Safety gate verified."))
            ),
        ]

        task.gate_decisions = gate_decisions
        task.audit_block_hash = interceptor_entry.get("entry_hash")
        
        # If blocked by governance
        if not approved or verdict == "BLOCKED":
            task.status = ResearchTaskStatus.BLOCKED
            task.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            task.error_summary = f"Research task blocked by Guardian Governance: {interceptor_entry.get('reasoning', 'Policy violation')}"
            self.tasks[task_id] = task
            return task

        # If approved, execute vendor research across each target
        vendor_results: List[VendorResearchResult] = []
        any_failed = False
        all_failed = True

        for v in vendors:
            v_name = v.get("name", "Unknown")
            v_domain = v.get("domain", "")
            res = self.adapter.research_vendor(
                vendor_name=v_name,
                target_domain=v_domain,
                categories=task.scope,
                allowed_domains=allowed_domains
            )
            vendor_results.append(res)
            if res.retrieval_status == "COMPLETED":
                all_failed = False
            else:
                any_failed = True

        task.results = vendor_results
        task.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if all_failed and len(vendors) > 0:
            task.status = ResearchTaskStatus.FAILED
            task.error_summary = "All vendor research queries failed or were blocked."
        elif any_failed:
            task.status = ResearchTaskStatus.PARTIAL
        else:
            task.status = ResearchTaskStatus.COMPLETED

        self.tasks[task_id] = task
        return task

    def get_task(self, task_id: str) -> Optional[ResearchTask]:
        return self.tasks.get(task_id)

    def list_tasks(self) -> List[ResearchTask]:
        return sorted(list(self.tasks.values()), key=lambda t: t.created_at, reverse=True)
