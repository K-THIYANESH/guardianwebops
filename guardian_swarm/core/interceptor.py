from typing import Tuple, Dict, Any, Optional
from guardian_swarm.core.policies import is_forbidden_tool, is_allowed_tool, is_high_risk_target
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.utils.audit import AuditLog
from guardian_swarm.core.escalation import EscalationQueue
from guardian_swarm.core.governance import GovernanceEngine

from guardian_swarm.core.user_rbac import UserRBACGate, UserSession
from guardian_swarm.core.confinement import ConfinementGate
from guardian_swarm.core.privacy_gate import PrivacyGate
from guardian_swarm.core.budget_gate import BudgetGate
from guardian_swarm.utils.logger import log_event
from guardian_swarm.core.exceptions import (
    GuardianSecurityException,
    RoleNotPermittedForTaskException,
    DataClassificationExceededException,
    SubagentSpawnDeniedException,
    UserSuspendedException,
    RolePermissionNotFoundException,
    TaskOutsideGroupScopeException,
    CrossGroupToolAccessException,
    ConfinementBreachDetectedException,
    InjectionTargetingBoundaryException,
    PIIDetectedReroutingException,
    ExternalAPIBlockedException,
    DataResidencyViolationException,
    UserWalletExhaustedException,
    TeamPoolExhaustedException,
    OrgCeilingExceededException,
    PreFlightCostExceedsBudgetException,
    PolicyViolationException,
    HighRiskTargetException,
    AISafetyViolationException
)

class GuardianInterceptor:
    """
    GuardianInterceptor intercepts proposed specialist agent actions and gates them.
    5-Gate Enterprise Governance Pipeline:
      GATE 1 -> User RBAC Gate
      GATE 2 -> Model Group Confinement Gate
      GATE 3 -> Privacy Gate
      GATE 4 -> Budget Gate
      GATE 5 -> AI Safety Gate (Tier 1 Policy + Tier 2 AI 3-Agent Debate)
    """
    def __init__(self, verification_agent: Optional[VerificationAgent] = None, audit_log: Optional[AuditLog] = None):
        self.verification_agent = verification_agent or VerificationAgent()
        self.audit_log = audit_log or AuditLog()
        self.escalation_queue = EscalationQueue()
        self.governance_engine = GovernanceEngine()

        # Wire Enterprise Governance Gates
        self.user_rbac = UserRBACGate()
        self.confinement = ConfinementGate()
        self.privacy_gate = PrivacyGate()
        self.budget_gate = BudgetGate()

        self.stats = {
            "total_intercepted": 0,
            "auto_approved": 0,
            "auto_blocked": 0,
            "ai_evaluated": 0,
            "ai_approved": 0,
            "ai_blocked": 0,
            "total_inference_time_ms": 0.0,
            "inference_count": 0,
            "tier1_resolved": 0,
            "tier2_resolved": 0,
            "human_escalations": 0,
            "total_latency_ms": 0.0
        }

    def intercept_action(
        self,
        agent_id: str,
        agent_type: str,
        tool: str,
        target: str,
        params: dict,
        user_session: Optional[UserSession] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        self.stats["total_intercepted"] += 1
        trace = []

        if user_session is None:
            user_id = params.get("user_id", "intern_user")
            name = params.get("user_name", "INTERN")
            role = params.get("user_role", "INTERN")
            department = params.get("department", "Engineering")
            user_session = UserSession(user_id=user_id, name=name, role=role, department=department)

        log_event("info", f"Intercepting action proposal: {tool} on {target}", {
            "agent_id": agent_id,
            "agent_type": agent_type,
            "user_id": user_session.user_id,
            "role": user_session.role
        })

        def _handle_gate_failure(e: GuardianSecurityException, gate_name: str):
            trace.append(f"[{gate_name}] Failed with code {e.error_code}: {e.message}")
            self.stats["auto_blocked"] += 1
            self.stats["tier1_resolved"] += 1
            log_event("warning", f"Security Gate Blocked Action ({e.error_code}): {e.message}", e.to_dict())
            entry = self.audit_log.create_entry(
                agent_id=agent_id,
                agent_type=agent_type,
                tool=tool,
                target=target,
                params={
                    **params,
                    "user_id": user_session.user_id,
                    "user_role": user_session.role,
                    "gate_failure": gate_name,
                    "error_code": e.error_code,
                    "user_help": e.user_help
                },
                verdict="BLOCKED",
                confidence=1.0,
                reasoning=f"[{gate_name}] {e.message}",
                trace=trace
            )
            return False, entry

        # -------------------------------------------------------------
        # GATE 1: User RBAC Gate
        # -------------------------------------------------------------
        try:
            task_category = params.get(
                "task_category",
                params.get("task_group", agent_type.upper() if agent_type.upper() in ["RESEARCH", "CODE", "DRAFTING", "SUPPORT", "DATA_ANALYSIS"] else "RESEARCH")
            )
            data_classification = params.get("data_classification", "INTERNAL")
            spawn_subagent = params.get("spawn_subagent", False)

            self.user_rbac.check(
                session=user_session,
                task_category=task_category,
                data_classification=data_classification,
                spawn_subagent=spawn_subagent
            )
            trace.append(f"[GATE 1: User RBAC] Passed for user '{user_session.user_id}' (Role: {user_session.role})")
        except GuardianSecurityException as e:
            return _handle_gate_failure(e, "GATE 1: User RBAC Gate")
        # -------------------------------------------------------------
        # GATE 2: Model Group Confinement Gate
        # -------------------------------------------------------------
        try:
            task_group = params.get("task_group", task_category)
            prompt = str(params.get("prompt", target))
            model_used = params.get("model_name")
            self.confinement.check(task_group=task_group, tool=tool, prompt=prompt, model=model_used)
            trace.append(f"[GATE 2: Confinement] Passed for TaskGroup '{task_group}' tool '{tool}'")
        except GuardianSecurityException as e:
            return _handle_gate_failure(e, "GATE 2: Model Group Confinement")
        # -------------------------------------------------------------
        # GATE 3: Privacy Gate
        # -------------------------------------------------------------
        clean_params = params.copy()
        try:
            data_class = params.get("data_classification", "INTERNAL")
            pii_action = params.get("pii_action", "reroute")
            allowed_regions = params.get("allowed_regions")
            target_region = params.get("target_region", params.get("region", "us-east-1"))
            prompt = str(params.get("prompt", target))

            max_allowed = self.user_rbac.matrix.get(user_session.role, {}).get("max_data_classification", "INTERNAL")

            scan_res = self.privacy_gate.scan(
                prompt=prompt,
                data_classification=data_class,
                pii_action=pii_action,
                allowed_regions=allowed_regions,
                target_region=target_region,
                max_allowed_classification=max_allowed,
                user_role=user_session.role
            )

            if scan_res.get("rerouted"):
                trace.append("[GATE 3: Privacy] PII detected in payload. Rerouting to local model execution.")
                clean_params["execution_backend"] = "local_model"
                params["execution_backend"] = "local_model"
            else:
                trace.append("[GATE 3: Privacy] Passed PII & data residency checks")
        except PIIDetectedReroutingException as e:
            trace.append(f"[GATE 3: Privacy] Notice (PGE_001): {e.message}")
            clean_params["execution_backend"] = "local_model"
            params["execution_backend"] = "local_model"
        except GuardianSecurityException as e:
            return _handle_gate_failure(e, "GATE 3: Privacy Gate")

        # -------------------------------------------------------------
        # GATE 4: Budget Gate
        # -------------------------------------------------------------
        try:
            model_name = params.get("model_name", "gpt-4o-mini")
            prompt = str(clean_params.get("prompt", target))
            budget_res = self.budget_gate.preflight(session=user_session, model=model_name, prompt=prompt)
            trace.append(f"[GATE 4: Budget] Pre-flight approved. Est tokens: {budget_res['tokens_est']} (${budget_res['cost_usd']} USD)")
        except GuardianSecurityException as e:
            return _handle_gate_failure(e, "GATE 4: Budget Gate")

        # -------------------------------------------------------------
        # GATE 5: AI Safety Gate (Tier 1 Policy + Tier 2 AI Debate)
        # -------------------------------------------------------------
        if is_forbidden_tool(agent_type, tool):
            verdict = "BLOCKED"
            confidence = 1.0
            reasoning = f"Policy Violation: Action '{tool}' is explicitly forbidden for agent role '{agent_type}'."
            trace.append("Tier 1 Match: Found in forbidden list. Auto-blocked.")
            self.stats["auto_blocked"] += 1
            self.stats["tier1_resolved"] += 1

            entry = self.audit_log.create_entry(
                agent_id=agent_id,
                agent_type=agent_type,
                tool=tool,
                target=target,
                params=params,
                verdict=verdict,
                confidence=confidence,
                reasoning=reasoning,
                trace=trace
            )
            return False, entry

        trace.append("Tier 1 Check: Scanning allowed list.")
        if is_allowed_tool(agent_type, tool):
            if is_high_risk_target(target):
                trace.append(f"Defense-in-Depth trigger: Target '{target}' is high-risk. Escalating to AI Verification.")
                trace.append("Escalated to AI")
            else:
                verdict = "APPROVED"
                confidence = 1.0
                reasoning = f"Policy Match: Action '{tool}' is explicitly allowed for agent role '{agent_type}'."
                trace.append("Tier 1 Match: Found in allowed list. Auto-approved.")
                self.stats["auto_approved"] += 1
                self.stats["tier1_resolved"] += 1

                self.budget_gate.deduct_user_tokens(user_id=user_session.user_id, tokens=budget_res['tokens_est'])

                entry = self.audit_log.create_entry(
                    agent_id=agent_id,
                    agent_type=agent_type,
                    tool=tool,
                    target=target,
                    params=params,
                    verdict=verdict,
                    confidence=confidence,
                    reasoning=reasoning,
                    trace=trace
                )
                return True, entry

        trace.append("Tier 2 Check: Escalated to AI Verification (3-Agent Debate).")
        self.stats["ai_evaluated"] += 1

        verdict, confidence, reasoning, elapsed_ms, debate_trace = self.verification_agent.verify_action(
            agent_id=agent_id,
            agent_type=agent_type,
            tool=tool,
            target=target,
            params=params
        )

        self.stats["total_inference_time_ms"] += elapsed_ms
        self.stats["total_latency_ms"] += elapsed_ms
        self.stats["inference_count"] += 1

        trace.append(f"AI Verification complete in {elapsed_ms:.1f}ms. Verdict: {verdict}, Confidence: {confidence:.2f}")

        approved = (verdict == "SAFE" or verdict == "APPROVED")
        if approved:
            self.stats["ai_approved"] += 1
            self.stats["tier2_resolved"] += 1
            self.budget_gate.deduct_user_tokens(user_id=user_session.user_id, tokens=budget_res['tokens_est'])
        elif verdict == "ESCALATE_TO_HUMAN":
            self.stats["human_escalations"] += 1
            self.stats["tier2_resolved"] += 1
        else:
            self.stats["ai_blocked"] += 1
            self.stats["tier2_resolved"] += 1

        entry = self.audit_log.create_entry(
            agent_id=agent_id,
            agent_type=agent_type,
            tool=tool,
            target=target,
            params=params,
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            trace=trace,
            debate_trace=debate_trace
        )

        if verdict == "ESCALATE_TO_HUMAN":
            self.escalation_queue.add(
                action={
                    "action_id": entry["action_id"],
                    "agent_id": agent_id,
                    "agent_type": agent_type,
                    "tool": tool,
                    "target": target,
                    "params": params
                },
                prosecutor_output=debate_trace.get("prosecutor", {}),
                defender_output=debate_trace.get("defender", {}),
                judge_output=debate_trace.get("judge", {})
            )

        return approved, entry
