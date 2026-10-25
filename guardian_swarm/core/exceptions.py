"""
Guardian Swarm Custom Exceptions & Error Codes
==============================================
Defines the standard set of security exceptions and structured error codes
(GSE_xxx, RBE_xxx, MGE_xxx, PGE_xxx, BGE_xxx) raised when an agent action proposal
or user task violates safety & governance guardrails.
"""
from typing import Dict, Any, Optional

class GuardianException(Exception):
    """Base exception for all Guardian Swarm errors."""
    def __init__(
        self,
        message: str,
        error_code: str,
        gate_name: str = "System",
        user_id: str = "system",
        details: Optional[Dict[str, Any]] = None,
        user_help: Optional[str] = None
    ):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.gate_name = gate_name
        self.user_id = user_id
        self.details = details or {}
        self.user_help = user_help or "Contact your system administrator for assistance."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "gate_name": self.gate_name,
            "user_id": self.user_id,
            "details": self.details,
            "user_help": self.user_help
        }

    def __str__(self):
        return f"[{self.error_code}] {self.message}"


class GuardianSecurityException(GuardianException, PermissionError):
    """Base class for safety & governance blocks, inheriting from PermissionError for backwards compatibility."""
    def __init__(
        self,
        message: str,
        error_code: str,
        gate_name: str = "Safety Gate",
        user_id: str = "unknown",
        details: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        tool: Optional[str] = None,
        target: Optional[str] = None,
        user_help: Optional[str] = None
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            gate_name=gate_name,
            user_id=user_id,
            details=details,
            user_help=user_help
        )
        self.agent_id = agent_id or user_id
        self.agent_type = agent_type or "agent"
        self.tool = tool or "action"
        self.target = target or "system"


# =====================================================================
# Gate 5 / System Safety Exceptions (GSE_001 – GSE_005)
# =====================================================================

class PolicyViolationException(GuardianSecurityException):
    """Error Code: GSE_001 — Raised when a proposed tool is explicitly forbidden by role-based safety policies."""
    def __init__(self, agent_id: str, agent_type: str, tool: str, target: str, reason: str = "Forbidden Tool", user_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        message = f"Agent '{agent_id}' proposed forbidden action: '{tool}' on '{target}'. Reason: {reason}"
        det = details or {}
        det.update({"reason": reason, "tool": tool, "target": target})
        super().__init__(
            message=message,
            error_code="GSE_001",
            gate_name="AI Safety Gate",
            user_id=user_id or agent_id,
            details=det,
            agent_id=agent_id,
            agent_type=agent_type,
            tool=tool,
            target=target,
            user_help="Action is explicitly forbidden by workspace policy. Contact your system admin."
        )


class HighRiskTargetException(GuardianSecurityException):
    """Error Code: GSE_002 — Raised when an allowed tool targets a sensitive resource or high-risk path."""
    def __init__(self, agent_id: str, agent_type: str, tool: str, target: str, reason: str = "High-Risk Path", user_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        message = f"Agent '{agent_id}' proposed action '{tool}' targeting high-risk resource: '{target}'. Reason: {reason}"
        det = details or {}
        det.update({"reason": reason, "tool": tool, "target": target})
        super().__init__(
            message=message,
            error_code="GSE_002",
            gate_name="AI Safety Gate",
            user_id=user_id or agent_id,
            details=det,
            agent_id=agent_id,
            agent_type=agent_type,
            tool=tool,
            target=target,
            user_help="Targeting high-risk resources is restricted. Seek manager authorization."
        )


class AISafetyViolationException(GuardianSecurityException):
    """Error Code: GSE_003 — Raised when a proposed action fails Tier 2 AI safety alignment checks."""
    def __init__(self, agent_id: str, agent_type: str, tool: str, target: str, reason: str, user_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        message = f"Agent '{agent_id}' proposed action '{tool}' on '{target}' which was flagged as unsafe by AI safety engine. Reason: {reason}"
        det = details or {}
        det.update({"reason": reason, "tool": tool, "target": target})
        super().__init__(
            message=message,
            error_code="GSE_003",
            gate_name="AI Safety Gate",
            user_id=user_id or agent_id,
            details=det,
            agent_id=agent_id,
            agent_type=agent_type,
            tool=tool,
            target=target,
            user_help="Action flagged during safety review. Rephrase your request or request human review."
        )


class LedgerVerificationException(GuardianSecurityException):
    """Error Code: GSE_004 — Raised when cryptographic audit chain scan detects tampering or signature mismatches."""
    def __init__(self, block_index: int, details_msg: str, user_id: str = "system"):
        message = f"Cryptographic Ledger Tampering Detected at Block #{block_index}. Details: {details_msg}"
        super().__init__(
            message=message,
            error_code="GSE_004",
            gate_name="Ledger Audit Gate",
            user_id=user_id,
            details={"block_index": block_index, "details": details_msg},
            agent_id="audit_ledger",
            agent_type="system",
            tool="verify_chain",
            target=f"block_{block_index}",
            user_help="Ledger tampering detected. System security incident logged."
        )


class HumanEscalationRequiredException(GuardianSecurityException):
    """Error Code: GSE_005 — Raised when a proposed action requires human verification/escalation due to borderline safety confidence."""
    def __init__(self, agent_id: str, agent_type: str, tool: str, target: str, reason: str, user_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        message = f"Agent '{agent_id}' proposed action '{tool}' on '{target}' requires human escalation. Reason: {reason}"
        det = details or {}
        det.update({"reason": reason, "tool": tool, "target": target})
        super().__init__(
            message=message,
            error_code="GSE_005",
            gate_name="Human Escalation Gate",
            user_id=user_id or agent_id,
            details=det,
            agent_id=agent_id,
            agent_type=agent_type,
            tool=tool,
            target=target,
            user_help="Task submitted for human approval in the Escalation Queue."
        )


# =====================================================================
# Gate 1: User RBAC Gate Exceptions (RBE_001 – RBE_005)
# =====================================================================

class RoleNotPermittedForTaskException(GuardianSecurityException):
    """Error Code: RBE_001 — RoleNotPermittedForTask: user role not on allow-list for task category."""
    def __init__(self, user_id: str, role: str, category: str, reason: str = "User role not on allow-list for task category", details: Optional[Dict[str, Any]] = None):
        message = f"User '{user_id}' (Role: {role}) denied access to task category '{category}'. Reason: {reason}"
        det = details or {}
        det.update({"role": role, "category": category, "reason": reason})
        super().__init__(
            message=message,
            error_code="RBE_001",
            gate_name="User RBAC Gate",
            user_id=user_id,
            details=det,
            agent_id=user_id,
            agent_type=role,
            tool=f"category:{category}",
            target="rbac_policy",
            user_help=f"Your account role '{role}' is not authorized for '{category}' tasks. Contact an administrator to upgrade access."
        )

# Alias for backwards compatibility
RoleNotPermittedException = RoleNotPermittedForTaskException


class DataClassificationExceededException(GuardianSecurityException):
    """Error Code: RBE_002 — DataClassificationExceeded: user role cannot access this data class."""
    def __init__(self, user_id: str, role: str, classification: str, max_allowed: str, reason: str = "User role cannot access this data class", details: Optional[Dict[str, Any]] = None):
        message = f"User '{user_id}' (Role: {role}) requested classification '{classification}' exceeding max allowed '{max_allowed}'. Reason: {reason}"
        det = details or {}
        det.update({"role": role, "classification": classification, "max_allowed": max_allowed, "reason": reason})
        super().__init__(
            message=message,
            error_code="RBE_002",
            gate_name="User RBAC Gate",
            user_id=user_id,
            details=det,
            agent_id=user_id,
            agent_type=role,
            tool=f"classification:{classification}",
            target="data_policy",
            user_help=f"Data classification level '{classification}' exceeds your allowed level '{max_allowed}'."
        )

# Alias for backwards compatibility
AgentTypeRestrictedException = DataClassificationExceededException


class SubagentSpawnDeniedException(GuardianSecurityException):
    """Error Code: RBE_003 — SubagentSpawnDenied: user role cannot spawn subagents."""
    def __init__(self, user_id: str, role: str, reason: str = "User role cannot spawn subagents", details: Optional[Dict[str, Any]] = None):
        message = f"Subagent spawn denied for user '{user_id}' (Role: {role}). Reason: {reason}"
        det = details or {}
        det.update({"role": role, "reason": reason})
        super().__init__(
            message=message,
            error_code="RBE_003",
            gate_name="User RBAC Gate",
            user_id=user_id,
            details=det,
            agent_id=user_id,
            agent_type=role,
            tool="spawn_subagent",
            target="subagent",
            user_help="Subagent spawning requires MANAGER or higher role."
        )


class UserSuspendedException(GuardianSecurityException):
    """Error Code: RBE_004 — UserSuspended: account is suspended or inactive."""
    def __init__(self, user_id: str, reason: str = "User account is suspended or inactive", details: Optional[Dict[str, Any]] = None):
        message = f"Access denied for user '{user_id}'. Account is suspended or inactive. Reason: {reason}"
        det = details or {}
        det.update({"user_id": user_id, "reason": reason})
        super().__init__(
            message=message,
            error_code="RBE_004",
            gate_name="User RBAC Gate",
            user_id=user_id,
            details=det,
            agent_id=user_id,
            agent_type="suspended",
            tool="login",
            target="user_status",
            user_help="Your account is suspended. Please contact IT Security to reinstate access."
        )


class RolePermissionNotFoundException(GuardianSecurityException):
    """Error Code: RBE_005 — RolePermissionNotFound: specified role or permission matrix entry not found."""
    def __init__(self, user_id: str, role: str, reason: str = "Specified role or permission matrix entry not found", details: Optional[Dict[str, Any]] = None):
        message = f"Role permission error for user '{user_id}' with role '{role}'. Reason: {reason}"
        det = details or {}
        det.update({"role": role, "reason": reason})
        super().__init__(
            message=message,
            error_code="RBE_005",
            gate_name="User RBAC Gate",
            user_id=user_id,
            details=det,
            agent_id=user_id,
            agent_type=role,
            tool="lookup_role",
            target="rbac_matrix",
            user_help="Invalid or unmapped user role detected."
        )


# =====================================================================
# Gate 2: Model Group Confinement Exceptions (MGE_001 – MGE_004)
# =====================================================================

class TaskOutsideGroupScopeException(GuardianSecurityException):
    """Error Code: MGE_001 — TaskOutsideGroupScope: request outside assigned group task domain."""
    def __init__(self, group: str, tool: str, reason: str = "Request outside assigned group task domain", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Action '{tool}' is outside assigned TaskGroup '{group}' scope. Reason: {reason}"
        det = details or {}
        det.update({"group": group, "tool": tool, "reason": reason})
        super().__init__(
            message=message,
            error_code="MGE_001",
            gate_name="Model Confinement Gate",
            user_id=user_id,
            details=det,
            agent_id=group,
            agent_type="model_group",
            tool=tool,
            target=group,
            user_help=f"The tool '{tool}' is not supported in the '{group}' model group."
        )


class CrossGroupToolAccessException(GuardianSecurityException):
    """Error Code: MGE_002 — CrossGroupToolAccess: attempt to invoke tool from another group."""
    def __init__(self, group: str, tool: str, target_group: str, reason: str = "Attempt to invoke tool from another group", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Cross-group tool access violation! Group '{group}' attempted tool '{tool}' owned by '{target_group}'. Reason: {reason}"
        det = details or {}
        det.update({"group": group, "tool": tool, "target_group": target_group, "reason": reason})
        super().__init__(
            message=message,
            error_code="MGE_002",
            gate_name="Model Confinement Gate",
            user_id=user_id,
            details=det,
            agent_id=group,
            agent_type="model_group",
            tool=tool,
            target=target_group,
            user_help=f"Tool '{tool}' belongs to group '{target_group}'. Change task mode to use this tool."
        )


class ConfinementBreachDetectedException(GuardianSecurityException):
    """Error Code: MGE_003 — ConfinementBreachDetected: structural boundary violation attempt."""
    def __init__(self, group: str, tool: str, reason: str = "Structural boundary violation attempt", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Confinement boundary breach detected for group '{group}' tool '{tool}'. Reason: {reason}"
        det = details or {}
        det.update({"group": group, "tool": tool, "reason": reason})
        super().__init__(
            message=message,
            error_code="MGE_003",
            gate_name="Model Confinement Gate",
            user_id=user_id,
            details=det,
            agent_id=group,
            agent_type="model_group",
            tool=tool,
            target=group,
            user_help="Structural boundary breach detected. Request blocked by confinement guardrail."
        )


class InjectionTargetingBoundaryException(GuardianSecurityException):
    """Error Code: MGE_004 — InjectionTargetingBoundary: prompt injection attempting group bypass."""
    def __init__(self, group: str, tool: str, reason: str = "Prompt injection attempting group bypass", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Prompt injection targeting group confinement boundary in group '{group}'. Reason: {reason}"
        det = details or {}
        det.update({"group": group, "tool": tool, "reason": reason})
        super().__init__(
            message=message,
            error_code="MGE_004",
            gate_name="Model Confinement Gate",
            user_id=user_id,
            details=det,
            agent_id=group,
            agent_type="model_group",
            tool=tool,
            target=group,
            user_help="Prompt contains forbidden boundary override keywords."
        )


# =====================================================================
# Gate 3: Privacy Gate Exceptions (PGE_001 – PGE_004)
# =====================================================================

class PIIDetectedReroutingException(GuardianSecurityException):
    """Error Code: PGE_001 — PIIDetectedRerouting: PII found, rerouting to local model."""
    def __init__(self, pii_types: list, reason: str = "PII found, rerouting to local model", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"PII detected ({', '.join(pii_types)}). Request rerouted to local execution model. Reason: {reason}"
        det = details or {}
        det.update({"pii_types": pii_types, "reason": reason})
        super().__init__(
            message=message,
            error_code="PGE_001",
            gate_name="Privacy Gate",
            user_id=user_id,
            details=det,
            agent_id="privacy_gate",
            agent_type="privacy",
            tool="pii_scan",
            target="local_model",
            user_help="Contains sensitive data (PII). Automatically rerouted to private local processing."
        )


class ExternalAPIBlockedException(GuardianSecurityException):
    """Error Code: PGE_002 — ExternalAPIBlocked: data classification forbids external call."""
    def __init__(self, data_classification: str, reason: str = "Data classification forbids external call", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"External API call blocked for classification '{data_classification}'. Reason: {reason}"
        det = details or {}
        det.update({"data_classification": data_classification, "reason": reason})
        super().__init__(
            message=message,
            error_code="PGE_002",
            gate_name="Privacy Gate",
            user_id=user_id,
            details=det,
            agent_id="privacy_gate",
            agent_type="privacy",
            tool="external_api",
            target=data_classification,
            user_help=f"Data level '{data_classification}' cannot be transmitted to external cloud models."
        )


class OutputRedactionAppliedException(GuardianSecurityException):
    """Error Code: PGE_003 — OutputRedactionApplied: PII removed from response before delivery."""
    def __init__(self, redacted_count: int, reason: str = "PII removed from response before delivery", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Output response redacted for {redacted_count} PII fields before delivery. Reason: {reason}"
        det = details or {}
        det.update({"redacted_count": redacted_count, "reason": reason})
        super().__init__(
            message=message,
            error_code="PGE_003",
            gate_name="Privacy Gate",
            user_id=user_id,
            details=det,
            agent_id="privacy_gate",
            agent_type="privacy",
            tool="redact",
            target="output",
            user_help="Response contained sensitive PII fields which were redacted prior to display."
        )


class DataResidencyViolationException(GuardianSecurityException):
    """Error Code: PGE_004 — DataResidencyViolation: request would move data outside permitted region."""
    def __init__(self, region: str, reason: str = "Request would move data outside permitted region", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Data residency violation! Region '{region}' is forbidden. Reason: {reason}"
        det = details or {}
        det.update({"region": region, "reason": reason})
        super().__init__(
            message=message,
            error_code="PGE_004",
            gate_name="Privacy Gate",
            user_id=user_id,
            details=det,
            agent_id="privacy_gate",
            agent_type="privacy",
            tool="residency_check",
            target=region,
            user_help=f"Data routing to region '{region}' violates organizational residency policy."
        )


class FileClassificationDeniedException(GuardianSecurityException):
    """Error Code: PGE_005 — FileClassificationDenied: file classification exceeds user allowed data level."""
    def __init__(self, file_path: str, classification: str, max_allowed: str, role: str, reason: str = "File classification exceeds user allowed data level", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"File classification denied for '{file_path}'! Classification '{classification}' exceeds user role '{role}' maximum allowed level '{max_allowed}'."
        det = details or {}
        det.update({"file_path": file_path, "classification": classification, "max_allowed": max_allowed, "role": role, "reason": reason})
        super().__init__(
            message=message,
            error_code="PGE_005",
            gate_name="Privacy Gate",
            user_id=user_id,
            details=det,
            agent_id="privacy_gate",
            agent_type="privacy",
            tool="filemind_classification",
            target=file_path,
            user_help=f"File classification '{classification}' exceeds your allowed level '{max_allowed}'."
        )


# =====================================================================
# Gate 4: Budget Gate Exceptions (BGE_001 – BGE_004)
# =====================================================================

class UserWalletExhaustedException(GuardianSecurityException):
    """Error Code: BGE_001 — UserWalletExhausted: user daily token budget fully consumed."""
    def __init__(self, user_id: str, used: int, limit: int, reason: str = "User daily token budget fully consumed", details: Optional[Dict[str, Any]] = None):
        message = f"User '{user_id}' daily token wallet exhausted ({used}/{limit} tokens). Reason: {reason}"
        det = details or {}
        det.update({"user_id": user_id, "used": used, "limit": limit, "reason": reason})
        super().__init__(
            message=message,
            error_code="BGE_001",
            gate_name="Budget Gate",
            user_id=user_id,
            details=det,
            agent_id=user_id,
            agent_type="user",
            tool="token_spend",
            target=user_id,
            user_help="Daily token allowance exhausted. Allocation resets at midnight or request extension from your manager."
        )


class TeamPoolExhaustedException(GuardianSecurityException):
    """Error Code: BGE_002 — TeamPoolExhausted: team monthly budget pool at ceiling."""
    def __init__(self, team_id: str, used: int, limit: int, reason: str = "Team monthly budget pool at ceiling", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Team pool '{team_id}' monthly token budget at ceiling ({used}/{limit} tokens). Reason: {reason}"
        det = details or {}
        det.update({"team_id": team_id, "used": used, "limit": limit, "reason": reason})
        super().__init__(
            message=message,
            error_code="BGE_002",
            gate_name="Budget Gate",
            user_id=user_id,
            details=det,
            agent_id=team_id,
            agent_type="team",
            tool="token_spend",
            target=team_id,
            user_help=f"Team monthly budget pool for '{team_id}' has reached capacity."
        )


class OrgCeilingExceededException(GuardianSecurityException):
    """Error Code: BGE_003 — OrgCeilingExceeded: org-wide hard cap would be breached."""
    def __init__(self, org_id: str, used: int, limit: int, reason: str = "Org-wide hard cap would be breached", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Organization '{org_id}' hard token ceiling exceeded ({used}/{limit} tokens). Reason: {reason}"
        det = details or {}
        det.update({"org_id": org_id, "used": used, "limit": limit, "reason": reason})
        super().__init__(
            message=message,
            error_code="BGE_003",
            gate_name="Budget Gate",
            user_id=user_id,
            details=det,
            agent_id=org_id,
            agent_type="org",
            tool="token_spend",
            target=org_id,
            user_help="Organization monthly token cap reached."
        )


class PreFlightCostExceedsBudgetException(GuardianSecurityException):
    """Error Code: BGE_004 — PreFlightCostExceedsBudget: estimated cost exceeds remaining budget."""
    def __init__(self, estimated_cost: int, remaining_budget: int, reason: str = "Estimated cost exceeds remaining budget", user_id: str = "system", details: Optional[Dict[str, Any]] = None):
        message = f"Pre-flight check failed! Estimated tokens ({estimated_cost}) exceeds remaining budget ({remaining_budget}). Reason: {reason}"
        det = details or {}
        det.update({"estimated_cost": estimated_cost, "remaining_budget": remaining_budget, "reason": reason})
        super().__init__(
            message=message,
            error_code="BGE_004",
            gate_name="Budget Gate",
            user_id=user_id,
            details=det,
            agent_id="budget_gate",
            agent_type="budget",
            tool="preflight",
            target="token_wallet",
            user_help=f"Task estimated cost ({estimated_cost} tokens) exceeds your remaining wallet balance ({remaining_budget} tokens)."
        )
