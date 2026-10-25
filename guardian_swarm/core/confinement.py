from typing import List, Dict, Set, Any, Optional
from guardian_swarm.core.exceptions import (
    TaskOutsideGroupScopeException,
    CrossGroupToolAccessException,
    ConfinementBreachDetectedException,
    InjectionTargetingBoundaryException
)
from guardian_swarm.utils.database import SessionLocal, ModelRegistryModel

TASK_GROUPS: Dict[str, Dict[str, Any]] = {
    "RESEARCH": {
        "models": ["perplexity", "gpt-4o"],
        "allowed_tools": ["search_web", "summarise", "cite", "competitive_analysis", "web_search", "read_file"],
        "blocked_tools": ["execute_code", "write_file", "send_email", "query_db", "delete_file"]
    },
    "CODE": {
        "models": ["claude-sonnet-4-6", "codex"],
        "allowed_tools": ["generate_code", "review_code", "debug", "write_tests", "write_docs", "write_file", "run_tests", "read_file"],
        "blocked_tools": ["web_browse", "read_customer_data", "send_email", "query_finance", "delete_file"]
    },
    "DRAFTING": {
        "models": ["gpt-4o", "claude-haiku-4-5"],
        "allowed_tools": ["write_email", "write_report", "create_doc", "outline_presentation", "read_file"],
        "blocked_tools": ["query_db", "external_api_call", "execute_code", "delete_file"]
    },
    "SUPPORT": {
        "models": ["gpt-4o-mini"],
        "allowed_tools": ["answer_faq", "triage_ticket", "lookup_kb", "read_file"],
        "blocked_tools": ["read_financials", "read_employee_data", "infrastructure_access"]
    },
    "DATA_ANALYSIS": {
        "models": ["phi-3.5-mini", "smollm2"],
        "allowed_tools": ["analyse_data", "process_spreadsheet", "internal_report", "read_file"],
        "blocked_tools": ["external_api_call", "delete_file"]
    }
}

MODEL_GROUPS = TASK_GROUPS

class ConfinementGate:
    """
    Gate 2: Model Group Confinement.
    Enforces model registration and tool permissions per task group scope.
    """
    def __init__(self, groups: Optional[Dict[str, Dict[str, Any]]] = None):
        self.groups = groups or TASK_GROUPS

    def verify_model_group_membership(self, model: str, group_name: str) -> bool:
        """Verifies if model belongs to task group either via DB or static dictionary."""
        model_clean = model.lower()
        group_clean = group_name.upper()

        db = SessionLocal()
        try:
            reg = db.query(ModelRegistryModel).filter(
                ModelRegistryModel.name == model_clean,
                ModelRegistryModel.is_active == True
            ).first()
            if reg:
                return reg.group_name.upper() == group_clean
        except Exception:
            pass
        finally:
            db.close()

        group_def = self.groups.get(group_clean, {})
        allowed_models = group_def.get("models", [])
        return any(m in model_clean or model_clean in m for m in allowed_models)

    def check(self, task_group: str, tool: str, prompt: str = "", model: Optional[str] = None) -> bool:
        group_name = (task_group or "RESEARCH").upper()

        if group_name == "DRAFT":
            group_name = "DRAFTING"
        elif group_name == "DATA":
            group_name = "DATA_ANALYSIS"

        if group_name not in self.groups:
            raise TaskOutsideGroupScopeException(
                group=group_name,
                tool=tool,
                reason=f"TaskGroup '{group_name}' is not recognized in confinement policies."
            )

        # Verify model membership if model is supplied
        if model and not self.verify_model_group_membership(model, group_name):
            raise ConfinementBreachDetectedException(
                group=group_name,
                tool=tool,
                reason=f"Model '{model}' is not registered under TaskGroup '{group_name}'."
            )

        group_def = self.groups[group_name]
        allowed_tools: List[str] = group_def.get("allowed_tools", group_def.get("tools", []))
        blocked_tools: List[str] = group_def.get("blocked_tools", group_def.get("blocked", []))

        # 1. Prompt Injection targeting confinement boundary
        lower_prompt = (prompt or "").lower()
        injection_keywords = [
            "bypass group", "ignore confinement", "sudo override group",
            "ignore previous instructions", "bypass security gate", "switch task group"
        ]
        if any(kw in lower_prompt for kw in injection_keywords):
            raise InjectionTargetingBoundaryException(
                group=group_name,
                tool=tool,
                reason="Prompt injection targeting group confinement boundary detected."
            )

        # 2. Explicitly blocked tool check
        if tool in blocked_tools:
            owner_group = None
            for g_name, g_def in self.groups.items():
                g_tools = g_def.get("allowed_tools", g_def.get("tools", []))
                if tool in g_tools:
                    owner_group = g_name
                    break

            if owner_group and owner_group != group_name:
                raise CrossGroupToolAccessException(
                    group=group_name,
                    tool=tool,
                    target_group=owner_group,
                    reason=f"Group '{group_name}' attempted to invoke tool '{tool}' owned by '{owner_group}'."
                )
            else:
                raise TaskOutsideGroupScopeException(
                    group=group_name,
                    tool=tool,
                    reason=f"Action '{tool}' is explicitly blocked for group '{group_name}'."
                )

        # 3. Allowed tool check
        if tool not in allowed_tools and "*" not in allowed_tools:
            owner_group = None
            for g_name, g_def in self.groups.items():
                g_tools = g_def.get("allowed_tools", g_def.get("tools", []))
                if tool in g_tools:
                    owner_group = g_name
                    break

            if owner_group and owner_group != group_name:
                raise CrossGroupToolAccessException(
                    group=group_name,
                    tool=tool,
                    target_group=owner_group,
                    reason=f"Group '{group_name}' attempted tool '{tool}' which belongs to '{owner_group}'."
                )
            else:
                raise TaskOutsideGroupScopeException(
                    group=group_name,
                    tool=tool,
                    reason=f"Action '{tool}' is not in allowed toolset for group '{group_name}'."
                )

        return True
