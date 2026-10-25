from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


class GovernanceEngine:
    """Lightweight governance layer supporting the corporate AI OS spec."""

    def __init__(self) -> None:
        self.user_roles = {
            "intern": "INTERN",
            "manager": "MANAGER",
            "exec": "EXEC",
        }
        self.task_groups = {
            "research": "RESEARCH",
            "code": "CODE",
            "draft": "DRAFT",
            "support": "SUPPORT",
            "data": "DATA",
        }
        self.group_tools = {
            "RESEARCH": ["search_web", "summarize", "extract_text", "analyze"],
            "CODE": ["read_file", "write_file", "run_test", "refactor"],
            "DRAFT": ["draft_email", "write_report", "create_outline"],
            "SUPPORT": ["answer_faq", "triage_ticket", "lookup_kb"],
            "DATA": ["analyze_data", "summarize_report"],
        }
        self.role_permissions = {
            "INTERN": {"RESEARCH", "DRAFT", "SUPPORT"},
            "MANAGER": {"RESEARCH", "CODE", "DRAFT", "SUPPORT", "DATA"},
            "EXEC": {"RESEARCH", "CODE", "DRAFT", "SUPPORT", "DATA"},
        }
        self.user_wallets = {
            "INTERN": 10000,
            "MANAGER": 50000,
            "EXEC": 200000,
        }
        self.team_pools = {
            "default": 500000,
        }
        self.pii_patterns = [
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            r"\b(?:phone|mobile|cell)\s*[:#]?\s*\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        ]

    def evaluate_rbac(self, user_role: str, task_category: str) -> Dict[str, object]:
        normalized_role = str(user_role).upper()
        normalized_task = str(task_category).upper()
        allowed = normalized_task in self.role_permissions.get(normalized_role, set())
        return {
            "allowed": allowed,
            "user_role": normalized_role,
            "task_category": normalized_task,
            "error_code": "RBE_001" if not allowed else None,
            "message": "Role permitted" if allowed else "Role not permitted for this task category",
        }

    def evaluate_confinement(self, task_group: str, tool_name: str) -> Dict[str, object]:
        normalized_group = str(task_group).upper()
        normalized_tool = str(tool_name).lower()
        allowed_tools = self.group_tools.get(normalized_group, [])
        allowed = normalized_tool in allowed_tools
        return {
            "allowed": allowed,
            "task_group": normalized_group,
            "tool_name": normalized_tool,
            "error_code": "MGE_002" if not allowed else None,
            "message": "Tool permitted" if allowed else "Tool outside model group scope",
        }

    def evaluate_privacy(self, text: str) -> Dict[str, object]:
        contains_pii = False
        for pattern in self.pii_patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                contains_pii = True
                break
        requires_local_model = contains_pii
        return {
            "contains_pii": contains_pii,
            "requires_local_model": requires_local_model,
            "classification": "SENSITIVE" if contains_pii else "PUBLIC",
            "error_code": "PGE_001" if contains_pii else None,
            "message": "PII detected, rerouting to local model" if contains_pii else "No PII detected",
        }

    def evaluate_budget(self, user_role: str, estimated_tokens: int, remaining_wallet: Optional[int] = None, team_pool_remaining: Optional[int] = None) -> Dict[str, object]:
        normalized_role = str(user_role).upper()
        wallet_limit = self.user_wallets.get(normalized_role, 0)
        wallet_remaining = remaining_wallet if remaining_wallet is not None else wallet_limit
        team_remaining = team_pool_remaining if team_pool_remaining is not None else self.team_pools.get("default", 0)
        allowed = estimated_tokens <= wallet_remaining and estimated_tokens <= team_remaining
        return {
            "allowed": allowed,
            "user_role": normalized_role,
            "estimated_tokens": estimated_tokens,
            "remaining_wallet": wallet_remaining,
            "team_pool_remaining": team_remaining,
            "error_code": "BGE_004" if not allowed else None,
            "message": "Budget check passed" if allowed else "Estimated cost exceeds remaining budget",
        }

    def evaluate_safety(self, target: str) -> Dict[str, object]:
        from guardian_swarm.core.policies import is_high_risk_target

        return {
            "allowed": not is_high_risk_target(target),
            "error_code": "GSE_002" if is_high_risk_target(target) else None,
            "message": "Safety gate passed" if not is_high_risk_target(target) else "High-risk target detected",
        }
