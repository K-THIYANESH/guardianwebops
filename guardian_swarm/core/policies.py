# Security policies for specialist agents in the Guardian runtime

# Confidence threshold for human escalation (0-10 scale)
CONFIDENCE_THRESHOLD = 6.0

# Tool lists matching the security requirements
AGENT_POLICIES = {
    "researcher": {
        "allowed_tools": ["search_web", "extract_text", "summarize", "analyze"],
        "forbidden_tools": ["delete_file", "write_file", "modify_system", "call_api"]
    },
    "deck_builder": {
        "allowed_tools": ["create_slide", "add_content", "format_deck", "export"],
        "forbidden_tools": ["delete_file", "modify_system", "call_api"]
    },
    "coder": {
        "allowed_tools": ["read_file", "write_file", "run_test", "refactor"],
        "forbidden_tools": ["delete_file", "modify_system", "call_api"]
    }
}

# High-risk targets that bypass Tier 1 allowed auto-approvals and trigger Tier 2 AI verification
HIGH_RISK_TARGET_KEYWORDS = [
    "/etc/passwd",
    "/etc/shadow",
    "transfer_funds",
    "security_settings",
    "/system/config",
    "passwd",
    "shadow",
    "private_key",
    ".env",
    "ssh_key",
    "database_credentials",
    "api_key"
]

def is_forbidden_tool(agent_type: str, tool: str) -> bool:
    policy = AGENT_POLICIES.get(agent_type, {})
    return tool in policy.get("forbidden_tools", [])

def is_allowed_tool(agent_type: str, tool: str) -> bool:
    policy = AGENT_POLICIES.get(agent_type, {})
    return tool in policy.get("allowed_tools", [])

def is_high_risk_target(target: str) -> bool:
    target_lower = target.lower()
    return any(keyword in target_lower for keyword in HIGH_RISK_TARGET_KEYWORDS)
