#!/usr/bin/env python3
"""
Guardian Swarm - Demo 1: Tier 1 Policy Gating
==============================================
Demonstrates the static policy checking layer (Tier 1).
Shows how forbidden tools are blocked instantly and allowed tools are approved
without requiring deep LLM verification.
"""

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import sys
import time

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import terminal_ui
from guardian_swarm.core.policies import AGENT_POLICIES
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.utils.audit import AuditLog

def print_policy_matrix():
    """Prints a beautiful table displaying agent roles and their static policies."""
    terminal_ui.rich_print("[bold][cyan]📋 SYSTEM ROLE POLICY MATRIX[/cyan][/bold]")
    table = terminal_ui.Table(headers=["Agent Role", "Allowed Tools (Auto-Approve)", "Forbidden Tools (Auto-Block)"], style="cyan")
    
    for role, policy in AGENT_POLICIES.items():
        allowed = ", ".join(f"[green]{t}[/]" for t in policy["allowed_tools"])
        forbidden = ", ".join(f"[red]{t}[/]" for t in policy["forbidden_tools"])
        table.add_row([f"[bold][white]{role.capitalize()}[/white][/bold]", allowed, forbidden])
        
    table.print()
    print()

def main():
    terminal_ui.Box(width=75, style="green", box_type="double") \
        .add_line("   🛡️  GUARDIAN SWARM - DEMO 1: TIER 1 POLICY GATING") \
        .add_line("      Static Rules Engine Interception & Gating") \
        .print()
    print()

    print_policy_matrix()

    # Instantiate core layers (forcing heuristics is fine since this test only exercises Tier 1)
    audit_log = AuditLog()
    verification_agent = VerificationAgent()
    verification_agent.is_heuristic = True # Keep fast for policy gating demo
    interceptor = GuardianInterceptor(verification_agent, audit_log)

    # Scenarios to run
    scenarios = [
        # (agent_id, agent_type, proposed_tool, proposed_target, params, description)
        ("researcher_01", "researcher", "search_web", "https://arxiv.org", {"query": "deep learning"}, "Researcher searching the web (Allowed)"),
        ("researcher_02", "researcher", "delete_file", "/system/config", {"recursive": True}, "Researcher trying to delete system config (Forbidden)"),
        ("coder_01", "coder", "write_file", "src/core.py", {"code": "print('ok')"}, "Coder writing code file (Allowed)"),
        ("coder_02", "coder", "call_api", "transfer_funds", {"amount": 1000}, "Coder invoking external payment API (Forbidden)"),
        ("designer_01", "deck_builder", "create_slide", "Overview Slide", {"index": 0}, "Deck Builder adding a slide (Allowed)"),
        ("designer_02", "deck_builder", "modify_system", "network_settings", {"port": 80}, "Deck Builder modifying network settings (Forbidden)"),
    ]

    terminal_ui.rich_print("[bold][cyan]🚀 RUNNING POLICY INTERCEPTION SWEEP...[/cyan][/bold]\n")

    for i, (agent_id, agent_type, tool, target, params, desc) in enumerate(scenarios, 1):
        terminal_ui.rich_print(f"[bold][white]Case 1.{i}: {desc}[/white][/bold]")
        terminal_ui.rich_print(f"👤 Agent: [magenta]{agent_id}[/] ([white]{agent_type}[/]) | ⚙️ Action: [cyan]{tool}[/] ➔ [gray]{target}[/]")
        
        # Intercept action
        approved, entry = interceptor.intercept_action(agent_id, agent_type, tool, target, params)
        
        # Print result card
        symbol = "✅ APPROVED" if approved else "🚫 BLOCKED"
        style = "green" if approved else "red"
        
        box = terminal_ui.Box(width=75, style=style)
        box.add_line(f"🛡️  VERDICT: [{style}][bold]{symbol}[/bold][/{style}]")
        box.add_line(f"📝 Reasoning: [gray]{entry['reasoning']}[/gray]")
        box.add_line(f"⏱️  Trace:     [faint]{' ➔ '.join(entry['investigation_trace'])}[/faint]")
        box.print()
        print()
        time.sleep(0.3)

    # Show summary
    summary_box = terminal_ui.Box(title="📊 POLICY SWEEP SUMMARY", width=75, style="cyan")
    summary_box.add_line(f" • Total Checked   : [cyan]{interceptor.stats['total_intercepted']}[/cyan]")
    summary_box.add_line(f" • Auto-Approved   : [green]{interceptor.stats['auto_approved']}[/green]")
    summary_box.add_line(f" • Auto-Blocked    : [red]{interceptor.stats['auto_blocked']}[/red]")
    summary_box.add_line(f" • Escalated to AI : [yellow]{interceptor.stats['ai_evaluated']}[/yellow] (Verify: should be 0)")
    summary_box.print()
    print()

if __name__ == "__main__":
    main()
