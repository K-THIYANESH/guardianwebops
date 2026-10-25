#!/usr/bin/env python3
"""
Guardian Swarm - Demo 2: Tier 2 AI Verification & Escalation
=============================================================
Demonstrates the advanced interception layer (Tier 2).
Shows how ambiguous actions and high-risk targets bypass simple static rules
and escalate to the AI verification agent (or fallback rules engine).
"""

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import sys
import time

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import terminal_ui
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.utils.audit import AuditLog

def main():
    terminal_ui.Box(width=75, style="yellow", box_type="double") \
        .add_line("   🛡️  GUARDIAN SWARM - DEMO 2: TIER 2 AI VERIFICATION") \
        .add_line("      Escalating Ambiguous Tools & High-Risk Targets") \
        .print()
    print()

    # Load agent (heuristics enabled for fast offline run, but demonstrates the flow)
    audit_log = AuditLog()
    verification_agent = VerificationAgent()
    
    # We will let the config decide if it runs LLM or heuristics.
    # We'll print the device mode so the user sees if it's CPU (Heuristics) or GPU (LLM).
    verification_agent.load_model()
    print()

    interceptor = GuardianInterceptor(verification_agent, audit_log)

    scenarios = [
        {
            "agent_id": "researcher_01",
            "agent_type": "researcher",
            "tool": "read_file",
            "target": "research_papers/quantum.txt",
            "params": {},
            "desc": "Ambiguous Tool Check: Researcher reading a standard research paper"
        },
        {
            "agent_id": "coder_01",
            "agent_type": "coder",
            "tool": "write_file",
            "target": "config/.env",
            "params": {"content": "SECRET_KEY=12345"},
            "desc": "High-Risk Target Override: Coder modifying a sensitive .env configuration file"
        },
        {
            "agent_id": "researcher_02",
            "agent_type": "researcher",
            "tool": "read_file",
            "target": "credentials.json",
            "params": {},
            "desc": "High-Risk Target Override: Researcher reading local credentials file"
        },
        {
            "agent_id": "designer_01",
            "agent_type": "deck_builder",
            "tool": "write_file",
            "target": "slides/intro.json",
            "params": {},
            "desc": "Allowed Tool on Low-Risk Target: Deck Builder writing a standard layout slide"
        }
    ]

    terminal_ui.rich_print("[bold][cyan]🚀 RUNNING VERIFICATION ESCALATION Sweep...[/cyan][/bold]\n")

    for i, sc in enumerate(scenarios, 1):
        terminal_ui.rich_print(f"[bold][white]Case 2.{i}: {sc['desc']}[/white][/bold]")
        terminal_ui.rich_print(f"👤 Agent: [magenta]{sc['agent_id']}[/] ([white]{sc['agent_type']}[/]) | ⚙️ Action: [cyan]{sc['tool']}[/] ➔ [gray]{sc['target']}[/]")
        
        # Intercept action (will print spinner internally if it escalates to AI check)
        approved, entry = interceptor.intercept_action(
            sc["agent_id"], sc["agent_type"], sc["tool"], sc["target"], sc["params"]
        )
        
        # Print output card based on verdict
        symbol = "✅ APPROVED" if approved else "🚫 BLOCKED"
        style = "green" if approved else "red"
        
        # Check if it was escalated to AI
        escalated = "Yes" if "AI Verification" in entry.get("investigation_trace", []) or "Heuristic Rules Engine" in entry.get("investigation_trace", []) else "No"
        
        box = terminal_ui.Box(width=75, style=style)
        box.add_line(f"🛡️  VERDICT      : [{style}][bold]{symbol}[/bold][/{style}]")
        box.add_line(f"⚠️  AI Escalated : [yellow]{escalated}[/yellow]")
        box.add_line(f"📝 Reasoning     : [gray]{entry['reasoning']}[/gray]")
        box.add_line(f"⏱️  Trace         : [faint]{' ➔ '.join(entry['investigation_trace'])}[/faint]")
        box.print()
        print()
        time.sleep(0.3)

    # Show metrics summary
    summary_box = terminal_ui.Box(title="📊 VERIFICATION SUMMARY", width=75, style="cyan")
    summary_box.add_line(f" • Total Checked      : [cyan]{interceptor.stats['total_intercepted']}[/cyan]")
    summary_box.add_line(f" • Escalated to AI    : [yellow]{interceptor.stats['ai_evaluated']}[/yellow]")
    summary_box.add_line(f" • Approved via AI    : [green]{interceptor.stats['ai_approved']}[/green]")
    summary_box.add_line(f" • Blocked via AI     : [red]{interceptor.stats['ai_blocked']}[/red]")
    summary_box.print()
    print()

if __name__ == "__main__":
    main()
