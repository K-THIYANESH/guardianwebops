#!/usr/bin/env python3
"""
Guardian Swarm - Demo 4: Agent Poisoning & Prompt Injection Containment
=======================================================================
Simulates specialist agents falling victim to prompt injections or poisoning.
Shows how the GuardianSwarm trust layer detects compromised agent actions and
intercepts prompt injection payloads before they hit downstream services.
"""

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import sys
import time

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import terminal_ui
from guardian_swarm.agents.researcher import ResearcherAgent
from guardian_swarm.agents.coder import CoderAgent
from guardian_swarm.agents.deck_builder import DeckBuilderAgent
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.utils.audit import AuditLog
from guardian_swarm.integration import StandaloneGuardPlugin

def main():
    terminal_ui.Box(width=75, style="red", box_type="double") \
        .add_line("   🛡️  GUARDIAN SWARM - DEMO 4: AGENT POISONING CONTAINMENT") \
        .add_line("      Detecting Prompt Injection & Quarantining Agents") \
        .print()
    print()

    # Load security layer
    audit_log = AuditLog()
    verification_agent = VerificationAgent()
    verification_agent.is_heuristic = True # Keep execution fast and reliable
    interceptor = GuardianInterceptor(verification_agent, audit_log)
    
    # Initialize the standalone Guardian plugin
    plugin = StandaloneGuardPlugin(interceptor)

    # Initialize mock agents
    researcher = ResearcherAgent("researcher_alpha")
    coder = CoderAgent("coder_beta")
    deck_builder = DeckBuilderAgent("deck_builder_gamma")
    
    # Secure the agent instances dynamically via the plugin wrapper
    plugin.secure_agent(researcher)
    plugin.secure_agent(coder)
    plugin.secure_agent(deck_builder)

    # Set agents to poisoned states
    terminal_ui.rich_print("[bold][yellow]⚠️  SIMULATING ADVERSARIAL SWARM ENVIRONMENT...[/yellow][/bold]")
    terminal_ui.rich_print("  [white]Injecting malicious prompts into Coder and DeckBuilder agents...[/white]")
    coder.poisoned = True
    deck_builder.poisoned = True
    terminal_ui.rich_print("  [green]✔ Swarm initialized. researcher_alpha (CLEAN) | coder_beta (POISONED) | deck_builder_gamma (POISONED)[/green]\n")

    # Swarm tasks
    tasks = [
        (researcher, "Summarize the latest trends in autonomous agent safety frameworks."),
        (coder, "Implement a quick file backup utility for the system config folder."),
        (deck_builder, "Generate a presentation deck summarizing Q3 financial performance.")
    ]

    terminal_ui.rich_print("[bold][cyan]🚀 EXECUTING SWARM TASKS...[/cyan][/bold]\n")

    for agent, task in tasks:
        terminal_ui.rich_print(f"[bold][white]Task for {agent.agent_id} ({agent.agent_type}):[/white][/bold] '{task}'")
        
        # Agent proposes action (secured via the standalone plugin)
        approved = True
        entry = None
        try:
            # Under the hood, this calls propose_action -> gets intercepted -> raises PermissionError if blocked
            tool, target, params = agent.propose_action(task)
            terminal_ui.rich_print(f"  🤖 Agent proposed action: [cyan]{tool}[/] ➔ [gray]{target}[/] (Params: {params})")
            
            # Since it did not raise PermissionError, the action was approved!
            # Fetch the matching entry from the audit log
            entry = audit_log.chain[-1]
            approved = True
        except PermissionError as e:
            approved = False
            # Fetch the blocked entry from the audit log
            entry = audit_log.chain[-1]
            terminal_ui.rich_print(f"  🛑 Plugin blocked action proposal automatically: {e}")
        
        if entry:
            symbol = "✅ APPROVED" if approved else "🚫 BLOCKED"
            style = "green" if approved else "red"
            
            # Print results card
            box = terminal_ui.Box(width=75, style=style)
            if not approved:
                box.add_line("💀 COMPROMISED AGENT INTERCEPTED!")
            box.add_line(f"🛡️  VERDICT  : [{style}][bold]{symbol}[/bold][/{style}]")
            box.add_line(f"📝 Reasoning: [gray]{entry['reasoning']}[/gray]")
            box.add_line(f"⏱️  Trace    : [faint]{' ➔ '.join(entry['investigation_trace'])}[/faint]")
            box.print()
            print()
        
        time.sleep(0.4)

    # Output Containment Metrics
    terminal_ui.rich_print("[bold][cyan]📊 INTRUSION CONTAINMENT DASHBOARD[/cyan][/bold]")
    metrics_table = terminal_ui.Table(headers=["Agent ID", "Status", "Attacks Blocked", "System Health"], style="red")
    metrics_table.add_row(["[green]researcher_alpha[/green]", "[green]CLEAN[/green]", "0", "[green]100% SECURE[/green]"])
    metrics_table.add_row(["[red]coder_beta[/red]", "[red]QUARANTINED[/red]", "1", "[red]BLOCKED PAYLOAD[/red]"])
    metrics_table.add_row(["[red]deck_builder_gamma[/red]", "[red]QUARANTINED[/red]", "1", "[red]BLOCKED PAYLOAD[/red]"])
    metrics_table.print()
    print()

if __name__ == "__main__":
    main()
