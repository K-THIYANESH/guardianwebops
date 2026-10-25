#!/usr/bin/env python3
"""
Guardian Swarm - Demo 5: Interactive Security Shell
===================================================
An interactive CLI shell that lets users propose custom agent actions
(specifying agent roles, tools, and targets) to test the security
boundaries, rules, and AI checks in real-time.
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

def print_help():
    """Prints the help screen listing available commands."""
    box = terminal_ui.Box(title="❓ SHELL GUIDE & OPTIONS", width=75, style="cyan")
    box.add_line(" 📁 System Roles   : researcher, coder, deck_builder")
    box.add_line(" ⚙️  Common Tools   : search_web, write_file, read_file, delete_file, call_api, modify_system")
    box.add_line(" 🎯 Sensitive Targets : /etc/passwd, .env, credentials.json, database.db")
    box.add_line(" 🔍 Special Commands:")
    box.add_line("    • [cyan]help[/cyan]           - Show this guidance box")
    box.add_line("    • [cyan]ledger[/cyan]         - View current cryptographic audit trail chain")
    box.add_line("    • [cyan]verify[/cyan]         - Run cryptographical verification sweep on logs")
    box.add_line("    • [cyan]exit[/cyan]/[cyan]quit[/cyan]       - Exit interactive shell and view session report")
    box.print()
    print()

def main():
    terminal_ui.Box(width=75, style="cyan", box_type="double") \
        .add_line("   🛡️  GUARDIAN SWARM - DEMO 5: INTERACTIVE SECURITY SHELL") \
        .add_line("      Test trust boundaries in real-time with custom actions") \
        .print()
    print()

    # Load core engines
    audit_log = AuditLog()
    verification_agent = VerificationAgent()
    verification_agent.is_heuristic = True # Keep checks fast and interactive
    interceptor = GuardianInterceptor(verification_agent, audit_log)

    print_help()

    terminal_ui.rich_print("[bold][green]✔ Security Swarm Interceptor is active and scanning inputs.[/green][/bold]")
    terminal_ui.rich_print("[bold][dim]Type 'help' at any time for options, or 'exit' to quit.[/dim][/bold]\n")

    while True:
        try:
            # 1. Get Agent Type
            agent_type = input("🛡️ Guardian-Shell > Select Agent Role (researcher/coder/deck_builder): ").strip().lower()
            if not agent_type:
                continue
            
            if agent_type in ["exit", "quit"]:
                break
            if agent_type == "help":
                print_help()
                continue
            if agent_type == "ledger":
                if not audit_log.chain:
                    terminal_ui.rich_print("  [yellow]Audit ledger is currently empty. Run some actions first![/yellow]\n")
                    continue
                terminal_ui.rich_print(f"[bold][white]Audit Ledger Log ({len(audit_log.chain)} entries):[/white][/bold]")
                for idx, block in enumerate(audit_log.chain):
                    box = terminal_ui.Box(title=f"Block #{idx} (Hash: {block['entry_hash'][:8]}...)", width=75, style="cyan")
                    box.add_line(f" • Agent ID   : {block['agent_id']}")
                    box.add_line(f" • Proposed   : {block['proposed_action']['tool']} ➔ {block['proposed_action']['target']}")
                    box.add_line(f" • Verdict    : [green]{block['verdict']}[/green]")
                    box.print()
                print()
                continue
            if agent_type == "verify":
                terminal_ui.rich_print("[bold][cyan]🔍 Verifying cryptographic audit chain...[/cyan][/bold]")
                valid, msg = audit_log.verify_chain()
                if valid:
                    terminal_ui.rich_print("  [green]✅ Chain is intact. Integrity verified.[/green]\n")
                else:
                    terminal_ui.rich_print(f"  [red]❌ Tampering detected: {msg}[/red]\n")
                continue

            if agent_type not in ["researcher", "coder", "deck_builder"]:
                terminal_ui.rich_print("  [red]Invalid role. Please select researcher, coder, or deck_builder (or 'help').[/red]\n")
                continue

            # 2. Get Tool Name
            tool = input("🛡️ Guardian-Shell > Enter Tool Name (e.g. read_file, call_api): ").strip()
            if tool.lower() in ["exit", "quit"]:
                break
            if not tool:
                terminal_ui.rich_print("  [red]Tool name cannot be empty.[/red]\n")
                continue

            # 3. Get Target Name
            target = input("🛡️ Guardian-Shell > Enter Target (e.g. file path, website URL): ").strip()
            if target.lower() in ["exit", "quit"]:
                break
            if not target:
                terminal_ui.rich_print("  [red]Target cannot be empty.[/red]\n")
                continue

            print()
            terminal_ui.rich_print(f"📡 Proposing action: [magenta]{agent_type}[/] proposes [cyan]{tool}[/] on target [gray]{target}[/]")

            # Run Interception
            approved, entry = interceptor.intercept_action(
                agent_id=f"user_{agent_type}_agent",
                agent_type=agent_type,
                proposed_tool=tool,
                proposed_target=target,
                params={}
            )

            # Print Verdict Card
            symbol = "✅ APPROVED" if approved else "🚫 BLOCKED"
            style = "green" if approved else "red"
            
            box = terminal_ui.Box(width=75, style=style)
            box.add_line(f"🛡️  INTERCEPTION RESULT: [{style}][bold]{symbol}[/bold][/{style}]")
            box.add_line(f"📝 Reasoning     : [gray]{entry['reasoning']}[/gray]")
            box.add_line(f"⏱️  Audit Trace   : [faint]{' ➔ '.join(entry['investigation_trace'])}[/faint]")
            box.print()
            print()

        except (KeyboardInterrupt, EOFError):
            print()
            break

    # Final report
    terminal_ui.rich_print("\n[bold][cyan]📊 SESSION METRICS OVERVIEW[/cyan][/bold]")
    print_dashboard_summary(interceptor.stats, audit_log)
    terminal_ui.rich_print("[bold][green]✔ Security Shell terminated. Goodbye![/bold][/green]\n")

def print_dashboard_summary(stats, audit_log):
    """Prints a beautiful summary of the interactive session."""
    valid, _ = audit_log.verify_chain()
    status_str = "[green]VALID[/green]" if valid else "[red]COMPROMISED[/red]"
    
    box = terminal_ui.Box(title="📊 GUARDIAN SWARM SESSION SUMMARY", width=75, style="cyan")
    box.add_line(f" • Total Processed    : [cyan]{stats['total_intercepted']}[/cyan]")
    box.add_line(f" • Approved Actions   : [green]{stats['auto_approved'] + stats['ai_approved']}[/green]")
    box.add_line(f" • Blocked Actions    : [red]{stats['auto_blocked'] + stats['ai_blocked']}[/red]")
    box.add_line(f" • Ledger Integrity   : {status_str}")
    box.add_line(f" • Total Audit Blocks : [white]{len(audit_log.chain)}[/white]")
    box.print()
    print()

if __name__ == "__main__":
    main()
