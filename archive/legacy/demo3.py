#!/usr/bin/env python3
"""
Guardian Swarm - Demo 3: Cryptographic Audit Ledger
====================================================
Demonstrates the secure SHA-256 hash-chained audit logging system.
Shows how logs are linked sequentially, how integrity sweeps are run,
and how unauthorized data modifications are detected.
"""

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import sys
import time

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import terminal_ui
from guardian_swarm.utils.audit import AuditLog

def print_block_details(block_index: int, block: dict):
    """Formats and prints details of an audit block inside a nice console box."""
    box = terminal_ui.Box(title=f"📜 AUDIT LEDGER BLOCK #{block_index}", width=75, style="cyan")
    box.add_line(f" 🔑 Action ID   : [white]{block['action_id']}[/white]")
    box.add_line(f" 🤖 Agent ID    : [magenta]{block['agent_id']}[/magenta]")
    box.add_line(f" ⚙️  Proposed    : [cyan]{block['proposed_action']['tool']}[/cyan] ➔ [gray]{block['proposed_action']['target']}[/gray]")
    box.add_line(f" ⚖️  Verdict     : [bold][green]{block['verdict']}[/green][/bold] (Confidence: [dim]{block['confidence']}%[/dim])")
    box.add_line(f" 🔗 Prev Hash   : [faint]{block['prev_hash']}[/faint]")
    box.add_line(f" 🔗 Block Hash  : [bold][yellow]{block['entry_hash']}[/yellow][/bold]")
    box.print()
    print()

def main():
    terminal_ui.Box(width=75, style="cyan", box_type="double") \
        .add_line("   🛡️  GUARDIAN SWARM - DEMO 3: CRYPTOGRAPHIC AUDIT LEDGER") \
        .add_line("      SHA-256 Ledger Chaining & Tamper Detection") \
        .print()
    print()

    # Initialize empty audit log
    audit_log = AuditLog()

    # Log 3 distinct activities to populate the chain
    actions = [
        ("researcher_alpha", "researcher", "search_web", "quantum computing research", "APPROVED", 100, "Policy match: Allowed tool", ["Tier 1 Check", "Approved"]),
        ("coder_beta", "coder", "write_file", "src/parser.py", "APPROVED", 100, "Policy match: Allowed tool", ["Tier 1 Check", "Approved"]),
        ("engineer_gamma", "coder", "read_file", ".env", "BLOCKED", 99, "AI Overrule: High-risk target override", ["Tier 1 Check", "AI Escalated", "Blocked"]),
    ]

    terminal_ui.rich_print("[bold][cyan]🚀 POPULATING CRYPTOGRAPHIC LEDGER CHAIN...[/cyan][/bold]")
    
    for agent_id, agent_type, tool, target, verdict, conf, reason, trace in actions:
        time.sleep(0.1)
        audit_log.create_entry(
            agent_id=agent_id,
            tool=tool,
            target=target,
            params={},
            verdict=verdict,
            confidence=conf,
            reasoning=reason,
            trace=trace
        )
        terminal_ui.rich_print(f"  ✔ Sequenced action by [magenta]{agent_id}[/] (Hash: [yellow]{audit_log.chain[-1]['entry_hash'][:12]}...[/])")
    print()

    # Print the current chain length and block details
    terminal_ui.rich_print(f"[bold][white]Ledger Chain size: {len(audit_log.chain)} blocks.[/white][/bold]\n")
    for i, block in enumerate(audit_log.chain):
        print_block_details(i, block)

    # Step 1: Verify valid chain
    terminal_ui.rich_print("[bold][cyan]🔍 RUNNING SYSTEM INTEGRITY SWEEP...[/cyan][/bold]")
    is_valid, error_msg = audit_log.verify_chain()
    
    if is_valid:
        terminal_ui.rich_print("  [green][bold]✅ LEDGER SECURE: Chain verified successfully. Integrity intact.[/green][/bold]\n")
    else:
        terminal_ui.rich_print(f"  [red][bold]❌ LEDGER CRITICAL: {error_msg}[/red][/bold]\n")

    # Step 2: Simulating unauthorized database injection / tampering
    terminal_ui.rich_print("[bold][red]⚠️  SIMULATING EXTERNAL INTRUSION: TAMPERING WITH LEDGER...[/red][/bold]")
    terminal_ui.rich_print("  [white]An attacker gains access and alters Block #1 verdict from [bold][green]APPROVED[/bold][/green] to [bold][red]BLOCKED[/red][/bold]...[/white]")
    
    # Store backup for revert
    original_verdict = audit_log.chain[1]["verdict"]
    # Tamper!
    audit_log.chain[1]["verdict"] = "BLOCKED"
    terminal_ui.rich_print("  [yellow]Tamper complete. Re-evaluating chain hashes...[/yellow]\n")

    # Step 3: Verify tampered chain
    terminal_ui.rich_print("[bold][cyan]🔍 RUNNING POST-TAMPER INTEGRITY SWEEP...[/cyan][/bold]")
    is_valid, error_msg = audit_log.verify_chain()
    
    if is_valid:
        terminal_ui.rich_print("  [green][bold]✅ LEDGER SECURE: Chain verified successfully.[/green][/bold]\n")
    else:
        box = terminal_ui.Box(title="🛡️  INTRUSION ALERT: TAMPERING DETECTED", width=75, style="red")
        box.add_line(f" [bold][red]SYSTEM ALERT: LOG TAMPER DETECTED[/bold][/red]")
        box.add_line(f" Reason: {error_msg}")
        box.add_line(" Impact: Logging audit chain compromised. Halting operations.")
        box.print()
        print()

    # Step 4: Revert and repair
    terminal_ui.rich_print("[bold][green]🔄 RESTORING DATA INTEGRITY...[/green][/bold]")
    audit_log.chain[1]["verdict"] = original_verdict
    terminal_ui.rich_print("  [white]Reverted log values to match hash checksums.[/white]")
    
    # Verify repaired chain
    is_valid, error_msg = audit_log.verify_chain()
    if is_valid:
        terminal_ui.rich_print("  [green][bold]✅ LEDGER SECURE: Chain integrity restored and verified.[/green][/bold]\n")

if __name__ == "__main__":
    main()
