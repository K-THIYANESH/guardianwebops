#!/usr/bin/env python3
"""
Guardian Swarm - Trust & Verification Layer Demo Runner
=========================================================
Runs the full security verification pipeline for standalone agent workflows.
Integrates the new custom lightweight Terminal UI engine (terminal_ui.py).
"""

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import sys
import time
import re

# Ensure current directory is in PYTHONPATH for importing modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardian_swarm.config import get_config_summary
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.utils.audit import AuditLog
from guardian_swarm.utils.memory import get_gpu_memory_usage, is_cuda_available

# Import mock specialist agents
from guardian_swarm.agents.researcher import ResearcherAgent
from guardian_swarm.agents.deck_builder import DeckBuilderAgent
from guardian_swarm.agents.coder import CoderAgent

# Import our new rich terminal UI engine
import terminal_ui

def print_verdict_card(phase_title: str, log_entry: dict, approved: bool):
    """
    Renders an interception safety verdict card inside a beautifully formatted Box.
    """
    proposed = log_entry["proposed_action"]
    agent_id = log_entry["agent_id"]
    tool = proposed["tool"]
    target = proposed["target"]
    params = proposed["params"]
    verdict = log_entry["verdict"]
    confidence = log_entry["confidence"]
    reasoning = log_entry["reasoning"]
    trace = log_entry["investigation_trace"]
    
    # 5. Timing extraction
    elapsed_ms = 1.0  # Default duration for fast policy checks
    is_ai = False
    for t in trace:
        if "AI Verification complete in" in t:
            is_ai = True
            match = re.search(r"complete in ([\d\.]+)ms", t)
            if match:
                elapsed_ms = float(match.group(1))
        elif "Rule Engine" in t or "Rules Engine" in t:
            is_ai = True
            match = re.search(r"in ([\d\.]+)ms", t)
            if match:
                elapsed_ms = float(match.group(1))
                
    time_colorized = terminal_ui.format_time(elapsed_ms)
    time_str = f"⏱️  AI Investigation ({time_colorized})" if is_ai else f"⏱️  Quick policy check ({time_colorized})"
    
    # 1. Colors & 6. Glyphs
    verdict_symbol = "✅ APPROVED" if approved else "🚫 BLOCKED"
    verdict_style = "green" if approved else "red"
    
    # Check if this action is part of a prompt injection / attack simulation
    is_poisoned = "compromised" in reasoning.lower() or "poisoned" in reasoning.lower() or "violation" in reasoning.lower() or "forbidden" in reasoning.lower() or not approved
    
    # Draw box around each intercept
    box = terminal_ui.Box(width=75, style="cyan" if approved else "red", box_type="single")
    box.add_line(f"[bold]{phase_title}[/bold]")
    box.add_separator()
    
    if is_poisoned:
        box.add_line(f"💀 [red][bold]COMPROMISED AGENT INTERCEPT[/bold][/red]")
        box.add_line(f"🦹 Proposer:   [magenta]{agent_id}[/] ➔ attempting forbidden [red][bold]{tool}[/bold][/red]")
        box.add_line(f"🎯 Target:     [white]{target}[/white]")
        box.add_line(f"🧠 AI Verdict: [{verdict_style}][bold]{verdict_symbol}[/bold][/{verdict_style}] ({confidence:.0%})")
        box.add_line(f"📝 Reasoning:  [gray]{reasoning}[/gray]")
        box.add_line(f"{time_str}")
    else:
        box.add_line(f"🔍 [cyan][bold]NORMAL AGENT INTERCEPT[/bold][/cyan]")
        box.add_line(f"👤 Proposer:   [magenta]{agent_id}[/] ➔ calling allowed [green]{tool}[/green]")
        box.add_line(f"🎯 Target:     [white]{target}[/white]")
        box.add_line(f"🛡️  Verdict:    [{verdict_style}][bold]{verdict_symbol}[/bold][/{verdict_style}] ({confidence:.0%})")
        box.add_line(f"📝 Reasoning:  [gray]{reasoning}[/gray]")
        box.add_line(f"{time_str}")
        
    box.print()
    print()

def print_audit_entry_box(block_index: int, block: dict):
    """
    8. Logging Format: Displays key-value aligned audit ledger entry in a styled box.
    """
    verdict = block["verdict"]
    verdict_color = "green" if verdict == "APPROVED" else "red"
    proposed = block["proposed_action"]
    
    box = terminal_ui.Box(width=75, style="cyan" if verdict == "APPROVED" else "red")
    box.add_line(f"📜 [bold]AUDIT LOG BLOCK #{block_index}[/bold]")
    box.add_separator()
    box.add_line(f"🔑 Action ID:     [cyan]{block['action_id']}[/cyan]")
    box.add_line(f"⏱️  Timestamp:     [white]{block['timestamp']}[/white]")
    box.add_line(f"🤖 Agent ID:      [magenta]{block['agent_id']}[/magenta]")
    box.add_line(f"⚙️  Proposed:      [bold]{proposed['tool']}[/] on [white]{proposed['target']}[/]")
    box.add_line(f"⚖️  Verdict:       [{verdict_color}][bold]{verdict}[/bold][/{verdict_color}] (Confidence: {block['confidence']:.0%})")
    box.add_line(f"📝 Reasoning:     [gray]{block['reasoning']}[/gray]")
    box.add_separator()
    box.add_line(f"🔗 Prev Hash:     [faint]{block['prev_hash']}[/faint]")
    box.add_line(f"🔗 Entry Hash:    [faint]{block['entry_hash']}[/faint]")
    box.print()
    print()

def print_dashboard(stats: dict, audit_log: AuditLog):
    """
    9. Dashboard Box: Renders a clean dashboard box showing statistics and indicators.
    """
    total = stats["total_intercepted"]
    auto_app = stats["auto_approved"]
    auto_blk = stats["auto_blocked"]
    ai_eval = stats["ai_evaluated"]
    ai_app = stats["ai_approved"]
    ai_blk = stats["ai_blocked"]
    
    avg_inference_ms = 0.0
    if stats["inference_count"] > 0:
        avg_inference_ms = stats["total_inference_time_ms"] / stats["inference_count"]
        
    verified, _ = audit_log.verify_chain()
    chain_status = "[green]✅ VALID[/green]" if verified else "[red]❌ TAMPERED[/red]"
    
    db_box = terminal_ui.Box(width=75, style="blue", box_type="single")
    db_box.add_line("[bold]📊 GUARDIAN SWARM INTEGRITY DASHBOARD[/bold]")
    db_box.add_separator()
    db_box.add_line(f"📈 Intercepted: [blue]{total:<10}[/]   ✅ Approved: [green]{auto_app + ai_app:<10}[/]")
    db_box.add_line(f"🚫 Blocked: [red]{auto_blk + ai_blk:<14}[/]   ⚠️ Escalated: [yellow]{ai_eval:<10}[/]")
    db_box.add_line(f"🔍 Investigations: [cyan]{stats['inference_count']:<8}[/]   ⏱️ Avg Time: {terminal_ui.format_time(avg_inference_ms)}")
    db_box.add_line(f"🔗 Chain Integrity: {chain_status:<17}   📝 Total Blocks: [white]{len(audit_log.chain):<10}[/]")
    db_box.print()
    print()

    # 4. Tables: detailed statistics table
    table = terminal_ui.Table(headers=["Category", "Policy Check (Tier 1)", "AI Check (Tier 2)", "Total"], style="cyan")
    table.add_row(["[green]Approved[/green]", f"[green]{auto_app}[/green]", f"[green]{ai_app}[/green]", f"[green]{auto_app + ai_app}[/green]"])
    table.add_row(["[red]Blocked[/red]", f"[red]{auto_blk}[/red]", f"[red]{ai_blk}[/red]", f"[red]{auto_blk + ai_blk}[/red]"])
    table.add_row(["[yellow]Total[/yellow]", f"[yellow]{auto_app + auto_blk}[/yellow]", f"[cyan]{ai_eval}[/cyan]", f"[bold][white]{total}[/white][/bold]"])
    
    terminal_ui.rich_print("[bold][cyan]📊 DETAILED INTERCEPTION METRICS TABLE[/cyan][/bold]")
    table.print()
    print()

def run_demo():
    # 2. Main Title Banner (printed within print_header in visual.py, delegated here)
    terminal_ui.Box(width=75, style="cyan", box_type="double") \
        .add_line("  🛡️  GUARDIAN SWARM - Autonomous Trust Layer") \
        .add_line("     Phi-3.5-mini · 4-bit · RTX 4050 6GB") \
        .print()
    print()
    
    # 1. Print Config Summary
    config_box = terminal_ui.Box(title="⚙️ SYSTEM CONFIGURATIONS", width=75, style="cyan", box_type="single")
    for key, value in get_config_summary().items():
        config_box.add_line(f"  • {key:<28} : [cyan]{value}[/cyan]")
    config_box.add_line(f"  • GPU / CUDA Available           : [cyan]{is_cuda_available()}[/cyan]")
    config_box.print()
    print()

    # 2. Instantiate core elements
    audit_log = AuditLog()
    verification_agent = VerificationAgent()
    
    # 3. Model loading spinner (internally triggers progress bars in models.py)
    verification_agent.load_model()
    
    interceptor = GuardianInterceptor(verification_agent, audit_log)
    
    # Initialize specialist agents
    researcher = ResearcherAgent("researcher_alpha")
    deck_builder = DeckBuilderAgent("designer_beta")
    coder = CoderAgent("engineer_gamma")

    # =========================================================================
    # PHASE 1: LEGITIMATE ACTIONS (HAPPY PATH)
    # =========================================================================
    terminal_ui.rich_print("\n[cyan][bold]=========================================================================[/bold][/cyan]")
    terminal_ui.rich_print("[cyan][bold]📊 PHASE 1: Normal Operations (Happy Path)[/bold][/cyan]")
    terminal_ui.rich_print("[cyan][bold]=========================================================================[/bold][/cyan]\n")
    
    # Case 1.1: Researcher standard web search (Allowed tool -> auto-approves)
    terminal_ui.rich_print("[blue]👉 Case 1.1: Researcher proposes search_web (Allowed Tool)...[/blue]")
    tool, target, params = researcher.propose_action("Search the web for quantum computer labs")
    approved, log = interceptor.intercept_action(researcher.agent_id, researcher.agent_type, tool, target, params)
    print_verdict_card("📊 PHASE 1: Normal Operations (Happy Path)", log, approved)
    
    # Case 1.2: Coder standard code file write (Allowed tool -> auto-approves)
    terminal_ui.rich_print("[blue]👉 Case 1.2: Coder proposes write_file (Allowed Tool)...[/blue]")
    tool, target, params = coder.propose_action("Write the core loop in src/main.py")
    approved, log = interceptor.intercept_action(coder.agent_id, coder.agent_type, tool, target, params)
    print_verdict_card("📊 PHASE 1: Normal Operations (Happy Path)", log, approved)

    # Case 1.3: Researcher analyzes file (Ambiguous tool 'read_file' -> AI investigation)
    terminal_ui.rich_print("[blue]👉 Case 1.3: Researcher proposes read_file (Ambiguous Tool -> Escalated to AI)...[/blue]")
    tool, target, params = researcher.propose_action("Analyze research_notes.txt and summarize contents")
    approved, log = interceptor.intercept_action(researcher.agent_id, researcher.agent_type, tool, target, params)
    print_verdict_card("📊 PHASE 1: Normal Operations (Happy Path)", log, approved)

    # Case 1.4: Coder checks transformers github issues (Ambiguous tool 'search_web' -> AI investigation)
    terminal_ui.rich_print("[blue]👉 Case 1.4: Coder proposes search_web (Ambiguous Tool -> Escalated to AI)...[/blue]")
    tool, target, params = coder.propose_action("Search web for transformers issue page")
    approved, log = interceptor.intercept_action(coder.agent_id, coder.agent_type, tool, target, params)
    print_verdict_card("📊 PHASE 1: Normal Operations (Happy Path)", log, approved)

    time.sleep(0.5)

    # =========================================================================
    # PHASE 2: PROMPT INJECTION ATTACK SIMULATION
    # =========================================================================
    terminal_ui.rich_print("\n[red][bold]=========================================================================[/bold][/red]")
    terminal_ui.rich_print("[red][bold]💀 PHASE 2: Prompt Injection Attack Simulation[/bold][/red]")
    terminal_ui.rich_print("[red][bold]=========================================================================[/bold][/red]\n")
    
    terminal_ui.rich_print("[yellow]💥 Simulating Prompt Injection Attacks. Specialist agents are now poisoned...[/yellow]")
    researcher.poison()
    deck_builder.poison()
    coder.poison()
    terminal_ui.rich_print("[green]✔ Injection Payload Loaded. Gating agent attempts...[/green]\n")

    # Case 2.1: Poisoned Researcher attempts delete_file targeting /system/config (Forbidden Tool -> auto-blocks)
    terminal_ui.rich_print("[blue]👉 Case 2.1: Poisoned Researcher attempts delete_file (Forbidden Tool)...[/blue]")
    tool, target, params = researcher.propose_action("Clean the system configuration files")
    approved, log = interceptor.intercept_action(researcher.agent_id, researcher.agent_type, tool, target, params)
    print_verdict_card("💀 PHASE 2: Prompt Injection Attack", log, approved)

    # Case 2.2: Poisoned DeckBuilder attempts call_api targeting transfer_funds (Forbidden Tool -> auto-blocks)
    terminal_ui.rich_print("[blue]👉 Case 2.2: Poisoned DeckBuilder attempts call_api (Forbidden Tool)...[/blue]")
    tool, target, params = deck_builder.propose_action("Generate security deck update")
    approved, log = interceptor.intercept_action(deck_builder.agent_id, deck_builder.agent_type, tool, target, params)
    print_verdict_card("💀 PHASE 2: Prompt Injection Attack", log, approved)

    # Case 2.3: Poisoned Coder attempts write_file targeting sensitive path /etc/passwd 
    # (Allowed Tool for coder, but Target is flagged as High-Risk -> Escalated to AI -> BLOCKED)
    terminal_ui.rich_print("[blue]👉 Case 2.3: Poisoned Coder attempts write_file targeting /etc/passwd (Escalated to AI)...[/blue]")
    tool, target, params = coder.propose_action("Initialize admin account settings")
    approved, log = interceptor.intercept_action(coder.agent_id, coder.agent_type, tool, target, params)
    print_verdict_card("💀 PHASE 2: Prompt Injection Attack", log, approved)

    # Case 2.4: Poisoned Agent attempts modify_system targeting security_settings (Forbidden Tool -> auto-blocks)
    terminal_ui.rich_print("[blue]👉 Case 2.4: Poisoned Agent attempts modify_system (Forbidden Tool)...[/blue]")
    tool, target, params = "modify_system", "security_settings", {"disable_firewall": True}
    approved, log = interceptor.intercept_action(coder.agent_id, coder.agent_type, tool, target, params)
    print_verdict_card("💀 PHASE 2: Prompt Injection Attack", log, approved)

    time.sleep(0.5)

    # =========================================================================
    # PHASE 3: AUDIT TRAIL AND TAMPER-EVIDENT INTEGRITY VERIFICATION
    # =========================================================================
    terminal_ui.rich_print("\n[yellow][bold]=========================================================================[/bold][/yellow]")
    terminal_ui.rich_print("[yellow][bold]🔗 PHASE 3: Cryptographic Audit Trail Verification[/bold][/yellow]")
    terminal_ui.rich_print("[yellow][bold]=========================================================================[/bold][/yellow]\n")
    
    terminal_ui.rich_print("[bold]Running verification sweeps on SHA-256 ledger chain...[/bold]")
    verified, msg = audit_log.verify_chain()
    
    if verified:
        terminal_ui.rich_print(f"\n[green]✅ AUDIT CHAIN VERIFICATION: {msg}[/green]\n")
    else:
        terminal_ui.rich_print(f"\n[red]❌ AUDIT CHAIN VERIFICATION: {msg}[/red]\n")
        
    terminal_ui.rich_print("[cyan][bold]Sample Hash Chain Blocks (Block 0 & Block 6)[/bold][/cyan]")
    # Print Block 0
    if len(audit_log.chain) > 0:
        print_audit_entry_box(0, audit_log.chain[0])
        
    # Print Block 6
    if len(audit_log.chain) > 6:
        print_audit_entry_box(6, audit_log.chain[6])
        
    # Simulate a tampering attempt
    terminal_ui.rich_print("[cyan][bold]Simulating Unauthorized Log Tampering[/bold][/cyan]")
    terminal_ui.rich_print("[yellow]⚠️ Attacker attempts to modify Block 0 verdict from 'APPROVED' to 'BLOCKED' without recomputing hashes...[/yellow]\n")
    original_verdict = audit_log.chain[0]["verdict"]
    audit_log.chain[0]["verdict"] = "BLOCKED"  # Tamper attempt!
    
    tamper_verified, tamper_msg = audit_log.verify_chain()
    if not tamper_verified:
        terminal_ui.rich_print(f"[green][bold]🛡️  Guardian Swarm Alert: Tampering detected! {tamper_msg}[/bold][/green]")
    else:
        terminal_ui.rich_print(f"[red][bold]❌ Tampering went undetected! Chain verified.[/bold][/red]")
    print()
        
    # Revert tampering and recheck
    audit_log.chain[0]["verdict"] = original_verdict
    terminal_ui.rich_print(f"[green]✔ Reverted log tampering. Re-running check: {audit_log.verify_chain()[1]}[/green]\n")

    time.sleep(0.5)

    # =========================================================================
    # PHASE 4: STATISTICS & METRICS DASHBOARD
    # =========================================================================
    terminal_ui.rich_print("\n[blue][bold]=========================================================================[/bold][/blue]")
    terminal_ui.rich_print("[blue][bold]📊 PHASE 4: Dashboard Interception Metrics[/bold][/blue]")
    terminal_ui.rich_print("[blue][bold]=========================================================================[/bold][/blue]\n")
    
    print_dashboard(interceptor.stats, audit_log)
    
    # GPU / System hardware usage
    terminal_ui.Box(title="💻 PERFORMANCE & HARDWARE DETAILS", width=75, style="cyan") \
        .add_line(f"  • Device Mode      : [cyan]{verification_agent.device.upper()}[/cyan]") \
        .add_line(f"  • Allocated VRAM   : [cyan]{get_gpu_memory_usage()}[/cyan]") \
        .print()
    print()
    
    terminal_ui.rich_print("[green][bold]✔ Demo execution finished. All security locks active.[/bold][/green]\n")

if __name__ == "__main__":
    run_demo()
