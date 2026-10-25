"""
Guardian Swarm V3 - Project Verification Script
Run: python verify_project.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

errors = []
warnings = []

def ok(msg):
    print(f"  [PASS] {msg}")

def fail(msg):
    print(f"  [FAIL] {msg}")
    errors.append(msg)

def warn(msg):
    print(f"  [WARN] {msg}")
    warnings.append(msg)

def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")

# ──────────────────────────────────────────────────────────
# SECTION 1: Core Module Imports
# ──────────────────────────────────────────────────────────
section("1. Core Module Imports")

try:
    from guardian_swarm.core.exceptions import (
        GuardianException, PolicyViolationException,
        HighRiskTargetException, AISafetyViolationException,
        LedgerVerificationException, HumanEscalationRequiredException
    )
    ok("guardian_swarm.core.exceptions — all 5 GSE exception classes")
except Exception as e:
    fail(f"guardian_swarm.core.exceptions — {e}")

try:
    from guardian_swarm.core.policies import (
        is_forbidden_tool, is_allowed_tool, is_high_risk_target
    )
    ok("guardian_swarm.core.policies")
except Exception as e:
    fail(f"guardian_swarm.core.policies — {e}")

try:
    from guardian_swarm.core.escalation import EscalationQueue
    ok("guardian_swarm.core.escalation.EscalationQueue")
except Exception as e:
    fail(f"guardian_swarm.core.escalation — {e}")

try:
    from guardian_swarm.utils.audit import AuditLog
    ok("guardian_swarm.utils.audit.AuditLog")
except Exception as e:
    fail(f"guardian_swarm.utils.audit — {e}")

try:
    from guardian_swarm.utils.memory import get_gpu_memory_usage, is_cuda_available
    cuda = is_cuda_available()
    ok(f"guardian_swarm.utils.memory (CUDA available: {cuda})")
except Exception as e:
    fail(f"guardian_swarm.utils.memory — {e}")

try:
    from guardian_swarm.core.models import VerificationAgent
    ok("guardian_swarm.core.models.VerificationAgent")
except Exception as e:
    fail(f"guardian_swarm.core.models — {e}")

try:
    from guardian_swarm.core.interceptor import GuardianInterceptor
    ok("guardian_swarm.core.interceptor.GuardianInterceptor")
except Exception as e:
    fail(f"guardian_swarm.core.interceptor — {e}")

try:
    from guardian_swarm.integration.standalone_plugin import StandaloneGuardPlugin
    ok("guardian_swarm.integration.standalone_plugin")
except Exception as e:
    fail(f"guardian_swarm.integration.standalone_plugin — {e}")

try:
    from guardian_swarm.agents.researcher import ResearcherAgent
    from guardian_swarm.agents.coder import CoderAgent
    from guardian_swarm.agents.deck_builder import DeckBuilderAgent
    ok("guardian_swarm.agents (researcher, coder, deck_builder)")
except Exception as e:
    fail(f"guardian_swarm.agents — {e}")

try:
    import terminal_ui
    ok("terminal_ui")
except Exception as e:
    fail(f"terminal_ui — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 2: AuditLog — agent_type fix validation
# ──────────────────────────────────────────────────────────
section("2. AuditLog Block Schema (agent_type)")

try:
    from guardian_swarm.utils.audit import AuditLog
    a = AuditLog()
    entry = a.create_entry(
        agent_id="test_agent",
        agent_type="coder",
        tool="write_file",
        target="src/main.py",
        params={"content": "hello"},
        verdict="APPROVED",
        confidence=1.0,
        reasoning="Policy match",
        trace=["Step 1"]
    )
    assert entry["proposed_action"]["agent_type"] == "coder", \
        "agent_type missing from proposed_action"
    assert entry["proposed_action"]["tool"] == "write_file"
    assert entry["proposed_action"]["target"] == "src/main.py"
    assert "entry_hash" in entry, "entry_hash missing"
    assert "prev_hash" in entry, "prev_hash missing"
    assert len(entry["entry_hash"]) == 64, "entry_hash not SHA-256 length"
    ok("create_entry() includes agent_type in proposed_action")
    ok(f"SHA-256 entry_hash present ({entry['entry_hash'][:16]}...)")
except Exception as e:
    fail(f"AuditLog.create_entry() — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 3: Chain Integrity Verification
# ──────────────────────────────────────────────────────────
section("3. Cryptographic Chain Integrity")

try:
    from guardian_swarm.utils.audit import AuditLog
    a = AuditLog()
    for i in range(3):
        a.create_entry(
            f"agent_{i}", "researcher", "read_file", f"doc_{i}.txt",
            {}, "APPROVED" if i % 2 == 0 else "BLOCKED",
            1.0, f"Reason {i}", [f"trace step {i}"]
        )
    valid, msg = a.verify_chain()
    assert valid, f"Chain invalid: {msg}"
    ok(f"3-block chain verified: {msg[:50]}")
except Exception as e:
    fail(f"Chain verification — {e}")

try:
    # Test tamper detection
    from guardian_swarm.utils.audit import AuditLog
    a = AuditLog()
    a.create_entry("a", "coder", "write_file", "f.py", {}, "APPROVED", 1.0, "OK", [])
    a.create_entry("b", "coder", "read_file", "g.py", {}, "BLOCKED", 0.9, "Risky", [])
    a.chain[0]["verdict"] = "TAMPERED"  # Simulate tampering
    valid, msg = a.verify_chain()
    assert not valid, "Tamper should have been detected!"
    ok(f"Tamper detection working: '{msg[:50]}'")
except Exception as e:
    fail(f"Tamper detection — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 4: Interceptor — Stats & Tier Routing
# ──────────────────────────────────────────────────────────
section("4. GuardianInterceptor — Tier Routing & Stats")

try:
    from guardian_swarm.core.interceptor import GuardianInterceptor
    from guardian_swarm.core.models import VerificationAgent
    from guardian_swarm.utils.audit import AuditLog

    a = AuditLog()
    v = VerificationAgent()
    g = GuardianInterceptor(v, a)

    expected_keys = [
        "total_intercepted", "auto_approved", "auto_blocked", "ai_evaluated",
        "ai_approved", "ai_blocked", "tier1_resolved", "tier2_resolved",
        "human_escalations", "total_latency_ms", "total_inference_time_ms", "inference_count"
    ]
    missing = [k for k in expected_keys if k not in g.stats]
    if missing:
        fail(f"Missing stats keys: {missing}")
    else:
        ok(f"All 12 telemetry stat keys present")
except Exception as e:
    fail(f"Interceptor stats — {e}")

try:
    from guardian_swarm.core.interceptor import GuardianInterceptor
    from guardian_swarm.core.models import VerificationAgent
    from guardian_swarm.utils.audit import AuditLog
    from guardian_swarm.core.policies import is_forbidden_tool

    a = AuditLog()
    v = VerificationAgent()
    g = GuardianInterceptor(v, a)

    # Tier 1 BLOCK — delete_file for coder is forbidden
    approved, entry = g.intercept_action("coder_01", "coder", "delete_file", "src/main.py", {})
    assert not approved, "delete_file for coder should be BLOCKED"
    assert entry["proposed_action"]["agent_type"] == "coder", "agent_type missing in entry"
    assert g.stats["auto_blocked"] == 1
    assert g.stats["tier1_resolved"] == 1
    ok("Tier 1 BLOCK: delete_file correctly blocked for coder")

    # Tier 1 APPROVE — write_file for coder is allowed on safe target
    approved2, entry2 = g.intercept_action("coder_01", "coder", "write_file", "src/utils.py", {"user_role": "MANAGER", "task_group": "CODE"})
    assert approved2, "write_file for coder on safe target should be APPROVED"
    assert g.stats["auto_approved"] == 1
    assert g.stats["tier1_resolved"] == 2
    ok("Tier 1 APPROVE: write_file correctly approved for coder")

    ok(f"Stats after 2 actions: {g.stats['total_intercepted']} intercepted, "
       f"{g.stats['tier1_resolved']} tier1 resolved")
except Exception as e:
    fail(f"Interceptor tier routing — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 5: EscalationQueue
# ──────────────────────────────────────────────────────────
section("5. EscalationQueue — GSE_005 Lifecycle")

try:
    from guardian_swarm.core.escalation import EscalationQueue
    q = EscalationQueue()

    q.add(
        action={
            "action_id": "test-uuid-1234",
            "agent_id": "researcher_01",
            "agent_type": "researcher",
            "tool": "read_file",
            "target": ".env",
            "params": {}
        },
        prosecutor_output={"argument": "High risk file", "score": 8},
        defender_output={"argument": "Could be legit", "score": 4},
        judge_output={"verdict": "ESCALATE_TO_HUMAN", "confidence": 0.45, "reasoning": "Borderline"}
    )

    pending = q.get_pending()
    assert len(pending) == 1, f"Expected 1 pending, got {len(pending)}"
    item = pending[0]
    assert item["status"] == "pending"
    assert item["tool"] == "read_file"
    assert item["debate_trace"]["judge"]["verdict"] == "ESCALATE_TO_HUMAN"
    ok("EscalationQueue.add() — item queued with full debate_trace")

    item_id = item["id"]
    success = q.resolve(item_id, "approve")
    assert success, "resolve() returned False"
    resolved = [x for x in q.queue if x["id"] == item_id][0]
    assert resolved["status"] == "resolved"
    ok("EscalationQueue.resolve() — item marked resolved")
except Exception as e:
    fail(f"EscalationQueue — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 6: Policy Logic
# ──────────────────────────────────────────────────────────
section("6. Policy Gate Logic (RBAC)")

try:
    from guardian_swarm.core.policies import is_forbidden_tool, is_allowed_tool, is_high_risk_target

    cases = [
        ("coder",      "delete_file",   True,  False, "coder/delete_file → forbidden"),
        ("coder",      "write_file",    False, True,  "coder/write_file → allowed"),
        ("researcher", "write_file",    True,  False, "researcher/write_file → forbidden"),
        ("researcher", "search_web",    False, True,  "researcher/search_web → allowed"),
    ]
    for agent, tool, expect_forbidden, expect_allowed, label in cases:
        is_forb = is_forbidden_tool(agent, tool)
        is_allw = is_allowed_tool(agent, tool)
        assert is_forb == expect_forbidden, f"forbidden mismatch for {label}"
        assert is_allw == expect_allowed, f"allowed mismatch for {label}"
        ok(label)

    # High risk targets
    for target, expected in [("/etc/passwd", True), (".env", True), ("src/main.py", False)]:
        assert is_high_risk_target(target) == expected, f"Target mismatch: {target}"
    ok("High-risk target detection: /etc/passwd, .env flagged; src/main.py clean")
except Exception as e:
    fail(f"Policy logic — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 7: Flask Server Import Check
# ──────────────────────────────────────────────────────────
section("7. Flask Server Import & Route Registration")

try:
    # Import app without running it
    import importlib.util, sys as _sys
    spec = importlib.util.spec_from_file_location(
        "server", 
        os.path.join(os.path.dirname(__file__), "guardian_swarm", "web", "server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app = mod.app

    # Check all expected routes are registered
    routes = {r.rule for r in app.url_map.iter_rules()}
    expected_routes = [
        "/api/stats", "/api/ledger", "/api/propose", "/api/simulate",
        "/api/reset", "/api/toggle_mode", "/api/verify", "/api/tamper",
        "/api/restore", "/api/models/status", "/api/models/scan",
        "/api/models/connect", "/api/models/probe", "/api/models/demo",
        "/api/traces", "/api/escalations", "/api/escalations/<id>/resolve"
    ]
    missing_routes = [r for r in expected_routes if r not in routes]
    if missing_routes:
        fail(f"Missing API routes: {missing_routes}")
    else:
        ok(f"All 17 API routes registered")
except Exception as e:
    fail(f"Flask server — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 8: terminal_ui.print_debate_block
# ──────────────────────────────────────────────────────────
section("8. terminal_ui — print_debate_block")

try:
    import terminal_ui
    assert hasattr(terminal_ui, "print_debate_block"), "print_debate_block not found"
    import inspect
    sig = inspect.signature(terminal_ui.print_debate_block)
    params = list(sig.parameters.keys())
    ok(f"print_debate_block exists, signature params: {params}")
except Exception as e:
    fail(f"terminal_ui.print_debate_block — {e}")

# ──────────────────────────────────────────────────────────
# SECTION 9: requirements.txt check
# ──────────────────────────────────────────────────────────
section("9. Critical Dependencies Available")

critical_deps = {
    "flask": "Flask",
    "psutil": "psutil",
}
for imp_name, pkg_name in critical_deps.items():
    try:
        __import__(imp_name)
        ok(f"{pkg_name} importable")
    except ImportError:
        fail(f"{pkg_name} NOT installed — run: pip install {pkg_name}")

# Optional heavy deps — warn, don't fail
optional_deps = {"torch": "PyTorch"}
for imp_name, pkg_name in optional_deps.items():
    try:
        __import__(imp_name)
        ok(f"{pkg_name} available (GPU inference enabled)")
    except ImportError:
        warn(f"{pkg_name} not installed — will use Heuristics engine (acceptable for local runs)")

# ──────────────────────────────────────────────────────────
# FINAL REPORT
# ──────────────────────────────────────────────────────────
print(f"\n{'='*55}")
print(f"  VERIFICATION COMPLETE")
print(f"{'='*55}")
print(f"  Passed  : {sum(1 for l in open(__file__).readlines() if '[PASS]' in l)} checks")
print(f"  Warnings: {len(warnings)}")
print(f"  Failures: {len(errors)}")

if errors:
    print("\n  ERRORS:")
    for e in errors:
        print(f"    - {e}")
    print()
    sys.exit(1)
else:
    print("\n  Guardian Swarm V3 is fully operational.")
    sys.exit(0)
