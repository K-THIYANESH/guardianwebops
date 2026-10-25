# Guardian Swarm V3: Complete System Architecture & Reference Manual

**Current Release:** `v3.0.0`  
**System Specification:** Guardian Swarm V3 Security & Trust Runtime  
**Package Specification:** `guardian-swarm 3.0.0` (Python >= 3.9)

Guardian Swarm V3 is a production-grade, secure, tamper-evident, and resource-aware trust layer for standalone agent workflows. By intercepting agent command proposals before they are executed, Guardian Swarm acts as an inline application firewall that enforces structural safety, filters prompt injections, and logs all verdicts to a cryptographically chained ledger.

---

## Project Directory Structure

```text
Guardian Swarm V3/
├── app.py                         # Standalone launcher for the dashboard
├── demo_pitch.py                  # End-to-end safety lifecycle walkthrough
├── preload.py                     # Runtime state preloading and backend selection
├── terminal_ui.py                 # ANSI console rendering engine + print_debate_block()
├── DOCUMENTATION.md               # Full developer & API documentation
├── SYSTEM_ARCHITECTURE.md         # This document
├── config/
│   ├── settings.py                # Centralized runtime settings
│   └── environment.py             # Environment/bootstrap helpers
├── guardian_swarm/
│   ├── __init__.py
│   ├── config.py                  # Backward-compatible runtime config aliases
│   ├── agents/
│   │   ├── base.py                # SpecialistAgent base class with poison() hooks
│   │   ├── researcher.py          # ResearcherAgent definition
│   │   ├── coder.py               # CoderAgent definition
│   │   └── deck_builder.py        # DeckBuilderAgent definition
│   ├── core/
│   │   ├── exceptions.py          # GSE_001–GSE_005 custom exceptions
│   │   ├── interceptor.py         # GuardianInterceptor — gating + 12-field telemetry
│   │   ├── escalation.py          # EscalationQueue — persistent human-in-the-loop buffer
│   │   ├── models.py              # VerificationAgent — 3-agent debate loop + server scanning
│   │   └── policies.py            # RBAC tool permissions & high-risk target patterns
│   ├── integration/
│   │   └── standalone_plugin.py   # Standalone guard plugin middleware wrapper
│   ├── utils/
│   │   ├── audit.py               # SHA-256 AuditLog — agent_type stored per block
│   │   ├── memory.py              # CUDA / GPU VRAM utilities
│   │   └── paths.py               # Centralized project-root and data-path resolution
│   └── web/
│       ├── server.py              # Flask REST API — 17 endpoints
│       ├── templates/
│       │   └── index.html         # Guardian Swarm V3 observability dashboard
│       └── static/
│           ├── js/dashboard.js    # V3 dashboard controller — live telemetry binding
│           └── css/styles.css     # Clean standalone dashboard theme
```

---

## Custom Error Codes & Security Exceptions

Defined in `guardian_swarm/core/exceptions.py`:

| Exception Class | Error Code | Category | Cause / Description |
| :--- | :---: | :---: | :--- |
| `PolicyViolationException` | **`GSE_001`** | Tier 1 Block | Action is on the agent's role-based forbidden tool list. |
| `HighRiskTargetException` | **`GSE_002`** | Tier 1 Block | Action target contains high-risk system keywords (e.g. `/etc/passwd`, `.env`). |
| `AISafetyViolationException` | **`GSE_003`** | Tier 2 Block | 3-agent debate determined action is a prompt injection or malicious vector. |
| `LedgerVerificationException` | **`GSE_004`** | System Threat | Hash chain validation detected altered logs or block signature discrepancy. |
| `HumanEscalationRequiredException` | **`GSE_005`** | User Gating | AI confidence below threshold — paused, queued for human approval. |

---

## Component-by-Component Reference

### 1. `guardian_swarm/core/exceptions.py`
Defines the base `GuardianException` and `GuardianSecurityException` (which inherits from `PermissionError` for backwards compatibility). All five GSE codes map to specific typed exception classes, enabling `except PolicyViolationException` granularity in downstream swarm loops.

### 2. `guardian_swarm/integration/standalone_plugin.py`
The standalone integration adapter. Provides:
- `plugin.secure_agent(agent)` — Overrides the agent's `propose_action` method to transparently route every call through the Guardian Interceptor.
- `@plugin.secure_tool(...)` — Decorator form for wrapping individual tool functions.

### 3. `guardian_swarm/core/interceptor.py`
Coordinates the verification lifecycle:
- **Tier 1:** Checks static RBAC permissions from `policies.py`. Forbidden tools are blocked in ~0 ms (no model cost). Allowed tools on safe targets are auto-approved. Allowed tools on high-risk targets are escalated to Tier 2.
- **Tier 2:** Calls `VerificationAgent.verify_action()` — returns verdict, confidence, reasoning, elapsed_ms, and debate_trace. On `ESCALATE_TO_HUMAN` verdicts, pushes to the `EscalationQueue`.
- **Telemetry:** Maintains a 12-field `stats` dict exposed by `/api/stats`:
  - `total_intercepted`, `auto_approved`, `auto_blocked`, `ai_evaluated`
  - `ai_approved`, `ai_blocked`, `human_escalations`
  - `tier1_resolved`, `tier2_resolved`
  - `total_latency_ms`, `total_inference_time_ms`, `inference_count`

### 4. `guardian_swarm/core/escalation.py`
Implements `EscalationQueue` — a persistent in-memory queue for `GSE_005` events. Each item contains:
- UUID `id`, timestamps, agent metadata, tool/target details
- Full `debate_trace` (Prosecutor / Defender / Judge arguments)
- `status`: `pending` → `resolved` after human decision

The queue is cleared on `/api/reset` and polled by the dashboard every 1.5 seconds.

### 5. `guardian_swarm/core/models.py`
Manages the 3-agent debate loop and model infrastructure:
- **Prosecutor Agent:** Evaluates attack vectors, privilege escalation risks, and injection patterns. Returns `argument` string + `score` (1–10 risk).
- **Defender Agent:** Evaluates benign use-cases and contextual legitimacy. Returns `argument` string + `score` (1–10 safety).
- **Judge Agent:** Synthesises both arguments into a final `verdict` (`SAFE` / `BLOCKED` / `ESCALATE_TO_HUMAN`) with a `confidence` float and `reasoning` string.
- **Inference Backends:** Local PyTorch (4-bit quantized Phi-3.5-mini), Ollama, LM Studio, vLLM, llama.cpp, or Heuristic Rules Engine.
- **Hardware Guardrails:** RAM-aware model selection using `psutil`; falls back gracefully down the tier ladder.

### 6. `guardian_swarm/core/policies.py`
Stores RBAC security profiles for `researcher`, `coder`, and `deck_builder` agents. Defines:
- `ALLOWED_TOOLS[agent_type]` — tools that pass Tier 1 automatically
- `FORBIDDEN_TOOLS[agent_type]` — tools blocked with zero overhead
- `HIGH_RISK_PATTERNS` — target substrings/regex that trigger Tier 2 even for allowed tools

### 7. `guardian_swarm/utils/audit.py`
Builds the cryptographically chained audit log. Key details:
- `create_entry(agent_id, agent_type, tool, target, params, verdict, confidence, reasoning, trace, debate_trace)` — now stores `agent_type` inside `proposed_action` for dashboard rendering.
- Each block is JSON-serialized with sorted keys, then SHA-256 hashed and linked to the previous block's hash.
- `resolve_entry(action_id, approved)` — re-hashes and re-chains the entire ledger from the resolved block onward, preserving cryptographic integrity after human decisions.
- `verify_chain()` — scans all blocks, recomputes hashes, and checks chain linkages. Returns `(bool, message)`.

### 8. `guardian_swarm/utils/memory.py`
Helper to query PyTorch CUDA features, parse GPU VRAM usage, and retrieve hardware allocation state for the dashboard hardware panel.

### 9. `terminal_ui.py`
Custom ANSI console rendering engine providing:
- Spinner animations with progress tracking
- Styled box-drawing headers and dashboards
- Statistics tables
- **`print_debate_block(agent_id, agent_type, tool, target, debate_trace)`** — renders the full Prosecutor / Defender / Judge debate trace in a structured, color-coded terminal block during Tier 2 verifications

### 10. `guardian_swarm/web/server.py` & Dashboard

A Flask-based monitoring server. Complete endpoint list:

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/stats` | Interceptor stats, hardware telemetry, engine mode, ledger integrity |
| `GET` | `/api/ledger` | Full SHA-256 audit chain |
| `POST` | `/api/propose` | Manual action submission (Sandbox card) |
| `POST` | `/api/simulate` | Start background swarm simulation |
| `POST` | `/api/reset` | Clear ledger, escalation queue, and all stats |
| `POST` | `/api/toggle_mode` | Toggle Heuristics ↔ Local AI |
| `POST` | `/api/verify` | Manual ledger integrity sweep |
| `POST` | `/api/tamper` | Inject tamper into Block 0 for integrity testing |
| `POST` | `/api/restore` | Restore tampered blocks |
| `GET` | `/api/models/status` | Engine, latency, throughput, preload state |
| `GET` | `/api/models/scan` | Scan localhost for AI servers |
| `POST` | `/api/models/connect` | Connect to a local AI server |
| `POST` | `/api/models/probe` | Send test prompt through active engine |
| `POST` | `/api/models/demo` | Run policy assessment across representative enforcement cases |
| `GET` | `/api/traces` | Last N blocks containing a debate_trace |
| `GET` | `/api/escalations` | All items in the human escalation queue |
| `POST` | `/api/escalations/<id>/resolve` | Approve or deny a queued escalation |

### 11. Dashboard (`index.html` + `dashboard.js` + `styles.css`)

The Guardian Swarm V3 observability dashboard provides:

| Panel | Description |
|:---|:---|
| **Metrics Grid** | Total intercepts, approved, blocked, AI escalations — polled every 1.5 s |
| **Security Telemetry** | Avg AI latency, Tier 1 zero-cost %, Tier 2/human escalation % |
| **Hardware Allocation** | Device type, CPU %, RAM %, GPU VRAM |
| **Human Escalation Queue** | Live GSE_005 events with expandable debate traces and Approve/Deny buttons |
| **Audit Ledger Timeline** | All blocks newest-first; each has a View Proof drawer with hashes + debate trace |
| **Sandbox Playground** | Manually test any agent/tool/target combination |
| **Safety Prober** | Direct prompt probing through the active engine |
| **Local Server Scanner** | Discover and connect Ollama / LM Studio instances |
| **Tamper Simulation** | Inject + detect + restore ledger tampering live |

---

## Running the Standalone Application

### Step 1: Initialize the Interceptor & Ledger

```python
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.utils.audit import AuditLog

audit_log = AuditLog()
verification_agent = VerificationAgent()
verification_agent.is_heuristic = True  # Or load LLM via verification_agent.load_model()
interceptor = GuardianInterceptor(verification_agent, audit_log)
```

### Step 2: Initialize the Plugin & Secure Your Swarm Agents

```python
from guardian_swarm.integration import StandaloneGuardPlugin
from guardian_swarm.agents.coder import CoderAgent

plugin = StandaloneGuardPlugin(interceptor)
coder = CoderAgent("coder_01")
plugin.secure_agent(coder)
```

### Step 3: Handle Security Exceptions in the Swarm Loop

```python
from guardian_swarm.core.exceptions import GuardianSecurityException

try:
    tool, target, params = coder.propose_action("Write the core loop in /etc/passwd")
    print(f"Action approved: {tool} on {target}")
except GuardianSecurityException as e:
    print(f"Intercepted threat: Error Code {e.error_code}")
    print(f"Reason: {e.message}")
    # Trigger quarantine or swarm halt logic here...
```

### Step 4: Accessing the Human Escalation Queue Programmatically

```python
# Check pending escalations
pending = interceptor.escalation_queue.get_pending()
for item in pending:
    print(f"[GSE_005] Agent: {item['agent_id']} | Tool: {item['tool']} | ID: {item['id']}")

# Resolve programmatically (or let the web dashboard handle it)
interceptor.escalation_queue.resolve(item['id'], 'approve')
audit_log.resolve_entry(item['id'], approved=True)
```

---

## Telemetry Metrics Explained

The `/api/stats` endpoint returns a `stats` dict. The dashboard's **Security Telemetry & Cost Efficiency** card derives three metrics from it:

| Dashboard Field | Formula | Interpretation |
|:---|:---|:---|
| **Avg Latency** | `total_latency_ms / ai_evaluated` | Mean ms per Tier 2 AI verification call |
| **Tier 1 Resolved** | `(tier1_resolved / total_intercepted) * 100` | % of actions resolved at zero model cost |
| **Tier 2 / Escalations** | `(tier2_resolved / total_intercepted) * 100` | % requiring AI debate; sub-label = `(X% human)` = `human_escalations / tier2_resolved * 100` |

A healthy production swarm should show **Tier 1 > 70%** (fast policy resolution) with **human escalation < 5%** (low ambiguity rate).
