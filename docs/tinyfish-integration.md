# TinyFish Integration Guide

## Overview

**Guardian WebOps** leverages **TinyFish** (`tinyfish.ai`) for automated web research, live web navigation, and evidence extraction from public websites.

Guardian WebOps applies zero-trust governance controls before any research task is executed against the live web.

---

## Architectural Responsibility

| Layer | Responsibility |
| :--- | :--- |
| **TinyFish** | Conducts public web navigation, searches vendor domains, and extracts source excerpts. |
| **Guardian Swarm** | Governs the boundary: Role RBAC, Tool Confinement, PII Privacy screening, Budget Guardrails, and SHA-256 Audit Logging. |
| **Guardian WebOps** | Presents structured evidence comparisons, source citations, missing information disclosures, and policy decisions. |

---

## Controlled Boundary & Confinement

1. **Approved Domain Filtering:** TinyFish requests are constrained to explicitly configured target vendor domains (e.g., `atlassian.com`, `linear.app`, `clickup.com`).
2. **SSRF & Private Target Prevention:** Internal addresses (`127.0.0.1`, `localhost`, `169.254.169.254`, `10.0.0.0/8`, `192.168.0.0/16`) are blocked before dispatch.
3. **Execution Mode Labeling:**
   - **Live Mode:** Dispatches queries via `tinyfish.TinyFish(api_key=...)` using `client.agent.run`.
   - **Simulated / Mock Mode:** Runs deterministic simulated retrieval with explicit `[SIMULATED]` badges on all findings. **Never masquerades mock outputs as live web evidence.**

---

## Setup & Configuration

### Prerequisites
- Python 3.9+ (Python 3.11+ required if installing the official `tinyfish` package)

### Environment Variable
Set your TinyFish API key in your environment or `.env` file:

```bash
export TINYFISH_API_KEY="sk-tinyfish-your-key-here"
```

### Running with Mock Mode
If `TINYFISH_API_KEY` is not provided or if the `tinyfish` package is not installed, Guardian WebOps will automatically initialize `TinyFishAdapter` in safe mock mode. All UI views and API responses will visibly indicate:
`TinyFish: Simulated Mode`.
