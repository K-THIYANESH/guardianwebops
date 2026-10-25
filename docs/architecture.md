# Guardian WebOps Architecture

## Product Statement
**Guardian WebOps** is the trust layer for autonomous web research. It merges TinyFish-powered public-web intelligence with Guardian Swarm's five-gate governance framework.

```mermaid
flowchart TD
    User([User / Engineer]) -->|Submits Research Task| UI[Guardian WebOps Dashboard]
    UI -->|POST /api/research/tasks| Orchestrator[Research Orchestrator]
    
    subgraph Governance ["Guardian Swarm V3 5-Gate Pipeline"]
        Gate1[Gate 1: Access Control RBAC]
        Gate2[Gate 2: Tool Confinement]
        Gate3[Gate 3: Privacy & Data Classification]
        Gate4[Gate 4: Budget Guardrails]
        Gate5[Gate 5: Safety & High-Risk Interceptor]
    end
    
    Orchestrator --> Gate1
    Gate1 --> Gate2
    Gate2 --> Gate3
    Gate3 --> Gate4
    Gate4 --> Gate5
    
    Gate5 -->|If Denied| BlockedResult[Record BLOCKED in Audit Log]
    Gate5 -->|If Approved| Adapter[TinyFish Integration Adapter]
    
    subgraph ResearchExecution ["Web Research Boundary"]
        Adapter -->|SSRF & Domain Filter| DomainCheck{Target Allowed?}
        DomainCheck -->|No| FailConfinement[Reject Domain]
        DomainCheck -->|Yes| TinyFishExecution{API Key Present?}
        TinyFishExecution -->|Yes| LiveTinyFish[Live TinyFish Agent]
        TinyFishExecution -->|No| MockTinyFish[Deterministic Mock Engine]
    end
    
    LiveTinyFish --> EvidenceModel[Structured Evidence Model]
    MockTinyFish --> EvidenceModel
    
    EvidenceModel --> Audit[Cryptographic SHA-256 Audit Log]
    EvidenceModel --> FinalReport[Vendor Comparison Report]
```

## Core Modules
- `guardian_swarm/integration/tinyfish_adapter.py`: Isolates TinyFish API from application business logic; performs SSRF filtering and provides honest simulated fallback.
- `guardian_swarm/core/evidence_models.py`: Pydantic models for `ResearchTask`, `VendorResearchResult`, and `ResearchClaim` with explicit `EvidenceStatus` values (`FOUND`, `MISSING`, `CONFLICTING`, `UNVERIFIED`, `FAILED_TO_RETRIEVE`).
- `guardian_swarm/core/research_service.py`: Orchestrates task execution through the 5-gate pipeline before web retrieval.
- `guardian_swarm/core/interceptor.py`: Enforces RBAC, Confinement, Privacy, Budget, and Safety rules.
- `guardian_swarm/utils/audit.py`: Cryptographically chained SHA-256 block ledger.
