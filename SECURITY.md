# Security Policy & Limitations

## Security Model

Guardian WebOps implements zero-trust governance around autonomous web research.

### 1. Fail-Closed Boundary
Protected operations fail closed:
- If a user lacks the required role permissions, execution stops at Gate 1.
- If a tool request falls outside the defined model group scope, execution stops at Gate 2.
- If high-risk internal keywords (`/etc/passwd`, `private_key`, `.env`, `credentials`) are targeted, execution stops at Gate 5.

### 2. SSRF & Domain Confinement
The `TinyFishAdapter` strictly prevents Server-Side Request Forgery (SSRF) and intranet scanning:
- Blocks loopback targets (`127.0.0.1`, `localhost`).
- Blocks private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- Blocks link-local cloud metadata addresses (`169.254.169.254`).
- Validates targets against allowed domain lists.

### 3. Audit Ledger Integrity
Every proposed action and gate outcome is permanently recorded with SHA-256 block hashing:
- Tampering with any historical block breaks the cryptographic chain link (`prev_hash`).
- An on-demand verification endpoint (`POST /api/verify`) computes hash validity across the entire ledger.

### 4. Known Boundaries & Limitations
- **External Web Behavior:** Guardian WebOps cannot govern remote headless browser steps executed inside a closed external SaaS provider beyond the request parameters and URLs sent to the provider.
- **Vendor Statements as Evidence:** Claims retrieved from public vendor websites reflect self-reported statements, not independent third-party audit validation. All claims are labeled accordingly.
