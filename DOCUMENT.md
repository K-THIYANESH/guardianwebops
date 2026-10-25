# Guardian Swarm V3: Enterprise AI OS & Security Trust Framework

**Release Version:** `v3.0.0-PROD`  
**Package:** `guardian-swarm 3.0.0`  
**License:** Enterprise Governance Specification  

---

## 1. Executive Overview & Purpose

**Guardian Swarm V3** is a zero-trust, enterprise-grade **Corporate AI Operating System (AI OS)** and dynamic application security firewall. It governs multi-agent AI task submissions, tool invocations, local/cloud model inferences, data access privileges, and budgetary resource allocations in real-time.

### Core Objectives
1. **Zero-Trust Governance**: No AI agent or tool execution bypasses policy verification. Every prompt payload and command proposal passes through a sequential 5-Gate Governance Pipeline before execution.
2. **Structural Data Privacy & FileMind Classification**: Prevents non-compliant data egress, detects PII via regular expressions, enforces regional data residency controls, and uses **FileMind** content-fingerprinted file classification to enforce role-based document access controls.
3. **Financial & Resource Guardrails**: Pre-flight token cost estimation (via `tiktoken`) prevents wallet exhaustion across User, Team, and Organization spending pools.
4. **Model Group Confinement**: Restricts AI models (`RESEARCH`, `CODE`, `DRAFTING`, `SUPPORT`, `DATA_ANALYSIS`) to permitted tool sets, preventing cross-domain tool invocation or prompt injection boundary escapes.
5. **Cryptographic Tamper-Evident Ledger**: Logs all decisions, inspection traces, debate outputs, and gate verdicts to a SHA-256 cryptographically chained SQLite database ledger.

---

## 2. Technical System Architecture

### 5-Gate Governance Pipeline Flow

```
   +-------------------------------------------------------------------------+
   |                       User Task / Prompt Payload                        |
   +-------------------------------------------------------------------------+
                                        |
                                        v
   +-------------------------------------------------------------------------+
   |  GATE 1: User RBAC Gate (RolePermissionMatrix & Account Status)          |
   |  - Validates user role against task category allow-lists               |
   |  - Checks subagent spawning rights & account suspension status         |
   +-------------------------------------------------------------------------+
                                        | (Passes)
                                        v
   +-------------------------------------------------------------------------+
   |  GATE 2: Model Group Confinement Gate (Domain & Tool Boundaries)         |
   |  - Verifies model group assignment (RESEARCH, CODE, etc.)                |
   |  - Blocks unauthorized tool calls & prompt boundary escapes             |
   +-------------------------------------------------------------------------+
                                        | (Passes)
                                        v
   +-------------------------------------------------------------------------+
   |  GATE 3: Privacy & FileMind Classification Gate                          |
   |  - Scans prompt PII (SSN, Email, Keys, CC) & enforces local rerouting     |
   |  - Runs FileMind fingerprint scan on referenced file paths               |
   |  - Validates regional data residency compliance                          |
   +-------------------------------------------------------------------------+
                                        | (Passes)
                                        v
   +-------------------------------------------------------------------------+
   |  GATE 4: Financial Budget Gate (Pre-Flight Cost Guardrails)              |
   |  - Calculates token pre-flight cost via tiktoken                         |
   |  - Enforces User Wallet, Team Pool, and Org Ceilings                     |
   +-------------------------------------------------------------------------+
                                        | (Passes)
                                        v
   +-------------------------------------------------------------------------+
   |  GATE 5: AI Safety Verification Agent & Cryptographic Audit Ledger       |
   |  - Evaluates heuristic injection patterns & critical tool targets       |
   |  - Writes verdict & trace to SHA-256 Chained SQLite Audit Log           |
   +-------------------------------------------------------------------------+
                                        |
                                        v
   +-------------------------------------------------------------------------+
   |                  Approved Execution / Cloud Model Call                  |
   +-------------------------------------------------------------------------+
```

---

## 3. Enterprise Database Layer & Schema Specification

The database is built on **SQLAlchemy / SQLite** (`guardian_swarm.db`), featuring **AES-128 Fernet encryption** for credentials.

### Schema Table Definitions

1. **`users` Table (`UserModel`)**
   - `user_id` (String, PK): Unique username/identifier (e.g. `intern_user`, `manager_user`).
   - `password_hash` (String): Werkzeug SHA-256 password hash.
   - `name` (String): Display name.
   - `role` (String): Role classification (`INTERN`, `EMPLOYEE`, `MANAGER`, `EXEC`, `ADMIN`).
   - `department` (String): Organizational team (e.g., `Engineering`, `IT Security`).
   - `daily_token_limit` (Integer): Daily token limit allocation.
   - `tokens_used_today` (Integer): Daily token consumption tracker.
   - `is_suspended` (Boolean): Account status flag.

2. **`api_keys` Table (`APIKeyModel`)**
   - `id` (Integer, PK): Auto-increment primary key.
   - `provider` (String, Unique): Model provider name (`openai`, `anthropic`, `google`, `xai`, `perplexity`, etc.).
   - `key_encrypted` (String): Fernet encrypted API key string.
   - `key_prefix` (String): Masked key prefix for UI display (e.g., `sk-ant-...1234`).
   - `status` (String): Connection status (`connected`, `invalid`, `untested`).
   - `updated_at` (DateTime): Timestamp of last key update.

3. **`model_registry` Table (`ModelRegistryModel`)**
   - `id` (Integer, PK): Primary key.
   - `name` (String, Unique): Model name (e.g., `gpt-4o`, `claude-sonnet-4-6`, `gemini-1.5-pro`).
   - `provider` (String): Hosting provider.
   - `type` (String): Model deployment type (`cloud` vs `local`).
   - `group_name` (String): Task group binding (`RESEARCH`, `CODE`, `DRAFTING`, `SUPPORT`, `DATA_ANALYSIS`).
   - `input_cost_per_m` (Float): USD cost per 1M input tokens.
   - `output_cost_per_m` (Float): USD cost per 1M output tokens.
   - `max_tokens` (Integer): Maximum context window size.
   - `is_active` (Boolean): Operational status.

4. **`audit_blocks` Table (`AuditBlockModel`)**
   - `block_index` (Integer, PK): Monotonically increasing block index.
   - `timestamp` (String): ISO 8601 UTC timestamp.
   - `agent_id` (String): Initiating agent/user ID.
   - `action_type` (String): Action category / tool name.
   - `target` (String): Target resource or system entity.
   - `verdict` (String): Decision verdict (`APPROVED`, `DENIED`, `ESCALATED`, `REROUTED`).
   - `confidence` (Float): Verification confidence score (0.0 to 1.0).
   - `reasoning` (Text): Explanation of verdict.
   - `governance_json` (Text): Full JSON string containing investigation trace, parameters, and debate steps.
   - `prev_hash` (String): SHA-256 hash of previous block.
   - `entry_hash` (String): SHA-256 hash of current block payload + `prev_hash`.

5. **`conversations` Table (`ConversationModel`)**
   - `conv_id` (String, PK): UUID conversation identifier.
   - `user_id` (String): FK to `users.user_id`.
   - `title` (String): Topic summary.
   - `created_at` (DateTime): Creation timestamp.

6. **`messages` Table (`MessageModel`)**
   - `id` (Integer, PK): Message primary key.
   - `conv_id` (String): FK to `conversations.conv_id`.
   - `role` (String): Message sender (`user`, `assistant`, `system`).
   - `content` (Text): Text body.
   - `tokens_used` (Integer): Tokens consumed by message.
   - `audit_block_index` (Integer, Nullable): Associated audit block.

7. **`filemind_cache` Table (`FileMindCacheModel`)**
   - `id` (Integer, PK): Primary key.
   - `path` (String, Unique): Canonical file system path.
   - `filemind_category` (String): Extracted category (`Documents`, `Spreadsheets`, etc.).
   - `guardian_classification` (String): Security level (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
   - `file_size` (Integer): Size in bytes.
   - `modified_time` (Float): File mtime.
   - `content_fingerprint` (String): SHA-256 content hash.
   - `scanned_at` (DateTime): Scan timestamp.
   - `expires_at` (DateTime): 24-hour cache TTL expiration.
   - `status` (String): Status (`classified`, `scanner_failure`).

---

## 4. Standardized Exception Hierarchy & Error Code Index

All security exceptions inherit from `GuardianSecurityException` -> `GuardianException`.

```
GuardianException
└── GuardianSecurityException
    ├── Gate 1 (RBAC):
    │   ├── RoleNotPermittedForTaskException (RBE_001)
    │   ├── DataClassificationExceededException (RBE_002)
    │   ├── SubagentSpawnDeniedException (RBE_003)
    │   ├── UserSuspendedException (RBE_004)
    │   └── RolePermissionNotFoundException (RBE_005)
    ├── Gate 2 (Confinement):
    │   ├── TaskOutsideGroupScopeException (MGE_001)
    │   ├── CrossGroupToolAccessException (MGE_002)
    │   ├── ConfinementBreachDetectedException (MGE_003)
    │   └── InjectionTargetingBoundaryException (MGE_004)
    ├── Gate 3 (Privacy & FileMind):
    │   ├── PIIDetectedReroutingException (PGE_001)
    │   ├── ExternalAPIBlockedException (PGE_002)
    │   ├── OutputRedactionAppliedException (PGE_003)
    │   ├── DataResidencyViolationException (PGE_004)
    │   └── FileClassificationDeniedException (PGE_005)
    ├── Gate 4 (Budget):
    │   ├── UserWalletExhaustedException (BGE_001)
    │   ├── TeamPoolExhaustedException (BGE_002)
    │   ├── OrgCeilingExceededException (BGE_003)
    │   └── PreFlightCostExceedsBudgetException (BGE_004)
    └── Gate 5 (Safety & Ledger):
        ├── PolicyViolationException (GSE_001)
        ├── HighRiskTargetException (GSE_002)
        ├── PromptInjectionAttemptException (GSE_003)
        ├── LedgerVerificationFailedException (GSE_004)
        └── EscalateToHumanException (GSE_005)
```

---

## 5. Comprehensive Module & Function Reference

This section details **every single function, class, and method** in the project from nook to corner.

---

### Module: `guardian_swarm.utils.database`

#### Functions
- `encrypt_string(plain_text: str) -> str`: Encrypts raw string using AES-128 Fernet key derived from secret phrase.
- `decrypt_string(cipher_text: str) -> str`: Decrypts Fernet cipher string back to plain text. Returns plain text if string is unencrypted.
- `mask_key(raw_key: str) -> str`: Masks API key showing provider prefix and last 4 characters (e.g. `sk-ant-...1234`).
- `init_db() -> None`: Initializes SQLite tables and seeds initial 5 users (`intern_user`, `employee_user`, `manager_user`, `exec_user`, `admin_user`) if database is empty.
- `get_db()`: Generator function yielding SQLAlchemy database session.

#### Classes
- `Base`: Declarative base for SQLAlchemy models.
- `UserModel`: ORM mapping for `users` table.
- `APIKeyModel`: ORM mapping for `api_keys` table.
- `ModelRegistryModel`: ORM mapping for `model_registry` table.
- `AuditBlockModel`: ORM mapping for `audit_blocks` table.
- `ConversationModel`: ORM mapping for `conversations` table.
- `MessageModel`: ORM mapping for `messages` table.
- `FileMindCacheModel`: ORM mapping for `filemind_cache` table.

---

### Module: `guardian_swarm.utils.logger`

#### Functions
- `get_logger(name: str = "guardian_swarm") -> logging.Logger`: Returns configured logger singleton with `JSONFormatter` attached to `sys.stdout`.
- `log_event(level: str, message: str, extra: Optional[Dict[str, Any]] = None, logger_name: str = "guardian_swarm") -> None`: Logs structured JSON log message with dynamic severity (`info`, `warning`, `error`, etc.).

#### Classes
- `JSONFormatter(logging.Formatter)`: Custom logging formatter that serializes log records into structured JSON strings containing UTC ISO timestamps, line numbers, function names, and extra fields.

---

### Module: `guardian_swarm.utils.audit`

#### Classes & Methods
- `AuditLog`: Cryptographically chained audit log engine backed by SQLite (`audit_blocks`).
  - `__init__()`: Initializes memory chain array and calls `_load_from_db()`.
  - `_load_from_db() -> None`: Loads audit records ordered by `block_index` from database into local memory chain.
  - `create_entry(agent_id: str, agent_type: str, tool: str, target: str, params: dict, verdict: str, confidence: float, reasoning: str, trace: List[str], debate_trace: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]`: Constructs new block entry, calculates SHA-256 hash chaining to previous entry hash, and persists to `audit_blocks` table.
  - `verify_integrity() -> Tuple[bool, int, str]`: Traverses the audit chain re-computing SHA-256 hashes sequentially to verify zero tampering. Returns `(is_valid, chain_length, error_message)`.

---

### Module: `guardian_swarm.core.exceptions`

#### Classes
- `GuardianException(Exception)`: Base system exception class with `to_dict()` method.
- `GuardianSecurityException(GuardianException)`: Base class for all governance gate exceptions. Populates `error_code`, `gate_name`, `user_id`, `details`, `agent_id`, `agent_type`, `tool`, `target`, and `user_help`.
- Specific exception classes:
  - `RoleNotPermittedForTaskException` (`RBE_001`)
  - `DataClassificationExceededException` (`RBE_002`)
  - `SubagentSpawnDeniedException` (`RBE_003`)
  - `UserSuspendedException` (`RBE_004`)
  - `RolePermissionNotFoundException` (`RBE_005`)
  - `TaskOutsideGroupScopeException` (`MGE_001`)
  - `CrossGroupToolAccessException` (`MGE_002`)
  - `ConfinementBreachDetectedException` (`MGE_003`)
  - `InjectionTargetingBoundaryException` (`MGE_004`)
  - `PIIDetectedReroutingException` (`PGE_001`)
  - `ExternalAPIBlockedException` (`PGE_002`)
  - `OutputRedactionAppliedException` (`PGE_003`)
  - `DataResidencyViolationException` (`PGE_004`)
  - `FileClassificationDeniedException` (`PGE_005`)
  - `UserWalletExhaustedException` (`BGE_001`)
  - `TeamPoolExhaustedException` (`BGE_002`)
  - `OrgCeilingExceededException` (`BGE_003`)
  - `PreFlightCostExceedsBudgetException` (`BGE_004`)
  - `PolicyViolationException` (`GSE_001`)
  - `HighRiskTargetException` (`GSE_002`)
  - `PromptInjectionAttemptException` (`GSE_003`)
  - `LedgerVerificationFailedException` (`GSE_004`)
  - `EscalateToHumanException` (`GSE_005`)

---

### Module: `guardian_swarm.core.models`

#### Classes & Methods
- `VerificationAgent`: Gate 5 AI Safety & Policy Verification engine.
  - `__init__()`: Sets up heuristic policies, forbidden targets (`/etc/shadow`, `.env`, `master.key`), and prohibited commands.
  - `is_prompt_injection(prompt: str) -> bool`: Scans prompt for injection attempts (`ignore previous instructions`, `system prompt override`).
  - `is_high_risk(target: str, params: dict) -> bool`: Checks if command targets system critical path or secret.
  - `analyze_action(agent_id: str, agent_type: str, tool: str, target: str, params: dict) -> Dict[str, Any]`: Analyzes proposal returning dictionary with `verdict` (`APPROVED`, `DENIED`, `ESCALATED`), `confidence`, `reasoning`, and `trace`.

---

### Module: `guardian_swarm.core.user_rbac`

#### Classes & Methods
- `UserSession`: Dataclass holding user session context (`user_id`, `role`, `department`, `daily_limit`, `tokens_used_today`, `is_suspended`).
- `UserRBACGate`: Gate 1 User RBAC Gate controller.
  - `__init__(matrix: Optional[Dict[str, Dict[str, Any]]] = None)`: Loads RBAC permission matrix for `INTERN`, `EMPLOYEE`, `MANAGER`, `EXEC`, and `ADMIN`.
  - `check(session: UserSession, task_category: str, data_classification: str = "INTERNAL", spawn_subagent: bool = False) -> bool`: Validates user role against category allow-list, maximum data classification level, subagent spawn permission, and suspension status. Raises `RBE_001` through `RBE_005` on failure.

---

### Module: `guardian_swarm.core.confinement`

#### Classes & Methods
- `ConfinementGate`: Gate 2 Model Group Confinement Gate controller.
  - `__init__(groups: Optional[Dict[str, Dict[str, Any]]] = None)`: Loads model group definitions for `RESEARCH`, `CODE`, `DRAFTING`, `SUPPORT`, and `DATA_ANALYSIS`.
  - `verify_model_group_membership(model: str, group_name: str) -> bool`: Checks whether model belongs to specified task group via database registry or fallback configuration.
  - `check(task_group: str, tool: str, prompt: str = "", model: Optional[str] = None) -> bool`: Enforces tool boundaries, checks model group membership, and screens prompt for boundary bypass attempts. Raises `MGE_001` through `MGE_004` on violation.

---

### Module: `guardian_swarm.core.privacy_gate`

#### Classes & Methods
- `PrivacyGate`: Gate 3 Privacy & FileMind Classification Gate controller.
  - `__init__()`: Initializes `FileMindClassifier` instance.
  - `detect_pii(text: str) -> Tuple[bool, List[str]]`: Scans input string against regex patterns (`EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `ADDRESS`, `IP_ADDRESS`, `DOB`, `API_KEY`). Returns `(has_pii, list_of_detected_types)`.
  - `scan(prompt: str, data_classification: str = "INTERNAL", pii_action: str = "reroute", allowed_regions: Optional[List[str]] = None, target_region: str = "us-east-1", max_allowed_classification: str = "INTERNAL", user_role: str = "EMPLOYEE") -> Dict[str, Any]`: Scans prompt for PII, runs FileMind classification on referenced file paths (raising `PGE_005` if file classification exceeds user allowed max level), and checks data residency compliance.

---

### Module: `guardian_swarm.core.budget_gate`

#### Classes & Methods
- `BudgetGate`: Gate 4 Financial Budget Gate controller.
  - `__init__()`: Loads wallet pools for user, team, and organization ceilings.
  - `estimate_tokens(prompt: str, target: str = "", params: Optional[dict] = None) -> int`: Pre-flight token estimator using `tiktoken` (cl100k_base encoding).
  - `check(user_session: UserSession, estimated_tokens: int) -> bool`: Validates estimated token cost against User Daily Wallet, Team Pool, and Org Ceiling. Raises `BGE_001` through `BGE_004` on budget exhaustion.

---

### Module: `guardian_swarm.core.filemind_classifier`

#### Classes & Methods
- `FileMindClassifier`: Content-aware file classifier integrating FileMind output categories with Guardian privacy policies.
  - `__init__(config_path: str = "config/filemind_mapping.yaml", db_path: str = "guardian_swarm.db")`: Loads mapping rules and initializes SQLite cache table.
  - `compute_fingerprint(filepath: str) -> Tuple[str, int, float]`: Computes SHA-256 content hash, file size in bytes, and mtime timestamp.
  - `classify_file(filepath: str) -> Dict[str, Any]`: Classifies single file using SHA-256 fingerprinting, 24-hour SQLite caching, and fail-secure fallback scanning. Returns dictionary containing category, classification, cache status, and scan status.
  - `classify_folder(folder_path: str, dry_run: bool = True) -> Dict[str, Any]`: Recursively scans directory tree classifying all detected files and storing results in SQLite cache.

---

### Module: `guardian_swarm.core.interceptor`

#### Classes & Methods
- `GuardianInterceptor`: Master interceptor orchestrating the 5-Gate Governance Pipeline.
  - `__init__(verification_agent: Optional[VerificationAgent] = None, audit_log: Optional[AuditLog] = None)`: Instantiates all 5 gate controllers and audit logging components.
  - `_handle_gate_failure(exception: GuardianSecurityException, gate_step: str) -> Tuple[bool, Dict[str, Any]]`: Formats gate failure responses, logs event, and creates DENIED audit block entry in ledger.
  - `intercept(user_session: UserSession, agent_id: str, agent_type: str, tool: str, target: str, params: dict) -> Tuple[bool, Dict[str, Any]]`: Executes full sequential 5-gate pipeline verification.

---

### Module: `guardian_swarm.core.inference`

#### Functions
- `count_tokens(text: str) -> int`: Returns token count using `tiktoken`.
- `execute_swarm_inference(prompt: str, model_name: str = "gemini-1.5-flash", system_instruction: str = "") -> Dict[str, Any]`: Routes task inference to registered cloud model providers (Google Gemini API, OpenAI, Anthropic, local fallback) using dynamic API key decryption from database.

---

### Module: `guardian_swarm.web.server`

#### Functions & API Routes
- `generate_jwt_token(user_id: str, role: str, name: str) -> str`: Generates signed JWT authentication token.
- `verify_jwt_token(token: str) -> Optional[Dict[str, Any]]`: Decodes and validates JWT token signature and expiration.
- `get_current_user_session() -> UserSession`: Extracts JWT token from Authorization header or falls back to default session user.
- `sse_stream()`: `/api/stream` Server-Sent Events (SSE) telemetry endpoint pushing real-time gate evaluation events to dashboard.
- `login()`: `POST /api/auth/login` Authenticates user credentials and returns JWT token.
- `get_me()`: `GET /api/auth/me` Returns active user session profile and wallet usage.
- `list_conversations()`: `GET /api/conversations` Lists user task conversations.
- `create_conversation()`: `POST /api/conversations` Creates new chat thread.
- `get_messages(conv_id)`: `GET /api/conversations/<conv_id>/messages` Returns message history for thread.
- `submit_task()`: `POST /api/tasks/submit` Main entry point for user tasks. Executes 5-Gate Governance Pipeline and returns model inference output.
- `escalate_decision()`: `POST /api/escalations/decision` Allows administrator to approve or deny human escalation tasks.
- `get_stats()`: `GET /api/stats` Returns platform aggregate metrics.
- `verify_ledger()`: `POST /api/verify` Runs cryptographic SHA-256 chain verification scan on audit ledger.
- `admin_api_keys()`: `GET, POST /api/admin/apikeys` Encrypts and registers provider API keys.
- `test_api_key_connection()`: `POST /api/admin/apikeys/test` Performs live ping test against provider API.
- `admin_models()`: `GET, POST /api/admin/models` Dynamic Model Registry CRUD management.
- `admin_groups()`: `GET, POST /api/admin/groups` Model group tool boundary configuration.
- `admin_roles()`: `GET, POST /api/admin/roles` Role permissions matrix administration.
- `admin_budget()`: `GET, POST /api/admin/budget` Team budget pools and org ceiling configuration.
- `admin_users()`: `GET, POST /api/admin/users` User accounts and token wallet administration.
- `admin_health()`: `GET /api/admin/health` Telemetry metrics and ledger status.
- `classify_folder_api()`: `POST /api/classify/folder` Triggers asynchronous FileMind classification scan on folder.
- `classify_status_api()`: `GET /api/classify/status` Retrieves status and progress of folder classification scan.
- `classify_file_api()`: `GET /api/classify/file` Fetches classification details for single file path.
- `classify_summary_api()`: `GET /api/classify/summary` Returns classification summary counts for dashboard widgets.

---

## 6. REST API Endpoint Reference Table

| Endpoint | Method | Required Role | Purpose |
| :--- | :--- | :--- | :--- |
| `/api/auth/login` | `POST` | Public | Authenticate credentials & obtain JWT |
| `/api/auth/me` | `GET` | Authenticated | Fetch active user session & wallet details |
| `/api/tasks/submit` | `POST` | Authenticated | Submit task through 5-Gate Governance Pipeline |
| `/api/conversations` | `GET, POST` | Authenticated | List or create chat threads |
| `/api/conversations/<id>/messages` | `GET` | Authenticated | Retrieve message history for thread |
| `/api/verify` | `POST` | Authenticated | Verify SHA-256 audit ledger integrity |
| `/api/stats` | `GET` | Authenticated | Fetch platform aggregate stats |
| `/api/stream` | `GET` | Authenticated | SSE live gate telemetry stream |
| `/api/admin/apikeys` | `GET, POST` | `ADMIN` | List or register encrypted provider API keys |
| `/api/admin/apikeys/test` | `POST` | `ADMIN` | Test provider API key connectivity |
| `/api/admin/models` | `GET, POST` | `ADMIN` | Manage dynamic Model Registry |
| `/api/admin/groups` | `GET, POST` | `ADMIN` | Configure model group tool boundaries |
| `/api/admin/roles` | `GET, POST` | `ADMIN` | Configure role permissions matrix |
| `/api/admin/budget` | `GET, POST` | `ADMIN` | Configure team budget pools & org ceiling |
| `/api/admin/users` | `GET, POST` | `ADMIN` | Manage user accounts & daily token limits |
| `/api/admin/health` | `GET` | `ADMIN` | Retrieve system telemetry & health status |
| `/api/classify/folder` | `POST` | `MANAGER+` | Trigger FileMind classification scan on folder |
| `/api/classify/status` | `GET` | `MANAGER+` | Retrieve status of active classification scan |
| `/api/classify/file` | `GET` | Authenticated | Fetch classification of individual file path |
| `/api/classify/summary` | `GET` | Authenticated | Fetch aggregate classification metrics |

---

## 7. Testing & Verification Suite

The repository contains **51 automated integration tests** across three test modules:
- `tests/test_corporate_ai_os.py` (40 tests): Core database seeding, Fernet key encryption, JWT auth, 5-gate pipeline checks, and exception error codes.
- `tests/test_data_integrity.py` (6 tests): Database schema integrity and admin endpoints.
- `tests/test_filemind_integration.py` (5 tests): FileMind content classifier, SQLite caching, fail-secure policies, `PGE_005` enforcement, and classification REST endpoints.

### Command Execution
```bash
python -m pytest tests/test_corporate_ai_os.py tests/test_data_integrity.py tests/test_filemind_integration.py -v
```
**Result:** `51 passed in 9.30s (100% Pass Rate)`
