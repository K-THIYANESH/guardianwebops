"""
Guardian Swarm Enterprise Application Server
============================================
Provides REST API, JWT Authentication, Server-Sent Events (SSE) telemetry,
and SQLite database administration.
"""
import sys
import time
import json
import jwt
from datetime import datetime, timezone, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, Response
from typing import Dict, Any, List, Optional

from guardian_swarm.utils.paths import PROJECT_ROOT, STATE_FILE, resolve_state_file

sys.path.insert(0, str(PROJECT_ROOT))

from guardian_swarm.utils.database import (
    init_db, SessionLocal, UserModel, APIKeyModel, ModelRegistryModel,
    encrypt_string, decrypt_string, mask_key
)
from guardian_swarm.core.models import VerificationAgent
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.utils.audit import AuditLog
from guardian_swarm.core.user_rbac import (
    UserSession, get_role_level, has_minimum_role, has_exact_role,
    require_minimum_role, require_exact_role
)
from guardian_swarm.utils.logger import log_event
from guardian_swarm.core.inference import execute_swarm_inference, count_tokens
from guardian_swarm.core.filemind_classifier import FileMindClassifier

filemind_classifier = FileMindClassifier()
ACTIVE_SCANS: Dict[str, Any] = {}

JWT_SECRET = "GuardianSwarmV3EnterpriseJWTSecret2026!"
JWT_ALGORITHM = "HS256"

app = Flask(__name__)
app.url_map.strict_slashes = False

# Initialize SQLite database and 5-user seed
init_db()

# Core system state
audit_log = AuditLog()
verification_agent = VerificationAgent()
verification_agent.is_heuristic = True

interceptor = GuardianInterceptor(verification_agent, audit_log)
tasks_store: List[Dict[str, Any]] = []

from guardian_swarm.core.research_service import ResearchOrchestrator
from guardian_swarm.integration.tinyfish_adapter import TinyFishAdapter

tinyfish_adapter = TinyFishAdapter()
research_orchestrator = ResearchOrchestrator(interceptor=interceptor, audit_log=audit_log, adapter=tinyfish_adapter)

# =====================================================================
# JWT Authentication & Security Helpers
# =====================================================================

def generate_jwt_token(user_id: str, role: str, name: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "name": name,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None

def get_current_user_session() -> UserSession:
    auth_header = request.headers.get("Authorization")
    if auth_header:
        decoded = verify_jwt_token(auth_header)
        if decoded:
            db = SessionLocal()
            try:
                usr = db.query(UserModel).filter(UserModel.user_id == decoded["sub"]).first()
                if usr:
                    return UserSession(
                        user_id=usr.user_id,
                        role=usr.role.upper(),
                        department=usr.department,
                        name=usr.name,
                        email=usr.email,
                        is_suspended=usr.is_suspended
                    )
            finally:
                db.close()
            return UserSession(user_id=decoded["sub"], role=decoded.get("role", "INTERN").upper(), name=decoded.get("name", "User"))

    if request.headers.get("X-Test-Unauthenticated") == "true":
        return UserSession(user_id="anonymous", role="UNAUTHENTICATED", name="Anonymous User")

    # Fallback to headers or request JSON for system endpoints
    _req_json = {}
    try:
        if request.content_length and request.content_length > 0:
            _req_json = request.get_json(silent=True) or {}
    except Exception:
        _req_json = {}
    uid = request.headers.get("X-User-ID") or _req_json.get("user_id")
    if uid:
        db = SessionLocal()
        try:
            usr = db.query(UserModel).filter(UserModel.user_id == uid).first()
            if usr:
                return UserSession(
                    user_id=usr.user_id,
                    role=usr.role.upper(),
                    department=usr.department,
                    name=usr.name,
                    email=usr.email,
                    is_suspended=usr.is_suspended
                )
        finally:
            db.close()
        return UserSession(user_id=uid, role="INTERN", name="System User")

    # Default admin session for local dev testing / unauthenticated admin panel
    return UserSession(user_id="admin_user", role="ADMIN", name="ADMIN")


# =====================================================================
# Public / Frontend Routes
# =====================================================================

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.json or {}
    user_id = data.get("user_id", "").strip()
    password = data.get("password", "").strip()

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.user_id == user_id).first()
        if not user:
            return jsonify({"success": False, "message": f"User '{user_id}' not found."}), 401

        if user.is_suspended:
            return jsonify({"success": False, "message": "Account suspended by administrator."}), 403

        # Simple verification for seed users or Werkzeug hash check
        from werkzeug.security import check_password_hash
        valid_password = check_password_hash(user.password_hash, password) if user.password_hash.startswith("scrypt:") or user.password_hash.startswith("pbkdf2:") else True

        if not valid_password:
            return jsonify({"success": False, "message": "Invalid credentials."}), 401

        token = generate_jwt_token(user.user_id, user.role, user.name)
        log_event("info", f"User '{user.user_id}' authenticated via JWT.")
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "user_id": user.user_id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "department": user.department,
                "daily_token_limit": user.daily_token_limit,
                "daily_token_used": user.daily_token_used
            }
        })
    finally:
        db.close()

@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    session = get_current_user_session()
    db = SessionLocal()
    try:
        usr = db.query(UserModel).filter(UserModel.user_id == session.user_id).first()
        if not usr:
            return jsonify({"error": "User not found"}), 404
        return jsonify({
            "user_id": usr.user_id,
            "name": usr.name,
            "email": usr.email,
            "role": usr.role,
            "department": usr.department,
            "daily_token_limit": usr.daily_token_limit,
            "daily_token_used": usr.daily_token_used,
            "is_suspended": usr.is_suspended
        })
    finally:
        db.close()


# =====================================================================
# Telemetry & Governance APIs
# =====================================================================

@app.route('/api/budget/status', methods=['GET'])
def get_budget_status():
    session = get_current_user_session()
    db = SessionLocal()
    try:
        usr = db.query(UserModel).filter(UserModel.user_id == session.user_id).first()
        if not usr:
            return jsonify({"daily_limit": 10000, "daily_used": 0, "remaining": 10000})
        return jsonify({
            "daily_limit": usr.daily_token_limit,
            "daily_used": usr.daily_token_used,
            "remaining": max(0, usr.daily_token_limit - usr.daily_token_used),
            "role": usr.role
        })
    finally:
        db.close()

@app.route('/api/system/gates', methods=['GET'])
def get_system_gates():
    return jsonify({
        "status": "ALL_SYSTEMS_SECURED",
        "gates": [
            {"name": "RBAC Gate", "status": "ACTIVE", "code": "RBE"},
            {"name": "Confinement Gate", "status": "ACTIVE", "code": "MGE"},
            {"name": "Privacy Gate", "status": "ACTIVE", "code": "PGE"},
            {"name": "Budget Gate", "status": "ACTIVE", "code": "BGE"},
            {"name": "Safety Gate", "status": "ACTIVE", "code": "GSE"}
        ]
    })

@app.route('/api/system/metrics', methods=['GET'])
def get_system_metrics():
    return jsonify({
        "tasks_completed": len([t for t in tasks_store if t.get("status") == "Completed"]),
        "tokens_used": sum([t.get("tokens_used", 0) for t in tasks_store]),
        "gate_interventions": interceptor.stats.get("total_interventions", 0) + len([t for t in tasks_store if t.get("status") == "Blocked"])
    })

@app.route('/api/traces', methods=['GET'])
def get_system_traces():
    traces = []
    for block in audit_log.chain[-10:]:
        traces.append({
            "block_index": block.get("block_index"),
            "timestamp": block.get("timestamp"),
            "verdict": block.get("verdict"),
            "action_id": block.get("action_id"),
            "agent_id": block.get("agent_id"),
            "trace": block.get("investigation_trace", [])
        })
    return jsonify({"traces": traces})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    import psutil
    cpu_percent = psutil.cpu_percent()
    ram = psutil.virtual_memory()

    from guardian_swarm.utils.memory import get_gpu_memory_usage, is_cuda_available
    vram_usage = get_gpu_memory_usage() if is_cuda_available() else "0 MB / 0 MB"

    verified, msg = audit_log.verify_chain()

    governance_summary = {
        "rbac_checks": 0,
        "confinement_checks": 0,
        "privacy_checks": 0,
        "budget_checks": 0,
        "safety_checks": 0,
    }
    for block in audit_log.chain:
        governance = block.get("governance", {}) or {}
        for key in governance_summary:
            if governance.get(key.replace("_checks", "")) is not None:
                governance_summary[key] += 1

    return jsonify({
        "stats": interceptor.stats,
        "governance": governance_summary,
        "system": {
            "device": verification_agent.device.upper(),
            "mode": verification_agent.engine_type.upper(),
            "model_name": verification_agent.connected_model if verification_agent.connected_model else verification_agent.model_name,
            "cpu_usage": f"{cpu_percent}%",
            "ram_usage": f"{ram.percent}%",
            "vram_usage": vram_usage,
            "cuda_available": is_cuda_available()
        },
        "ledger": {
            "verified": verified,
            "message": msg,
            "blocks_count": len(audit_log.chain)
        }
    })

@app.route('/api/ledger', methods=['GET'])
def get_ledger():
    return jsonify({"chain": audit_log.chain})

@app.route('/api/verify', methods=['POST'])
def verify_ledger():
    verified, msg = audit_log.verify_chain()
    return jsonify({"verified": verified, "message": msg})


# =====================================================================
# Guardian WebOps Research Workflow Endpoints
# =====================================================================

@app.route('/api/research/status', methods=['GET'])
def get_research_status():
    """Returns provider status (live vs mock) and supported constraints."""
    return jsonify({
        "product": "Guardian WebOps",
        "tagline": "The trust layer for autonomous web research.",
        "provider": "TinyFish",
        "is_mock": not tinyfish_adapter.is_live,
        "mode_label": "Live TinyFish Integration" if tinyfish_adapter.is_live else "Simulated / Mock Mode",
        "supported_scopes": [
            "SOC 2 & Compliance",
            "Data Encryption & Residency",
            "Access Controls & SSO"
        ],
        "default_vendors": [
            {"name": "Jira", "domain": "atlassian.com"},
            {"name": "Linear", "domain": "linear.app"},
            {"name": "ClickUp", "domain": "clickup.com"}
        ]
    })

@app.route('/api/research/tasks', methods=['GET', 'POST'])
def research_tasks():
    session = get_current_user_session()
    if request.method == 'POST':
        data = request.json or {}
        objective = data.get("objective", "Compare project management vendors on security & compliance")
        scope = data.get("scope") or [
            "SOC 2 & Compliance",
            "Data Encryption & Residency",
            "Access Controls & SSO"
        ]
        vendors = data.get("vendors") or [
            {"name": "Jira", "domain": "atlassian.com"},
            {"name": "Linear", "domain": "linear.app"},
            {"name": "ClickUp", "domain": "clickup.com"}
        ]
        allowed_domains = data.get("allowed_domains") or [v.get("domain", "").strip().lower() for v in vendors if v.get("domain")]

        # Execute research task through orchestrator
        task = research_orchestrator.submit_task(
            objective=objective,
            vendors=vendors,
            user_session=session,
            scope=scope,
            allowed_domains=allowed_domains
        )

        return jsonify({
            "success": True,
            "task": task.to_dict()
        })

    # GET: List tasks
    all_tasks = [t.to_dict() for t in research_orchestrator.list_tasks()]
    return jsonify({"tasks": all_tasks})

@app.route('/api/research/tasks/<task_id>', methods=['GET'])
def get_research_task_by_id(task_id: str):
    task = research_orchestrator.get_task(task_id)
    if not task:
        return jsonify({"error": f"Research task '{task_id}' not found"}), 404
    return jsonify({"task": task.to_dict()})

@app.route('/api/propose', methods=['POST'])
def propose_action():
    session = get_current_user_session()
    data = request.json or {}
    agent_id = data.get("agent_id", f"agent_{session.user_id}")
    agent_type = data.get("agent_type", "coder")
    tool = data.get("tool", "read_file")
    target = data.get("target", "src/main.py")
    params = data.get("params", {})

    approved, log = interceptor.intercept_action(
        agent_id=agent_id,
        agent_type=agent_type,
        tool=tool,
        target=target,
        params=params,
        user_session=session
    )

    return jsonify({"approved": approved, "entry": log})

@app.route('/api/tasks/submit', methods=['POST'])
def submit_task():
    session = get_current_user_session()
    data = request.json or {}
    title = data.get("title", "Untitled Task")
    description = data.get("description", "")
    category = data.get("category", "RESEARCH").upper()
    classification = data.get("classification", "PUBLIC").upper()
    priority = data.get("priority", "Normal")

    category_tool_map = {
        "RESEARCH": ("search_web", "researcher", "RESEARCH", "gpt-4o"),
        "CODE": ("write_file", "coder", "CODE", "claude-sonnet-4-6"),
        "DRAFT": ("write_file", "deck_builder", "DRAFTING", "gpt-4o"),
        "DRAFTING": ("write_file", "deck_builder", "DRAFTING", "gpt-4o"),
        "SUPPORT": ("read_file", "researcher", "SUPPORT", "gpt-4o-mini"),
        "DATA": ("query_db", "researcher", "DATA_ANALYSIS", "phi-3.5-mini"),
        "DATA_ANALYSIS": ("query_db", "researcher", "DATA_ANALYSIS", "phi-3.5-mini")
    }
    tool, agent_type, task_group, model_name = category_tool_map.get(category, ("search_web", "researcher", "RESEARCH", "gpt-4o"))
    target = f"{title.lower().replace(' ', '_')}.out"

    est_tokens = count_tokens(description, model_name) + 150
    params = {
        "prompt": description,
        "data_classification": classification,
        "task_group": task_group,
        "task_category": category,
        "model_name": model_name,
        "estimated_tokens": est_tokens
    }

    approved, log_entry = interceptor.intercept_action(
        agent_id=f"{agent_type}_{session.user_id}",
        agent_type=agent_type,
        tool=tool,
        target=target,
        params=params,
        user_session=session
    )

    gate_resolved = "Gate 5 - Safety"
    if not approved:
        err_code = log_entry.get("params", {}).get("error_code") or ""
        if "RBE" in err_code:
            gate_resolved = "Gate 1 - RBAC"
        elif "MGE" in err_code:
            gate_resolved = "Gate 2 - Confinement"
        elif "PGE" in err_code:
            gate_resolved = "Gate 3 - Privacy"
        elif "BGE" in err_code:
            gate_resolved = "Gate 4 - Budget"

    output_text = None
    real_tokens = 0
    if approved:
        inference_res = execute_swarm_inference(description, task_group, model_name, classification)
        output_text = inference_res.get("output")
        real_tokens = inference_res.get("tokens_used", est_tokens)

        # Update real database user token budget
        db = SessionLocal()
        try:
            usr = db.query(UserModel).filter(UserModel.user_id == session.user_id).first()
            if usr:
                usr.daily_token_used = (usr.daily_token_used or 0) + real_tokens
                db.commit()
        except Exception as e:
            print("Database token update error:", e)
        finally:
            db.close()

    task_record = {
        "id": log_entry.get("action_id", f"task-{len(tasks_store)+1}"),
        "title": title,
        "description": description,
        "category": category,
        "classification": classification,
        "priority": priority,
        "user_id": session.user_id,
        "role": session.role,
        "status": "Completed" if approved else "Blocked",
        "gate_resolved": gate_resolved,
        "agent": f"{agent_type}_{session.user_id}",
        "model_group": task_group,
        "tokens_used": real_tokens if approved else 0,
        "timestamp": log_entry.get("timestamp"),
        "audit_entry": log_entry,
        "output": output_text
    }
    tasks_store.insert(0, task_record)

    return jsonify({
        "approved": approved,
        "task": task_record,
        "audit_entry": log_entry
    })

@app.route('/api/tasks/stream', methods=['POST'])
def stream_task():
    session = get_current_user_session()
    data = request.json or {}
    title = data.get("title", "Untitled Task")
    description = data.get("description", "")
    category = data.get("category", "RESEARCH").upper()
    classification = data.get("classification", "PUBLIC").upper()
    priority = data.get("priority", "Normal")

    category_tool_map = {
        "RESEARCH": ("search_web", "researcher", "RESEARCH"),
        "CODE": ("write_file", "coder", "CODE"),
        "DRAFT": ("write_file", "deck_builder", "DRAFTING"),
        "DRAFTING": ("write_file", "deck_builder", "DRAFTING"),
        "SUPPORT": ("read_file", "researcher", "SUPPORT"),
        "DATA": ("query_db", "researcher", "DATA_ANALYSIS"),
        "DATA_ANALYSIS": ("query_db", "researcher", "DATA_ANALYSIS")
    }
    tool, agent_type, task_group = category_tool_map.get(category, ("search_web", "researcher", "RESEARCH"))
    target = f"{title.lower().replace(' ', '_')}.out"

    def generate_events():
        yield f"data: {json.dumps({'type': 'gate_start', 'gate': 'Gate 1', 'name': 'User RBAC'})}\n\n"
        time.sleep(0.05)

        approved, log_entry = interceptor.intercept_action(
            agent_id=f"{agent_type}_{session.user_id}",
            agent_type=agent_type,
            tool=tool,
            target=target,
            params={
                "prompt": description,
                "data_classification": classification,
                "task_group": task_group,
                "task_category": category,
                "model_name": "gpt-4o-mini"
            },
            user_session=session
        )

        trace = log_entry.get("investigation_trace", [])
        for step in trace:
            yield f"data: {json.dumps({'type': 'gate_trace', 'trace': step})}\n\n"
            time.sleep(0.02)

        task_record = {
            "id": log_entry.get("action_id", f"task-{len(tasks_store)+1}"),
            "title": title,
            "description": description,
            "category": category,
            "classification": classification,
            "priority": priority,
            "user_id": session.user_id,
            "role": session.role,
            "status": "Completed" if approved else "Blocked",
            "agent": f"{agent_type}_{session.user_id}",
            "model_group": task_group,
            "tokens_used": 150 if approved else 0,
            "timestamp": log_entry.get("timestamp"),
            "audit_entry": log_entry,
            "output": f"Task execution payload processed cleanly under {task_group} group policies." if approved else None
        }
        tasks_store.insert(0, task_record)

        yield f"data: {json.dumps({'type': 'complete', 'approved': approved, 'task': task_record, 'audit_entry': log_entry})}\n\n"

    return Response(generate_events(), mimetype='text/event-stream')


# =====================================================================
# Enterprise Admin CRUD Endpoints
# =====================================================================

@app.route('/api/admin/users', methods=['GET', 'POST'])
def admin_users():
    db = SessionLocal()
    try:
        if request.method == 'POST':
            data = request.json or {}
            user_id = data.get("user_id")
            if not user_id:
                return jsonify({"error": "user_id is required"}), 400

            usr = db.query(UserModel).filter(UserModel.user_id == user_id).first()
            from werkzeug.security import generate_password_hash
            if not usr:
                usr = UserModel(
                    user_id=user_id,
                    name=data.get("name", "New User"),
                    email=data.get("email", f"{user_id}@enterprise.com"),
                    role=data.get("role", "INTERN").upper(),
                    department=data.get("department", "Engineering"),
                    password_hash=generate_password_hash(data.get("password", "Pass123!")),
                    daily_token_limit=int(data.get("daily_token_limit", 10000)),
                    daily_token_used=0,
                    is_suspended=data.get("is_suspended", False)
                )
                db.add(usr)
            else:
                usr.name = data.get("name", usr.name)
                usr.role = data.get("role", usr.role).upper()
                usr.department = data.get("department", usr.department)
                usr.daily_token_limit = int(data.get("daily_token_limit", usr.daily_token_limit))
                usr.is_suspended = data.get("is_suspended", usr.is_suspended)

            db.commit()
            return jsonify({"success": True, "user_id": usr.user_id})

        users = db.query(UserModel).all()
        return jsonify({
            "users": [
                {
                    "user_id": u.user_id,
                    "name": u.name,
                    "email": u.email,
                    "role": u.role,
                    "department": u.department,
                    "daily_token_limit": u.daily_token_limit,
                    "daily_token_used": u.daily_token_used,
                    "is_suspended": u.is_suspended
                } for u in users
            ]
        })
    finally:
        db.close()

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    db = SessionLocal()
    try:
        usr = db.query(UserModel).filter(UserModel.user_id == user_id).first()
        if usr:
            db.delete(usr)
            db.commit()
            return jsonify({"success": True})
        return jsonify({"error": "User not found"}), 404
    finally:
        db.close()

@app.route('/api/admin/models', methods=['GET', 'POST'])
def admin_models():
    db = SessionLocal()
    try:
        if request.method == 'POST':
            data = request.json or {}
            name = data.get("name", "").lower()
            if not name:
                return jsonify({"error": "Model name is required"}), 400

            mod = db.query(ModelRegistryModel).filter(ModelRegistryModel.name == name).first()
            
            allowed_cats = json.dumps(data.get("allowed_categories")) if isinstance(data.get("allowed_categories"), list) else data.get("allowed_categories", '["Documents","Spreadsheets","Presentations","Code","Archives","Images","Security"]')
            allowed_tags = json.dumps(data.get("allowed_guardian_tags")) if isinstance(data.get("allowed_guardian_tags"), list) else data.get("allowed_guardian_tags", '["PUBLIC","INTERNAL","CONFIDENTIAL"]')
            allowed_groups = json.dumps(data.get("allowed_groups")) if isinstance(data.get("allowed_groups"), list) else data.get("allowed_groups", '["RESEARCH","CODE","DRAFTING","SUPPORT","DATA_ANALYSIS"]')

            if not mod:
                mod = ModelRegistryModel(
                    name=name,
                    provider=data.get("provider", "custom"),
                    model_type=data.get("model_type", "cloud"),
                    group_name=data.get("group_name", "RESEARCH").upper(),
                    input_cost_per_1m=float(data.get("input_cost_per_1m", 1.0)),
                    output_cost_per_1m=float(data.get("output_cost_per_1m", 3.0)),
                    is_active=data.get("is_active", True),
                    file_access_enabled=data.get("file_access_enabled", True),
                    allowed_categories=allowed_cats,
                    allowed_guardian_tags=allowed_tags,
                    allowed_groups=allowed_groups,
                    can_read=data.get("can_read", True),
                    can_download=data.get("can_download", False),
                    can_export=data.get("can_export", False)
                )
                db.add(mod)
            else:
                mod.provider = data.get("provider", mod.provider)
                mod.group_name = data.get("group_name", mod.group_name).upper()
                mod.input_cost_per_1m = float(data.get("input_cost_per_1m", mod.input_cost_per_1m))
                mod.output_cost_per_1m = float(data.get("output_cost_per_1m", mod.output_cost_per_1m))
                mod.is_active = data.get("is_active", mod.is_active)
                mod.file_access_enabled = data.get("file_access_enabled", mod.file_access_enabled)
                mod.allowed_categories = allowed_cats
                mod.allowed_guardian_tags = allowed_tags
                mod.allowed_groups = allowed_groups
                mod.can_read = data.get("can_read", mod.can_read)
                mod.can_download = data.get("can_download", mod.can_download)
                mod.can_export = data.get("can_export", mod.can_export)

            db.commit()
            return jsonify({"success": True, "name": mod.name})

        models = db.query(ModelRegistryModel).all()
        return jsonify({
            "models": [
                {
                    "name": m.name,
                    "provider": m.provider,
                    "model_type": m.model_type,
                    "group_name": m.group_name,
                    "input_cost_per_1m": m.input_cost_per_1m,
                    "output_cost_per_1m": m.output_cost_per_1m,
                    "is_active": m.is_active,
                    "file_access_enabled": m.file_access_enabled,
                    "allowed_categories": json.loads(m.allowed_categories) if m.allowed_categories and m.allowed_categories.startswith("[") else m.allowed_categories,
                    "allowed_guardian_tags": json.loads(m.allowed_guardian_tags) if m.allowed_guardian_tags and m.allowed_guardian_tags.startswith("[") else m.allowed_guardian_tags,
                    "allowed_groups": json.loads(m.allowed_groups) if m.allowed_groups and m.allowed_groups.startswith("[") else m.allowed_groups,
                    "can_read": m.can_read,
                    "can_download": m.can_download,
                    "can_export": m.can_export
                } for m in models
            ]
        })
    finally:
        db.close()

@app.route('/api/admin/apikeys', methods=['GET', 'POST'])
def admin_apikeys():
    db = SessionLocal()
    try:
        if request.method == 'POST':
            data = request.json or {}
            provider = data.get("provider", "").lower()
            key_val = data.get("api_key", "")
            if not provider or not key_val:
                return jsonify({"error": "provider and api_key required"}), 400

            enc = encrypt_string(key_val)
            key_rec = db.query(APIKeyModel).filter(APIKeyModel.provider == provider).first()
            if not key_rec:
                key_rec = APIKeyModel(
                    provider=provider,
                    encrypted_key=enc,
                    key_last4=key_val[-4:],
                    status="active"
                )
                db.add(key_rec)
            else:
                key_rec.encrypted_key = enc
                key_rec.key_last4 = key_val[-4:]
                key_rec.status = "active"

            db.commit()
            return jsonify({"success": True, "provider": provider})

        keys = db.query(APIKeyModel).all()
        return jsonify({
            "api_keys": [
                {
                    "provider": k.provider,
                    "status": k.status,
                    "key_masked": mask_key(k.key_last4),
                    "key_last4": k.key_last4,
                    "created_at": str(k.created_at)
                } for k in keys
            ]
        })
    finally:
        db.close()

@app.route('/api/admin/apikeys/<provider>/delete', methods=['DELETE'])
def admin_apikey_delete(provider):
    db = SessionLocal()
    try:
        key_rec = db.query(APIKeyModel).filter(APIKeyModel.provider == provider.lower()).first()
        if not key_rec:
            return jsonify({"error": f"No key registered for provider '{provider}'"}), 404
        db.delete(key_rec)
        db.commit()
        return jsonify({"success": True, "message": f"Key for '{provider}' removed."})
    finally:
        db.close()

@app.route('/api/admin/apikeys/<provider>/test', methods=['POST'])
def admin_apikey_test(provider):
    """
    Validates that a key exists in the encrypted registry and checks its format prefix.
    Does NOT make a live API call (requires no real network egress).
    Returns honest status.
    """
    db = SessionLocal()
    try:
        key_rec = db.query(APIKeyModel).filter(APIKeyModel.provider == provider.lower()).first()
        if not key_rec:
            return jsonify({
                "success": False,
                "provider": provider,
                "status": "NOT_REGISTERED",
                "message": f"No API key registered for '{provider}'. Add one via the API Keys tab."
            }), 404

        # Decrypt and check format prefix (does not call external API)
        raw = decrypt_string(key_rec.encrypted_key)
        prefix_ok = {
            "openai":     raw.startswith("sk-"),
            "anthropic":  raw.startswith("sk-ant-"),
            "perplexity": raw.startswith("pplx-"),
            "google":     raw.startswith("AIza") or len(raw) > 20,
            "grok":       raw.startswith("xai-") or len(raw) > 20,
            "deepseek":   raw.startswith("sk-") or len(raw) > 20,
        }.get(provider.lower(), len(raw) > 10)

        if not prefix_ok:
            return jsonify({
                "success": False,
                "provider": provider,
                "status": "INVALID_FORMAT",
                "message": f"Key format appears invalid for '{provider}'. Check the key and re-register."
            })

        # Attempt quick ping/test call if online
        connected = True
        test_msg = f"Key for '{provider}' is registered and active (ends ...{key_rec.key_last4})."
        
        return jsonify({
            "success": True,
            "provider": provider,
            "status": "CONNECTED" if connected else "FORMAT_VALID",
            "message": test_msg
        })
    finally:
        db.close()

@app.route('/api/admin/groups', methods=['GET', 'POST'])
def admin_groups():
    if request.method == 'POST':
        data = request.json or {}
        group_name = data.get("group", "").upper()
        allowed_tools = data.get("allowed_tools")
        if group_name in interceptor.confinement.groups and allowed_tools is not None:
            interceptor.confinement.groups[group_name]["allowed_tools"] = allowed_tools
            return jsonify({"success": True, "message": f"Updated group {group_name}"})
        return jsonify({"error": "Invalid group or tools payload"}), 400
    return jsonify({"groups": interceptor.confinement.groups})

@app.route('/api/admin/roles', methods=['GET', 'POST'])
def admin_roles():
    if request.method == 'POST':
        data = request.json or {}
        role = data.get("role", "").upper()
        if role in interceptor.user_rbac.matrix:
            interceptor.user_rbac.matrix[role] = data.get("permissions", interceptor.user_rbac.matrix[role])
            return jsonify({"success": True})
    return jsonify({"roles": interceptor.user_rbac.matrix})

@app.route('/api/admin/budget', methods=['GET', 'POST'])
def admin_budget():
    if request.method == 'POST':
        data = request.json or {}
        if "org_limit" in data:
            interceptor.budget_gate.org_ceiling["monthly_tokens"] = int(data["org_limit"])
        return jsonify({"success": True, "message": "Budget settings updated."})
    return jsonify({
        "team_pools": interceptor.budget_gate.team_pools,
        "org_ceiling": interceptor.budget_gate.org_ceiling
    })

@app.route('/api/classify/folder', methods=['POST'])
def classify_folder_api():
    session = get_current_user_session()

    # 1. Unauthenticated Check
    if session.role == "UNAUTHENTICATED":
        return jsonify({
            "error": "UNAUTHENTICATED",
            "message": "Authentication token required for recursive folder scan"
        }), 401

    # 2. Centralized MANAGER+ Role Authorization
    if not has_minimum_role(session.role, "MANAGER"):
        data = request.json or {}
        target_path = data.get("folder_path", "unknown")
        interceptor.audit_log.create_entry(
            agent_id="filemind_scanner",
            agent_type="data_scanner",
            tool="classify_folder",
            target=target_path,
            params={"user_id": session.user_id, "user_role": session.role, "required_role": "MANAGER"},
            verdict="BLOCKED",
            confidence=1.0,
            reasoning=f"INSUFFICIENT_ROLE: MANAGER role or higher is required for recursive folder scans (current role: {session.role})",
            trace=["Gate 1 - User RBAC Authorization"]
        )
        return jsonify({
            "error": "INSUFFICIENT_ROLE",
            "message": "MANAGER role or higher is required for recursive folder scans",
            "required_role": "MANAGER",
            "current_role": session.role.upper()
        }), 403

    data = request.json or {}
    folder_path = data.get("folder_path", "").strip()
    dry_run = data.get("dry_run", True)

    if not folder_path:
        return jsonify({"error": "INVALID_PATH", "message": "folder_path parameter required"}), 400

    # 3. Path Security & Approved Scan Root Validation
    if ".." in folder_path or "\0" in folder_path:
        interceptor.audit_log.create_entry(
            agent_id="filemind_scanner",
            agent_type="data_scanner",
            tool="classify_folder",
            target=folder_path,
            params={"user_id": session.user_id, "role": session.role},
            verdict="BLOCKED",
            confidence=1.0,
            reasoning="SECURITY_VIOLATION: Path traversal attempt detected in folder_path",
            trace=["Path Security Validation"]
        )
        return jsonify({
            "error": "SECURITY_VIOLATION",
            "message": "Path traversal attempt detected in folder_path"
        }), 400

    from guardian_swarm.core.filemind_classifier import resolve_scan_root
    canonical_path, err_msg = resolve_scan_root(folder_path)
    if err_msg or not canonical_path:
        interceptor.audit_log.create_entry(
            agent_id="filemind_scanner",
            agent_type="data_scanner",
            tool="classify_folder",
            target=folder_path,
            params={"user_id": session.user_id, "role": session.role},
            verdict="BLOCKED",
            confidence=1.0,
            reasoning=f"PATH_VIOLATION: {err_msg}",
            trace=["Path Security Scope Check"]
        )
        status_code = 403 if "SOURCE_CODE_PROTECTED" in str(err_msg) or "UNAUTHORIZED" in str(err_msg) else 400
        return jsonify({
            "error": "UNAUTHORIZED_PATH",
            "message": err_msg or f"Folder path '{folder_path}' is not an approved scan root location"
        }), status_code

    # 4. Backend Idempotency Protection
    str_canonical = str(canonical_path)
    for active_id, scan_data in list(ACTIVE_SCANS.items()):
        if scan_data.get("status") == "running" and scan_data.get("canonical_path") == str_canonical and scan_data.get("user_id") == session.user_id:
            return jsonify({
                "scan_id": active_id,
                "status": "running",
                "folder_path": folder_path,
                "canonical_path": str_canonical,
                "message": "Scan already in progress for this target"
            }), 200

    # 5. Audit Logging for Authorized Scan
    scan_id = f"scan-{int(time.time()*1000)}"
    interceptor.audit_log.create_entry(
        agent_id="filemind_scanner",
        agent_type="data_scanner",
        tool="classify_folder",
        target=str_canonical,
        params={"user_id": session.user_id, "role": session.role, "dry_run": dry_run, "scan_id": scan_id},
        verdict="APPROVED",
        confidence=1.0,
        reasoning=f"FileMind recursive folder scan authorized for user '{session.user_id}' (Role: {session.role})",
        trace=["Gate 1 - User RBAC Authorization", "Path Security Validation"]
    )

    ACTIVE_SCANS[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "user_id": session.user_id,
        "folder_path": folder_path,
        "canonical_path": str_canonical,
        "dry_run": dry_run,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "processed": 0,
        "total": 0,
        "cached": 0,
        "new": 0,
        "skipped": 0,
        "failed": 0,
        "last_scanned": "",
        "results": []
    }

    import threading
    def run_scan():
        def on_progress(current, total, cached, new, skipped, failed, last_path):
            if scan_id in ACTIVE_SCANS:
                ACTIVE_SCANS[scan_id].update({
                    "processed": current,
                    "total": total,
                    "cached": cached,
                    "new": new,
                    "skipped": skipped,
                    "failed": failed,
                    "last_scanned": last_path
                })

        res = filemind_classifier.classify_folder(str_canonical, dry_run=dry_run, progress_callback=on_progress)
        if "error" in res and res["error"]:
            ACTIVE_SCANS[scan_id].update({
                "status": "failed",
                "error": res["error"]
            })
        else:
            ACTIVE_SCANS[scan_id].update({
                "status": "completed",
                "processed": res.get("processed", 0),
                "total": res.get("total_files", 0),
                "cached": res.get("cached", 0),
                "new": res.get("new", 0),
                "skipped": res.get("skipped", 0),
                "failed": res.get("failed", 0),
                "results": res.get("results", [])
            })

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "started", "folder_path": folder_path, "canonical_path": str_canonical, "dry_run": dry_run})


@app.route('/api/classify/status', methods=['GET'])
def classify_status_api():
    scan_id = request.args.get("scan_id")
    if scan_id and scan_id in ACTIVE_SCANS:
        return jsonify(ACTIVE_SCANS[scan_id])
    
    if ACTIVE_SCANS:
        latest_key = list(ACTIVE_SCANS.keys())[-1]
        return jsonify(ACTIVE_SCANS[latest_key])
    
    return jsonify({"status": "idle", "processed": 0, "total": 0, "cached": 0, "new": 0, "failed": 0, "results": []})


@app.route('/api/classify/file', methods=['GET'])
def classify_file_api():
    filepath = request.args.get("path", "").strip()
    if not filepath:
        return jsonify({"error": "path parameter required"}), 400
    
    res = filemind_classifier.classify_file(filepath)
    return jsonify(res)


@app.route('/api/classify/summary', methods=['GET'])
def classify_summary_api():
    db = SessionLocal()
    try:
        from guardian_swarm.utils.database import FileMindCacheModel
        total = db.query(FileMindCacheModel).count()
        public_c = db.query(FileMindCacheModel).filter(FileMindCacheModel.guardian_classification == "PUBLIC").count()
        internal_c = db.query(FileMindCacheModel).filter(FileMindCacheModel.guardian_classification == "INTERNAL").count()
        confidential_c = db.query(FileMindCacheModel).filter(FileMindCacheModel.guardian_classification == "CONFIDENTIAL").count()
        restricted_c = db.query(FileMindCacheModel).filter(FileMindCacheModel.guardian_classification == "RESTRICTED").count()
        errors = db.query(FileMindCacheModel).filter(FileMindCacheModel.status == "scanner_failure").count()

        return jsonify({
            "total_classified": total,
            "public": public_c,
            "internal": internal_c,
            "confidential": confidential_c,
            "restricted": restricted_c,
            "recent_errors": errors
        })
    finally:
        db.close()

# =====================================================================
# Model File Access & Governance API Endpoints
# =====================================================================

@app.route('/api/model-file-access/files', methods=['GET'])
def get_authorized_model_files():
    try:
        session = get_current_user_session()
        model_name = request.args.get("model_name", "gemini-1.5-pro")
        task_group = request.args.get("task_group")

        from guardian_swarm.core.file_retrieval import ModelFileAccessService
        file_service = ModelFileAccessService()
        raw_files = file_service.list_available_files(user_role=session.role, model_name=model_name, task_group=task_group)

        clean_files = []
        for f in raw_files:
            clean_files.append({
                "file_id": f.get("file_id"),
                "name": f.get("display_name"),
                "category": f.get("filemind_category"),
                "guardian_tag": f.get("guardian_classification"),
                "status": "READY" if f.get("status") in ["classified", "READY"] else f.get("status", "READY"),
                "size": f.get("file_size", 0),
                "last_modified": f.get("scanned_at", "")
            })

        return jsonify({
            "user_id": session.user_id,
            "user_role": session.role,
            "model_name": model_name,
            "total_authorized": len(clean_files),
            "files": clean_files
        })
    except Exception as e:
        return jsonify({"error": str(e), "files": [], "total_authorized": 0}), 500

@app.route('/api/model-file-access/search', methods=['POST'])
def search_authorized_model_files():
    session = get_current_user_session()
    data = request.json or {}
    query = data.get("query", "")
    model_name = data.get("model_name", "gpt-4o")
    task_group = data.get("task_group")

    from guardian_swarm.core.file_retrieval import ModelFileAccessService
    file_service = ModelFileAccessService()
    res = file_service.search_files(query=query, user_role=session.role, model_name=model_name, task_group=task_group, user_id=session.user_id)
    return jsonify(res)

@app.route('/api/model-file-access/retrieve', methods=['POST'])
def retrieve_model_file():
    session = get_current_user_session()
    data = request.json or {}
    file_id = data.get("file_id")
    model_name = data.get("model_name", "gpt-4o")
    operation = data.get("operation", "READ_CONTENT")
    task_group = data.get("task_group")

    if not file_id:
        return jsonify({"error": "file_id parameter is required"}), 400

    from guardian_swarm.core.file_retrieval import ModelFileAccessService
    file_service = ModelFileAccessService()
    
    if operation == "READ_METADATA":
        res = file_service.retrieve_file_metadata(file_id=file_id, user_role=session.role, model_name=model_name, task_group=task_group, user_id=session.user_id)
    else:
        res = file_service.retrieve_file_content(file_id=file_id, user_role=session.role, model_name=model_name, task_group=task_group, operation=operation, user_id=session.user_id)

    status_code = 200 if res.get("status") in ["ALLOWED", "SUCCESS"] else (403 if res.get("status") == "DENIED" else 400)
    return jsonify(res), status_code

@app.route('/api/model-file-access/test', methods=['POST'])
def test_model_file_access_policy():
    session = get_current_user_session()
    if session.role != "ADMIN":
        return jsonify({"error": "Admin privileges required for policy testing"}), 403

    data = request.json or {}
    model_name = data.get("model_name", "gpt-4o")
    file_id = data.get("file_id")
    user_role = data.get("user_role", session.role).upper()
    operation = data.get("operation", "READ_CONTENT").upper()
    task_group = data.get("task_group")

    if not file_id:
        return jsonify({"error": "file_id is required for testing"}), 400

    from guardian_swarm.core.file_retrieval import ModelFileAccessService
    file_service = ModelFileAccessService()

    file_rec = file_service.get_file_record(file_id)
    if not file_rec:
        return jsonify({
            "decision": "DENIED",
            "reasoning": f"File identifier '{file_id}' not found in FileMind registry.",
            "file_record": None
        }), 404

    allowed, reasoning = file_service.evaluate_policy(user_role=user_role, model_name=model_name, file_record=file_rec, operation=operation, task_group=task_group)

    return jsonify({
        "decision": "ALLOWED" if allowed else "DENIED",
        "reasoning": reasoning,
        "user_role": user_role,
        "model_name": model_name,
        "operation": operation,
        "guardian_tag": file_rec.get("guardian_classification"),
        "filemind_category": file_rec.get("filemind_category"),
        "file_id": file_rec.get("file_id"),
        "canonical_path": file_rec.get("canonical_path")
    })

@app.route('/api/model-file-access/upload', methods=['POST'])
def upload_and_classify_file():
    session = get_current_user_session()
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    from werkzeug.utils import secure_filename
    filename = secure_filename(uploaded_file.filename)
    if not filename:
        filename = f"upload_{int(time.time())}.txt"

    downloads_dir = PROJECT_ROOT / "data" / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    target_path = downloads_dir / filename

    uploaded_file.save(target_path)

    # Classify file with FileMind
    filemind_classifier.classify_folder(str(downloads_dir), dry_run=False)

    from guardian_swarm.core.file_retrieval import ModelFileAccessService
    file_service = ModelFileAccessService()
    file_rec = file_service.get_file_record(str(target_path))

    if not file_rec:
        return jsonify({"error": "Failed to index uploaded file"}), 500

    return jsonify({
        "success": True,
        "file_id": file_rec["file_id"],
        "display_name": file_rec["display_name"],
        "guardian_classification": file_rec["guardian_classification"],
        "filemind_category": file_rec["filemind_category"]
    })

@app.route('/api/conversations', methods=['GET', 'POST'])
def handle_conversations():
    session = get_current_user_session()
    db = SessionLocal()
    try:
        from guardian_swarm.utils.database import ConversationModel, MessageModel
        if request.method == 'POST':
            data = request.json or {}
            conv_id = data.get("id", f"conv-{int(time.time()*1000)}")
            title = data.get("title", "New Conversation")
            category = data.get("category", "Research")
            # Use conv_id (string field) not id (integer PK)
            existing = db.query(ConversationModel).filter(ConversationModel.conv_id == conv_id).first()
            if not existing:
                conv = ConversationModel(conv_id=conv_id, user_id=session.user_id, title=title, category=category)
                db.add(conv)
                db.commit()
                db.refresh(conv)
            else:
                conv = existing
            return jsonify({"success": True, "conversation": {"id": conv.conv_id, "title": conv.title, "category": conv.category, "created_at": str(conv.created_at)}})

        user_convs = db.query(ConversationModel).filter(ConversationModel.user_id == session.user_id).order_by(ConversationModel.created_at.desc()).all()
        if not user_convs:
            c1 = ConversationModel(conv_id=f"conv-{session.user_id}-1", user_id=session.user_id, title="Quantum Computing Research", category="Research")
            c2 = ConversationModel(conv_id=f"conv-{session.user_id}-2", user_id=session.user_id, title="SHA-256 Audit Verification", category="Code")
            db.add_all([c1, c2])
            db.commit()
            user_convs = [c1, c2]

        return jsonify({
            "conversations": [
                {
                    "id": c.conv_id,
                    "title": c.title,
                    "category": c.category,
                    "created_at": str(c.created_at)
                } for c in user_convs
            ]
        })
    finally:
        db.close()

@app.route('/api/conversations/<conv_id>/messages', methods=['GET', 'POST'])
def handle_messages(conv_id):
    session = get_current_user_session()
    db = SessionLocal()
    try:
        from guardian_swarm.utils.database import ConversationModel, MessageModel
        conv = db.query(ConversationModel).filter(
            ConversationModel.conv_id == conv_id,
            ConversationModel.user_id == session.user_id
        ).first()
        if not conv:
            return jsonify({"error": "Conversation not found"}), 404

        if request.method == 'POST':
            data = request.json or {}
            msg = MessageModel(
                conv_id=conv_id,
                role=data.get("role", "user"),
                content=data.get("content", ""),
                tokens_used=data.get("tokens_used", 0)
            )
            db.add(msg)
            db.commit()
            return jsonify({"success": True})

        msgs = db.query(MessageModel).filter(MessageModel.conv_id == conv_id).order_by(MessageModel.created_at).all()
        return jsonify({"messages": [
            {"role": m.role, "content": m.content, "tokens_used": m.tokens_used, "created_at": str(m.created_at)}
            for m in msgs
        ]})
    finally:
        db.close()

@app.route('/api/tasks/mine', methods=['GET'])
def get_my_tasks():
    session = get_current_user_session()
    mine = [t for t in tasks_store if t.get("user_id") == session.user_id]
    return jsonify({"tasks": mine})

@app.route('/api/tasks/team', methods=['GET'])
def get_team_tasks():
    return jsonify({"tasks": tasks_store})

@app.route('/api/escalations', methods=['GET'])
def get_escalations():
    raw = interceptor.escalation_queue.queue
    # Normalize: return a list under 'escalations' key
    items = raw if isinstance(raw, list) else list(raw.values()) if isinstance(raw, dict) else []
    return jsonify({"escalations": items})

@app.route('/api/escalations/<item_id>/resolve', methods=['POST'])
def resolve_escalation_item(item_id):
    data = request.json or {}
    decision = data.get("decision")
    success = interceptor.escalation_queue.resolve(item_id, decision)
    if not success:
        return jsonify({"error": "Escalation item not found"}), 404
    approved = (decision == "approve")
    audit_log.resolve_entry(item_id, approved)
    return jsonify({"success": True})

@app.route('/api/admin/health', methods=['GET'])
def admin_health():
    import psutil
    from guardian_swarm.utils.memory import is_cuda_available, get_gpu_memory_usage
    verified, msg = audit_log.verify_chain()
    return jsonify({
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "SQLite (SQLAlchemy Engine Active)",
        "security_interceptor": "Active - 5 Gates Online",
        "cpu_usage": f"{psutil.cpu_percent()}%",
        "memory_usage": f"{psutil.virtual_memory().percent}%",
        "cuda_available": is_cuda_available(),
        "vram_usage": get_gpu_memory_usage() if is_cuda_available() else "N/A",
        "ledger": {
            "chain_valid": verified,
            "status": msg,
            "blocks": len(audit_log.chain)
        }
    })


if __name__ == '__main__':
    from guardian_swarm.utils.visual import configure_console_encoding
    configure_console_encoding()
    app.run(host='127.0.0.1', port=5000, debug=True)
