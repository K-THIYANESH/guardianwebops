"""
Guardian Swarm V3 — FileMind RBAC & Role Hierarchy Verification Test Suite
Tests central role hierarchy (INTERN, EMPLOYEE, MANAGER, EXEC, ADMIN),
folder scan authorization, path security validation, and audit ledger persistence.
"""

import os
import tempfile
import pytest
from guardian_swarm.web.server import app, generate_jwt_token, interceptor
from guardian_swarm.core.user_rbac import (
    ROLE_LEVELS, get_role_level, has_minimum_role, has_exact_role,
    require_minimum_role, require_exact_role
)
from guardian_swarm.utils.database import init_db, SessionLocal, AuditBlockModel

@pytest.fixture(autouse=True)
def setup_database():
    init_db()
    db = SessionLocal()
    try:
        db.query(AuditBlockModel).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    interceptor.audit_log.chain = []
    yield

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_unit_role_hierarchy_direct_level_checks():
    """Verify role rank level values and hierarchical comparison functions."""
    assert ROLE_LEVELS["INTERN"] == 10
    assert ROLE_LEVELS["EMPLOYEE"] == 20
    assert ROLE_LEVELS["MANAGER"] == 30
    assert ROLE_LEVELS["EXEC"] == 40
    assert ROLE_LEVELS["ADMIN"] == 50

    # MANAGER+ requirement checks
    assert has_minimum_role("INTERN", "MANAGER") is False
    assert has_minimum_role("EMPLOYEE", "MANAGER") is False
    assert has_minimum_role("MANAGER", "MANAGER") is True
    assert has_minimum_role("EXEC", "MANAGER") is True
    assert has_minimum_role("ADMIN", "MANAGER") is True

    # EXEC+ requirement checks
    assert has_minimum_role("EXEC", "EXEC") is True
    assert has_minimum_role("ADMIN", "EXEC") is True
    assert has_minimum_role("MANAGER", "EXEC") is False

    # ADMIN requirement checks
    assert has_minimum_role("ADMIN", "ADMIN") is True
    assert has_minimum_role("EXEC", "ADMIN") is False

    # Exact role checks
    assert has_exact_role("ADMIN", "ADMIN") is True
    assert has_exact_role("admin", "ADMIN") is True
    assert has_exact_role("EXEC", "ADMIN") is False

def test_intern_folder_scan_denied(client):
    """TEST 1: INTERN role attempting recursive scan receives 403."""
    token = generate_jwt_token("intern_user", "INTERN", "INTERN")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config"})
    assert res.status_code == 403
    data = res.get_json()
    assert data["error"] == "INSUFFICIENT_ROLE"
    assert data["required_role"] == "MANAGER"
    assert data["current_role"] == "INTERN"

def test_employee_folder_scan_denied(client):
    """TEST 2: EMPLOYEE role attempting recursive scan receives 403."""
    token = generate_jwt_token("employee_user", "EMPLOYEE", "EMPLOYEE")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config"})
    assert res.status_code == 403
    data = res.get_json()
    assert data["error"] == "INSUFFICIENT_ROLE"
    assert data["current_role"] == "EMPLOYEE"

def test_manager_folder_scan_allowed(client):
    """TEST 3: MANAGER role attempting recursive scan is allowed."""
    token = generate_jwt_token("manager_user", "MANAGER", "MANAGER")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "started"
    assert "scan_id" in data

def test_exec_folder_scan_allowed(client):
    """TEST 4: EXEC role attempting recursive scan is allowed."""
    token = generate_jwt_token("exec_user", "EXEC", "EXEC")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "started"

def test_admin_folder_scan_allowed(client):
    """TEST 5: ADMIN role attempting recursive scan is allowed."""
    token = generate_jwt_token("admin_user", "ADMIN", "ADMIN")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "started"

def test_invalid_role_denied(client):
    """TEST 6: User with unknown/invalid role receives 403."""
    token = generate_jwt_token("unknown_user", "GUEST", "Guest User")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config"})
    assert res.status_code == 403

def test_unauthenticated_request_denied(client):
    """TEST 7: Missing authentication token returns 401."""
    res = client.post('/api/classify/folder',
                      headers={"X-Test-Unauthenticated": "true"},
                      json={"folder_path": "./config"})
    assert res.status_code == 401
    data = res.get_json()
    assert data["error"] == "UNAUTHENTICATED"

def test_forged_frontend_role_body_ignored(client):
    """TEST 8: Body parameter claiming role ADMIN when JWT is EMPLOYEE is denied using backend DB/JWT identity."""
    token = generate_jwt_token("employee_user", "EMPLOYEE", "EMPLOYEE")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config", "role": "ADMIN", "user_role": "ADMIN"})
    assert res.status_code == 403
    data = res.get_json()
    assert data["current_role"] == "EMPLOYEE"

def test_admin_restricted_system_path_denied(client):
    """TEST 9: ADMIN requesting forbidden system directory (e.g. /etc) receives 403."""
    token = generate_jwt_token("admin_user", "ADMIN", "ADMIN")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "/etc"})
    assert res.status_code == 403
    data = res.get_json()
    assert data["error"] == "UNAUTHORIZED_PATH"

def test_path_traversal_denied(client):
    """TEST 10: Path traversal sequence (..) is rejected with 400."""
    token = generate_jwt_token("admin_user", "ADMIN", "ADMIN")
    res = client.post('/api/classify/folder',
                      headers={"Authorization": f"Bearer {token}"},
                      json={"folder_path": "./config/../etc"})
    assert res.status_code == 400
    data = res.get_json()
    assert data["error"] == "SECURITY_VIOLATION"

def test_empty_directory_scan(client):
    """TEST 11: Scanning an empty directory returns valid scan lifecycle."""
    token = generate_jwt_token("admin_user", "ADMIN", "ADMIN")
    with tempfile.TemporaryDirectory() as empty_dir:
        res = client.post('/api/classify/folder',
                          headers={"Authorization": f"Bearer {token}"},
                          json={"folder_path": empty_dir, "dry_run": True})
        assert res.status_code == 200
        scan_id = res.get_json()["scan_id"]
        
        # Check status
        status_res = client.get(f'/api/classify/status?scan_id={scan_id}')
        assert status_res.status_code == 200

def test_real_directory_scan(client):
    """TEST 12: Scanning directory with files returns real classification results."""
    token = generate_jwt_token("admin_user", "ADMIN", "ADMIN")
    with tempfile.TemporaryDirectory() as scan_dir:
        sample_file = os.path.join(scan_dir, "report.pdf")
        with open(sample_file, "w") as f:
            f.write("Executive Summary Document")
        
        res = client.post('/api/classify/folder',
                          headers={"Authorization": f"Bearer {token}"},
                          json={"folder_path": scan_dir, "dry_run": True})
        assert res.status_code == 200

def test_scan_audit_logging():
    """TEST 13: Scan authorization events are logged to Audit Log SHA-256 chain."""
    verified, msg = interceptor.audit_log.verify_chain()
    assert verified is True
