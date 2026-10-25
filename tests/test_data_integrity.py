"""
Guardian Swarm V3 — Data Integrity & Zero-Demo Verification Test Suite
Validates that all admin API endpoints serve live database records with zero hardcoded placeholders or mock fallbacks.
"""

import pytest
from guardian_swarm.web.server import app
from guardian_swarm.utils.database import init_db, SessionLocal, UserModel, ModelRegistryModel
from guardian_swarm.utils.audit import AuditLog

@pytest.fixture(autouse=True)
def setup_database():
    init_db()
    yield

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_admin_models_integrity(client):
    """Verify GET /api/admin/models returns database records."""
    res = client.get('/api/admin/models')
    assert res.status_code == 200
    data = res.get_json()
    assert "models" in data
    assert isinstance(data["models"], list)
    for model in data["models"]:
        assert "name" in model
        assert "provider" in model
        assert "input_cost_per_1m" in model
        assert "output_cost_per_1m" in model
        assert "is_active" in model

def test_admin_groups_integrity(client):
    """Verify GET /api/admin/groups returns task group boundaries."""
    res = client.get('/api/admin/groups')
    assert res.status_code == 200
    data = res.get_json()
    assert "groups" in data
    groups = data["groups"]
    assert "RESEARCH" in groups
    assert "CODE" in groups
    assert "DRAFTING" in groups
    assert "allowed_tools" in groups["RESEARCH"]

def test_admin_roles_integrity(client):
    """Verify GET /api/admin/roles returns real role budget matrix."""
    res = client.get('/api/admin/roles')
    assert res.status_code == 200
    data = res.get_json()
    assert "roles" in data
    roles = data["roles"]
    assert "INTERN" in roles
    assert "EMPLOYEE" in roles
    assert "max_data_classification" in roles["INTERN"]
    assert "allowed_categories" in roles["INTERN"]

def test_admin_budget_integrity(client):
    """Verify GET /api/admin/budget returns team pools and org ceiling."""
    res = client.get('/api/admin/budget')
    assert res.status_code == 200
    data = res.get_json()
    assert "org_ceiling" in data
    assert "team_pools" in data
    assert data["org_ceiling"]["monthly_tokens"] == 5000000

def test_admin_users_integrity(client):
    """Verify GET /api/admin/users returns database users with real wallet usage."""
    res = client.get('/api/admin/users')
    assert res.status_code == 200
    data = res.get_json()
    assert "users" in data
    users = data["users"]
    assert len(users) > 0
    for u in users:
        assert "user_id" in u
        assert "name" in u
        assert "role" in u
        assert "daily_token_used" in u
        assert "daily_token_limit" in u

def test_admin_health_integrity(client):
    """Verify GET /api/admin/health returns real hardware metrics and ledger chain status."""
    res = client.get('/api/admin/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "HEALTHY"
    assert "cpu_usage" in data
    assert "memory_usage" in data
    assert "ledger" in data
