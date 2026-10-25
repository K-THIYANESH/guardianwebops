"""
Unit & Integration Test Suite for Guardian Swarm V3 Model File Access & Governance
==================================================================================
Verifies policy enforcement, RBAC, model registry capabilities, file content extraction,
audit logging, prompt injection protection, and information disclosure prevention.
"""
import pytest
import os
import tempfile
import json
from pathlib import Path

from guardian_swarm.utils.database import init_db, SessionLocal, FileMindCacheModel, ModelRegistryModel, UserModel
from guardian_swarm.core.file_retrieval import ModelFileAccessService, FileContentExtractor
from guardian_swarm.utils.audit import AuditLog
from guardian_swarm.web.server import app


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    init_db()
    db = SessionLocal()
    try:
        from datetime import datetime, timezone, timedelta
        exp_time = datetime.now(timezone.utc) + timedelta(days=7)
        # Create test classified files in FileMind cache if not present
        if db.query(FileMindCacheModel).filter(FileMindCacheModel.path == "C:\\data\\public_spec.txt").count() == 0:
            db.add_all([
                FileMindCacheModel(
                    path="C:\\data\\public_spec.txt",
                    filemind_category="Documents",
                    guardian_classification="PUBLIC",
                    file_size=1024,
                    expires_at=exp_time,
                    status="classified"
                ),
                FileMindCacheModel(
                    path="C:\\data\\internal_design.txt",
                    filemind_category="Documents",
                    guardian_classification="INTERNAL",
                    file_size=2048,
                    expires_at=exp_time,
                    status="classified"
                ),
                FileMindCacheModel(
                    path="C:\\data\\confidential_financials.csv",
                    filemind_category="Spreadsheets",
                    guardian_classification="CONFIDENTIAL",
                    file_size=4096,
                    expires_at=exp_time,
                    status="classified"
                ),
                FileMindCacheModel(
                    path="C:\\data\\restricted_exec_salaries.xlsx",
                    filemind_category="Spreadsheets",
                    guardian_classification="RESTRICTED",
                    file_size=8192,
                    expires_at=exp_time,
                    status="classified"
                )
            ])
            db.commit()
    finally:
        db.close()


def test_default_deny_unknown_model():
    service = ModelFileAccessService()
    file_rec = service.get_file_record("C:\\data\\public_spec.txt")
    assert file_rec is not None

    # Test unknown model
    allowed, reasoning = service.evaluate_policy(
        user_role="ADMIN",
        model_name="non_existent_model_xyz",
        file_record=file_rec,
        operation="READ_CONTENT"
    )
    assert allowed is False
    assert "not registered" in reasoning


def test_disabled_model_file_access():
    service = ModelFileAccessService()
    file_rec = service.get_file_record("C:\\data\\public_spec.txt")

    # Explicitly set smollm2 file_access_enabled=False in DB for test
    db = SessionLocal()
    try:
        m = db.query(ModelRegistryModel).filter(ModelRegistryModel.name == "smollm2").first()
        if m:
            m.file_access_enabled = False
            db.commit()
    finally:
        db.close()

    allowed, reasoning = service.evaluate_policy(
        user_role="ADMIN",
        model_name="smollm2",
        file_record=file_rec,
        operation="READ_CONTENT"
    )
    assert allowed is False
    assert "disabled" in reasoning.lower()


def test_user_rbac_hierarchical_denial():
    service = ModelFileAccessService()
    confidential_rec = service.get_file_record("C:\\data\\confidential_financials.csv")
    assert confidential_rec is not None

    # INTERN user (level 10) attempting to read CONFIDENTIAL file (requires level 30 MANAGER+)
    allowed, reasoning = service.evaluate_policy(
        user_role="INTERN",
        model_name="gpt-4o",
        file_record=confidential_rec,
        operation="READ_CONTENT"
    )
    assert allowed is False
    assert "does not meet required role" in reasoning

    # EMPLOYEE user (level 20) attempting to read CONFIDENTIAL file -> DENIED
    allowed_emp, reasoning_emp = service.evaluate_policy(
        user_role="EMPLOYEE",
        model_name="gpt-4o",
        file_record=confidential_rec,
        operation="READ_CONTENT"
    )
    assert allowed_emp is False

    # MANAGER user (level 30) attempting to read CONFIDENTIAL file -> ALLOWED
    allowed_mgr, _ = service.evaluate_policy(
        user_role="MANAGER",
        model_name="gpt-4o",
        file_record=confidential_rec,
        operation="READ_CONTENT"
    )
    assert allowed_mgr is True


def test_model_tag_allowlist_restriction():
    service = ModelFileAccessService()
    confidential_rec = service.get_file_record("C:\\data\\confidential_financials.csv")

    # Explicitly set codex allowed_guardian_tags='["PUBLIC","INTERNAL"]' in DB
    db = SessionLocal()
    try:
        m = db.query(ModelRegistryModel).filter(ModelRegistryModel.name == "codex").first()
        if m:
            m.allowed_guardian_tags = '["PUBLIC","INTERNAL"]'
            db.commit()
    finally:
        db.close()

    allowed, reasoning = service.evaluate_policy(
        user_role="ADMIN",
        model_name="codex",
        file_record=confidential_rec,
        operation="READ_CONTENT"
    )
    assert allowed is False
    assert "only permitted to access Guardian tags" in reasoning


def test_operation_permission_restrictions():
    service = ModelFileAccessService()
    public_rec = service.get_file_record("C:\\data\\public_spec.txt")

    # perplexity model has can_download=False, can_export=False
    allowed_read, _ = service.evaluate_policy(
        user_role="ADMIN",
        model_name="perplexity",
        file_record=public_rec,
        operation="READ_CONTENT"
    )
    assert allowed_read is True

    allowed_dl, reasoning_dl = service.evaluate_policy(
        user_role="ADMIN",
        model_name="perplexity",
        file_record=public_rec,
        operation="DOWNLOAD"
    )
    assert allowed_dl is False
    assert "does not have DOWNLOAD permission" in reasoning_dl


def test_information_disclosure_prevention():
    service = ModelFileAccessService()

    # INTERN user requesting available files for claude-haiku-4-5
    intern_files = service.list_available_files(user_role="INTERN", model_name="claude-haiku-4-5")
    intern_tags = {f["guardian_classification"] for f in intern_files}
    
    # Must contain ONLY PUBLIC files, NO CONFIDENTIAL or RESTRICTED files
    assert "CONFIDENTIAL" not in intern_tags
    assert "RESTRICTED" not in intern_tags
    assert all(f["guardian_classification"] == "PUBLIC" for f in intern_files)


def test_content_extraction_safety_and_limits():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("Line 1: Confidential project blueprint.\n" * 100)
        temp_txt = f.name

    try:
        res = FileContentExtractor.extract(temp_txt)
        assert res["status"] == "SUCCESS"
        assert "Confidential project blueprint" in res["content"]
    finally:
        if os.path.exists(temp_txt):
            os.remove(temp_txt)

    # Test unsupported file extension (.exe)
    with tempfile.NamedTemporaryFile("wb", suffix=".exe", delete=False) as f:
        f.write(b"\x90\x90\x90")
        temp_exe = f.name
    try:
        res_exe = FileContentExtractor.extract(temp_exe)
        assert res_exe["status"] == "UNSUPPORTED_FILE_TYPE"
    finally:
        if os.path.exists(temp_exe):
            os.remove(temp_exe)


def test_prompt_context_formatting_injection_protection():
    service = ModelFileAccessService()
    retrieval_res = {
        "status": "ALLOWED",
        "file_id": "file-101",
        "filename": "Public_Guide.txt",
        "filemind_category": "Documents",
        "guardian_classification": "PUBLIC",
        "content": "Step 1: Follow enterprise compliance protocols."
    }

    context_str = service.format_as_model_context(retrieval_res)
    assert "AUTHORIZED FILE DATA CONTEXT" in context_str
    assert "UNTRUSTED DATA" in context_str
    assert "Step 1: Follow enterprise compliance protocols." in context_str


def test_web_api_endpoints():
    client = app.test_client()
    from guardian_swarm.web.server import generate_jwt_token
    admin_token = generate_jwt_token("admin_user", "ADMIN", "ADMIN")
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    # 1. GET /api/model-file-access/files
    res_list = client.get('/api/model-file-access/files?model_name=gpt-4o', headers=headers)
    assert res_list.status_code == 200
    data = res_list.get_json()
    assert "files" in data
    assert "total_authorized" in data

    # 2. POST /api/model-file-access/search
    res_search = client.post('/api/model-file-access/search', json={
        "query": "public",
        "model_name": "gpt-4o"
    }, headers=headers)
    assert res_search.status_code == 200
    s_data = res_search.get_json()
    assert s_data["total_matches"] >= 1

    # 3. POST /api/model-file-access/test (Admin test endpoint)
    res_test = client.post('/api/model-file-access/test', json={
        "model_name": "codex",
        "file_id": "C:\\data\\confidential_financials.csv",
        "user_role": "ADMIN",
        "operation": "READ_CONTENT"
    }, headers=headers)
    assert res_test.status_code == 200
    t_data = res_test.get_json()
    assert t_data["decision"] == "DENIED"
    assert "only permitted to access Guardian tags" in t_data["reasoning"]
