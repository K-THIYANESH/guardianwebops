"""
End-to-End Verification Test for FileMind -> Model File Access -> Attach -> Model Context Flow
===============================================================================================
Fulfills Section 30 of Master Prompt.
"""
import os
import json
import pytest
from pathlib import Path

from guardian_swarm.web.server import app, generate_jwt_token
from guardian_swarm.utils.database import SessionLocal, init_db, FileMindCacheModel, ModelRegistryModel
from guardian_swarm.core.filemind_classifier import FileMindClassifier
from guardian_swarm.core.file_retrieval import ModelFileAccessService
from guardian_swarm.core.inference import execute_swarm_inference


def test_end_to_end_filemind_model_attachment_flow():
    # 0. Initialize DB and prep environment
    init_db()
    
    # 1. Create real test file
    test_dir = Path("data/downloads")
    test_dir.mkdir(parents=True, exist_ok=True)
    test_file_path = test_dir / "guardian_attachment_test.txt"
    test_file_path.write_text("FILEMIND_MODEL_ACCESS_TEST_73921", encoding="utf-8")

    # 2. FileMind processes it
    classifier = FileMindClassifier()
    scan_res = classifier.classify_file(str(test_file_path))
    assert scan_res["status"] == "classified"

    # 3. Verify FileMind cache state
    db = SessionLocal()
    try:
        cache_rec = db.query(FileMindCacheModel).filter(FileMindCacheModel.path.like("%guardian_attachment_test.txt")).first()
        assert cache_rec is not None
        assert cache_rec.status == "classified"
        file_id = f"file-{cache_rec.id}"
    finally:
        db.close()

    # 4. Call GET /api/model-file-access/files?model_name=gemini-1.5-pro via Flask Test Client
    with app.test_client() as client:
        token = generate_jwt_token("admin_user", "ADMIN", "ADMIN")
        headers = {"Authorization": f"Bearer {token}"}
        res = client.get("/api/model-file-access/files?model_name=gemini-1.5-pro", headers=headers)
        
        assert res.status_code == 200
        data = res.get_json()
        assert data["model_name"] == "gemini-1.5-pro"
        assert data["total_authorized"] >= 1
        
        # Verify file presence and schema sanitization (no local paths exposed)
        matched_file = None
        for f in data["files"]:
            assert "canonical_path" not in f
            assert "path" not in f
            if f["file_id"] == file_id:
                matched_file = f
                
        assert matched_file is not None
        assert matched_file["name"] == "guardian_attachment_test.txt"
        assert matched_file["status"] == "READY"

    # 5. Retrieve file content via ModelFileAccessService
    file_service = ModelFileAccessService()
    ret_res = file_service.retrieve_file_content(
        file_id=file_id,
        user_role="ADMIN",
        model_name="gemini-1.5-pro",
        operation="READ_CONTENT"
    )
    assert ret_res["status"] == "ALLOWED"
    assert "FILEMIND_MODEL_ACCESS_TEST_73921" in ret_res["content"]

    # 6. Model Context Resolution & Swarm Inference Execution
    prompt = f"What is the verification phrase in {file_id}?"
    inf_res = execute_swarm_inference(
        prompt=prompt,
        model_name="gemini-1.5-pro",
        user_role="ADMIN",
        user_id="admin_user"
    )
    assert inf_res["file_access_status"] == "ALLOWED"
    assert "FILEMIND_MODEL_ACCESS_TEST_73921" in inf_res["output"] or "FILEMIND_MODEL_ACCESS_TEST_73921" in str(inf_res)

    # 7. Test Unauthorized Access (RBAC Denial / IDOR Protection)
    # Intern user should be denied access to RESTRICTED files
    from datetime import datetime, timezone, timedelta
    db = SessionLocal()
    try:
        db.query(FileMindCacheModel).filter(FileMindCacheModel.path == "data/legacy_docs/restricted_payroll_test_unique.csv").delete()
        restr_rec = FileMindCacheModel(
            path="data/legacy_docs/restricted_payroll_test_unique.csv",
            content_fingerprint="dummyhash123",
            file_size=100,
            filemind_category="Spreadsheets",
            guardian_classification="RESTRICTED",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            status="classified"
        )
        db.add(restr_rec)
        db.commit()
        restr_file_id = f"file-{restr_rec.id}"
    finally:
        db.close()

    denied_res = file_service.retrieve_file_content(
        file_id=restr_file_id,
        user_role="INTERN",
        model_name="gemini-1.5-pro",
        operation="READ_CONTENT"
    )
    assert denied_res["status"] == "DENIED"
    assert "does not meet required role" in denied_res["error"]
