"""
Guardian Swarm V3 — FileMind Integration & Privacy Gate 3 Test Suite
Validates content-aware file classification, SQLite caching, path security, PGE_005 enforcement, and REST API contracts.
"""

import os
import time
import pytest
from pathlib import Path
from guardian_swarm.web.server import app
from guardian_swarm.utils.database import init_db, SessionLocal, FileMindCacheModel
from guardian_swarm.core.filemind_classifier import FileMindClassifier
from guardian_swarm.core.privacy_gate import PrivacyGate
from guardian_swarm.core.exceptions import FileClassificationDeniedException

@pytest.fixture(autouse=True)
def setup_database():
    init_db()
    yield

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_filemind_classifier_basic(tmp_path):
    """Test file classification for documents and spreadsheets with fail-secure defaults."""
    classifier = FileMindClassifier()

    doc_file = tmp_path / "contract.pdf"
    doc_file.write_text("Standard non-disclosure contract content.")

    res_doc = classifier.classify_file(str(doc_file))
    assert res_doc["filemind_category"] == "Documents"
    assert res_doc["guardian_classification"] == "INTERNAL"
    assert res_doc["status"] == "classified"

    sheet_file = tmp_path / "employee_salary.xlsx"
    sheet_file.write_text("Salary breakdown data.")

    res_sheet = classifier.classify_file(str(sheet_file))
    assert res_sheet["filemind_category"] == "Spreadsheets"
    assert res_sheet["guardian_classification"] == "CONFIDENTIAL"
    assert res_sheet["status"] == "classified"

def test_filemind_caching_and_fingerprinting(tmp_path):
    """Test SQLite caching, TTL, and content modification re-triggering."""
    classifier = FileMindClassifier()
    test_file = tmp_path / "report.docx"
    test_file.write_text("Initial report text.")

    # 1. Initial scan -> Cache MISS (new)
    res1 = classifier.classify_file(str(test_file))
    assert res1["cache_status"] == "new"

    # 2. Second scan -> Cache HIT
    res2 = classifier.classify_file(str(test_file))
    assert res2["cache_status"] == "cached"

    # 3. Modify file content -> Cache invalidation -> Re-scan
    time.sleep(0.1)
    test_file.write_text("Modified report text with updated content.")
    res3 = classifier.classify_file(str(test_file))
    assert res3["cache_status"] == "new"

def test_filemind_fail_secure(tmp_path):
    """Test fail-secure behavior for non-existent file or traversal attack."""
    classifier = FileMindClassifier()

    # Non-existent file
    res_missing = classifier.classify_file(str(tmp_path / "ghost_file.xyz"))
    assert res_missing["guardian_classification"] == "RESTRICTED"
    assert res_missing["status"] == "scanner_failure"

    # Path traversal attack
    res_traversal = classifier.classify_file("../../etc/passwd")
    assert res_traversal["guardian_classification"] == "RESTRICTED"
    assert res_traversal["status"] == "scanner_failure"

def test_privacy_gate_pge_005_enforcement(tmp_path):
    """Test Gate 3 Privacy Gate raises PGE_005 when file classification exceeds user allowed max level."""
    gate = PrivacyGate()

    doc_path = tmp_path / "contract.pdf"
    doc_path.write_text("Contract text")

    sheet_path = tmp_path / "employee_salary.xlsx"
    sheet_path.write_text("Salary data")

    # 1. EMPLOYEE reading contract.pdf (INTERNAL vs INTERNAL) -> Allowed
    res1 = gate.scan(
        prompt=f"Read the file '{doc_path}' for me",
        max_allowed_classification="INTERNAL",
        user_role="EMPLOYEE"
    )
    assert res1 is not None

    # 2. EMPLOYEE reading employee_salary.xlsx (CONFIDENTIAL vs INTERNAL) -> Blocked with PGE_005
    with pytest.raises(FileClassificationDeniedException) as exc_info:
        gate.scan(
            prompt=f"Read '{sheet_path}'",
            max_allowed_classification="INTERNAL",
            user_role="EMPLOYEE"
        )
    assert exc_info.value.error_code == "PGE_005"
    assert "CONFIDENTIAL" in exc_info.value.message

    # 3. MANAGER reading employee_salary.xlsx (CONFIDENTIAL vs CONFIDENTIAL) -> Allowed
    res3 = gate.scan(
        prompt=f"Read '{sheet_path}'",
        max_allowed_classification="CONFIDENTIAL",
        user_role="MANAGER"
    )
    assert res3 is not None

def test_classify_api_endpoints(client, tmp_path):
    """Test REST endpoints /api/classify/folder, /api/classify/status, /api/classify/file, and /api/classify/summary."""
    from guardian_swarm.web.server import generate_jwt_token
    token = generate_jwt_token("manager_user", "MANAGER", "MANAGER")
    headers = {"Authorization": f"Bearer {token}"}

    doc = tmp_path / "doc1.pdf"
    doc.write_text("Doc 1")
    sheet = tmp_path / "sheet1.xlsx"
    sheet.write_text("Sheet 1")

    # 1. POST /api/classify/folder (MANAGER role simulation)
    res = client.post('/api/classify/folder', json={
        "folder_path": str(tmp_path),
        "dry_run": True
    }, headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "scan_id" in data
    scan_id = data["scan_id"]

    # Wait for thread scan completion
    time.sleep(0.5)

    # 2. GET /api/classify/status
    res_status = client.get(f'/api/classify/status?scan_id={scan_id}')
    assert res_status.status_code == 200
    data_status = res_status.get_json()
    assert data_status["processed"] >= 2

    # 3. GET /api/classify/file
    res_file = client.get(f'/api/classify/file?path={doc}')
    assert res_file.status_code == 200
    assert res_file.get_json()["guardian_classification"] == "INTERNAL"

    # 4. GET /api/classify/summary
    res_sum = client.get('/api/classify/summary')
    assert res_sum.status_code == 200
    assert res_sum.get_json()["total_classified"] >= 2

def test_bytecode_pyc_skipping(tmp_path):
    """Test Python bytecode (.pyc) and __pycache__ files are skipped with status SKIPPED."""
    classifier = FileMindClassifier()
    pyc_file = tmp_path / "compiled.pyc"
    pyc_file.write_bytes(b"\x03\x00\x00\x00bytecode_data")

    res = classifier.classify_file(str(pyc_file))
    assert res["status"] == "SKIPPED"
    assert res["guardian_classification"] == "SKIPPED"
    assert res["error_reason"] == "PYTHON_CACHE"

def test_virtual_path_resolution():
    """Test virtual path mapping (/download -> data/downloads)."""
    from guardian_swarm.core.filemind_classifier import resolve_scan_root
    from guardian_swarm.utils.paths import PROJECT_ROOT

    canonical, err = resolve_scan_root("/download")
    assert err is None
    assert canonical == (PROJECT_ROOT / "data" / "downloads").resolve()

def test_source_code_protection():
    """Test scanning core source directories returns SOURCE_CODE_PROTECTED."""
    from guardian_swarm.core.filemind_classifier import resolve_scan_root
    from guardian_swarm.utils.paths import PROJECT_ROOT

    canonical, err = resolve_scan_root(str(PROJECT_ROOT / "guardian_swarm"))
    assert canonical is None
    assert "SOURCE_CODE_PROTECTED" in err

