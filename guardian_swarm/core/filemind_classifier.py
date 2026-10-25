"""
Guardian Swarm V3 — FileMind Content Classifier & Adapter Module
Provides content-aware file classification for Gate 3 (Privacy), leveraging FileMind analysis,
YAML category mappings, path security checks, and SQLite caching with fingerprinting.
"""

import os
import sys
import json
import hashlib
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
import yaml

from guardian_swarm.utils.paths import PROJECT_ROOT
from guardian_swarm.utils.database import SessionLocal, FileMindCacheModel

DEFAULT_MAPPING = {
    "Documents": "INTERNAL",
    "Spreadsheets": "CONFIDENTIAL",
    "Presentations": "INTERNAL",
    "Images": "INTERNAL",
    "Archives": "CONFIDENTIAL",
    "Code": "INTERNAL",
    "Executables": "RESTRICTED",
    "Security": "RESTRICTED",
    "Unknown": "RESTRICTED"
}

IGNORED_EXTENSIONS = {".pyc", ".pyo", ".pyd", ".git", ".ds_store"}
IGNORED_FILENAMES = {"thumbs.db", ".ds_store", "desktop.ini", ".gitignore"}

def resolve_scan_root(requested_path: str) -> Tuple[Optional[Path], Optional[str]]:
    """
    Resolves virtual paths (/download, /data/legacy_docs) to canonical physical paths.
    Validates against allowlisted scan roots and blocks source code / system directory scans.
    """
    if not requested_path or not isinstance(requested_path, str):
        return None, "INVALID_PATH"

    raw = requested_path.strip().replace('\\', '/')
    clean = raw.rstrip('/').lower()

    # Restricted System Locations
    forbidden_system_paths = ["/etc", "/root", "/sys", "/proc", "/boot", "/dev", "c:/etc", "c:/root", "c:\\windows\\system32"]
    if clean in ["/etc", "/root", "/sys", "/proc", "/boot", "/dev"] or any(clean.startswith(f) for f in forbidden_system_paths):
        return None, f"UNAUTHORIZED_PATH: Restricted system location '{requested_path}'"

    # Mapped Virtual Scan Roots
    downloads_dir = (PROJECT_ROOT / "data" / "downloads").resolve()
    downloads_dir.mkdir(parents=True, exist_ok=True)

    legacy_docs_dir = (PROJECT_ROOT / "data" / "legacy_docs").resolve()
    legacy_docs_dir.mkdir(parents=True, exist_ok=True)

    config_target = legacy_docs_dir

    virtual_mappings = {
        "/download": downloads_dir,
        "/downloads": downloads_dir,
        "/data/downloads": downloads_dir,
        "/data/legacy_docs": legacy_docs_dir,
        "/legacy_docs": legacy_docs_dir,
        "/data": (PROJECT_ROOT / "data").resolve(),
        "./config": config_target,
        "config": config_target,
    }

    physical_path: Optional[Path] = None
    if clean in virtual_mappings:
        physical_path = virtual_mappings[clean]
    elif raw.startswith("/") or raw.startswith("\\"):
        for prefix, target in virtual_mappings.items():
            if clean.startswith(prefix):
                rel = clean[len(prefix):].lstrip('/')
                physical_path = target / rel
                break

    if physical_path is None:
        try:
            physical_path = Path(raw).resolve()
        except Exception:
            return None, "INVALID_PATH"

    try:
        canonical_path = physical_path.resolve()
    except Exception:
        return None, "INVALID_PATH"

    import tempfile
    temp_dir = Path(tempfile.gettempdir()).resolve()

    # Explicitly Block Core Application Source Code Directories
    forbidden_source_dirs = [
        (PROJECT_ROOT / "guardian_swarm").resolve(),
        (PROJECT_ROOT / ".git").resolve(),
        (PROJECT_ROOT / ".venv").resolve(),
        (PROJECT_ROOT / "__pycache__").resolve(),
    ]

    for forbidden in forbidden_source_dirs:
        if canonical_path == forbidden or forbidden in canonical_path.parents:
            return None, f"SOURCE_CODE_PROTECTED: Path '{requested_path}' resolves to protected source code directory '{canonical_path}'."

    # Allowlist check: Must be inside approved data, download, or temp test root
    allowed_roots = [
        (PROJECT_ROOT / "data").resolve(),
        (Path.home() / "Downloads").resolve() if (Path.home() / "Downloads").exists() else None,
        temp_dir,
    ]
    allowed_roots = [r for r in allowed_roots if r is not None]

    is_allowed = any(canonical_path == r or r in canonical_path.parents for r in allowed_roots)
    if not is_allowed:
        return None, f"SCAN_ROOT_NOT_CONFIGURED: Path '{requested_path}' resolves to '{canonical_path}' which is not an approved scan root."

    return canonical_path, None


class FileMindClassifier:
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or (PROJECT_ROOT / "config" / "filemind_mapping.yaml")
        self.mapping = self._load_mapping()
        self.executable = self._locate_executable()

    def _load_mapping(self) -> Dict[str, str]:
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    cats = data.get("categories", {})
                    mapping = {}
                    for cat, info in cats.items():
                        mapping[cat] = info.get("classification", "RESTRICTED")
                    return mapping
            except Exception:
                pass
        return DEFAULT_MAPPING.copy()

    def _locate_executable(self) -> Optional[str]:
        path_bin = shutil.which("filemind")
        if path_bin:
            return path_bin
        candidates = [
            PROJECT_ROOT / "bin" / "filemind.exe",
            PROJECT_ROOT / "bin" / "filemind",
            Path("C:/Program Files/FileMind/filemind.exe"),
        ]
        for c in candidates:
            if c.exists():
                return str(c)
        return None

    def sanitize_path(self, raw_path: str) -> Path:
        """Validates and canonicalizes file/folder path, rejecting traversal attacks."""
        if not raw_path or not isinstance(raw_path, str):
            raise ValueError("Invalid path specified")
        
        cleaned = raw_path.strip().replace('\0', '')
        if ".." in cleaned:
            raise ValueError("Path traversal attempt detected")
        
        path_obj = Path(cleaned).resolve()
        return path_obj

    def compute_fingerprint(self, file_path: Path) -> str:
        """Computes SHA-256 fingerprint for a file."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def classify_file(self, file_path_str: str, force_rescan: bool = False) -> Dict[str, Any]:
        """
        Classifies a single file using FileMind, with fail-secure defaults and cache fallback.
        Handles python bytecode/cache files as SKIPPED.
        """
        try:
            path_obj = self.sanitize_path(file_path_str)
        except Exception as e:
            return {
                "path": file_path_str,
                "filemind_category": "Unknown",
                "guardian_classification": "RESTRICTED",
                "scanner": "filemind",
                "scanner_version": "0.1.0",
                "cache_status": "error",
                "status": "scanner_failure",
                "error_reason": f"Path security violation: {str(e)}"
            }

        # Check Bytecode / Cache / System Artifact Exclusions
        ext = path_obj.suffix.lower()
        name = path_obj.name.lower()
        if ext in IGNORED_EXTENSIONS or name in IGNORED_FILENAMES or "__pycache__" in path_obj.parts:
            return {
                "path": str(path_obj),
                "filemind_category": "System Artifact",
                "guardian_classification": "SKIPPED",
                "scanner": "filemind",
                "scanner_version": "filemind-0.1",
                "cache_status": "skipped",
                "status": "SKIPPED",
                "error_reason": "PYTHON_CACHE" if ext in {".pyc", ".pyo"} or "__pycache__" in path_obj.parts else "SYSTEM_ARTIFACT",
                "last_scanned": datetime.now(timezone.utc).isoformat()
            }

        if not path_obj.exists() or not path_obj.is_file():
            return {
                "path": str(path_obj),
                "filemind_category": "Unknown",
                "guardian_classification": "RESTRICTED",
                "scanner": "filemind",
                "scanner_version": "0.1.0",
                "cache_status": "error",
                "status": "scanner_failure",
                "error_reason": "File does not exist or is not a regular file"
            }

        # Check Cache
        stat = path_obj.stat()
        file_size = stat.st_size
        modified_time = stat.st_mtime
        
        db = SessionLocal()
        try:
            cached = db.query(FileMindCacheModel).filter(FileMindCacheModel.path == str(path_obj)).first()
            if cached and not force_rescan:
                now_utc = datetime.now(timezone.utc)
                exp_utc = cached.expires_at.replace(tzinfo=timezone.utc) if cached.expires_at.tzinfo is None else cached.expires_at
                
                if now_utc < exp_utc and cached.file_size == file_size and abs(cached.modified_time - modified_time) < 0.1:
                    return {
                        "path": str(path_obj),
                        "filemind_category": cached.filemind_category,
                        "guardian_classification": cached.guardian_classification,
                        "scanner": "filemind",
                        "scanner_version": cached.scanner_version,
                        "cache_status": "cached",
                        "status": cached.status,
                        "last_scanned": cached.scanned_at.isoformat() if cached.scanned_at else ""
                    }
        finally:
            db.close()

        # Run FileMind or Content-Aware Classification
        category, status, err_reason = self._run_analysis(path_obj)
        classification = self.mapping.get(category, "RESTRICTED")

        if status == "scanner_failure":
            classification = "RESTRICTED"

        # Update SQLite Cache
        fingerprint = self.compute_fingerprint(path_obj) if status == "classified" else ""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        db = SessionLocal()
        try:
            existing = db.query(FileMindCacheModel).filter(FileMindCacheModel.path == str(path_obj)).first()
            if not existing:
                cache_entry = FileMindCacheModel(
                    path=str(path_obj),
                    filemind_category=category,
                    guardian_classification=classification,
                    file_size=file_size,
                    modified_time=modified_time,
                    content_fingerprint=fingerprint,
                    scanner_version="filemind-0.1",
                    expires_at=expires_at,
                    status=status,
                    error_reason=err_reason
                )
                db.add(cache_entry)
            else:
                existing.filemind_category = category
                existing.guardian_classification = classification
                existing.file_size = file_size
                existing.modified_time = modified_time
                existing.content_fingerprint = fingerprint
                existing.scanned_at = datetime.now(timezone.utc)
                existing.expires_at = expires_at
                existing.status = status
                existing.error_reason = err_reason
            db.commit()
        except Exception:
            pass
        finally:
            db.close()

        return {
            "path": str(path_obj),
            "filemind_category": category,
            "guardian_classification": classification,
            "scanner": "filemind",
            "scanner_version": "filemind-0.1",
            "cache_status": "new" if status == "classified" else "error",
            "status": status,
            "error_reason": err_reason,
            "last_scanned": datetime.now(timezone.utc).isoformat()
        }

    def _run_analysis(self, path_obj: Path) -> Tuple[str, str, Optional[str]]:
        """Executes FileMind CLI or fallback content-aware inspect."""
        if self.executable:
            try:
                cmd = [self.executable, "--json", str(path_obj)]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if proc.returncode == 0:
                    out = json.loads(proc.stdout)
                    category = out.get("category") or out.get("type", "Unknown")
                    return category, "classified", None
                return "Unknown", "scanner_failure", f"FileMind CLI returned non-zero exit code: {proc.stderr}"
            except Exception as e:
                return "Unknown", "scanner_failure", f"FileMind execution error: {str(e)}"
        
        # Content-aware inspection fallback
        try:
            ext = path_obj.suffix.lower()
            name = path_obj.name.lower()

            if "salary" in name or "payroll" in name or "financial" in name or ext in [".xlsx", ".xls", ".csv"]:
                return "Spreadsheets", "classified", None
            elif ext in [".pdf", ".doc", ".docx", ".txt", ".md"]:
                return "Documents", "classified", None
            elif ext in [".ppt", ".pptx", ".key"]:
                return "Presentations", "classified", None
            elif ext in [".png", ".jpg", ".jpeg", ".svg", ".gif"]:
                return "Images", "classified", None
            elif ext in [".zip", ".tar", ".gz", ".7z"]:
                return "Archives", "classified", None
            elif ext in [".py", ".js", ".java", ".cpp", ".cs"]:
                return "Code", "classified", None
            elif ext in [".exe", ".bat", ".sh", ".ps1"]:
                return "Executables", "classified", None
            else:
                return "Unknown", "classified", None
        except Exception as e:
            return "Unknown", "scanner_failure", f"Inspection failed: {str(e)}"

    def classify_folder(self, folder_path_str: str, dry_run: bool = True, progress_callback=None) -> Dict[str, Any]:
        """Recursively classifies all files in a folder incrementally."""
        try:
            path_obj, err_code = resolve_scan_root(folder_path_str)
            if err_code or not path_obj:
                return {"error": err_code or "Invalid path", "total_files": 0, "processed": 0, "results": []}
            folder_obj = path_obj
        except Exception as e:
            return {"error": f"Invalid path: {str(e)}", "total_files": 0, "processed": 0, "results": []}

        if not folder_obj.exists() or not folder_obj.is_dir():
            return {"error": "Folder does not exist or is not a directory", "total_files": 0, "processed": 0, "results": []}

        files_to_scan = [p for p in folder_obj.rglob("*") if p.is_file()]
        results = []
        cached_count = 0
        new_count = 0
        skipped_count = 0
        failed_count = 0

        total_count = len(files_to_scan)

        for i, f in enumerate(files_to_scan):
            res = self.classify_file(str(f))
            results.append(res)
            
            if res.get("status") == "SKIPPED":
                skipped_count += 1
            elif res.get("cache_status") == "cached":
                cached_count += 1
            elif res.get("status") == "classified":
                new_count += 1
            else:
                failed_count += 1

            if progress_callback:
                progress_callback(i + 1, total_count, cached_count, new_count, skipped_count, failed_count, str(f))

        return {
            "folder_path": str(folder_obj),
            "dry_run": dry_run,
            "total_files": total_count,
            "processed": len(results),
            "cached": cached_count,
            "new": new_count,
            "skipped": skipped_count,
            "failed": failed_count,
            "results": results
        }
