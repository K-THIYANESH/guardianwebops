from pathlib import Path
import shutil


def _find_project_root(start: Path) -> Path:
    current = start.resolve()
    markers = (".git", "pyproject.toml", "README.md", "app.py")
    for candidate in [current, *current.parents]:
        if any((candidate / marker).exists() for marker in markers):
            return candidate
    return current


PROJECT_ROOT = _find_project_root(Path(__file__).resolve())
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
STATE_FILE = DATA_DIR / "runtime_state.json"
LEGACY_STATE_FILE = PROJECT_ROOT / "runtime_state.json"
LOG_DIR = DATA_DIR / "logs"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"


for path in (DATA_DIR, LOG_DIR, ARTIFACTS_DIR, MODELS_DIR):
    path.mkdir(parents=True, exist_ok=True)


def resolve_state_file() -> Path:
    if STATE_FILE.exists():
        return STATE_FILE
    if LEGACY_STATE_FILE.exists():
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        shutil.move(str(LEGACY_STATE_FILE), str(STATE_FILE))
        return STATE_FILE
    return STATE_FILE


def ensure_project_paths() -> dict:
    state_file = resolve_state_file()
    for path in (DATA_DIR, LOG_DIR, ARTIFACTS_DIR):
        path.mkdir(parents=True, exist_ok=True)
    return {
        "project_root": str(PROJECT_ROOT),
        "data_dir": str(DATA_DIR),
        "models_dir": str(MODELS_DIR),
        "state_file": str(state_file),
        "log_dir": str(LOG_DIR),
        "artifacts_dir": str(ARTIFACTS_DIR),
    }
