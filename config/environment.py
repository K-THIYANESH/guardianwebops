"""Environment helpers for the standalone Guardian runtime."""

from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def ensure_runtime_dirs() -> None:
    from guardian_swarm.utils.paths import DATA_DIR, LOG_DIR, ARTIFACTS_DIR
    for path in (DATA_DIR, LOG_DIR, ARTIFACTS_DIR):
        path.mkdir(parents=True, exist_ok=True)
