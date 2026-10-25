from pathlib import Path

from guardian_swarm.utils.paths import DATA_DIR, MODELS_DIR, PROJECT_ROOT, STATE_FILE


def test_project_root_points_to_workspace():
    assert PROJECT_ROOT.exists()
    assert PROJECT_ROOT.is_dir()
    assert PROJECT_ROOT.name.lower() in {"guardian swarm v3", "guardian-swarm-v3", "guardianswarm-main", "guardianswarm-system-main", "guardianwebops"}


def test_runtime_state_and_model_paths_are_absolute_and_organized():
    assert DATA_DIR.is_absolute()
    assert MODELS_DIR.is_absolute()
    assert STATE_FILE.is_absolute()
    assert STATE_FILE.parent == DATA_DIR
    assert MODELS_DIR.parent == PROJECT_ROOT
