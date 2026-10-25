from config.settings import settings


def test_settings_defaults_are_resolved():
    assert settings.project_root.exists()
    assert settings.models_dir.exists()
    assert settings.data_dir.exists()
    assert settings.state_file.parent == settings.data_dir
