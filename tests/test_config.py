import pytest

from app.config import Settings


def test_defaults_resolve_database_under_instance(tmp_path):
    settings = Settings.from_environment(tmp_path)

    assert settings.host == "127.0.0.1"
    assert settings.port == 5000
    assert settings.debug is False
    assert settings.database_path == tmp_path / "apache_analyzer.sqlite3"


def test_environment_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_HOST", "localhost")
    monkeypatch.setenv("APP_PORT", "5051")
    monkeypatch.setenv("APP_DEBUG", "true")
    monkeypatch.setenv("DATABASE_PATH", "logs/events.sqlite3")

    settings = Settings.from_environment(tmp_path)

    assert settings.host == "localhost"
    assert settings.port == 5051
    assert settings.debug is True
    assert settings.database_path == tmp_path / "logs" / "events.sqlite3"


def test_absolute_database_path_is_preserved(monkeypatch, tmp_path):
    database_path = tmp_path / "data" / "events.sqlite3"
    monkeypatch.setenv("DATABASE_PATH", str(database_path))

    settings = Settings.from_environment(tmp_path / "instance")

    assert settings.database_path == database_path


@pytest.mark.parametrize("value", ["", "five", "0", "-1", "65536", "5.5"])
def test_invalid_ports_fail_at_startup(monkeypatch, tmp_path, value):
    monkeypatch.setenv("APP_PORT", value)

    with pytest.raises(ValueError, match="APP_PORT"):
        Settings.from_environment(tmp_path)


@pytest.mark.parametrize("value", ["", "maybe", "2"])
def test_invalid_debug_values_fail_at_startup(monkeypatch, tmp_path, value):
    monkeypatch.setenv("APP_DEBUG", value)

    with pytest.raises(ValueError, match="APP_DEBUG"):
        Settings.from_environment(tmp_path)


@pytest.mark.parametrize("name", ["APP_HOST", "DATABASE_PATH"])
def test_empty_settings_fail_at_startup(monkeypatch, tmp_path, name):
    monkeypatch.setenv(name, "  ")

    with pytest.raises(ValueError, match=name):
        Settings.from_environment(tmp_path)
