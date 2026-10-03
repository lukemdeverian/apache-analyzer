import pytest


@pytest.fixture(autouse=True)
def clean_settings_environment(monkeypatch):
    """Keep local environment settings from affecting the test suite."""
    for name in ("APP_HOST", "APP_PORT", "APP_DEBUG", "DATABASE_PATH"):
        monkeypatch.delenv(name, raising=False)
