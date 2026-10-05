"""Application factory for the local Apache log analyzer."""

from collections.abc import Mapping
from typing import Any

from flask import Flask

from app.cli import init_app as init_cli_app
from app.config import Settings
from app.database import init_app as init_database_app


def create_app(config_overrides: Mapping[str, Any] | None = None) -> Flask:
    """Create an independent application with validated local settings."""
    app = Flask(__name__, instance_relative_config=True)
    settings = Settings.from_environment(app.instance_path)
    app.config.from_mapping(settings.as_flask_config())
    app.config.update(config_overrides or {})
    init_database_app(app)
    init_cli_app(app)

    @app.get("/health")
    def health() -> dict[str, str]:
        """Report process liveness without opening a database or log file."""
        return {"service": "apache-analyzer", "status": "ok"}

    return app
