"""Environment settings for a local application with SQLite storage."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _parse_debug(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError("APP_DEBUG must be true or false (also accepts 1/0, yes/no, on/off).")


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    debug: bool
    database_path: Path

    @classmethod
    def from_environment(cls, instance_path: str | Path) -> "Settings":
        """Read settings and resolve relative database paths under instance/."""
        host = os.environ.get("APP_HOST", "127.0.0.1").strip()
        if not host:
            raise ValueError("APP_HOST must not be empty.")

        try:
            port = int(os.environ.get("APP_PORT", "5000"))
        except ValueError as exc:
            raise ValueError("APP_PORT must be an integer between 1 and 65535.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("APP_PORT must be an integer between 1 and 65535.")

        database_value = os.environ.get("DATABASE_PATH", "apache_analyzer.sqlite3").strip()
        if not database_value:
            raise ValueError("DATABASE_PATH must not be empty.")
        if "://" in database_value or database_value.startswith("file:") or database_value == ":memory:":
            raise ValueError("DATABASE_PATH must be a local file path.")
        database_path = Path(database_value).expanduser()
        if not database_path.is_absolute():
            database_path = Path(instance_path) / database_path

        return cls(
            host=host,
            port=port,
            debug=_parse_debug(os.environ.get("APP_DEBUG", "false")),
            database_path=database_path.resolve(),
        )

    def as_flask_config(self) -> dict[str, Any]:
        return {
            "APP_HOST": self.host,
            "APP_PORT": self.port,
            "DEBUG": self.debug,
            "DATABASE_PATH": str(self.database_path),
        }
