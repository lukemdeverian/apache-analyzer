"""Alert evidence values and analyst statuses used by storage and detection."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "resolved", "false_positive"]
SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive")


@dataclass(frozen=True, slots=True, kw_only=True)
class Alert:
    rule_id: str
    title: str
    description: str
    severity: Severity
    grouping_key: str
    first_seen: datetime
    last_seen: datetime
    source_ip: str | None = None
    status: AlertStatus = "new"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
