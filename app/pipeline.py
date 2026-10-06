"""Atomic Apache imports and persistent alert correlation."""

from dataclasses import asdict, dataclass
from datetime import timezone, tzinfo
from pathlib import Path

from app.alerts import Alert
from app.database import transaction
from app.detection import DetectionEngine
from app.events import ApacheLogType
from app.ingestion import DEFAULT_MAX_LINE_BYTES, ImportSummary, ingest_file
from app.storage import SQLiteStore

DEFAULT_REQUEST_CORRELATION_SECONDS = 300


@dataclass(frozen=True, slots=True)
class DetectionSummary:
    findings: int = 0
    alerts_created: int = 0
    alert_updates: int = 0
    alerts_merged: int = 0
    findings_unchanged: int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    import_summary: ImportSummary
    detection: DetectionSummary

    def as_dict(self) -> dict:
        return {**self.import_summary.as_dict(), "detection": self.detection.as_dict()}


def _correlation_seconds(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 86400:
        raise ValueError("request_correlation_seconds must be an integer between 1 and 86400.")
    return value


def detect_events(
    store: SQLiteStore, *, engine: DetectionEngine | None = None,
    request_correlation_seconds: int = DEFAULT_REQUEST_CORRELATION_SECONDS,
) -> DetectionSummary:
    """Scan all stored evidence and atomically correlate findings into alerts.

    Replaying chronological history handles late imports and uses stored
    evidence links to skip findings already represented by their rule/group.
    A failure rolls back this scan's creations, updates, and merges together.
    """
    request_gap = _correlation_seconds(request_correlation_seconds)
    detector = engine if engine is not None else DetectionEngine()
    counts = DetectionSummary().as_dict()
    with transaction(store.connection):
        findings = detector.iter_findings(store)
        try:
            for finding in findings:
                candidate = Alert(
                    rule_id=finding.rule_id, title=finding.title, description=finding.description,
                    severity=finding.severity, grouping_key=finding.grouping_key,
                    source_ip=finding.source_ip, first_seen=finding.first_seen, last_seen=finding.last_seen,
                )
                result = store.correlate_alert(
                    candidate, finding.event_ids,
                    max_gap_seconds=finding.window_seconds if finding.window_seconds is not None else request_gap,
                )
                counts["findings"] += 1
                counts["alerts_created"] += result.created
                counts["alert_updates"] += result.updated
                counts["alerts_merged"] += result.merged_alerts
                counts["findings_unchanged"] += not result.created and not result.updated
        finally:
            findings.close()
    return DetectionSummary(**counts)


def analyze_file(
    path: str | Path, log_type: ApacheLogType, store: SQLiteStore, *,
    error_timezone: tzinfo = timezone.utc, max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    engine: DetectionEngine | None = None,
    request_correlation_seconds: int = DEFAULT_REQUEST_CORRELATION_SECONDS,
    source_label: str | None = None,
) -> AnalysisSummary:
    """Import a file and scan evidence in one transaction, including alert writes."""
    _correlation_seconds(request_correlation_seconds)
    with transaction(store.connection):
        imported = ingest_file(
            path, log_type, store, error_timezone=error_timezone,
            max_line_bytes=max_line_bytes, source_label=source_label,
        )
        detection = detect_events(store, engine=engine, request_correlation_seconds=request_correlation_seconds)
    return AnalysisSummary(import_summary=imported, detection=detection)
