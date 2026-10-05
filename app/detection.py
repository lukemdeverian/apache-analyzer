"""Read-only Apache request and burst detection over chronological evidence."""

from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from app.alerts import Severity
from app.events import ApacheLogType
from app.signatures import (
    DEFAULT_ALLOWED_METHODS, RequestInspection, sensitive_file, sql_injection,
    traversal, unusual_method, validate_allowed_methods, xss,
)
from app.storage import SQLiteStore, StoredEvent


@dataclass(frozen=True, slots=True)
class RuleSettings:
    threshold: int
    window_seconds: int
    min_distinct_paths: int = 1

    def __post_init__(self) -> None:
        if type(self.threshold) is not int or self.threshold < 1:
            raise ValueError("threshold must be a positive integer.")
        if type(self.window_seconds) is not int or not 1 <= self.window_seconds <= 86400:
            raise ValueError("window_seconds must be an integer between 1 and 86400.")
        if type(self.min_distinct_paths) is not int or not 1 <= self.min_distinct_paths <= self.threshold:
            raise ValueError("min_distinct_paths must be an integer between 1 and threshold.")


@dataclass(frozen=True, slots=True)
class BehavioralRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    settings: RuleSettings
    status_codes: tuple[int, ...] = ()  # Empty means any access response status.
    requires_path: bool = False
    group_by_path: bool = False
    log_type: ApacheLogType = "access"
    group_by_source: bool = True
    levels: tuple[str, ...] = ()
    server_group: str = ""

    def grouping_key(self, item: StoredEvent) -> str | None:
        event = item.event
        if event.log_type != self.log_type:
            return None
        if self.group_by_source and event.source_ip is None:
            return None
        if self.status_codes and event.status_code not in self.status_codes:
            return None
        if self.requires_path and (event.path is None or not event.path.startswith("/")):
            return None
        if self.levels and event.level not in self.levels:
            return None
        if not self.group_by_source:
            return self.server_group
        key = f"ip:{event.source_ip}"
        return f"{key}|path:{event.path}" if self.group_by_path else key


BEHAVIORAL_RULES = (
    BehavioralRule(
        "APACHE-PATH-ENUMERATION", "Possible path enumeration",
        "Repeated 403/404 responses across distinct paths from one logged IP.",
        "medium", RuleSettings(10, 300, 5), (403, 404), requires_path=True,
    ),
    BehavioralRule(
        "APACHE-HTTP-ERRORS", "Repeated HTTP access errors",
        "Repeated 403/404 responses from one logged IP, including repeated paths.",
        "medium", RuleSettings(20, 300), (403, 404),
    ),
    BehavioralRule(
        "APACHE-AUTH-FAILURES", "Repeated authentication failures",
        "Repeated 401 responses from one logged IP to the same path.",
        "high", RuleSettings(10, 300), (401,), requires_path=True, group_by_path=True,
    ),
    BehavioralRule(
        "APACHE-REQUEST-BURST", "High request volume",
        "A burst of access records from one logged IP, regardless of response status.",
        "medium", RuleSettings(120, 60),
    ),
)

SERVER_RULES = (
    BehavioralRule(
        "APACHE-SERVER-ERRORS", "HTTP server error burst",
        "HTTP 5xx responses across clients in the imported server logs.",
        "high", RuleSettings(20, 60), tuple(range(500, 600)),
        group_by_source=False, server_group="server:http-5xx",
    ),
    BehavioralRule(
        "APACHE-ERROR-BURST", "Apache error-log burst",
        "Error, critical, alert, or emergency records across modules and clients.",
        "high", RuleSettings(10, 60), log_type="error", group_by_source=False,
        levels=("error", "crit", "alert", "emerg"), server_group="server:apache-errors",
    ),
)


@dataclass(frozen=True, slots=True)
class RequestRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    matcher: Callable[[RequestInspection], str | None]
    settings: None = None  # Each matching request is its own finding.


REQUEST_RULES = (
    RequestRule(
        "APACHE-TRAVERSAL", "Possible path traversal probe",
        "Parent-directory segments in the request path or query.", "high", traversal,
    ),
    RequestRule(
        "APACHE-SQL-INJECTION", "Possible SQL injection probe",
        "Selected SQL syntax signatures in the request path or query.", "high", sql_injection,
    ),
    RequestRule(
        "APACHE-XSS", "Possible XSS probe",
        "Script tags, HTML event handlers, or JavaScript URIs in the path or query.", "high", xss,
    ),
    RequestRule(
        "APACHE-SENSITIVE-FILE", "Sensitive-file request",
        "Known configuration, credential, repository, database, or backup paths.", "medium", sensitive_file,
    ),
    RequestRule(
        "APACHE-UNUSUAL-METHOD", "Unusual HTTP method",
        "A parsed HTTP method outside the configured expected set.", "medium", unusual_method,
    ),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionFinding:
    """One matched request or time window; later correlation combines findings."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    grouping_key: str
    source_ip: str | None
    first_seen: datetime
    last_seen: datetime
    event_ids: tuple[int, ...]
    anchor_event_id: int
    window_seconds: int | None  # None for a single-request signature.
    threshold: int
    distinct_path_count: int

    @property
    def event_count(self) -> int:
        return len(self.event_ids)


def _time(value: datetime | None, name: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime.")
    return value.astimezone(timezone.utc)


def _subtract_window(value: datetime, seconds: int) -> datetime:
    try:
        return value - timedelta(seconds=seconds)
    except OverflowError:
        return datetime.min.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class _Group:
    events: deque[StoredEvent] = field(default_factory=deque)
    paths: Counter[str] = field(default_factory=Counter)


class _RuleWindow:
    """Expire all groups in time order, including IPs that stop sending requests."""

    def __init__(self, rule: BehavioralRule):
        self.rule = rule
        self.history: deque[tuple[str, StoredEvent]] = deque()
        self.groups: dict[str, _Group] = {}

    def expire(self, now: datetime) -> None:
        cutoff = _subtract_window(now, self.rule.settings.window_seconds)
        while self.history and self.history[0][1].event.timestamp < cutoff:
            key, item = self.history.popleft()
            group = self.groups[key]
            group.events.popleft()
            if item.event.path is not None:
                group.paths[item.event.path] -= 1
                if group.paths[item.event.path] == 0:
                    del group.paths[item.event.path]
            if not group.events:
                del self.groups[key]

    def add(self, key: str, item: StoredEvent) -> _Group:
        group = self.groups.setdefault(key, _Group())
        group.events.append(item)
        if item.event.path is not None:
            group.paths[item.event.path] += 1
        self.history.append((key, item))
        return group

    def finding(self, key: str, group: _Group, anchor: StoredEvent) -> DetectionFinding | None:
        settings = self.rule.settings
        count, distinct = len(group.events), len(group.paths)
        if count < settings.threshold:
            return None
        # Rules without a distinct-path condition can include missing requests.
        if settings.min_distinct_paths > 1 and distinct < settings.min_distinct_paths:
            return None
        if self.rule.rule_id == "APACHE-PATH-ENUMERATION":
            detail = f"{count} HTTP 403/404 responses across {distinct} distinct paths"
        elif self.rule.rule_id == "APACHE-HTTP-ERRORS":
            detail = f"{count} HTTP 403/404 responses"
        elif self.rule.rule_id == "APACHE-AUTH-FAILURES":
            detail = f"{count} HTTP 401 responses to path {anchor.event.path!r}"
        elif self.rule.rule_id == "APACHE-SERVER-ERRORS":
            detail = f"{count} HTTP 5xx responses"
        elif self.rule.rule_id == "APACHE-ERROR-BURST":
            detail = f"{count} Apache error/crit/alert/emerg records"
        else:
            detail = f"{count} access records"
        subject = f"Logged IP {anchor.event.source_ip}" if self.rule.group_by_source else "Imported server logs"
        return DetectionFinding(
            rule_id=self.rule.rule_id, title=self.rule.title, severity=self.rule.severity,
            description=(
                f"{subject} produced {detail} within "
                f"{settings.window_seconds} seconds (threshold: {settings.threshold})."
            ),
            grouping_key=key, source_ip=anchor.event.source_ip if self.rule.group_by_source else None,
            first_seen=group.events[0].event.timestamp, last_seen=anchor.event.timestamp,
            event_ids=tuple(item.id for item in group.events), anchor_event_id=anchor.id,
            window_seconds=settings.window_seconds, threshold=settings.threshold,
            distinct_path_count=distinct,
        )


class DetectionEngine:
    """Evaluate stored Apache logs without changing events or creating alerts.

    Each scan has its own state. Records are read in timestamp/ID order, so file
    order and import order do not affect time windows. Windows include both ends
    and only records encountered through the anchor; future evidence is excluded.
    Once a threshold is met, each subsequent matching record produces a finding.
    """

    def __init__(
        self, settings: Mapping[str, RuleSettings] | None = None, *,
        allowed_methods: Iterable[str] | None = None,
    ):
        overrides = dict(settings or {})
        window_rules = BEHAVIORAL_RULES + SERVER_RULES
        known_ids = {rule.rule_id for rule in window_rules}
        if overrides.keys() - known_ids:
            raise ValueError("Settings must name a known window rule; request signatures have no thresholds.")
        for rule_id, value in overrides.items():
            if not isinstance(value, RuleSettings):
                raise ValueError(f"{rule_id} settings must be a RuleSettings value.")
            if rule_id != "APACHE-PATH-ENUMERATION" and value.min_distinct_paths != 1:
                raise ValueError("Only the path-enumeration rule accepts min_distinct_paths above 1.")
        self._window_rules = tuple(
            replace(rule, settings=overrides.get(rule.rule_id, rule.settings))
            for rule in window_rules
        )
        self.allowed_methods = validate_allowed_methods(
            DEFAULT_ALLOWED_METHODS if allowed_methods is None else allowed_methods,
        )
        self.rules = self._window_rules + REQUEST_RULES

    def iter_findings(
        self, store: SQLiteStore, *, start: datetime | None = None,
        end: datetime | None = None, source_ip: str | None = None,
    ) -> Iterator[DetectionFinding]:
        """Stream findings for anchors in an optional inclusive time/IP range.

        A start filter still loads earlier context for the longest rule window.
        An IP filter excludes server-wide rules, which have no single source IP.
        Memory retains active windows; callers should consume or close this
        iterator while the store's connection is open. No evidence page cap is
        applied. Repeated scans return the same findings until evidence changes.
        """
        start, end = _time(start, "start"), _time(end, "end")
        if start is not None and end is not None and start > end:
            raise ValueError("start must not be later than end.")
        context_start = (
            _subtract_window(start, max(rule.settings.window_seconds for rule in self._window_rules))
            if start is not None else None
        )
        events = store.iter_events(source_ip=source_ip, start=context_start, end=end)
        windows = tuple(
            _RuleWindow(rule) for rule in self._window_rules
            if source_ip is None or rule.group_by_source
        )
        try:
            for item in events:
                for window in windows:
                    window.expire(item.event.timestamp)
                    key = window.rule.grouping_key(item)
                    if key is None:
                        continue
                    group = window.add(key, item)
                    if start is None or item.event.timestamp >= start:
                        finding = window.finding(key, group, item)
                        if finding is not None:
                            yield finding
                if item.event.log_type != "access" or (start is not None and item.event.timestamp < start):
                    continue
                inspection = RequestInspection.from_event(item.event, self.allowed_methods)
                for rule in REQUEST_RULES:
                    reason = rule.matcher(inspection)
                    if reason is not None:
                        event = item.event
                        key = (
                            f"ip:{event.source_ip}" if event.source_ip is not None else
                            f"host:{event.source_host}" if event.source_host is not None else
                            "server:unattributed-requests"
                        )
                        yield DetectionFinding(
                            rule_id=rule.rule_id, title=rule.title, severity=rule.severity,
                            description=f"Request matched {reason}; response HTTP {event.status_code}.",
                            grouping_key=key, source_ip=event.source_ip,
                            first_seen=event.timestamp, last_seen=event.timestamp,
                            event_ids=(item.id,), anchor_event_id=item.id,
                            window_seconds=None, threshold=1,
                            distinct_path_count=int(event.path is not None),
                        )
        finally:
            events.close()
