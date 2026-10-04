"""Normalized Apache evidence, independent of storage and the web application."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

ApacheLogType = Literal["access", "error"]


@dataclass(frozen=True, slots=True, kw_only=True)
class ApacheEvent:
    """One Apache record with a UTC timestamp and its original log evidence.

    Fields that are unavailable in a log format remain None. Raw evidence omits
    only the final line ending. An error record's assumed_timezone identifies
    the caller-supplied timezone used for its otherwise offset-free timestamp.
    """

    log_type: ApacheLogType
    log_format: str
    timestamp: datetime
    raw_log: str
    source_file: str | None = None
    line_number: int | None = None
    source_host: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    assumed_timezone: str | None = None

    # Access-log fields. Targets retain percent encoding and dot segments.
    remote_logname: str | None = None
    username: str | None = None
    request: str | None = None
    method: str | None = None
    request_target: str | None = None
    path: str | None = None
    query_string: str | None = None
    protocol: str | None = None
    status_code: int | None = None
    response_bytes: int | None = None
    referrer: str | None = None
    user_agent: str | None = None

    # Error-log fields. Thread IDs can be decimal or hexadecimal strings.
    module: str | None = None
    level: str | None = None
    process_id: int | None = None
    thread_id: str | None = None
    error_code: str | None = None
    message: str | None = None
