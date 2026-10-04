"""Pure parsers for Apache common/combined access and standard error records."""

import re
from datetime import datetime, timedelta, timezone, tzinfo
from ipaddress import ip_address

from app.events import ApacheEvent, ApacheLogType

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_QUOTED_FIELD = r'(?:[^"\\\r\n]|\\[^\r\n])*'
_ACCESS = re.compile(
    r"[ \t]*(?P<host>[^ \t\r\n]+)[ \t]+(?P<ident>[^ \t\r\n]+)"
    r"[ \t]+(?P<user>[^ \t\r\n]+)[ \t]+\[(?P<time>[^\]\r\n]+)\]"
    rf'[ \t]+"(?P<request>{_QUOTED_FIELD})"'
    r"[ \t]+(?P<status>[0-9]{3})[ \t]+(?P<bytes>[0-9]+|-)"
    rf'(?:[ \t]+"(?P<referrer>{_QUOTED_FIELD})"[ \t]+"(?P<agent>{_QUOTED_FIELD})")?'
    r"[ \t]*"
)
_ACCESS_TIME = re.compile(
    r"(?P<day>[0-9]{2})/(?P<month>[A-Za-z]{3})/(?P<year>[0-9]{4}):"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2}) "
    r"(?P<sign>[+-])(?P<offset_hour>[0-9]{2})(?P<offset_minute>[0-9]{2})"
)
_REQUEST = re.compile(
    r"(?P<method>[!#$%&'*+.^_`|~0-9A-Za-z-]+)[ \t]+(?P<target>[^ \t\r\n]+)"
    r"(?:[ \t]+(?P<protocol>HTTP/[0-9]+(?:\.[0-9]+)?))?"
)
_ABSOLUTE_TARGET = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*(?P<suffix>.*)")
_ESCAPE = re.compile(r'\\(?:x(?P<hex>[0-9A-Fa-f]{2})|(?P<char>["\\abfnrtv]))')
_ESCAPE_BYTES = {
    '"': b'"', "\\": b"\\", "a": b"\a", "b": b"\b", "f": b"\f",
    "n": b"\n", "r": b"\r", "t": b"\t", "v": b"\v",
}
_ERROR = re.compile(
    r"[ \t]*\[(?P<time>[^\]\r\n]+)\][ \t]+"
    r"\[(?:(?P<module>[A-Za-z0-9_.-]+):)?"
    r"(?P<level>emerg|alert|crit|error|warn|notice|info|debug|trace[1-8])\]"
    r"[ \t]+(?P<remaining>[^\r\n]+)"
)
_ERROR_TIME = re.compile(
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[ \t]+(?P<month>[A-Za-z]{3})"
    r"[ \t]+(?P<day>[0-9]{1,2})[ \t]+(?P<hour>[0-9]{2}):"
    r"(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,6}))?[ \t]+(?P<year>[0-9]{4})"
)
_PROCESS = re.compile(
    r"\[pid (?P<pid>[0-9]+)(?::tid (?P<tid>[0-9]+|0x[0-9A-Fa-f]+))?\]"
    r"[ \t]+(?P<remaining>[^\r\n]+)"
)
_CLIENT = re.compile(
    r"\[client (?P<endpoint>\[[^\]\r\n]+\](?::[0-9]+)?|[^\] \t\r\n]+)\]"
    r"[ \t]+(?P<message>[^\r\n]+)"
)
_ERROR_CODE = re.compile(r"(?:^|[ \t])(?P<code>AH[0-9]{5}):")


def _prepare_line(line: str, line_number: int | None) -> str | None:
    if line_number is not None and (
        isinstance(line_number, bool) or not isinstance(line_number, int) or line_number < 1
    ):
        raise ValueError("line_number must be a positive integer.")
    raw_log = line.removesuffix("\n").removesuffix("\r")
    if "\n" in raw_log or "\r" in raw_log:
        return None
    return raw_log


def _unescape(value: str) -> str:
    """Decode Apache escapes once, including escaped UTF-8 bytes."""
    decoded = bytearray()
    position = 0
    for match in _ESCAPE.finditer(value):
        decoded.extend(value[position:match.start()].encode("utf-8"))
        if match["hex"] is not None:
            decoded.append(int(match["hex"], 16))
        else:
            decoded.extend(_ESCAPE_BYTES[match["char"]])
        position = match.end()
    decoded.extend(value[position:].encode("utf-8"))
    # Invalid UTF-8 bytes stay visible as escapes; raw_log is always untouched.
    return decoded.decode("utf-8", errors="backslashreplace")


def _optional(value: str | None) -> str | None:
    return None if value is None or value == "-" else _unescape(value)


def _ip_or_none(host: str | None) -> str | None:
    try:
        return str(ip_address(host)) if host is not None else None
    except ValueError:
        return None


def _timestamp(match: re.Match[str], timestamp_timezone: tzinfo) -> datetime:
    month = _MONTHS.get(match["month"])
    if month is None:
        raise ValueError("Unrecognized Apache timestamp month.")
    fraction = match.groupdict().get("fraction") or ""
    result = datetime(
        int(match["year"]), month, int(match["day"]),
        int(match["hour"]), int(match["minute"]), int(match["second"]),
        microsecond=int(fraction.ljust(6, "0")), tzinfo=timestamp_timezone,
    )
    if result.utcoffset() is None:
        raise ValueError("The timestamp timezone must supply a UTC offset.")
    return result.astimezone(timezone.utc)


def _access_timestamp(value: str) -> datetime:
    match = _ACCESS_TIME.fullmatch(value)
    if match is None:
        raise ValueError("Invalid Apache access timestamp.")
    hours, minutes = int(match["offset_hour"]), int(match["offset_minute"])
    if hours > 23 or minutes > 59:
        raise ValueError("Invalid timestamp UTC offset.")
    offset = timedelta(hours=hours, minutes=minutes)
    if match["sign"] == "-":
        offset = -offset
    return _timestamp(match, timezone(offset))


def _split_target(target: str, method: str) -> tuple[str | None, str | None]:
    if method == "CONNECT":
        return None, None
    absolute = _ABSOLUTE_TARGET.fullmatch(target)
    if absolute is not None:
        target = absolute["suffix"] or "/"
        if target.startswith("?"):
            target = "/" + target
    path, separator, query = target.partition("?")
    return path, query if separator else None


def parse_access_line(
    line: str, *, source_file: str | None = None, line_number: int | None = None,
) -> ApacheEvent | None:
    """Parse a common/combined line; return None for malformed log records.

    Missing or malformed request lines remain valid evidence with unpopulated
    request fields. No hostname lookups or URL decoding are performed.
    """
    raw_log = _prepare_line(line, line_number)
    match = _ACCESS.fullmatch(raw_log) if raw_log is not None else None
    if match is None:
        return None
    try:
        timestamp = _access_timestamp(match["time"])
        status = int(match["status"])
        response_bytes = 0 if match["bytes"] == "-" else int(match["bytes"])
        if not 100 <= status <= 599:
            return None
        host = _optional(match["host"])
        # Split before unescaping so escaped whitespace cannot become separators.
        request_match = _REQUEST.fullmatch(match["request"])
        method, target, protocol, path, query = None, None, None, None, None
        if request_match is not None:
            method = _unescape(request_match["method"])
            target = _unescape(request_match["target"])
            protocol = request_match["protocol"]
            path, query = _split_target(target, method)
        return ApacheEvent(
            log_type="access",
            log_format="combined" if match["agent"] is not None else "common",
            timestamp=timestamp, raw_log=raw_log,
            source_file=source_file, line_number=line_number,
            source_host=host, source_ip=_ip_or_none(host),
            remote_logname=_optional(match["ident"]), username=_optional(match["user"]),
            request=_optional(match["request"]), method=method, request_target=target,
            path=path, query_string=query,
            protocol=protocol,
            status_code=status, response_bytes=response_bytes,
            referrer=_optional(match["referrer"]), user_agent=_optional(match["agent"]),
        )
    except (ValueError, OverflowError):
        return None


def _client_endpoint(endpoint: str, *, modern: bool) -> tuple[str, str, int | None]:
    host, port = endpoint, None
    if endpoint.startswith("["):
        bracketed = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", endpoint)
        if bracketed is None:
            raise ValueError("Invalid bracketed client address.")
        host, port = bracketed[1], bracketed[2]
    elif ":" in endpoint:
        candidate_host, _, candidate_port = endpoint.rpartition(":")
        # Apache 2.4's %a logs IP:port, including unbracketed IPv6. In the
        # legacy layout a valid bare IPv6 address takes precedence instead.
        if modern or _ip_or_none(endpoint) is None:
            if (
                _ip_or_none(candidate_host) is not None
                and candidate_port.isascii() and candidate_port.isdigit()
            ):
                host, port = candidate_host, candidate_port
    address = str(ip_address(host))
    parsed_port = int(port) if port is not None else None
    if parsed_port is not None and not 0 <= parsed_port <= 65535:
        raise ValueError("Invalid client port.")
    return host, address, parsed_port


def parse_error_line(
    line: str, *, source_file: str | None = None, line_number: int | None = None,
    error_timezone: tzinfo = timezone.utc,
) -> ApacheEvent | None:
    """Parse standard 2.4 or legacy error lines using an explicit timezone.

    Default error timestamps do not carry an offset. UTC is the documented
    fallback and assumed_timezone records the interpretation used.
    """
    if not isinstance(error_timezone, tzinfo):
        raise ValueError("error_timezone must be a datetime.tzinfo instance.")
    try:
        offset = datetime(2000, 1, 1, tzinfo=error_timezone).utcoffset()
    except (TypeError, ValueError, NotImplementedError) as exc:
        raise ValueError("error_timezone must supply a valid UTC offset.") from exc
    if offset is None:
        raise ValueError("error_timezone must supply a UTC offset.")
    raw_log = _prepare_line(line, line_number)
    match = _ERROR.fullmatch(raw_log) if raw_log is not None else None
    if match is None:
        return None
    time_match = _ERROR_TIME.fullmatch(match["time"])
    if time_match is None:
        return None
    try:
        timestamp = _timestamp(time_match, error_timezone)
        remaining = match["remaining"]
        process_id, thread_id = None, None
        if remaining.startswith("[pid "):
            process = _PROCESS.fullmatch(remaining)
            if process is None:
                return None
            process_id, thread_id = int(process["pid"]), process["tid"]
            remaining = process["remaining"]
        modern = match["module"] is not None or process_id is not None
        host, address, port = None, None, None
        if remaining.startswith("[client "):
            client = _CLIENT.fullmatch(remaining)
            if client is None:
                return None
            host, address, port = _client_endpoint(client["endpoint"], modern=modern)
            remaining = client["message"]
        if not remaining.strip():
            return None
        error_code = _ERROR_CODE.search(remaining)
        return ApacheEvent(
            log_type="error", log_format="error_2_4" if modern else "error_legacy",
            timestamp=timestamp, raw_log=raw_log,
            source_file=source_file, line_number=line_number,
            source_host=host, source_ip=address, source_port=port,
            assumed_timezone=str(error_timezone),
            module=match["module"], level=match["level"],
            process_id=process_id, thread_id=thread_id,
            error_code=error_code["code"] if error_code else None, message=remaining,
        )
    except (ValueError, OverflowError):
        return None


def parse_apache_line(
    line: str, log_type: ApacheLogType, *,
    source_file: str | None = None, line_number: int | None = None,
    error_timezone: tzinfo = timezone.utc,
) -> ApacheEvent | None:
    """Select an Apache parser explicitly; reject unsupported log types."""
    if log_type == "access":
        return parse_access_line(line, source_file=source_file, line_number=line_number)
    if log_type == "error":
        return parse_error_line(
            line, source_file=source_file, line_number=line_number,
            error_timezone=error_timezone,
        )
    raise ValueError("Unsupported Apache log type; choose 'access' or 'error'.")
