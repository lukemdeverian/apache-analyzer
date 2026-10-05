"""Small request signatures; decoded inspection views never replace evidence."""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from html import unescape
from urllib.parse import unquote, unquote_plus

from app.events import ApacheEvent

DEFAULT_ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"})
_METHOD_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_PATH_TRAVERSAL = re.compile(r"(?:^|[/\\])\.\.(?=$|[/\\])")
_QUERY_TRAVERSAL = re.compile(r"(?:^|[/\\=])\.\.(?=$|[/\\&])")
_SQL_SEPARATOR = r"(?:\s|/\*[^*]{0,128}\*/)+"
_SQL_PATTERNS = (
    ("UNION SELECT", re.compile(
        rf"\bunion{_SQL_SEPARATOR}(?:all{_SQL_SEPARATOR})?select\b", re.IGNORECASE,
    )),
    ("literal SQL comparison", re.compile(
        r"\b(?:or|and)\s+(?:[0-9]{1,10}\s*=\s*[0-9]{1,10}(?!\w)|"
        r"['\"][a-z0-9]{1,32}['\"]\s*=\s*['\"][a-z0-9]{1,32}(?:['\"]|$|(?=[&#])))",
        re.IGNORECASE,
    )),
    ("SQL delay function", re.compile(r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*[0-9]", re.IGNORECASE)),
    ("stacked SQL statement", re.compile(
        r";\s*(?:(?:drop|alter|truncate)\s+table\b|insert\s+into\b|delete\s+from\b|"
        r"update\s+[a-z_][a-z0-9_]{0,63}\s+set\b)", re.IGNORECASE,
    )),
)
_XSS_PATTERNS = (
    ("script tag", re.compile(r"<\s*script(?=[\s/>])", re.IGNORECASE)),
    ("HTML event handler", re.compile(
        r"(?:<[^<>]{0,512}[\s/]|['\"]\s+)on[a-z]{3,32}\s*=", re.IGNORECASE,
    )),
    ("JavaScript URI", re.compile(r"\bjavascript\s*:", re.IGNORECASE)),
)
_HTML_ENTITY = re.compile(
    r"&(?:#[xX][0-9a-fA-F]{1,8}(?![0-9a-fA-F])|#[0-9]{1,10}(?![0-9])|"
    r"[A-Za-z][A-Za-z0-9]{0,31}(?![A-Za-z0-9]));?"
)
_SECRET_FILES = frozenset({
    ".htaccess", ".htpasswd", "wp-config.php", "config.php", "web.config",
    "id_rsa", "id_ed25519",
})
_BACKUP_SUFFIXES = (".sql", ".sqlite", ".sqlite3", ".db", ".bak", ".old", ".orig", ".swp", "~")


def validate_allowed_methods(methods: Iterable[str]) -> frozenset[str]:
    if isinstance(methods, (str, bytes)):
        raise ValueError("allowed_methods must be a collection of HTTP method tokens.")
    try:
        values = tuple(methods)
    except TypeError as exc:
        raise ValueError("allowed_methods must be a collection of HTTP method tokens.") from exc
    if not values or any(not isinstance(value, str) or _METHOD_TOKEN.fullmatch(value) is None for value in values):
        raise ValueError("allowed_methods must contain valid, nonempty HTTP method tokens.")
    return frozenset(values)


def _views(value: str | None, *, query: bool = False) -> tuple[str, ...]:
    if value is None:
        return ()
    values = [value]
    for depth in range(2):
        decoded = unquote_plus(value) if query and depth == 0 else unquote(value)
        if decoded == value:
            break
        values.append(decoded)
        value = decoded
    return tuple(values)


@dataclass(frozen=True, slots=True)
class RequestInspection:
    path_views: tuple[str, ...]
    query_views: tuple[str, ...]
    method: str | None
    allowed_methods: frozenset[str]

    @classmethod
    def from_event(cls, event: ApacheEvent, allowed_methods: frozenset[str]) -> "RequestInspection":
        return cls(_views(event.path), _views(event.query_string, query=True), event.method, allowed_methods)

    def targets(self) -> Iterator[tuple[str, str]]:
        for location, values in (("path", self.path_views), ("query", self.query_views)):
            for value in values:
                yield location, value


def traversal(inspection: RequestInspection) -> str | None:
    for location, value in inspection.targets():
        pattern = _PATH_TRAVERSAL if location == "path" else _QUERY_TRAVERSAL
        if pattern.search(value):
            return f"parent-directory segment in the request {location}"
    return None


def sql_injection(inspection: RequestInspection) -> str | None:
    for location, value in inspection.targets():
        for name, pattern in _SQL_PATTERNS:
            if pattern.search(value):
                return f"{name} signature in the request {location}"
    return None


def xss(inspection: RequestInspection) -> str | None:
    for location, value in inspection.targets():
        # Decode bounded references individually. A huge decimal reference can
        # raise in html.unescape on Python's integer-conversion limit; leaving
        # it intact must not prevent other references or records being checked.
        html_view = _HTML_ENTITY.sub(lambda match: unescape(match[0]), value)
        for candidate in (value, html_view):
            for name, pattern in _XSS_PATTERNS:
                if pattern.search(candidate):
                    return f"{name} signature in the request {location}"
    return None


def sensitive_file(inspection: RequestInspection) -> str | None:
    for value in inspection.path_views:
        parts = value.casefold().replace("\\", "/").split("/")
        for part in parts:
            if part in {".git", ".svn", ".hg"}:
                return "version-control metadata path"
            if part == ".env" or part.startswith(".env.") or part in _SECRET_FILES:
                return "configuration or credential file path"
        if parts[-1].endswith(_BACKUP_SUFFIXES):
            return "database or backup file suffix"
    return None


def unusual_method(inspection: RequestInspection) -> str | None:
    if inspection.method is not None and inspection.method not in inspection.allowed_methods:
        return "HTTP method outside the configured allowed_methods set"
    return None
