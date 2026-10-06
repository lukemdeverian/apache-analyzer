"""Bounded JSON investigation endpoints for the local Apache analyzer."""

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any

from flask import Blueprint, Flask, Response, current_app, request
from werkzeug.exceptions import HTTPException, NotFound

from app.alerts import ALERT_STATUSES, SEVERITIES
from app.database import get_database, transaction
from app.detection import BEHAVIORAL_RULES, REQUEST_RULES, SERVER_RULES
from app.pipeline import DEFAULT_REQUEST_CORRELATION_SECONDS
from app.signatures import DEFAULT_ALLOWED_METHODS
from app.storage import SQLiteStore, StoredAlert, StoredEvent

api = Blueprint("api", __name__, url_prefix="/api")
_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_COMMON_FILTERS = {"source_ip", "start", "end"}
_PAGE_PARAMETERS = {"limit", "offset", "order"}


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _invalid(message: str) -> None:
    raise APIError(400, "invalid_request", message)


def _query(allowed: set[str]) -> None:
    if request.args.keys() - allowed:
        _invalid("Unknown query parameter.")
    if any(len(values) != 1 for _, values in request.args.lists()):
        _invalid("Query parameters must not be repeated.")


def _integer(value: str, name: str, minimum: int, maximum: int = 2**63 - 1) -> int:
    if not re.fullmatch(r"[0-9]{1,19}", value) or not minimum <= int(value) <= maximum:
        _invalid(f"{name} must be an integer between {minimum} and {maximum}.")
    return int(value)


def _choice(name: str, choices: tuple[str, ...], default: str | None = None) -> str | None:
    value = request.args.get(name, default)
    if value is not None and value not in choices:
        _invalid(f"{name} must be one of: {', '.join(choices)}.")
    return value


def _timestamp(name: str) -> datetime | None:
    value = request.args.get(name)
    if value is None:
        return None
    if _TIME.fullmatch(value):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (ValueError, OverflowError):
            pass
    _invalid(f"{name} must be an RFC 3339 timestamp with Z or an explicit UTC offset.")


def _common_filters() -> dict[str, Any]:
    source_ip = request.args.get("source_ip")
    if source_ip is not None:
        try:
            if len(source_ip) > 45 or "%" in source_ip:
                raise ValueError
            source_ip = str(ip_address(source_ip))
        except ValueError:
            _invalid("source_ip must be an IPv4 or IPv6 address.")
    start, end = _timestamp("start"), _timestamp("end")
    if start is not None and end is not None and start > end:
        _invalid("start must not be later than end.")
    return {"source_ip": source_ip, "start": start, "end": end}


def _page(default_order: str = "desc") -> dict[str, Any]:
    return {
        "limit": _integer(request.args.get("limit", "100"), "limit", 1, 1000),
        "offset": _integer(request.args.get("offset", "0"), "offset", 0),
        "newest_first": _choice("order", ("asc", "desc"), default_order) == "desc",
    }


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def _event(item: StoredEvent) -> dict[str, Any]:
    return {"id": item.id, **_json_value(asdict(item.event))}


def _alert(item: StoredAlert) -> dict[str, Any]:
    return {"id": item.id, "event_count": item.event_count, **_json_value(asdict(item.alert))}


def _pagination(page: dict[str, Any], total: int, returned: int) -> dict[str, Any]:
    return {
        "limit": page["limit"], "offset": page["offset"], "total": total,
        "returned": returned, "has_more": page["offset"] + returned < total,
    }


@contextmanager
def _store() -> Iterator[SQLiteStore]:
    try:
        connection = get_database()
        try:
            store = SQLiteStore(connection)
        except RuntimeError as exc:
            raise APIError(
                503, "database_not_ready",
                "Database schema is missing or incompatible. Run 'flask --app app init-db' "
                "to initialize or upgrade an owned version 1 database. Other schemas require a migration.",
            ) from exc
        # Lists, counts, details and aggregates share a consistent snapshot.
        # The same boundary makes status writes atomic.
        with transaction(connection):
            yield store
    except (sqlite3.Error, OSError, ValueError) as exc:
        current_app.logger.exception("Investigation API database operation failed.")
        raise APIError(503, "database_unavailable", "The local database is unavailable.") from exc


def _find_alert(store: SQLiteStore, alert_id: int) -> StoredAlert:
    item = store.get_alert(alert_id)
    if item is None:
        raise NotFound("Alert not found.")
    return item


@api.get("/events")
def events() -> dict[str, Any]:
    _query(_COMMON_FILTERS | _PAGE_PARAMETERS | {"log_type"})
    filters = {**_common_filters(), "log_type": _choice("log_type", ("access", "error"))}
    page = _page()
    with _store() as store:
        items = [_event(item) for item in store.list_events(**filters, **page)]
        total = store.count_events(**filters)
    return {"items": items, "pagination": _pagination(page, total, len(items))}


@api.get("/events/<event_id>")
def event_detail(event_id: str) -> dict[str, Any]:
    _query(set())
    identity = _integer(event_id, "event_id", 1)
    with _store() as store:
        item = store.get_event(identity)
        if item is None:
            raise NotFound("Event not found.")
        return {"item": _event(item)}


@api.get("/alerts")
def alerts() -> dict[str, Any]:
    _query(_COMMON_FILTERS | _PAGE_PARAMETERS | {"rule_id", "severity", "status"})
    rule_id = request.args.get("rule_id")
    if rule_id is not None and (not rule_id.strip() or len(rule_id) > 128):
        _invalid("rule_id must contain between 1 and 128 characters.")
    filters = {
        **_common_filters(), "rule_id": rule_id,
        "severity": _choice("severity", SEVERITIES), "status": _choice("status", ALERT_STATUSES),
    }
    page = _page()
    with _store() as store:
        items = [_alert(item) for item in store.list_alerts(**filters, **page)]
        total = store.count_alerts(**filters)
    return {"items": items, "pagination": _pagination(page, total, len(items))}


@api.get("/alerts/<alert_id>")
def alert_detail(alert_id: str) -> dict[str, Any]:
    _query(set())
    identity = _integer(alert_id, "alert_id", 1)
    with _store() as store:
        return {"item": _alert(_find_alert(store, identity)), "requested_id": identity}


@api.get("/alerts/<alert_id>/events")
def alert_evidence(alert_id: str) -> dict[str, Any]:
    _query({"limit", "offset"})
    identity = _integer(alert_id, "alert_id", 1)
    page = _page("asc")
    with _store() as store:
        alert = _find_alert(store, identity)
        items = [
            _event(item) for item in store.get_alert_events(
                alert.id, limit=page["limit"], offset=page["offset"],
            )
        ]
    return {
        "alert_id": alert.id, "requested_id": identity, "items": items,
        "pagination": _pagination(page, alert.event_count, len(items)),
    }


@api.patch("/alerts/<alert_id>/status")
def alert_status(alert_id: str) -> dict[str, Any]:
    _query(set())
    identity = _integer(alert_id, "alert_id", 1)
    request.max_content_length = 1024
    body = request.get_json()
    if not isinstance(body, dict) or set(body) != {"status"}:
        _invalid("The JSON body must contain exactly one field: status.")
    if not isinstance(body["status"], str) or body["status"] not in ALERT_STATUSES:
        _invalid(f"status must be one of: {', '.join(ALERT_STATUSES)}.")
    with _store() as store:
        item = store.set_alert_status(identity, body["status"])
        if item is None:
            raise NotFound("Alert not found.")
        return {"item": _alert(item), "requested_id": identity}


@api.get("/rules")
def rules() -> dict[str, Any]:
    _query(set())
    items = []
    for rule in BEHAVIORAL_RULES + SERVER_RULES + REQUEST_RULES:
        item = {
            "rule_id": rule.rule_id, "title": rule.title,
            "description": rule.description, "severity": rule.severity,
            "log_type": getattr(rule, "log_type", "access"),
            "kind": "window" if rule.settings is not None else "request",
            "settings": asdict(rule.settings) if rule.settings is not None else None,
        }
        if rule.settings is not None:
            item.update(
                status_codes=list(rule.status_codes), levels=list(rule.levels),
                requires_path=rule.requires_path,
                grouping="server" if not rule.group_by_source else (
                    "source_ip_and_path" if rule.group_by_path else "source_ip"
                ),
            )
        else:
            item["grouping"] = "source_ip_or_host"
        items.append(item)
    return {
        "items": items, "configuration": "defaults",
        "allowed_methods": sorted(DEFAULT_ALLOWED_METHODS),
        "request_correlation_seconds": DEFAULT_REQUEST_CORRELATION_SECONDS,
    }


@api.get("/stats")
def statistics() -> dict[str, Any]:
    _query(_COMMON_FILTERS)
    filters = _common_filters()
    with _store() as store:
        return _json_value(store.statistics(**filters))


def _error_response(error: APIError) -> tuple[dict[str, Any], int]:
    return {"error": {"code": error.code, "message": error.message}}, error.status


def _http_error(error: HTTPException) -> Response | HTTPException:
    if request.path != "/api" and not request.path.startswith("/api/"):
        return error
    response = error.get_response()
    response.data = current_app.json.dumps({
        "error": {
            "code": error.name.lower().replace(" ", "_"),
            "message": error.description if error.code != 500 else "An internal error occurred.",
        },
    })
    response.content_type = "application/json"
    return response


def init_app(app: Flask) -> None:
    app.register_blueprint(api)
    app.register_error_handler(APIError, _error_response)
    # Routing 404/405 errors occur before Flask can choose a blueprint.
    app.register_error_handler(HTTPException, _http_error)

    @app.after_request
    def investigation_headers(response: Response) -> Response:
        if request.path == "/api" or request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response
