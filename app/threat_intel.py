"""Optional AbuseIPDB and AlienVault OTX IP reputation with key rotation and a local cache.

Lookups only run when explicitly requested (dashboard button or CLI). Results are
cached in a separate SQLite file shared by both websites, so viewing assessments
never spends API quota. Raw provider values are stored; the malicious thresholds
are applied when results are read, so changing a threshold needs no re-query.
"""

import json
import sqlite3
import threading
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from app.database import connect_database

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEYS_PATH = PROJECT_ROOT / "threat_intel_keys.toml"
CACHE_FILENAME = "threat_intel.sqlite3"
PROVIDERS = ("abuseipdb", "otx")
PROVIDER_LABELS = {"abuseipdb": "AbuseIPDB", "otx": "AlienVault OTX"}
# AbuseIPDB: abuseConfidenceScore (0-100). OTX: reputation field (1 = malicious, 0 = clean).
THRESHOLDS = {"abuseipdb": 70, "otx": 1}
CACHE_DAYS = None  # Results never expire; use --refresh to force a re-check.
REQUEST_TIMEOUT_SECONDS = 10
MAX_CONSECUTIVE_FAILURES = 3
DEFAULT_RETIRE_SECONDS = 3600
ABUSEIPDB_MAX_AGE_DAYS = 90

# fetch(url, headers) -> (status, headers, body). Network failures raise OSError.
Fetch = Callable[[str, Mapping[str, str]], tuple[int, Mapping[str, str], bytes]]

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS ip_reputation ("
    " source_ip TEXT NOT NULL,"
    " provider TEXT NOT NULL CHECK (provider IN ('abuseipdb', 'otx')),"
    " score INTEGER NOT NULL CHECK (score >= 0),"
    " checked_at TEXT NOT NULL,"
    " PRIMARY KEY (source_ip, provider))"
)


class ThreatIntelConfigError(ValueError):
    """The key file exists but cannot be used."""


class _LookupFailed(Exception):
    pass


def load_keys(path: str | Path = DEFAULT_KEYS_PATH) -> dict[str, list[str]]:
    """Read ordered keys per provider; a missing file means no keys."""
    path = Path(path)
    keys: dict[str, list[str]] = {provider: [] for provider in PROVIDERS}
    if not path.exists():
        return keys
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ThreatIntelConfigError(f"Cannot read API key file {path.name}: {exc}") from exc
    for provider in PROVIDERS:
        section = data.get(provider, {})
        values = section.get("keys", []) if isinstance(section, dict) else None
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ThreatIntelConfigError(f"[{provider}] keys in {path.name} must be a list of strings.")
        seen = set()
        for value in values:
            value = value.strip()
            if value and value not in seen:
                seen.add(value)
                keys[provider].append(value)
    return keys


def cache_path_for(database_path: str | Path) -> str:
    """Store the shared cache beside the configured evidence database."""
    if str(database_path) == ":memory:":
        return ":memory:"
    return str(Path(database_path).with_name(CACHE_FILENAME))


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _result(provider: str, score: int, checked_at: str) -> dict:
    threshold = THRESHOLDS[provider]
    return {
        "provider": provider, "label": PROVIDER_LABELS[provider], "score": score,
        "threshold": threshold, "malicious": score >= threshold, "checked_at": checked_at,
    }


def read_reputation(cache_path: str | Path) -> dict[str, list[dict]]:
    """Return cached results per IP without creating the cache file."""
    if str(cache_path) == ":memory:" or not Path(cache_path).exists():
        return {}
    connection = connect_database(cache_path)
    try:
        connection.execute(_SCHEMA)
        rows = connection.execute(
            "SELECT source_ip, provider, score, checked_at FROM ip_reputation ORDER BY source_ip, provider"
        ).fetchall()
    finally:
        connection.close()
    results: dict[str, list[dict]] = {}
    for row in rows:
        if row["provider"] in PROVIDERS:
            results.setdefault(row["source_ip"], []).append(_result(row["provider"], row["score"], row["checked_at"]))
    return results


def describe(result: Mapping) -> str:
    if result["provider"] == "abuseipdb":
        return f"AbuseIPDB abuse confidence score {result['score']} (threshold {result['threshold']})."
    return f"AlienVault OTX lists this IP in {result['score']} threat pulse(s) (threshold {result['threshold']})."


def eligible_ip(value: str) -> bool:
    """Only public addresses have meaningful reputation; never send private ones."""
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def urllib_fetch(url: str, headers: Mapping[str, str]) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, headers={**headers, "User-Agent": "apache-analyzer"})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, dict(response.headers), response.read(1_048_576)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, dict(exc.headers or {}), exc.read(65536)


@dataclass
class KeyState:
    """Remember keys that hit a limit so later batches skip them until they reset."""

    retired_until: dict[tuple[str, str], datetime] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def available(self, provider: str, key: str, now: datetime) -> bool:
        with self.lock:
            until = self.retired_until.get((provider, key))
            if until is not None and until <= now:
                del self.retired_until[(provider, key)]
                until = None
            return until is None

    def retire(self, provider: str, key: str, until: datetime) -> None:
        with self.lock:
            self.retired_until[(provider, key)] = until


KEY_STATE = KeyState()


def _retry_after(headers: Mapping[str, str], now: datetime) -> datetime:
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    try:
        seconds = int(value) if value is not None else DEFAULT_RETIRE_SECONDS
    except ValueError:
        seconds = DEFAULT_RETIRE_SECONDS
    return now + timedelta(seconds=min(max(seconds, 1), 86400))


class _Provider:
    def __init__(self, name: str, keys: list[str], fetch: Fetch, state: KeyState, now: datetime):
        self.name, self.fetch, self.state, self.now = name, fetch, state, now
        self.keys = [key for key in keys if state.available(name, key, now)]
        self.configured = len(keys)
        self.rate_limited = self.rejected = 0
        self.failures = 0
        self.stopped_reason: str | None = None if self.keys else ("no_keys" if not keys else "all_keys_rate_limited")

    @property
    def active(self) -> bool:
        return self.stopped_reason is None

    def _request(self, address: str, key: str) -> tuple[str, dict[str, str]]:
        if self.name == "abuseipdb":
            query = urllib.parse.urlencode({"ipAddress": address, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS})
            return (f"https://api.abuseipdb.com/api/v2/check?{query}",
                    {"Key": key, "Accept": "application/json"})
        family = "IPv6" if ip_address(address).version == 6 else "IPv4"
        return (f"https://otx.alienvault.com/api/v1/indicators/{family}/{urllib.parse.quote(address, safe=':')}/general",
                {"X-OTX-API-KEY": key, "Accept": "application/json"})

    def _score(self, body: bytes) -> int:
        data = json.loads(body)
        if self.name == "abuseipdb":
            score = data["data"]["abuseConfidenceScore"]
        else:
            score = data["reputation"]
        if type(score) is not int or score < 0:
            raise ValueError("unexpected score")
        return score

    def lookup(self, address: str) -> int | None:
        """Return the score, rotating keys on limits; None once every key is used up."""
        while self.keys:
            key = self.keys[0]
            url, headers = self._request(address, key)
            try:
                status, response_headers, body = self.fetch(url, headers)
            except OSError as exc:
                self._failed()
                raise _LookupFailed(f"network error: {exc}") from exc
            if status == 429:
                # Session/daily limit reached: keep going with the next key in the list.
                self.state.retire(self.name, key, _retry_after(response_headers, self.now))
                self.rate_limited += 1
                self.keys.pop(0)
                continue
            if status in (401, 403):
                self.state.retire(self.name, key, self.now + timedelta(seconds=DEFAULT_RETIRE_SECONDS))
                self.rejected += 1
                self.keys.pop(0)
                continue
            if status != 200:
                self._failed()
                raise _LookupFailed(f"HTTP {status}")
            try:
                score = self._score(body)
            except (ValueError, KeyError, TypeError) as exc:
                self._failed()
                raise _LookupFailed("unexpected response format") from exc
            self.failures = 0
            return score
        self.stopped_reason = "all_keys_rate_limited" if not self.rejected or self.rate_limited else "all_keys_rejected"
        return None

    def _failed(self) -> None:
        self.failures += 1
        if self.failures >= MAX_CONSECUTIVE_FAILURES:
            self.stopped_reason = "repeated_failures"

    def summary(self) -> dict:
        return {
            "label": PROVIDER_LABELS[self.name], "keys_configured": self.configured,
            "keys_rate_limited": self.rate_limited, "keys_rejected": self.rejected,
            "stopped": self.stopped_reason,
        }


def check_ips(
    addresses: Iterable[str], *, keys: Mapping[str, list[str]], cache_path: str | Path,
    fetch: Fetch = urllib_fetch, state: KeyState = KEY_STATE, refresh: bool = False,
    limit: int | None = None, now: datetime | None = None,
) -> dict:
    """Look up IPs that lack a fresh cached result. Never raises for provider problems."""
    now = now or datetime.now(timezone.utc)
    candidates = sorted({str(ip_address(value)) for value in addresses if eligible_ip(value)})
    providers = [_Provider(name, list(keys.get(name, [])), fetch, state, now) for name in PROVIDERS]
    counts = {"checked": {name: 0 for name in PROVIDERS}, "errors": {name: 0 for name in PROVIDERS}}
    connection = connect_database(cache_path)
    try:
        connection.execute(_SCHEMA)
        if CACHE_DAYS is None:
            cached = {
                (row["source_ip"], row["provider"])
                for row in connection.execute("SELECT source_ip, provider FROM ip_reputation")
            }
        else:
            fresh_after = _utc(now - timedelta(days=CACHE_DAYS))
            cached = {
                (row["source_ip"], row["provider"])
                for row in connection.execute("SELECT source_ip, provider FROM ip_reputation WHERE checked_at >= ?", (fresh_after,))
            }
        pending = [
            address for address in candidates
            if refresh or any((address, provider.name) not in cached for provider in providers if provider.configured)
        ]
        processed = 0
        for address in pending:
            if limit is not None and processed >= limit:
                break
            if not any(provider.active for provider in providers):
                break
            processed += 1
            for provider in providers:
                if not provider.active or (not refresh and (address, provider.name) in cached):
                    continue
                try:
                    score = provider.lookup(address)
                except _LookupFailed:
                    counts["errors"][provider.name] += 1
                    continue
                if score is None:
                    continue
                # Autocommit: each saved result survives even if a later lookup fails.
                connection.execute(
                    "INSERT INTO ip_reputation (source_ip, provider, score, checked_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT (source_ip, provider) DO UPDATE SET score = excluded.score, checked_at = excluded.checked_at",
                    (address, provider.name, score, _utc(now)),
                )
                counts["checked"][provider.name] += 1
        remaining = len(pending) - processed
    finally:
        connection.close()
    return {
        "public_ips": len(candidates), "needing_lookup": len(pending), "processed": processed,
        "remaining": remaining, "checked": counts["checked"], "errors": counts["errors"],
        "providers": {provider.name: provider.summary() for provider in providers},
        "can_continue": remaining > 0 and any(provider.active for provider in providers),
    }
