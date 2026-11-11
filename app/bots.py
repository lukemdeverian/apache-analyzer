"""Explainable IP assessments within one website's imported Apache evidence."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections.abc import Mapping
from ipaddress import ip_address
from urllib.parse import urlsplit

from app.parsers import access_extensions
from app.signatures import DEFAULT_ALLOWED_METHODS, RequestInspection, wordpress_probe
from app.storage import SQLiteStore
from app.threat_intel import THRESHOLDS, describe as describe_reputation
from app.user_agents import declared_agent
from app.verified_crawlers import CrawlerRanges, crawler_claim, default_ranges

USER_AGENT_FORMATS = frozenset({"combined", "extended_combined"})

SITE_HOST = "chronoscrate.xyz"
CLASSIFICATIONS = ("confirmed_bot", "suspected_bot", "verified_crawler", "not_a_bot")
CLASSIFICATION_LABELS = dict(zip(
    CLASSIFICATIONS, ("Confirmed bot", "Suspected bot", "Verified crawler", "Not a bot"),
))
RECOMMENDATIONS = {
    "confirmed_bot": "review_for_block", "suspected_bot": "monitor_or_challenge",
    "verified_crawler": "allow_or_use_robots_txt", "not_a_bot": "allow_and_monitor",
}
# Reputation can only move an IP into Confirmed bot, and verified crawler identity outranks it.
REPUTATION_SETTLED = frozenset({"confirmed_bot", "verified_crawler"})
TRACKED_PAGES = ("/", "/checkout")
SAMPLE_LIMIT = 10
_LANGUAGE = re.compile(
    r"(?P<tag>[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*)"
    r"(?:\s*;\s*q=(?P<weight>0(?:\.[0-9]{1,3})?|1(?:\.0{1,3})?))?"
)


def policy(hostname: str = SITE_HOST) -> dict:
    return {
        "website": "https://" + hostname,
        "tracked_pages": list(TRACKED_PAGES),
        "classifications": CLASSIFICATION_LABELS,
        "normal_signal": "Successful GET of a CSS resource (2xx or 304).",
        "neutral_signals": ["html", "home_page", "checkout", "language"],
        "risk_policy": "Any IP-attributed risk alert except false positives overrides browsing signals.",
        "wordpress_policy": (
            "Unexpected WordPress entry-point requests confirm bots even without a saved alert; "
            "linked false-positive decisions are respected."
        ),
        "threat_intel_policy": (
            f"AbuseIPDB abuse confidence score of {THRESHOLDS['abuseipdb']} or higher, or an AlienVault OTX "
            "reputation of 1 (malicious), confirms a bot. Results come from cached lookups."
        ),
        "user_agent_policy": (
            "A User-Agent that declares a crawler, AI agent, scanner, or HTTP library, or a missing "
            "User-Agent in a combined log, confirms a bot. Browser-like User-Agents prove nothing."
        ),
        "crawler_policy": (
            "An IP inside a crawler operator's published IP ranges (Google, Microsoft, OpenAI, Apple, "
            "Perplexity, DuckDuckGo) is a verified crawler and is never exported, whatever else it did. "
            "A User-Agent claiming one of those crawlers from any other IP is impersonation and confirms a bot."
        ),
        "interpretation": "Rule-based labels describe observed history; they do not prove automation or humanity.",
        "scope": "Import this site's logs. Standard Apache layouts do not include the requested host.",
        "sample_limit": SAMPLE_LIMIT,
    }


def _languages(fields: dict[str, str]) -> tuple[bool, list[str]]:
    # Different aliases in the same record are ambiguous too.
    values = [fields[name] for name in ("lang", "accept-language", "accept_language") if name in fields]
    if len(values) != 1 or len(values[0]) > 512:
        return bool(values), []
    languages = []
    for part in values[0].split(","):
        match = _LANGUAGE.fullmatch(part.strip())
        if match is not None and (match["weight"] is None or float(match["weight"]) > 0):
            languages.append(match["tag"])
    return True, languages


def _site_path(target: str | None, path: str | None, hostname: str) -> str | None:
    if not target or any(ord(char) < 33 or ord(char) == 127 for char in target):
        return None
    if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", target):
        try:
            address = urlsplit(target)
            if (
                address.scheme.lower() not in ("http", "https")
                or address.hostname != hostname or address.username is not None
                or address.password is not None or address.port not in (None, 80, 443)
            ):
                return None
        except ValueError:
            return None
    elif not target.startswith("/") or target.startswith("//"):
        return None
    return path


def _dismissed_wordpress_probe(store: SQLiteStore, event_id: int, source_ip: str) -> bool:
    cursor = store.connection.execute(
        "SELECT 1 FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id "
        "WHERE ae.event_id = ? AND a.source_ip = ? "
        "AND a.rule_id = 'APACHE-WORDPRESS-PROBE' AND a.status = 'false_positive' LIMIT 1",
        (event_id, source_ip),
    )
    try:
        return cursor.fetchone() is not None
    finally:
        cursor.close()


@dataclass
class _Profile:
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    request_count: int = 0
    home_requests: int = 0
    checkout_requests: int = 0
    html_requests: int = 0
    css_requests: int = 0
    language_logged_requests: int = 0
    language_requests: int = 0
    languages: set[str] = field(default_factory=set)
    browsing_evidence: dict[str, int] = field(default_factory=dict)
    risk_alert_count: int = 0
    risk_alerts: list[dict] = field(default_factory=list)
    wordpress_probe_count: int = 0
    wordpress_probe_evidence: list[dict] = field(default_factory=list)
    threat_intel: list[dict] = field(default_factory=list)
    declared_agent_count: int = 0
    declared_agents: dict[tuple[str, str], dict] = field(default_factory=dict)
    verified_crawler: dict | None = None
    crawler_claims: dict[tuple[str, str], dict] = field(default_factory=dict)

    def add_crawler_claim(self, claim, verifiable: bool, user_agent: str, event_id: int) -> None:
        key = (claim.operator, claim.token.casefold())
        if key in self.crawler_claims:
            self.crawler_claims[key]["requests"] += 1
        elif len(self.crawler_claims) < SAMPLE_LIMIT:
            verified = self.verified_crawler is not None and self.verified_crawler["operator"] == claim.operator
            self.crawler_claims[key] = {
                "operator": claim.operator, "token": claim.token, "user_agent": user_agent,
                "event_id": event_id, "requests": 1, "verifiable": verifiable,
                "impersonation": verifiable and not verified,
            }

    def add_declared_agent(self, agent, user_agent: str | None, event_id: int) -> None:
        self.declared_agent_count += 1
        key = (agent.category, agent.name.casefold())
        if key in self.declared_agents:
            self.declared_agents[key]["requests"] += 1
        elif len(self.declared_agents) < SAMPLE_LIMIT:
            self.declared_agents[key] = {
                "category": agent.category, "label": agent.label, "name": agent.name,
                "reason": agent.reason(), "user_agent": user_agent, "event_id": event_id, "requests": 1,
            }

    def result(self) -> dict:
        normal = bool(self.css_requests)
        intel_hits = [result for result in self.threat_intel if result["malicious"]]
        impersonations = [claim for claim in self.crawler_claims.values() if claim["impersonation"]]
        risk = bool(
            self.risk_alert_count or self.wordpress_probe_count or intel_hits
            or self.declared_agent_count or impersonations
        )
        if self.verified_crawler is not None:
            classification = "verified_crawler"
        else:
            classification = "confirmed_bot" if risk else "not_a_bot" if normal else "suspected_bot"
        reasons = []
        if (verified := self.verified_crawler) is not None:
            reasons.append(
                f"IP is inside {verified['prefix']}, which {verified['operator']} publishes for "
                f"{verified['crawler']} ({verified['source_url']}, list dated {(verified['creation_time'] or 'unknown')[:10]})."
            )
            claimed = sorted({claim["token"] for claim in self.crawler_claims.values() if not claim["impersonation"]})
            if claimed:
                reasons.append(f"User-Agent also identifies it as {', '.join(claimed)}.")
        for claim in impersonations:
            reasons.append(
                f"User-Agent claims {claim['token']} ({claim['operator']}), but the IP is not in "
                f"{claim['operator']}'s published crawler ranges; likely impersonation ({claim['requests']} request(s))."
            )
        if self.risk_alert_count:
            reasons.append(f"{self.risk_alert_count} IP-attributed risk alert(s), excluding false positives.")
        if self.wordpress_probe_count:
            reasons.append(
                f"{self.wordpress_probe_count} unexpected WordPress entry-point request(s) on a site without WordPress; "
                "a single request confirms a bot, including HTTP 404 responses."
            )
        reasons.extend(describe_reputation(result) for result in intel_hits)
        for agent in self.declared_agents.values():
            reasons.append(agent["reason"] + f" ({agent['requests']} request(s))")
        if self.css_requests:
            reasons.append("Successfully requested CSS.")
        if verified is not None:
            reasons.append(
                "Published crawler ranges take priority over all other signals; blocking this IP blocks the "
                "genuine crawler. Use robots.txt to limit what it fetches."
            )
        elif self.risk_alert_count and normal:
            reasons.append("Risk alerts take priority over normal browsing signals.")
        elif self.wordpress_probe_count and normal:
            reasons.append("WordPress probes take priority over normal browsing signals.")
        elif intel_hits and normal:
            reasons.append("Threat intelligence takes priority over normal browsing signals.")
        elif self.declared_agent_count and normal:
            reasons.append("A declared automated User-Agent takes priority over normal browsing signals.")
        if classification == "suspected_bot":
            reasons.append("No successful CSS request in the selected history.")
            reasons.append("HTML, page visits, and language preferences are neutral; review before considering a block.")
        return {
            "source_ip": self.source_ip, "classification": classification,
            "label": CLASSIFICATION_LABELS[classification],
            "recommendation": RECOMMENDATIONS[classification],
            "reasons": reasons, "first_seen": self.first_seen, "last_seen": self.last_seen,
            "request_count": self.request_count, "home_requests": self.home_requests,
            "checkout_requests": self.checkout_requests, "html_requests": self.html_requests,
            "css_requests": self.css_requests, "language_requests": self.language_requests,
            "language_logged_requests": self.language_logged_requests,
            "languages": sorted(self.languages),
            "browsing_evidence": [
                {"signal": signal, "event_id": identity} for signal, identity in self.browsing_evidence.items()
            ],
            "risk_alert_count": self.risk_alert_count, "risk_alerts": self.risk_alerts,
            "wordpress_probe_count": self.wordpress_probe_count,
            "wordpress_probe_evidence": self.wordpress_probe_evidence,
            "threat_intel": self.threat_intel, "threat_intel_hits": len(intel_hits),
            "declared_agent_count": self.declared_agent_count,
            "declared_agents": list(self.declared_agents.values()),
            "verified_crawler": self.verified_crawler,
            "crawler_claims": list(self.crawler_claims.values()),
            "impersonation": bool(impersonations),
        }


def assess_bots(
    store: SQLiteStore, *, source_ip: str | None = None,
    start: datetime | None = None, end: datetime | None = None,
    hostname: str = SITE_HOST, reputation: Mapping[str, list[dict]] | None = None,
    crawlers: CrawlerRanges | None = None,
) -> tuple[list[dict], dict]:
    """Derive assessments from current evidence, analyst decisions, cached
    reputation lookups, and stored crawler ranges; never ban and never call an
    external service."""
    crawlers = default_ranges() if crawlers is None else crawlers
    profiles: dict[str, _Profile] = {}
    unattributed = 0
    for item in store.iter_events(source_ip=source_ip, log_type="access", start=start, end=end):
        event = item.event
        try:
            address = str(ip_address(event.source_ip)) if event.source_ip is not None else None
        except ValueError:
            address = None
        if address is None:
            unattributed += 1
            continue
        if address not in profiles:
            profiles[address] = _Profile(
                address, event.timestamp, event.timestamp,
                threat_intel=list((reputation or {}).get(address, ())),
                verified_crawler=crawlers.lookup(address),
            )
        profile = profiles[address]
        profile.request_count += 1
        profile.last_seen = event.timestamp
        # Existing evidence must classify correctly before a detection rescan.
        if (
            wordpress_probe(RequestInspection.from_event(event, DEFAULT_ALLOWED_METHODS))
            and not _dismissed_wordpress_probe(store, item.id, address)
        ):
            profile.wordpress_probe_count += 1
            if len(profile.wordpress_probe_evidence) < SAMPLE_LIMIT:
                profile.wordpress_probe_evidence.append({"event_id": item.id})
        # Common-format logs never record the header, so absence means nothing there.
        if event.log_format in USER_AGENT_FORMATS and (agent := declared_agent(event.user_agent)) is not None:
            # Browsers open spare connections that time out (408) before sending a
            # request line or headers; only a received request can omit the header.
            if agent.category != "missing" or event.method is not None:
                profile.add_declared_agent(agent, event.user_agent, item.id)
        if event.log_format in USER_AGENT_FORMATS and (claim := crawler_claim(event.user_agent)) is not None:
            profile.add_crawler_claim(claim, claim.operator in crawlers.operators, event.user_agent, item.id)
        fields = access_extensions(event.raw_log)
        logged, languages = _languages(fields)
        profile.language_logged_requests += logged
        profile.language_requests += bool(languages)
        for language in languages:
            if len(profile.languages) < SAMPLE_LIMIT:
                profile.languages.add(language)
        path = _site_path(event.request_target, event.path, hostname)
        success = event.status_code is not None and (200 <= event.status_code < 300 or event.status_code == 304)
        if event.method != "GET" or not success or path is None:
            continue
        home, checkout = path == "/", path in ("/checkout", "/checkout/")
        html = home or checkout or path.lower().endswith((".html", ".htm")) or fields.get("sfd") == "document"
        css = path.lower().endswith(".css") or fields.get("sfd") == "style"
        profile.home_requests += home
        profile.checkout_requests += checkout
        profile.html_requests += html
        profile.css_requests += css
        if css:
            profile.browsing_evidence.setdefault("css", item.id)

    # Attribute only alerts whose own source IP matches linked access evidence.
    # Server-wide alerts do not identify an individual malicious visitor.
    clauses = ["a.source_ip IS NOT NULL", "a.status != 'false_positive'", "e.log_type = 'access'", "e.source_ip = a.source_ip"]
    values = []
    if source_ip is not None:
        clauses.append("e.source_ip = ?")
        values.append(source_ip)
    for operator, timestamp in ((">=", start), ("<=", end)):
        if timestamp is not None:
            clauses.append(f"e.timestamp {operator} ?")
            values.append(timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds"))
    cursor = store.connection.execute(
        "SELECT a.id, a.source_ip, a.rule_id, a.title, a.severity, a.status, "
        "MIN(e.id) AS event_id, COUNT(*) AS evidence_count "
        "FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id "
        "JOIN events e ON e.id = ae.event_id WHERE " + " AND ".join(clauses)
        + " GROUP BY a.id ORDER BY a.id DESC", values,
    )
    try:
        for row in cursor:
            profile = profiles.get(row["source_ip"])
            if profile is not None:
                profile.risk_alert_count += 1
                if len(profile.risk_alerts) < SAMPLE_LIMIT:
                    profile.risk_alerts.append({key: row[key] for key in row.keys() if key != "source_ip"})
    finally:
        cursor.close()
    items = [profile.result() for profile in profiles.values()]
    summary = {
        "total": len(items), "unattributed_requests": unattributed,
        "by_classification": {classification: 0 for classification in CLASSIFICATIONS},
    }
    for item in items:
        summary["by_classification"][item["classification"]] += 1
    summary["ban_candidates"] = summary["by_classification"]["confirmed_bot"]
    summary["threat_intel_confirmed"] = sum(1 for item in items if item["threat_intel_hits"])
    summary["threat_intel_checked"] = sum(1 for item in items if item["threat_intel"])
    summary["declared_agent_confirmed"] = sum(
        1 for item in items if item["declared_agent_count"] and item["classification"] == "confirmed_bot"
    )
    summary["impersonation_confirmed"] = sum(
        1 for item in items if item["impersonation"] and item["classification"] == "confirmed_bot"
    )
    summary["crawler_ranges_updated"] = crawlers.updated
    return items, summary
