"""Verify crawler identity against IP ranges that operators publish.

A User-Agent can be copied by anyone, but a completed TCP request cannot come
from an address the client does not control. An IP inside an operator's
published crawler ranges is therefore that operator's crawler; a User-Agent
that claims the crawler from any other IP is an impersonation.
"""

import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from ipaddress import ip_address, ip_network
from pathlib import Path

RANGES_PATH = Path(__file__).resolve().parent / "data" / "crawler_ranges.json"
DOWNLOAD_TIMEOUT_SECONDS = 60
MAX_SOURCE_BYTES = 4_194_304


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    operator: str
    label: str
    url: str


SOURCES = (
    Source("google_common", "Google", "Googlebot and common crawlers",
           "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"),
    Source("google_special", "Google", "special-case crawlers such as AdsBot",
           "https://developers.google.com/static/crawling/ipranges/special-crawlers.json"),
    Source("google_user_triggered", "Google", "user-triggered fetchers",
           "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json"),
    Source("google_user_triggered_google", "Google", "Google-owned user-triggered fetchers",
           "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json"),
    Source("bing", "Microsoft", "bingbot", "https://www.bing.com/toolbox/bingbot.json"),
    Source("openai_gptbot", "OpenAI", "GPTBot", "https://openai.com/gptbot.json"),
    Source("openai_searchbot", "OpenAI", "OAI-SearchBot", "https://openai.com/searchbot.json"),
    Source("openai_chatgpt_user", "OpenAI", "ChatGPT-User", "https://openai.com/chatgpt-user.json"),
    Source("apple", "Apple", "Applebot", "https://search.developer.apple.com/applebot.json"),
    Source("perplexity_bot", "Perplexity", "PerplexityBot", "https://www.perplexity.ai/perplexitybot.json"),
    Source("perplexity_user", "Perplexity", "Perplexity-User", "https://www.perplexity.ai/perplexity-user.json"),
    Source("duckduckgo", "DuckDuckGo", "DuckDuckBot", "https://duckduckgo.com/duckduckbot.json"),
)
_SOURCES = {source.id: source for source in SOURCES}

# User-Agent product tokens each operator documents for the crawlers above.
_CLAIM_TOKENS = {
    "Google": (
        "Googlebot", "Googlebot-Image", "Googlebot-News", "Googlebot-Video", "GoogleOther",
        "GoogleOther-Image", "GoogleOther-Video", "Google-InspectionTool", "Google-CloudVertexBot",
        "Storebot-Google", "AdsBot-Google", "AdsBot-Google-Mobile", "Mediapartners-Google",
        "APIs-Google", "FeedFetcher-Google", "Google-Read-Aloud", "GoogleProducer",
        "Google-Site-Verification", "Google-Safety",
    ),
    "Microsoft": ("bingbot", "msnbot", "BingPreview", "adidxbot"),
    "OpenAI": ("GPTBot", "OAI-SearchBot", "ChatGPT-User"),
    "Apple": ("Applebot",),
    "Perplexity": ("PerplexityBot", "Perplexity-User"),
    "DuckDuckGo": ("DuckDuckBot", "DuckAssistBot"),
}
_TOKEN_OPERATOR = {token.casefold(): operator for operator, tokens in _CLAIM_TOKENS.items() for token in tokens}
_CLAIM_PATTERN = re.compile(
    r"(?<![A-Za-z0-9-])(?:"
    + "|".join(re.escape(token) for token in sorted(_TOKEN_OPERATOR, key=len, reverse=True))
    + r")(?![A-Za-z0-9-])",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Claim:
    operator: str
    token: str


@lru_cache(maxsize=4096)
def crawler_claim(user_agent: str | None) -> Claim | None:
    """Return the verifiable crawler a User-Agent claims to be, if any."""
    match = _CLAIM_PATTERN.search(user_agent or "")
    return None if match is None else Claim(_TOKEN_OPERATOR[match[0].casefold()], match[0])


class CrawlerRanges:
    """Published prefixes indexed by (version, prefix length, network) for O(lengths) lookups."""

    def __init__(self, data: dict):
        self.sources: dict[str, dict] = {}
        self._index: dict[tuple[int, int, int], tuple[str, str]] = {}
        self._lengths: dict[int, set[int]] = {4: set(), 6: set()}
        for source_id, entry in (data.get("sources") or {}).items():
            source = _SOURCES.get(source_id)
            if source is None:
                continue
            prefixes = entry.get("prefixes") or []
            self.sources[source_id] = {"creation_time": entry.get("creation_time"), "prefix_count": len(prefixes)}
            for text in prefixes:
                network = ip_network(text, strict=False)
                self._lengths[network.version].add(network.prefixlen)
                self._index.setdefault(
                    (network.version, network.prefixlen, int(network.network_address)), (source_id, str(network)),
                )
        self.operators = frozenset(_SOURCES[source_id].operator for source_id in self.sources)
        self.updated = data.get("updated")

    def lookup(self, address: str) -> dict | None:
        """Return the published source and prefix that contain address, or None."""
        value = ip_address(address)
        if value.version == 6 and value.ipv4_mapped is not None:
            value = value.ipv4_mapped
        bits = 32 if value.version == 4 else 128
        number = int(value)
        for length in sorted(self._lengths[value.version], reverse=True):
            mask = ((1 << length) - 1) << (bits - length)
            found = self._index.get((value.version, length, number & mask))
            if found is not None:
                source = _SOURCES[found[0]]
                return {
                    "operator": source.operator, "crawler": source.label, "prefix": found[1],
                    "source_url": source.url, "creation_time": self.sources[found[0]]["creation_time"],
                }
        return None


def load_ranges(path: Path = RANGES_PATH) -> CrawlerRanges:
    return CrawlerRanges(json.loads(path.read_text(encoding="utf-8")))


_cached: tuple[tuple[str, int], CrawlerRanges] | None = None


def default_ranges() -> CrawlerRanges:
    """The vendored ranges, reloaded when crawler-ranges rewrites the file."""
    global _cached
    try:
        key = (str(RANGES_PATH), RANGES_PATH.stat().st_mtime_ns)
    except OSError:
        return CrawlerRanges({})
    if _cached is None or _cached[0] != key:
        _cached = (key, load_ranges(RANGES_PATH))
    return _cached[1]


def parse_source(body: bytes) -> dict:
    """Validate one published file ({"creationTime", "prefixes": [{"ipv4Prefix"|"ipv6Prefix"}]})."""
    document = json.loads(body)
    prefixes = []
    for item in document["prefixes"]:
        text = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        prefixes.append(str(ip_network(text, strict=False)))
    if not prefixes:
        raise ValueError("The file lists no prefixes.")
    return {"creation_time": document.get("creationTime"), "prefixes": sorted(set(prefixes))}


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "apache-analyzer", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        return response.read(MAX_SOURCE_BYTES)


def update_ranges(path: Path = RANGES_PATH, fetch: Callable[[str], bytes] = download,
                  only: Iterable[str] | None = None) -> dict:
    """Download every source; a failed source keeps its previous prefixes."""
    try:
        previous = json.loads(path.read_text(encoding="utf-8")).get("sources", {})
    except (OSError, ValueError):
        previous = {}
    wanted = set(only) if only is not None else None
    sources, results = {}, []
    for source in SOURCES:
        if wanted is not None and source.id not in wanted:
            if source.id in previous:
                sources[source.id] = previous[source.id]
            continue
        try:
            entry = parse_source(fetch(source.url))
        except (OSError, urllib.error.URLError, ValueError, KeyError, TypeError) as exc:
            if source.id in previous:
                sources[source.id] = previous[source.id]
            results.append({"source": source.id, "url": source.url, "ok": False, "error": str(exc) or type(exc).__name__,
                            "kept_previous": source.id in previous})
            continue
        sources[source.id] = {"url": source.url, **entry}
        results.append({"source": source.id, "url": source.url, "ok": True, "prefixes": len(entry["prefixes"]),
                        "creation_time": entry["creation_time"]})
    document = {"updated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sources": sources}
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".crawler_ranges.", suffix=".json")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=1)
            output.write("\n")
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return {"path": str(path), "updated": document["updated"], "sources": results}
