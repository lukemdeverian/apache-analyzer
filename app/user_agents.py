"""Recognize clients that declare automation in their User-Agent header.

A declared crawler or tool is automated by its own account, so a match confirms a
bot. The reverse is not true: browser-looking User-Agents are trivially spoofed.
"""

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# Vendored from https://github.com/ai-robots-txt/ai.robots.txt (MIT, see ai_robots.LICENSE).
AI_ROBOTS_PATH = Path(__file__).resolve().parent / "data" / "ai_robots.json"
CATEGORY_LABELS = {
    "missing": "Missing User-Agent",
    "ai_crawler": "AI crawler or agent",
    "scanner": "Security scanner",
    "automation": "Automation tool or HTTP library",
    "crawler": "Self-declared crawler",
}
# Upstream tokens that are ordinary words or Electron app names and appear in
# User-Agents of people using desktop apps, so they cannot confirm automation.
_AMBIGUOUS_AI_TOKENS = frozenset(token.casefold() for token in (
    "Code", "Codex", "Cursor", "Devin", "Dot", "Instinct", "LCC", "Muse", "OpenAI",
    "Operator", "Trae", "UseAI", "YaK", "Hunyuan", "Anomura", "Lightpanda",
))
_SCANNERS = (
    "sqlmap", "nikto", "nuclei", "wpscan", "zgrab", "masscan", "nmap", "dirbuster",
    "gobuster", "feroxbuster", "ffuf", "wfuzz", "acunetix", "netsparker", "openvas",
    "nessus", "qualys", "censysinspect", "expanse", "xpanse", "Palo Alto Networks", "l9explore",
    "internetmeasurement", "infrawatch", "ModatScanner", "CyberConvoyScout", "originscan",
    "Hello, World", "Hello World", "fasthttp", "Odin",
)
_AUTOMATION = (
    "curl", "wget", "python-requests", "python-urllib", "python-httpx", "aiohttp", "httpx",
    "go-http-client", "okhttp", "java", "apache-httpclient", "libwww-perl", "lwp-trivial",
    "axios", "node-fetch", "undici", "got", "ruby", "php", "guzzlehttp", "headlesschrome",
    "phantomjs", "puppeteer", "playwright", "selenium", "httpie", "postmanruntime",
    "insomnia", "colly", "http.rb", "reqwest", "winhttp", "powershell", "libcurl",
)
# Device names that contain "bot" inside real browser User-Agents.
_CRAWLER_FALSE_POSITIVES = re.compile(r"cubot", re.IGNORECASE)
_CRAWLER = re.compile(r"[a-z0-9_-]*(?:bot|crawler|crawl|spider|scraper|scanner|slurp)(?![a-z])", re.IGNORECASE)
# Browsers always add platform and engine details after the product token.
_BARE_MOZILLA = re.compile(r"Mozilla/[0-9.]+", re.IGNORECASE)


def _token_pattern(tokens) -> re.Pattern:
    alternatives = "|".join(re.escape(token) for token in sorted(tokens, key=len, reverse=True))
    return re.compile(rf"(?<![A-Za-z0-9])(?:{alternatives})(?![A-Za-z0-9])", re.IGNORECASE)


def _load_ai_tokens(path: Path = AI_ROBOTS_PATH) -> dict[str, str]:
    """Return lowercase token -> operator, skipping upstream policy and ambiguous entries."""
    data = json.loads(path.read_text(encoding="utf-8"))
    tokens = {}
    for token, details in data.items():
        if token.startswith("__") or token.casefold() in _AMBIGUOUS_AI_TOKENS or len(token) < 3:
            continue
        operator = details.get("operator", "") if isinstance(details, dict) else ""
        tokens[token.casefold()] = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", operator).strip()
    return tokens


_AI_TOKENS = _load_ai_tokens()
_AI_PATTERN = _token_pattern(_AI_TOKENS)
# Automation clients usually lead with their product token ("curl/8.4.0").
_SCANNER_PATTERN = _token_pattern(_SCANNERS)
_AUTOMATION_PATTERN = re.compile(
    rf"^(?:{'|'.join(re.escape(name) for name in _AUTOMATION)})(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])(?:HeadlessChrome|PhantomJS|python-requests|Go-http-client|okhttp|Scrapy)(?![A-Za-z0-9])",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class DeclaredAgent:
    category: str
    name: str

    @property
    def label(self) -> str:
        return CATEGORY_LABELS[self.category]

    def reason(self) -> str:
        if self.category == "missing":
            return "Sent no User-Agent header; every mainstream browser sends one."
        return f"{self.label} in User-Agent: {self.name}."


@lru_cache(maxsize=4096)
def declared_agent(user_agent: str | None) -> DeclaredAgent | None:
    """Classify one User-Agent value; None means it does not declare automation.

    Callers pass None only for formats that log the header as "-" or empty.
    """
    value = (user_agent or "").strip()
    if not value:
        return DeclaredAgent("missing", "-")
    if match := _SCANNER_PATTERN.search(value):
        return DeclaredAgent("scanner", match[0])
    if match := _AI_PATTERN.search(value):
        operator = _AI_TOKENS.get(match[0].casefold(), "")
        return DeclaredAgent("ai_crawler", match[0] + (f" ({operator})" if operator else ""))
    if match := _AUTOMATION_PATTERN.search(value):
        return DeclaredAgent("automation", match[0])
    if _BARE_MOZILLA.fullmatch(value):
        return DeclaredAgent("automation", value + " with no browser details")
    for match in _CRAWLER.finditer(value):
        if not _CRAWLER_FALSE_POSITIVES.fullmatch(match[0]):
            return DeclaredAgent("crawler", match[0])
    return None
