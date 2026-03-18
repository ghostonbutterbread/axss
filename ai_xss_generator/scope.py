"""Scope enforcement for active scans.

Supports six source types:
  auto       — derived from seed URL registered domain (default, no config needed)
  manual     — user-supplied domains/patterns (comma-separated)
  h1         — HackerOne program scope via API (h1:HANDLE)
  bugcrowd   — Bugcrowd program scope via API (bc:SLUG)
  intigriti  — Intigriti program scope via API (ig:HANDLE)
  page       — any URL fetched and LLM-parsed for scope info

All sources produce a ScopeConfig. The is_in_scope() helper is the single
check used by the crawler and orchestrator.

Credential loading order for platform sources:
  1. Environment variable (H1_API_USERNAME, H1_API_TOKEN, etc.)
  2. ~/.axss/keys file (key=value or key: value per line)
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

# Known two-part TLDs for registered-domain extraction (no tldextract dependency)
_MULTI_TLDS = frozenset({
    "co.uk", "co.jp", "co.nz", "co.za", "co.in", "co.kr",
    "com.au", "com.br", "com.cn", "com.mx", "com.ar",
    "org.uk", "net.uk", "me.uk", "ac.uk", "gov.uk",
    "ne.jp", "or.jp", "ac.jp", "go.jp",
})


@dataclass
class ScopeConfig:
    """Resolved scope for a scan session.

    allowed_patterns — hostnames or glob patterns that ARE in scope.
    excluded_patterns — patterns that are NOT in scope (take priority).
    An empty allowed_patterns list means "allow everything" (no restriction).
    """
    allowed_patterns: list[str] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=list)
    source: str = "auto"        # "auto" | "manual" | "h1" | "bugcrowd" | "intigriti"
    program_name: str = ""

    def is_empty(self) -> bool:
        """True when no allow-list is configured — scope is unrestricted."""
        return not self.allowed_patterns


def scope_from_urls(seed_urls: list[str]) -> ScopeConfig:
    """Auto-derive scope from a batch of seed URLs.

    Collects all unique registered domains across the list so the entire batch
    is treated as one scope — no LLM call, no per-URL overhead.
    Example: [https://api.example.com, https://app.example.com]
             → allows example.com + *.example.com  (deduped)
    """
    if not seed_urls:
        return ScopeConfig(source="auto")

    patterns: list[str] = []
    seen: set[str] = set()
    for url in seed_urls:
        hostname = _host(url)
        if not hostname:
            continue
        registered = _registered_domain(hostname)
        if registered not in seen:
            seen.add(registered)
            patterns.append(registered)
            patterns.append(f"*.{registered}")

    if not patterns:
        log.warning("scope_from_urls: could not extract any hostname from input URLs")
        return ScopeConfig(source="auto")

    return ScopeConfig(allowed_patterns=patterns, source="auto")


def scope_from_url(seed_url: str) -> ScopeConfig:
    """Auto-derive scope from a single seed URL. Convenience wrapper."""
    return scope_from_urls([seed_url])


def scope_from_manual(domains: list[str]) -> ScopeConfig:
    """Build scope from a user-supplied domain/pattern list.

    Prefix a pattern with ! to exclude it.
    Lines starting with # are treated as comments.
    """
    allowed: list[str] = []
    excluded: list[str] = []
    for raw in domains:
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("!"):
            excluded.append(entry[1:].strip())
        else:
            allowed.append(entry)
    return ScopeConfig(allowed_patterns=allowed, excluded_patterns=excluded, source="manual")


def scope_from_h1(handle: str) -> ScopeConfig:
    """Fetch in-scope web assets from the HackerOne API.

    Requires credentials — set H1_API_USERNAME and H1_API_TOKEN as environment
    variables or add them to ~/.axss/keys (h1_username=... / h1_token=...).

    Only URL and DOMAIN asset types are included; mobile, CIDR, etc. are skipped.
    """
    username, token = _load_h1_creds()
    if not username or not token:
        raise ValueError(
            "HackerOne API credentials not found. "
            "Set H1_API_USERNAME and H1_API_TOKEN environment variables, "
            "or add h1_username and h1_token to ~/.axss/keys."
        )

    url = f"https://api.hackerone.com/v1/programs/{handle}"
    try:
        resp = requests.get(url, auth=(username, token), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch H1 scope for '{handle}': {exc}") from exc

    allowed: list[str] = []
    excluded: list[str] = []
    program_name = data.get("attributes", {}).get("name", handle)

    for entry in (
        data.get("relationships", {})
            .get("structured_scope", {})
            .get("data", [])
    ):
        attrs = entry.get("attributes", {})
        asset_type = attrs.get("asset_type", "")
        identifier = (attrs.get("asset_identifier") or "").strip()
        in_scope = attrs.get("eligible_for_submission", True)

        if asset_type not in ("URL", "DOMAIN"):
            continue
        if not identifier:
            continue

        # Strip scheme from URL assets so we get a hostname/pattern
        if asset_type == "URL":
            parsed = urlparse(identifier)
            identifier = parsed.hostname or identifier

        if in_scope:
            allowed.append(identifier)
        else:
            excluded.append(identifier)

    log.info("H1 scope '%s': %d allowed, %d excluded", program_name, len(allowed), len(excluded))
    return ScopeConfig(
        allowed_patterns=allowed,
        excluded_patterns=excluded,
        source="h1",
        program_name=program_name,
    )


def scope_from_bugcrowd(slug: str) -> ScopeConfig:
    """Fetch in-scope assets from the Bugcrowd REST API v4.

    Requires BUGCROWD_API_KEY environment variable or bugcrowd_api_key in ~/.axss/keys.
    """
    api_key = _load_key("bugcrowd_api_key", "BUGCROWD_API_KEY")
    if not api_key:
        raise ValueError(
            "Bugcrowd API key not found. "
            "Set BUGCROWD_API_KEY environment variable or add bugcrowd_api_key to ~/.axss/keys."
        )

    headers = {
        "Accept": "application/vnd.bugcrowd.v4+json",
        "Authorization": f"Token {api_key}",
    }
    url = f"https://api.bugcrowd.com/engagements/{slug}/scope/in_scope"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch Bugcrowd scope for '{slug}': {exc}") from exc

    allowed: list[str] = []
    for entry in data.get("data", []):
        target = (entry.get("attributes", {}).get("target") or "").strip()
        if target and ("." in target or "*" in target):
            # Strip scheme if present
            if "://" in target:
                target = urlparse(target).hostname or target
            allowed.append(target)

    log.info("Bugcrowd scope '%s': %d targets", slug, len(allowed))
    return ScopeConfig(allowed_patterns=allowed, source="bugcrowd", program_name=slug)


def scope_from_intigriti(handle: str) -> ScopeConfig:
    """Fetch in-scope domains from the Intigriti API.

    Requires INTIGRITI_API_TOKEN environment variable or intigriti_api_token in ~/.axss/keys.
    """
    api_token = _load_key("intigriti_api_token", "INTIGRITI_API_TOKEN")
    if not api_token:
        raise ValueError(
            "Intigriti API token not found. "
            "Set INTIGRITI_API_TOKEN environment variable or add intigriti_api_token to ~/.axss/keys."
        )

    headers = {"Authorization": f"Bearer {api_token}"}
    url = f"https://api.intigriti.com/core/user/program/{handle}/scope"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch Intigriti scope for '{handle}': {exc}") from exc

    allowed: list[str] = []
    excluded: list[str] = []
    entries = data if isinstance(data, list) else data.get("data", [])

    for entry in entries:
        endpoint = (entry.get("endpoint") or entry.get("value") or "").strip()
        scope_type = (entry.get("type") or entry.get("category") or "").lower()
        in_scope = entry.get("inScope", entry.get("in_scope", True))

        if not endpoint:
            continue
        # Skip non-web asset types
        if scope_type and scope_type not in ("", "domain", "url", "web", "wildcard"):
            continue

        # Normalise: strip URL to hostname
        if endpoint.startswith("http"):
            parsed = urlparse(endpoint)
            endpoint = parsed.hostname or endpoint

        if in_scope:
            allowed.append(endpoint)
        else:
            excluded.append(endpoint)

    log.info("Intigriti scope '%s': %d allowed, %d excluded", handle, len(allowed), len(excluded))
    return ScopeConfig(
        allowed_patterns=allowed,
        excluded_patterns=excluded,
        source="intigriti",
        program_name=handle,
    )


# Map of lowercase prefix → platform key
_PLATFORM_PREFIXES: dict[str, str] = {
    "h1": "h1",
    "hackerone": "h1",
    "bc": "bugcrowd",
    "bugcrowd": "bugcrowd",
    "ig": "intigriti",
    "intigriti": "intigriti",
}


def resolve_scope(scope_arg: str | None, seed_urls: list[str]) -> ScopeConfig:
    """Parse the unified --scope argument and return a ScopeConfig.

    scope_arg formats:
      None / 'auto'                        → auto-derive from seed URL
      'h1:HANDLE'                          → HackerOne API
      'hackerone:HANDLE'                   → HackerOne API
      'bc:SLUG'                            → Bugcrowd API
      'bugcrowd:SLUG'                      → Bugcrowd API
      'ig:HANDLE'                          → Intigriti API
      'intigriti:HANDLE'                   → Intigriti API
      'https://app.intigriti.com/...'      → auto-detect platform, API then LLM fallback
      'https://hackerone.com/...'          → auto-detect platform, API then LLM fallback
      'https://bugcrowd.com/...'           → auto-detect platform, API then LLM fallback
      'https://...' (any other URL)        → fetch page, LLM-parse scope
      'http://...'                         → fetch page, LLM-parse scope
      'domain.com,*.other.com'             → comma-separated manual list
    """
    if scope_arg is None or scope_arg.strip().lower() in ("auto", ""):
        return scope_from_urls(seed_urls)

    # Platform prefix (case-insensitive)
    lower = scope_arg.lower()
    for prefix, platform in _PLATFORM_PREFIXES.items():
        if lower.startswith(f"{prefix}:"):
            handle = scope_arg[len(prefix) + 1:].strip()
            if not handle:
                raise ValueError(f"No handle/slug provided after '{prefix}:'")
            if platform == "h1":
                return scope_from_h1(handle)
            if platform == "bugcrowd":
                return scope_from_bugcrowd(handle)
            if platform == "intigriti":
                return scope_from_intigriti(handle)

    # URL → try platform auto-detection first, fall back to LLM page parse
    if scope_arg.startswith("http://") or scope_arg.startswith("https://"):
        detected = _detect_platform_url(scope_arg)
        if detected:
            platform, handle = detected
            try:
                if platform == "h1":
                    return scope_from_h1(handle)
                if platform == "bugcrowd":
                    return scope_from_bugcrowd(handle)
                if platform == "intigriti":
                    return scope_from_intigriti(handle)
            except ValueError as exc:
                log.info(
                    "API credentials not configured for %s (%s); "
                    "falling back to LLM page parse",
                    platform, exc,
                )
        return scope_from_page_url(scope_arg)

    # Fallback: comma- or whitespace-separated manual domain list
    domains = [d.strip() for d in re.split(r"[,\s]+", scope_arg) if d.strip()]
    return scope_from_manual(domains)


def scope_from_page_url(url: str) -> ScopeConfig:
    """Fetch a URL and use an LLM to extract in-scope / out-of-scope targets.

    Works with bug bounty program pages, security.txt files, or any scope doc.
    Uses Playwright to render JS-heavy SPAs; falls back to plain HTTP on error.
    Requires OPENROUTER_API_KEY or OPENAI_API_KEY (env vars or ~/.axss/keys).
    """
    log.info("Fetching scope page: %s", url)
    text = _fetch_page_text(url)

    log.info("Asking LLM to parse scope from page (%d chars)", len(text))
    parsed = _llm_parse_scope(text, url)

    allowed = parsed.get("in_scope", [])
    excluded = parsed.get("out_of_scope", [])
    notes = parsed.get("notes", "")
    if notes:
        log.info("Scope notes: %s", notes)

    log.info("Page scope: %d in-scope, %d out-of-scope", len(allowed), len(excluded))
    return ScopeConfig(
        allowed_patterns=allowed,
        excluded_patterns=excluded,
        source="page",
        program_name=url,
    )


def _llm_parse_scope(content: str, source_url: str) -> dict:
    """Call an LLM to extract scope information from page text.

    Returns dict: {"in_scope": [...], "out_of_scope": [...], "notes": "..."}
    Tries OpenRouter first, then OpenAI.
    """
    from ai_xss_generator.config import load_api_key  # avoid circular at module level

    api_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    base_url = "https://openrouter.ai/api/v1"
    model = "anthropic/claude-3-5-haiku"

    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
        base_url = "https://api.openai.com/v1"
        model = "gpt-4o-mini"

    if not api_key:
        raise RuntimeError(
            "No LLM API key found for scope parsing. "
            "Set OPENROUTER_API_KEY or OPENAI_API_KEY, "
            "or use a platform prefix (e.g. --scope h1:HANDLE)."
        )

    system = (
        "You are a security researcher's assistant. Extract bug bounty program scope "
        "from page content. Return strict JSON only, no markdown."
    )
    user = (
        f"Extract the bug bounty scope from this page (source: {source_url}).\n\n"
        "Return JSON with exactly this structure:\n"
        "{\n"
        '  "in_scope": ["domain1.com", "*.domain2.com"],\n'
        '  "out_of_scope": ["excluded.com"],\n'
        '  "notes": "one-line summary of any key restrictions"\n'
        "}\n\n"
        "Rules:\n"
        "- Extract hostnames/domains only (no URL paths)\n"
        "- Use *.domain.com format for wildcard subdomains\n"
        "- Skip non-web assets (mobile apps, IP ranges, executables)\n"
        "- If a domain appears in an out-of-scope section, put it in out_of_scope\n\n"
        f"Page content:\n{content}"
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if "openrouter" in base_url:
        headers["HTTP-Referer"] = "https://github.com/axss"
        headers["X-Title"] = "axss"

    resp = requests.post(
        f"{base_url}/chat/completions",
        headers=headers,
        json={
            "model": model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
        },
        timeout=30,
    )
    resp.raise_for_status()
    raw = resp.json()["choices"][0]["message"]["content"]

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        log.warning("LLM scope parse returned invalid JSON")
        return {"in_scope": [], "out_of_scope": [], "notes": "LLM returned non-JSON response"}


def is_in_scope(url: str, scope: ScopeConfig) -> bool:
    """Return True if *url* is within scope.

    Empty scope (no patterns) allows everything.
    Excluded patterns take priority over allowed patterns.
    Supports exact hostnames, *.domain.com wildcards, and fnmatch patterns.
    """
    if scope.is_empty():
        return True

    hostname = _host(url)
    if not hostname:
        return False

    # Exclusions take priority
    for pattern in scope.excluded_patterns:
        if _matches_pattern(hostname, pattern):
            return False

    for pattern in scope.allowed_patterns:
        if _matches_pattern(hostname, pattern):
            return True

    return False


# ── Internal helpers ──────────────────────────────────────────────────────────

# Top-level paths on each platform that are not program handles
_H1_NON_PROGRAM: frozenset[str] = frozenset({
    "login", "logout", "users", "reports", "hacktivity", "leaderboard",
    "opportunities", "bounty-programs", "directory", "settings", "security",
    "blog", "signup", "404", "500",
})
_BC_NON_PROGRAM: frozenset[str] = frozenset({
    "login", "logout", "user", "settings", "programs", "leaderboard",
    "blog", "about", "signup", "404", "500",
})


def _detect_platform_url(url: str) -> tuple[str, str] | None:
    """Detect a known bug bounty platform URL and return (platform, handle).

    Supported patterns:
      https://app.intigriti.com/programs/{company}/{handle}/...
      https://hackerone.com/{handle}
      https://hackerone.com/programs/{handle}
      https://bugcrowd.com/{slug}

    Returns None for unrecognised or ambiguous URLs.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")

    if host == "app.intigriti.com":
        m = re.match(r"^/programs/[^/]+/([^/]+)", path)
        if m:
            return ("intigriti", m.group(1))

    if host in ("hackerone.com", "www.hackerone.com"):
        m = re.match(r"^/programs/([^/]+)", path)
        if m:
            return ("h1", m.group(1))
        m = re.match(r"^/([^/]+)$", path)
        if m and m.group(1) not in _H1_NON_PROGRAM:
            return ("h1", m.group(1))

    if host in ("bugcrowd.com", "www.bugcrowd.com"):
        m = re.match(r"^/([^/]+)$", path)
        if m and m.group(1) not in _BC_NON_PROGRAM:
            return ("bugcrowd", m.group(1))

    return None


def _fetch_page_text(url: str) -> str:
    """Return visible text from a URL, using Playwright for JS-heavy pages.

    Playwright renders the full SPA before extracting text; falls back to a
    plain HTTP GET if Playwright is unavailable or fails.
    """
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            try:
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=30_000)
                html = page.content()
            finally:
                browser.close()
        log.debug("Playwright rendered scope page (%d bytes)", len(html))
    except Exception as exc:
        log.debug("Playwright render failed, falling back to requests: %s", exc)
        try:
            resp = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0 (compatible; axss-scope/1.0)"},
            )
            resp.raise_for_status()
            html = resp.text
        except Exception as req_exc:
            raise RuntimeError(f"Failed to fetch scope page '{url}': {req_exc}") from req_exc

    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s{2,}", " ", text).strip()[:8000]
    return text


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _registered_domain(hostname: str) -> str:
    """Best-effort registered domain without tldextract."""
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 else hostname.lower()
    return ".".join(parts[-2:])


def _matches_pattern(hostname: str, pattern: str) -> bool:
    """Match hostname against a scope pattern.

    Handles: exact match, *.domain.com wildcard, fnmatch glob.
    """
    hostname = hostname.lower()
    pattern = pattern.lower().strip()

    # Strip scheme if someone put a full URL in patterns
    if "://" in pattern:
        pattern = urlparse(pattern).hostname or pattern

    if not pattern:
        return False

    if hostname == pattern:
        return True

    # *.example.com — matches sub.example.com but NOT example.com itself
    if pattern.startswith("*."):
        base = pattern[2:]
        return hostname.endswith("." + base)

    # General fnmatch for any other wildcard
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(hostname, pattern)

    return False


def _load_key(key_name: str, env_var: str) -> str:
    """Load a key from env var first, then ~/.axss/keys file."""
    val = os.environ.get(env_var, "").strip()
    if val:
        return val
    keys_file = os.path.expanduser("~/.axss/keys")
    try:
        for line in open(keys_file).read().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in ("=", ": ", ":"):
                if line.startswith(f"{key_name}{sep}"):
                    return line[len(f"{key_name}{sep}"):].strip()
    except Exception:
        pass
    return ""


def _load_h1_creds() -> tuple[str, str]:
    username = _load_key("h1_username", "H1_API_USERNAME")
    token = _load_key("h1_token", "H1_API_TOKEN")
    return username, token
