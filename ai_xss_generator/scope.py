"""Scope enforcement for active scans.

Supports five source types:
  auto       — derived from seed URL registered domain (default, no config needed)
  manual     — user-supplied domains/patterns via --scope-domain
  h1         — HackerOne program scope via API (--scope-h1)
  bugcrowd   — Bugcrowd program scope via API (--scope-bugcrowd)
  intigriti  — Intigriti program scope via API (--scope-intigriti)

All sources produce a ScopeConfig. The is_in_scope() helper is the single
check used by the crawler and orchestrator.

Credential loading order for platform sources:
  1. Environment variable (H1_API_USERNAME, H1_API_TOKEN, etc.)
  2. ~/.axss/keys file (key=value or key: value per line)
"""
from __future__ import annotations

import fnmatch
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


def scope_from_url(seed_url: str) -> ScopeConfig:
    """Auto-derive scope from the seed URL.

    Allows the registered domain and all of its subdomains.
    Example: seed https://api.example.com → allows example.com + *.example.com
    """
    hostname = _host(seed_url)
    if not hostname:
        log.warning("scope_from_url: could not extract hostname from %s", seed_url)
        return ScopeConfig(source="auto")
    registered = _registered_domain(hostname)
    return ScopeConfig(
        allowed_patterns=[registered, f"*.{registered}"],
        source="auto",
    )


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
