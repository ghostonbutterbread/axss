from __future__ import annotations

import json
import logging
import shlex
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ai_xss_generator.auth import build_auth_headers, load_netscape_cookies, parse_headers
from ai_xss_generator.config import CONFIG_DIR

log = logging.getLogger(__name__)

AUTH_PROFILES_PATH = CONFIG_DIR / "auth_profiles.json"
_LOGIN_PATH_TOKENS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "session",
    "frontdoor",
)


@dataclass(slots=True)
class AuthProfile:
    program: str
    name: str
    source_type: str
    base_url: str
    domains: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""
    last_used_at: str = ""
    last_validated_at: str = ""
    invalid_reason: str = ""

    @property
    def ref(self) -> str:
        return f"{self.program}/{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AuthProfile":
        return cls(
            program=str(raw.get("program", "") or "").strip(),
            name=str(raw.get("name", "") or "").strip(),
            source_type=str(raw.get("source_type", "") or "").strip(),
            base_url=str(raw.get("base_url", "") or "").strip(),
            domains=[str(item).strip() for item in raw.get("domains", []) if str(item).strip()],
            headers={str(k): str(v) for k, v in dict(raw.get("headers", {}) or {}).items()},
            cookies={str(k): str(v) for k, v in dict(raw.get("cookies", {}) or {}).items()},
            notes=str(raw.get("notes", "") or ""),
            created_at=str(raw.get("created_at", "") or ""),
            updated_at=str(raw.get("updated_at", "") or ""),
            last_used_at=str(raw.get("last_used_at", "") or ""),
            last_validated_at=str(raw.get("last_validated_at", "") or ""),
            invalid_reason=str(raw.get("invalid_reason", "") or ""),
        )


@dataclass(slots=True)
class AuthValidationResult:
    valid: bool = False
    invalid: bool = False
    reason: str = ""
    final_url: str = ""
    status_code: int | None = None


@dataclass(slots=True)
class AuthImportPreview:
    profile: AuthProfile
    existing_profile: AuthProfile | None = None
    source_label: str = ""

    @property
    def cookie_count(self) -> int:
        return len(self.profile.cookies)

    @property
    def header_count(self) -> int:
        return len(self.profile.headers)

    @property
    def domains_preview(self) -> str:
        return ", ".join(self.profile.domains) if self.profile.domains else "n/a"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _empty_store() -> dict[str, Any]:
    return {"active_profile": "", "profiles": []}


def load_auth_store() -> dict[str, Any]:
    try:
        raw = json.loads(AUTH_PROFILES_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return _empty_store()
    if not isinstance(raw, dict):
        return _empty_store()
    store = _empty_store()
    store["active_profile"] = str(raw.get("active_profile", "") or "").strip()
    store["profiles"] = [
        profile.to_dict()
        for profile in sorted(
            [AuthProfile.from_dict(item) for item in raw.get("profiles", []) if isinstance(item, dict)],
            key=lambda item: (item.program, item.name),
        )
        if profile.program and profile.name
    ]
    return store


def save_auth_store(store: dict[str, Any]) -> None:
    AUTH_PROFILES_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUTH_PROFILES_PATH.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")


def list_auth_profiles(store: dict[str, Any] | None = None) -> list[AuthProfile]:
    active_store = store or load_auth_store()
    return [AuthProfile.from_dict(item) for item in active_store.get("profiles", []) if isinstance(item, dict)]


def _normalize_ref(program: str, name: str) -> str:
    return f"{program.strip()}/{name.strip()}"


def resolve_profile_ref(ref: str, store: dict[str, Any] | None = None) -> AuthProfile | None:
    active_store = store or load_auth_store()
    profiles = list_auth_profiles(active_store)
    needle = str(ref or "").strip()
    if not needle:
        return None
    if "/" in needle:
        program, _, name = needle.partition("/")
        for profile in profiles:
            if profile.program == program and profile.name == name:
                return profile
        return None
    exact = [profile for profile in profiles if profile.name == needle]
    if len(exact) == 1:
        return exact[0]
    return None


def get_active_profile(store: dict[str, Any] | None = None) -> AuthProfile | None:
    active_store = store or load_auth_store()
    active_ref = str(active_store.get("active_profile", "") or "").strip()
    if not active_ref:
        return None
    return resolve_profile_ref(active_ref, active_store)


def upsert_profile(profile: AuthProfile, store: dict[str, Any] | None = None) -> dict[str, Any]:
    active_store = store or load_auth_store()
    profiles = list_auth_profiles(active_store)
    updated = False
    now = _now_iso()
    for idx, existing in enumerate(profiles):
        if existing.program == profile.program and existing.name == profile.name:
            profile.created_at = existing.created_at or profile.created_at or now
            profiles[idx] = profile
            updated = True
            break
    if not updated:
        if not profile.created_at:
            profile.created_at = now
        profiles.append(profile)
    profile.updated_at = now
    active_store["profiles"] = [item.to_dict() for item in sorted(profiles, key=lambda item: (item.program, item.name))]
    save_auth_store(active_store)
    return active_store


def delete_profile(ref: str, store: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
    active_store = store or load_auth_store()
    profiles = list_auth_profiles(active_store)
    resolved = resolve_profile_ref(ref, active_store)
    if resolved is None:
        return active_store, False
    active_store["profiles"] = [
        item.to_dict()
        for item in profiles
        if not (item.program == resolved.program and item.name == resolved.name)
    ]
    if active_store.get("active_profile") == resolved.ref:
        active_store["active_profile"] = ""
    save_auth_store(active_store)
    return active_store, True


def set_active_profile(ref: str, store: dict[str, Any] | None = None) -> tuple[dict[str, Any], AuthProfile | None]:
    active_store = store or load_auth_store()
    resolved = resolve_profile_ref(ref, active_store)
    if resolved is None:
        return active_store, None
    active_store["active_profile"] = resolved.ref
    save_auth_store(active_store)
    return active_store, resolved


def clear_active_profile(store: dict[str, Any] | None = None) -> dict[str, Any]:
    active_store = store or load_auth_store()
    active_store["active_profile"] = ""
    save_auth_store(active_store)
    return active_store


def _parse_cookie_header(cookie_value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in cookie_value.split(";"):
        part = item.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name:
            cookies[name] = value.strip()
    return cookies


def _split_cookie_header(headers: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    clean_headers = dict(headers)
    cookie_value = ""
    for name in list(clean_headers.keys()):
        if name.lower() == "cookie":
            cookie_value = clean_headers.pop(name)
            break
    return clean_headers, _parse_cookie_header(cookie_value)


def _domains_from_base_url(base_url: str) -> list[str]:
    host = urllib.parse.urlparse(base_url).netloc.strip().lower()
    return [host] if host else []


def _sniff_source_type(raw: str, path: str | None = None) -> str:
    if path and path.lower().endswith(".har"):
        return "har"
    text = raw.strip()
    first_line = text.splitlines()[0].strip() if text.splitlines() else ""
    if text.startswith("curl "):
        return "curl"
    if first_line.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")) and " HTTP/" in first_line:
        return "burp_request"
    if "HTTP/" in first_line and "\nHost:" in text:
        return "burp_request"
    if "Netscape HTTP Cookie File" in text or ("\t" in text and len(text.splitlines()) > 0):
        return "cookies_txt"
    return "header_block"


def _parse_burp_request(raw: str) -> tuple[str, dict[str, str], dict[str, str]]:
    lines = raw.replace("\r\n", "\n").splitlines()
    if not lines:
        raise ValueError("Empty request input.")
    request_line = lines[0].strip()
    if " " not in request_line:
        raise ValueError("Request line is malformed.")
    method, _, remainder = request_line.partition(" ")
    target, _, _version = remainder.partition(" ")
    header_lines: list[str] = []
    for line in lines[1:]:
        if not line.strip():
            break
        header_lines.append(line)
    headers = parse_headers(header_lines)
    host = headers.get("Host", "").strip()
    if not host and target.startswith(("http://", "https://")):
        base_url = target
    elif host:
        scheme = "https"
        if target.startswith("http://"):
            scheme = "http"
        elif target.startswith("https://"):
            scheme = "https"
        base_url = urllib.parse.urljoin(f"{scheme}://{host}", target)
    else:
        raise ValueError("Burp/raw request import needs a Host header or absolute request URL.")
    clean_headers, cookies = _split_cookie_header(headers)
    clean_headers.pop("Host", None)
    clean_headers.pop("Content-Length", None)
    return base_url, clean_headers, cookies


def _parse_curl_command(raw: str) -> tuple[str, dict[str, str], dict[str, str]]:
    try:
        parts = shlex.split(raw)
    except ValueError as exc:
        raise ValueError(f"Could not parse curl command: {exc}") from exc
    if not parts or parts[0] != "curl":
        raise ValueError("curl import must start with 'curl'.")
    url = ""
    header_lines: list[str] = []
    cookie_header = ""
    idx = 1
    while idx < len(parts):
        part = parts[idx]
        if part in {"-H", "--header"} and idx + 1 < len(parts):
            header_lines.append(parts[idx + 1])
            idx += 2
            continue
        if part in {"-b", "--cookie"} and idx + 1 < len(parts):
            cookie_header = parts[idx + 1]
            idx += 2
            continue
        if part == "--url" and idx + 1 < len(parts):
            url = parts[idx + 1]
            idx += 2
            continue
        if not part.startswith("-") and not url:
            url = part
        idx += 1
    if not url:
        raise ValueError("curl import needs a URL.")
    headers = parse_headers(header_lines)
    clean_headers, cookies = _split_cookie_header(headers)
    if cookie_header:
        cookies.update(_parse_cookie_header(cookie_header))
    clean_headers.pop("Content-Length", None)
    return url, clean_headers, cookies


def _parse_header_block(raw: str) -> tuple[str, dict[str, str], dict[str, str]]:
    headers = parse_headers([line for line in raw.replace("\r\n", "\n").splitlines() if line.strip()])
    clean_headers, cookies = _split_cookie_header(headers)
    origin = ""
    for name in ("Origin", "Referer"):
        if name in clean_headers:
            parsed = urllib.parse.urlparse(clean_headers[name])
            if parsed.scheme and parsed.netloc:
                origin = urllib.parse.urlunparse(parsed._replace(path="", params="", query="", fragment=""))
                break
    return origin, clean_headers, cookies


def import_auth_profile(
    *,
    source: str,
    program: str,
    profile_name: str,
    source_type: str = "auto",
    notes: str = "",
) -> AuthProfile:
    source_path = Path(source)
    raw = source_path.read_text(encoding="utf-8", errors="replace") if source_path.exists() else source
    detected_type = _sniff_source_type(raw, str(source_path) if source_path.exists() else None)
    effective_type = detected_type if source_type == "auto" else source_type
    if effective_type == "burp_request":
        base_url, headers, cookies = _parse_burp_request(raw)
    elif effective_type == "curl":
        base_url, headers, cookies = _parse_curl_command(raw)
    elif effective_type == "cookies_txt":
        cookies = load_netscape_cookies(str(source_path) if source_path.exists() else source)
        base_url = ""
        headers = {}
    elif effective_type == "header_block":
        base_url, headers, cookies = _parse_header_block(raw)
    else:
        raise ValueError(f"Unsupported auth import type: {effective_type}")

    return AuthProfile(
        program=program.strip(),
        name=profile_name.strip(),
        source_type=effective_type,
        base_url=base_url.strip(),
        domains=_domains_from_base_url(base_url),
        headers=headers,
        cookies=cookies,
        notes=notes.strip(),
    )


def preview_auth_import(
    *,
    source: str,
    program: str,
    profile_name: str,
    source_type: str = "auto",
    notes: str = "",
    store: dict[str, Any] | None = None,
) -> AuthImportPreview:
    profile = import_auth_profile(
        source=source,
        program=program,
        profile_name=profile_name,
        source_type=source_type,
        notes=notes,
    )
    active_store = store or load_auth_store()
    existing = resolve_profile_ref(profile.ref, active_store)
    return AuthImportPreview(
        profile=profile,
        existing_profile=existing,
        source_label=profile.source_type,
    )


def merge_profiles(existing: AuthProfile, incoming: AuthProfile) -> AuthProfile:
    merged_headers = {**existing.headers, **incoming.headers}
    merged_cookies = {**existing.cookies, **incoming.cookies}
    merged_domains = sorted(set(existing.domains) | set(incoming.domains))
    merged_notes = existing.notes.strip()
    incoming_notes = incoming.notes.strip()
    if incoming_notes and incoming_notes not in merged_notes:
        merged_notes = f"{merged_notes}\n{incoming_notes}".strip()
    return AuthProfile(
        program=existing.program,
        name=existing.name,
        source_type=incoming.source_type or existing.source_type,
        base_url=incoming.base_url or existing.base_url,
        domains=merged_domains,
        headers=merged_headers,
        cookies=merged_cookies,
        notes=merged_notes,
        created_at=existing.created_at,
        updated_at=existing.updated_at,
        last_used_at=existing.last_used_at,
        last_validated_at=existing.last_validated_at,
        invalid_reason="",
    )


def apply_import_preview(
    preview: AuthImportPreview,
    *,
    mode: str = "save",
    store: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], AuthProfile]:
    active_store = store or load_auth_store()
    if mode not in {"save", "replace", "merge"}:
        raise ValueError(f"Unsupported import mode: {mode}")
    target = preview.profile
    if mode == "merge":
        if preview.existing_profile is None:
            raise ValueError("Merge requested but no existing profile matched the target ref.")
        target = merge_profiles(preview.existing_profile, preview.profile)
    elif mode == "replace":
        if preview.existing_profile is not None:
            target.created_at = preview.existing_profile.created_at
            target.last_used_at = preview.existing_profile.last_used_at
            target.last_validated_at = preview.existing_profile.last_validated_at
    updated_store = upsert_profile(target, active_store)
    resolved = resolve_profile_ref(target.ref, updated_store) or target
    return updated_store, resolved


def build_headers_from_profile(profile: AuthProfile) -> dict[str, str]:
    result = dict(profile.headers)
    if profile.cookies:
        cookie_value = "; ".join(f"{name}={value}" for name, value in profile.cookies.items())
        if cookie_value:
            result["Cookie"] = cookie_value
    return result


def profile_matches_url(profile: AuthProfile, url: str) -> bool:
    host = urllib.parse.urlparse(url).netloc.lower()
    if not host:
        return False
    for domain in profile.domains:
        needle = domain.lower().lstrip(".")
        if host == needle or host.endswith(f".{needle}"):
            return True
    base_host = urllib.parse.urlparse(profile.base_url).netloc.lower()
    return bool(base_host and (host == base_host or host.endswith(f".{base_host}")))


def resolve_scan_profile(
    *,
    explicit_profile: str | None,
    target_url: str | None,
    store: dict[str, Any] | None = None,
) -> tuple[AuthProfile | None, str]:
    active_store = store or load_auth_store()
    explicit = str(explicit_profile or "").strip()
    if explicit:
        if explicit.lower() == "none":
            return None, ""
        resolved = resolve_profile_ref(explicit, active_store)
        if resolved is None:
            raise ValueError(f"Unknown auth profile: {explicit}")
        return resolved, "explicit"
    active = get_active_profile(active_store)
    if active and target_url and profile_matches_url(active, target_url):
        return active, "active"
    return None, ""


def merge_scan_auth_headers(
    *,
    profile: AuthProfile | None,
    extra_headers: list[str] | None = None,
    cookies_path: str | None = None,
) -> dict[str, str]:
    profile_headers = build_headers_from_profile(profile) if profile is not None else {}
    cli_headers = build_auth_headers(headers=extra_headers, cookies_path=cookies_path)
    return {**profile_headers, **cli_headers}


def touch_profile_last_used(ref: str, store: dict[str, Any] | None = None) -> dict[str, Any]:
    active_store = store or load_auth_store()
    resolved = resolve_profile_ref(ref, active_store)
    if resolved is None:
        return active_store
    resolved.last_used_at = _now_iso()
    resolved.invalid_reason = ""
    return upsert_profile(resolved, active_store)


def record_profile_validation(
    profile: AuthProfile,
    validation: AuthValidationResult,
    store: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile.last_validated_at = _now_iso()
    profile.invalid_reason = validation.reason if validation.invalid else ""
    return upsert_profile(profile, store)


def _is_loginish_url(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(token in path for token in _LOGIN_PATH_TOKENS)


def validate_profile(
    profile: AuthProfile,
    fetcher: Callable[[str, dict[str, str]], dict[str, Any]] | None = None,
) -> AuthValidationResult:
    if not profile.base_url:
        return AuthValidationResult(valid=False, invalid=False, reason="No base URL to validate against.")
    if fetcher is None:
        from ai_xss_generator.spiders import crawl_urls

        def _default_fetcher(url: str, headers: dict[str, str]) -> dict[str, Any]:
            return crawl_urls([url], rate=1.0, auth_headers=headers).get(url, {})

        fetcher = _default_fetcher

    result = fetcher(profile.base_url, build_headers_from_profile(profile))
    final_url = str(result.get("final_url", "") or "")
    status_code = result.get("status_code")
    if isinstance(status_code, str) and status_code.isdigit():
        status_code = int(status_code)
    if result.get("error"):
        return AuthValidationResult(
            valid=False,
            invalid=False,
            reason=f"Validation inconclusive: {result['error']}",
            final_url=final_url,
            status_code=status_code if isinstance(status_code, int) else None,
        )
    if isinstance(status_code, int) and status_code in {401, 403}:
        return AuthValidationResult(
            valid=False,
            invalid=True,
            reason=f"Received HTTP {status_code}.",
            final_url=final_url,
            status_code=status_code,
        )
    if final_url and final_url != profile.base_url and _is_loginish_url(final_url) and not _is_loginish_url(profile.base_url):
        return AuthValidationResult(
            valid=False,
            invalid=True,
            reason="Redirected to a login/auth page during validation.",
            final_url=final_url,
            status_code=status_code if isinstance(status_code, int) else None,
        )
    return AuthValidationResult(
        valid=True,
        invalid=False,
        reason="Session appears valid.",
        final_url=final_url or profile.base_url,
        status_code=status_code if isinstance(status_code, int) else None,
    )


def purge_invalid_profiles(
    store: dict[str, Any] | None = None,
    fetcher: Callable[[str, dict[str, str]], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[tuple[AuthProfile, AuthValidationResult]]]:
    active_store = store or load_auth_store()
    profiles = list_auth_profiles(active_store)
    kept: list[AuthProfile] = []
    removed: list[tuple[AuthProfile, AuthValidationResult]] = []
    active_ref = str(active_store.get("active_profile", "") or "").strip()

    for profile in profiles:
        validation = validate_profile(profile, fetcher=fetcher)
        profile.last_validated_at = _now_iso()
        profile.invalid_reason = validation.reason if validation.invalid else ""
        if validation.invalid:
            removed.append((profile, validation))
            continue
        kept.append(profile)

    active_store["profiles"] = [profile.to_dict() for profile in sorted(kept, key=lambda item: (item.program, item.name))]
    if active_ref and all(profile.ref != active_ref for profile in kept):
        active_store["active_profile"] = ""
    save_auth_store(active_store)
    return active_store, removed
