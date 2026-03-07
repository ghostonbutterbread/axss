"""xssy.uk lab client.

Fetches all published XSS labs from https://xssy.uk, instantiates them,
and returns their live HTML for downstream parsing and payload generation.

API (reverse-engineered from the site's JS bundle):
  GET  /api/allLabs?type=1          list all published XSS labs
  GET  /api/allLabs/{id}            full lab detail (includes static token)
  POST /api/allLabs/{id}/getInstance  create a fresh user-specific instance
                                      (requires Authorization: Bearer <jwt>)
  Lab URL: https://{token}.xssy.uk/

Authentication is optional.  Without a JWT the static token from the lab
detail endpoint is used — this points to a shared demo instance, which is
still useful for HTML structure analysis and payload generation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

_BASE = "https://xssy.uk"
_TIMEOUT = 15
_UA = "axss/learn (+authorized security testing; xssy.uk labs)"

# Difficulty labels — from GET /api/rating (id → name)
RATING_LABELS: dict[int, str] = {
    35: "Hidden",
    1:  "Novice",
    33: "Apprentice",
    2:  "Adept",
    34: "Expert",
    3:  "Master",
}


@dataclass
class XssyLab:
    id: int
    name: str
    token: str           # static demo token (always available, no auth needed)
    rating: int          # numeric difficulty score
    rating_label: str
    objective: str       # e.g. "Trigger alert", "Capture Cookie"
    solution_url: str    # YouTube walkthrough URL if published
    tags: list[str] = field(default_factory=list)
    out_of_band: bool = False
    payload_hosting: bool = False

    @property
    def lab_url(self) -> str:
        return f"https://{self.token}.xssy.uk/"

    @property
    def difficulty(self) -> str:
        return self.rating_label


def _session(jwt: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": _UA})
    if jwt:
        s.headers["Authorization"] = f"Bearer {jwt}"
    return s


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def fetch_all_labs(
    jwt: str | None = None,
    min_rating: int | None = None,
    max_rating: int | None = None,
    objective_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Return the raw list of all published XSS labs from /api/allLabs?type=1.

    Parameters
    ----------
    jwt:              Optional JWT for authenticated requests (shows solved status).
    min_rating:       Only return labs with rating >= this value.
    max_rating:       Only return labs with rating <= this value.
    objective_filter: Case-insensitive substring match against objective name.
    """
    endpoint = "/api/allLabs" + ("Auth" if jwt else "") + "?type=1"
    with _session(jwt) as s:
        resp = s.get(f"{_BASE}{endpoint}", timeout=_TIMEOUT)
        resp.raise_for_status()
    labs = resp.json()
    if min_rating is not None:
        labs = [l for l in labs if l.get("rating", 0) >= min_rating]
    if max_rating is not None:
        labs = [l for l in labs if l.get("rating", 0) <= max_rating]
    if objective_filter:
        lo = objective_filter.lower()
        labs = [l for l in labs if lo in str(l.get("objective") or "").lower()]
    return labs


def fetch_lab_detail(lab_id: int, jwt: str | None = None) -> dict[str, Any]:
    """Fetch full detail for one lab, including its static demo token."""
    with _session(jwt) as s:
        resp = s.get(f"{_BASE}/api/allLabs/{lab_id}", timeout=_TIMEOUT)
        resp.raise_for_status()
    return resp.json()


def get_lab_instance(lab_id: int, jwt: str) -> str:
    """Create a fresh user-specific lab instance.  Returns the token string.

    Requires a valid JWT (log in on xssy.uk, copy the token from localStorage
    key 'userData' → .token and pass it via --xssy-token).
    """
    with _session(jwt) as s:
        resp = s.post(
            f"{_BASE}/api/allLabs/{lab_id}/getInstance",
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    token = resp.json().get("token", "")
    if not token:
        raise RuntimeError(f"getInstance response missing 'token' field: {resp.text[:200]}")
    return token


def fetch_lab_html(token: str, timeout: int = _TIMEOUT) -> str:
    """Fetch the live HTML from a lab instance URL."""
    url = f"https://{token}.xssy.uk/"
    resp = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": _UA},
        allow_redirects=True,
    )
    resp.raise_for_status()
    return resp.text


def _parse_lab(detail: dict[str, Any]) -> XssyLab:
    rating_raw = detail.get("rating", {})
    if isinstance(rating_raw, dict):
        rating_int = rating_raw.get("score", rating_raw.get("id", 1))
        rating_label = rating_raw.get("name", RATING_LABELS.get(rating_int, str(rating_int)))
    else:
        rating_int = int(rating_raw or 1)
        rating_label = RATING_LABELS.get(rating_int, str(rating_int))

    objective_raw = detail.get("objective")
    objective = objective_raw.get("name", "") if isinstance(objective_raw, dict) else str(objective_raw or "")

    tags_raw = detail.get("tags", [])
    tags = [t.get("name", str(t)) if isinstance(t, dict) else str(t) for t in (tags_raw or [])]

    lab_id = int(detail.get("id") or 0)
    return XssyLab(
        id=lab_id,
        name=detail.get("name", f"Lab {lab_id}"),
        token=detail.get("token") or detail.get("qtoken") or "",
        rating=rating_int,
        rating_label=rating_label,
        objective=objective,
        solution_url=detail.get("solutionUrl") or "",
        tags=tags,
        out_of_band=bool(detail.get("outOfBand")),
        payload_hosting=bool(detail.get("payloadHosting")),
    )


# ---------------------------------------------------------------------------
# High-level: fetch all labs with full detail
# ---------------------------------------------------------------------------

def load_labs(
    jwt: str | None = None,
    min_rating: int | None = None,
    max_rating: int | None = None,
    objective_filter: str | None = None,
    delay: float = 0.3,
    progress: Any = None,
) -> list[XssyLab]:
    """Fetch full detail for every lab matching the filters.

    Makes one request per lab to get its token and metadata.
    *delay* (seconds) is inserted between detail requests to be polite.

    Parameters
    ----------
    progress: optional callable(str) for status messages.
    """
    stub_list = fetch_all_labs(
        jwt=jwt,
        min_rating=min_rating,
        max_rating=max_rating,
        objective_filter=objective_filter,
    )
    if progress:
        progress(f"Found {len(stub_list)} labs matching filters.")

    labs: list[XssyLab] = []
    for i, stub in enumerate(stub_list):
        lab_id = stub["id"]
        try:
            if i > 0 and delay > 0:
                time.sleep(delay)
            detail = fetch_lab_detail(lab_id, jwt=jwt)
            lab = _parse_lab(detail)
            if lab.token:
                labs.append(lab)
                if progress:
                    progress(f"  [{i+1}/{len(stub_list)}] {lab.name} ({lab.difficulty}) — {lab.lab_url}")
            else:
                if progress:
                    progress(f"  [{i+1}/{len(stub_list)}] {lab.name} — no token, skipping")
        except Exception as exc:
            if progress:
                progress(f"  [{i+1}/{len(stub_list)}] lab {lab_id}: error — {exc}")

    return labs
