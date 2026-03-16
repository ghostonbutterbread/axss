"""Session validity guard for authenticated scans.

Detects auth failures (401/403 responses, login-page redirects) so the
operator knows their session has expired before or during a scan.

Usage
-----
Pre-scan (CLI layer):
    guard = SessionGuard(session_check_url="https://app.example.com/dashboard")
    try:
        guard.pre_scan_check(auth_headers)
    except SessionExpiredWarning as exc:
        warn(str(exc))
        # operator can abort or continue at their discretion

Mid-scan (HTTP layer — e.g. probe.py):
    guard.check_http_status(url, response.status_code)

Mid-scan (Playwright layer — e.g. executor.py):
    guard.check_browser_url(original_url, page.url)
"""
from __future__ import annotations

import logging
import re
import threading
import urllib.parse

log = logging.getLogger(__name__)

# Path fragments that strongly suggest a login page redirect.
_LOGIN_PATH_RE = re.compile(
    r"/(login|signin|sign[-_]in|auth|session/new|oauth/authorize"
    r"|sso|saml|cas/login|account/login|users/sign_in)(/|$|\?|#)",
    re.IGNORECASE,
)


class SessionExpiredWarning(Exception):
    """Raised when a pre-scan session check detects an expired/invalid session."""


class SessionGuard:
    """Tracks auth failure signals during a scan and emits one-time warnings.

    Designed to be shared across threads within a single scan process; uses
    an internal lock to guarantee the warning fires at most once.
    """

    def __init__(self, session_check_url: str | None = None) -> None:
        self._check_url = session_check_url
        self._warned = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Pre-scan: validate the session before spending time on the scan
    # ------------------------------------------------------------------

    def pre_scan_check(self, auth_headers: dict[str, str]) -> None:
        """Probe *session_check_url* and raise SessionExpiredWarning if invalid.

        Does nothing when no *session_check_url* was configured.
        Network errors are silently logged at DEBUG so they never block a scan.
        """
        if not self._check_url:
            return
        try:
            from scrapling.fetchers import FetcherSession

            with FetcherSession(
                impersonate="chrome",
                stealthy_headers=True,
                timeout=15,
                follow_redirects=True,
                retries=1,
            ) as session:
                merged = {
                    **auth_headers,
                    "User-Agent": "axss/0.1 (+authorized security testing; scrapling)",
                }
                response = session.get(self._check_url, headers=merged)
                status = (
                    getattr(response, "status_code", None)
                    or getattr(response, "status", 0)
                    or 0
                )
                final_url = str(
                    getattr(response, "url", self._check_url) or self._check_url
                )
                if status in (401, 403):
                    raise SessionExpiredWarning(
                        f"Session check returned HTTP {status} from {self._check_url}. "
                        "Your auth token or cookies may be expired — "
                        "re-run with fresh --header / --cookies credentials."
                    )
                final_path = urllib.parse.urlparse(final_url).path
                if _LOGIN_PATH_RE.search(final_path):
                    raise SessionExpiredWarning(
                        f"Session check was redirected to a login page: {final_url}. "
                        "Your auth token or cookies appear to be expired — "
                        "re-run with fresh --header / --cookies credentials."
                    )
        except SessionExpiredWarning:
            raise
        except Exception as exc:
            log.debug("Session pre-scan check failed (network/parse error): %s", exc)

    # ------------------------------------------------------------------
    # Mid-scan: reactive detection
    # ------------------------------------------------------------------

    def check_http_status(self, url: str, status: int) -> None:
        """Emit a one-time WARNING when the HTTP layer receives a 401 or 403."""
        if status not in (401, 403):
            return
        with self._lock:
            if self._warned:
                return
            self._warned = True
        log.warning(
            "AUTH: HTTP %d from %s — session may have expired. "
            "Re-run with fresh --header / --cookies credentials.",
            status,
            url,
        )

    def check_browser_url(self, original_url: str, final_url: str) -> None:
        """Emit a one-time WARNING when Playwright navigation lands on a login page."""
        if not final_url or final_url == original_url:
            return
        final_path = urllib.parse.urlparse(final_url).path
        if not _LOGIN_PATH_RE.search(final_path):
            return
        with self._lock:
            if self._warned:
                return
            self._warned = True
        log.warning(
            "AUTH: navigation to %s redirected to login page %s — "
            "session may have expired. Re-run with fresh --header / --cookies credentials.",
            original_url,
            final_url,
        )
