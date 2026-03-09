"""Playwright-based payload executor and execution detector.

Fires XSS payloads into a live browser and detects confirmed execution via:
  1. alert() / confirm() / prompt() dialog events
  2. console.log() / console.error() output
  3. Outbound network requests to a marker hostname (precursor to callback server)

One ActiveExecutor instance is created per worker process and reused across
all payload attempts for that URL, so the browser is only launched once.
"""
from __future__ import annotations

import logging
import urllib.parse
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# Marker hostname embedded in network-beacon payloads so we can detect OOB calls
# even without a real callback server running.
_BEACON_HOST = "axss.internal.confirm"

# Per-payload navigation timeout in milliseconds
_NAV_TIMEOUT_MS = 8_000


@dataclass(slots=True)
class ExecutionResult:
    """Result of a single payload fire attempt."""

    confirmed: bool
    """True when JS execution was positively detected."""

    method: str
    """How execution was detected: 'dialog' | 'console' | 'network' | ''."""

    detail: str
    """Human-readable description of what was detected."""

    transform_name: str
    """Name of the transform variant that was used."""

    payload: str
    """The exact payload string that was injected."""

    param_name: str
    """URL parameter the payload was injected into."""

    fired_url: str
    """Full URL that was navigated to."""

    error: str | None = None
    """Any error that prevented the attempt."""


class ActiveExecutor:
    """Manages a shared Playwright browser for payload execution detection.

    Usage (within a worker process):
        executor = ActiveExecutor()
        executor.start()
        try:
            result = executor.fire(url, param_name, payload, all_params, transform_name)
        finally:
            executor.stop()
    """

    def __init__(self, auth_headers: dict[str, str] | None = None) -> None:
        self._pw = None
        self._browser = None
        self._started = False
        self._auth_headers: dict[str, str] = auth_headers or {}

    def start(self) -> None:
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        self._started = True
        log.debug("ActiveExecutor: Playwright browser started.")

    def stop(self) -> None:
        if self._browser:
            try:
                self._browser.close()
            except Exception as exc:
                log.debug("Browser close error (possible resource leak): %s", exc)
        if self._pw:
            try:
                self._pw.stop()
            except Exception as exc:
                log.debug("Playwright stop error (possible resource leak): %s", exc)
        self._started = False
        log.debug("ActiveExecutor: Playwright browser stopped.")

    def fire(
        self,
        url: str,
        param_name: str,
        payload: str,
        all_params: dict[str, str],
        transform_name: str,
    ) -> ExecutionResult:
        """Navigate to *url* with *payload* injected into *param_name*.

        Registers dialog / console / network handlers BEFORE navigation so
        events fired on page load are captured.

        Returns an ExecutionResult regardless of whether execution was confirmed.
        """
        if not self._started or self._browser is None:
            return ExecutionResult(
                confirmed=False,
                method="",
                detail="",
                transform_name=transform_name,
                payload=payload,
                param_name=param_name,
                fired_url="",
                error="Executor not started",
            )

        fired_url = _build_url(url, param_name, payload, all_params)

        confirmed = False
        method = ""
        detail = ""

        # Merge auth headers; Accept is always set; auth headers must not override it
        extra_headers = {**self._auth_headers, "Accept": "text/html,application/xhtml+xml"}
        context = self._browser.new_context(
            ignore_https_errors=True,
            # Block fonts/images/media for speed — we only care about JS execution
            extra_http_headers=extra_headers,
        )
        try:
            page = context.new_page()

            # Block heavy resources to keep navigation fast
            page.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in {"image", "media", "font", "stylesheet"}
                else route.continue_(),
            )

            # --- Detection hook 1: dialog (alert / confirm / prompt) ---
            def _on_dialog(dialog):
                nonlocal confirmed, method, detail
                confirmed = True
                method = "dialog"
                detail = f"alert() dialog triggered — message: {dialog.message!r}"
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", _on_dialog)

            # --- Detection hook 2: console output ---
            def _on_console(msg):
                nonlocal confirmed, method, detail
                if not confirmed:
                    confirmed = True
                    method = "console"
                    detail = f"console.{msg.type}() fired — text: {msg.text!r}"

            page.on("console", _on_console)

            # --- Detection hook 3: outbound network request to beacon host ---
            def _on_request(req):
                nonlocal confirmed, method, detail
                if not confirmed and _BEACON_HOST in req.url:
                    confirmed = True
                    method = "network"
                    detail = f"OOB network request detected: {req.url!r}"

            page.on("request", _on_request)

            # Navigate — use domcontentloaded so we don't wait for all assets
            try:
                page.goto(fired_url, timeout=_NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            except Exception as nav_exc:
                # Navigation errors (timeout, net error) don't mean no execution —
                # a dialog event may have already fired and been caught.
                if not confirmed:
                    log.debug("Navigation error for %s: %s", fired_url, nav_exc)

        except Exception as exc:
            return ExecutionResult(
                confirmed=False,
                method="",
                detail="",
                transform_name=transform_name,
                payload=payload,
                param_name=param_name,
                fired_url=fired_url,
                error=str(exc),
            )
        finally:
            try:
                context.close()
            except Exception:
                pass

        return ExecutionResult(
            confirmed=confirmed,
            method=method,
            detail=detail,
            transform_name=transform_name,
            payload=payload,
            param_name=param_name,
            fired_url=fired_url,
        )


def _build_url(url: str, param_name: str, payload: str, all_params: dict[str, str]) -> str:
    """Return *url* with *param_name* replaced by *payload*, others preserved."""
    parsed = urllib.parse.urlparse(url)
    params = {**all_params, param_name: payload}
    new_query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))
