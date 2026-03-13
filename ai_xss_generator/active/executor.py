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
from typing import Any

from ai_xss_generator.browser_nav import goto_with_edge_recovery, same_origin_root
from ai_xss_generator.active.console_signals import (
    console_init_script,
    is_execution_console_text,
    strip_execution_console_text,
)

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


@dataclass(slots=True)
class DeliveryPlan:
    fired_url: str
    payload_value: str
    param_overrides: dict[str, str] = field(default_factory=dict)
    preflight_urls: list[str] = field(default_factory=list)
    follow_up_urls: list[str] = field(default_factory=list)


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
        sink_url: str | None = None,
        payload_overrides: dict[str, str] | None = None,
        payload_candidate: Any = None,
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

        plan = _build_delivery_plan(
            url=url,
            param_name=param_name,
            payload=payload,
            all_params=all_params,
            payload_overrides=payload_overrides,
            payload_candidate=payload_candidate,
        )
        fired_url = plan.fired_url

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
            page.add_init_script(console_init_script())

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
                if not confirmed and is_execution_console_text(msg.text):
                    confirmed = True
                    method = "console"
                    detail = (
                        f"console.{msg.type}() fired — "
                        f"text: {strip_execution_console_text(msg.text)!r}"
                    )

            page.on("console", _on_console)

            # --- Detection hook 3: outbound network request to beacon host ---
            def _on_request(req):
                nonlocal confirmed, method, detail
                if not confirmed and _BEACON_HOST in req.url:
                    confirmed = True
                    method = "network"
                    detail = f"OOB network request detected: {req.url!r}"

            page.on("request", _on_request)

            for preflight_url in plan.preflight_urls:
                if confirmed:
                    break
                ok, phases, nav_exc = goto_with_edge_recovery(
                    page,
                    preflight_url,
                    timeout_ms=_NAV_TIMEOUT_MS,
                )
                if not ok and nav_exc is not None:
                    log.debug("Preflight navigation error for %s after %s: %s", preflight_url, phases, nav_exc)

            # Navigate — use domcontentloaded so we don't wait for all assets
            ok, phases, nav_exc = goto_with_edge_recovery(
                page,
                fired_url,
                timeout_ms=_NAV_TIMEOUT_MS,
            )
            if not ok and nav_exc is not None and not confirmed:
                # Navigation errors (timeout, net error) don't mean no execution —
                # a dialog event may have already fired and been caught.
                log.debug("Navigation error for %s after %s: %s", fired_url, phases, nav_exc)

            # --sink-url: navigate to the user-specified render page to catch
            # GET-based stored XSS where the payload shows up elsewhere.
            follow_ups = list(dict.fromkeys(
                plan.follow_up_urls + ([sink_url] if sink_url else [])
            ))
            for follow_up_url in follow_ups:
                if confirmed:
                    break
                ok, phases, _nav_exc = goto_with_edge_recovery(
                    page,
                    follow_up_url,
                    timeout_ms=_NAV_TIMEOUT_MS,
                )
                if not ok and _nav_exc is not None:
                    log.debug("fire: follow-up nav error for %s after %s: %s", follow_up_url, phases, _nav_exc)

        except Exception as exc:
            return ExecutionResult(
                confirmed=False,
                method="",
                detail="",
                transform_name=transform_name,
                payload=plan.payload_value,
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
            payload=plan.payload_value,
            param_name=param_name,
            fired_url=fired_url,
        )


    def fire_post(
        self,
        source_page_url: str,
        action_url: str,
        param_name: str,
        payload: str,
        all_param_names: list[str],
        csrf_field: str | None,
        transform_name: str,
        sink_url: str | None = None,
        payload_overrides: dict[str, str] | None = None,
        payload_candidate: Any = None,
    ) -> "ExecutionResult":
        """Navigate to *source_page_url*, fill *param_name* with *payload*, submit the form.

        Relies on the browser rendering the form page (including any dynamic CSRF token).
        The CSRF token is left untouched — it's already filled by the server-rendered form.

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
                fired_url=source_page_url,
                error="Executor not started",
            )

        confirmed = False
        method = ""
        detail = ""
        # Guard: only count execution events that happen AFTER the payload is
        # submitted.  Without this, console.log() calls on the form page itself
        # (e.g. analytics scripts) would fire _on_console and give a false positive
        # before we have even injected anything.
        payload_submitted = False

        extra_headers = {**self._auth_headers, "Accept": "text/html,application/xhtml+xml"}
        context = self._browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=extra_headers,
        )
        try:
            page = context.new_page()
            page.add_init_script(console_init_script())

            page.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in {"image", "media", "font", "stylesheet"}
                else route.continue_(),
            )

            def _on_dialog(dialog):
                nonlocal confirmed, method, detail
                if payload_submitted:
                    confirmed = True
                    method = "dialog"
                    detail = f"alert() dialog triggered — message: {dialog.message!r}"
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", _on_dialog)

            def _on_console(msg):
                nonlocal confirmed, method, detail
                if payload_submitted and not confirmed and is_execution_console_text(msg.text):
                    confirmed = True
                    method = "console"
                    detail = (
                        f"console.{msg.type}() fired — "
                        f"text: {strip_execution_console_text(msg.text)!r}"
                    )

            page.on("console", _on_console)

            def _on_request(req):
                nonlocal confirmed, method, detail
                if payload_submitted and not confirmed and _BEACON_HOST in req.url:
                    confirmed = True
                    method = "network"
                    detail = f"OOB network request detected: {req.url!r}"

            page.on("request", _on_request)

            # Step 1: Load the form page (server fills in CSRF token automatically)
            ok, phases, nav_exc = goto_with_edge_recovery(
                page,
                source_page_url,
                timeout_ms=_NAV_TIMEOUT_MS,
            )
            if not ok and nav_exc is not None:
                log.debug("fire_post: source page load error for %s after %s: %s", source_page_url, phases, nav_exc)

            plan = _build_post_delivery_plan(
                source_page_url=source_page_url,
                param_name=param_name,
                payload=payload,
                payload_overrides=payload_overrides,
                payload_candidate=payload_candidate,
                sink_url=sink_url,
            )

            # Step 2: Fill the target param with the payload
            try:
                for field_name, field_value in plan.param_overrides.items():
                    page.fill(f'[name="{field_name}"]', field_value, timeout=3000)
            except Exception as fill_exc:
                log.debug("fire_post: fill failed for %s: %s", param_name, fill_exc)
                return ExecutionResult(
                    confirmed=False,
                    method="",
                    detail="",
                transform_name=transform_name,
                payload=plan.payload_value,
                param_name=param_name,
                fired_url=source_page_url,
                error=f"fill failed: {fill_exc}",
                )

            # Step 3: Submit the form — try submit button first, fall back to JS submit
            # Mark payload_submitted=True before submit so post-submit events are captured.
            payload_submitted = True
            try:
                submit_btn = page.locator('[type="submit"]').first
                if submit_btn.count() > 0:
                    submit_btn.click(timeout=3000)
                else:
                    page.evaluate("document.forms[0] && document.forms[0].submit()")
                # Wait briefly for post-submit navigation / JS execution
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=_NAV_TIMEOUT_MS)
                except Exception:
                    pass
            except Exception as submit_exc:
                log.debug("fire_post: submit error: %s", submit_exc)
                # Submit failed — roll back the flag so follow-up page events
                # (e.g. analytics console.log) are not mistaken for execution.
                payload_submitted = False

            # Step 4: Navigate to follow-up pages to catch session-stored XSS.
            # After the form POST, the payload may be stored server-side and
            # reflected (unescaped) on a subsequent page — most commonly the
            # origin root or the source form page.  Navigate to both so the
            # existing dialog/console/network hooks can detect execution there.
            if not confirmed:
                import urllib.parse as _up
                _pp = _up.urlparse(source_page_url)
                _origin_root = same_origin_root(source_page_url)
                # sink_url (manually specified) is first — highest priority
                _follow_ups = list(dict.fromkeys(
                    list(plan.follow_up_urls)
                    + ([sink_url] if sink_url else [])
                    + [source_page_url, _origin_root]
                ))
                for _fu in _follow_ups:
                    if confirmed:
                        break
                    ok, phases, _nav_exc = goto_with_edge_recovery(
                        page,
                        _fu,
                        timeout_ms=_NAV_TIMEOUT_MS,
                    )
                    if not ok and _nav_exc is not None:
                        log.debug("fire_post: follow-up nav error for %s after %s: %s", _fu, phases, _nav_exc)

        except Exception as exc:
            return ExecutionResult(
                confirmed=False,
                method="",
                detail="",
                transform_name=transform_name,
                payload=plan.payload_value,
                param_name=param_name,
                fired_url=source_page_url,
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
            payload=plan.payload_value,
            param_name=param_name,
            fired_url=source_page_url,
        )

    def fire_upload(
        self,
        source_page_url: str,
        action_url: str,
        file_field_names: list[str],
        companion_overrides: dict[str, str],
        file_name: str,
        file_content: str,
        transform_name: str,
        sink_url: str | None = None,
    ) -> "ExecutionResult":
        """Load an upload form page, submit a crafted file, and watch follow-up pages."""
        if not self._started or self._browser is None:
            return ExecutionResult(
                confirmed=False,
                method="",
                detail="",
                transform_name=transform_name,
                payload=file_name,
                param_name=file_field_names[0] if file_field_names else "file",
                fired_url=source_page_url,
                error="Executor not started",
            )

        confirmed = False
        method = ""
        detail = ""
        payload_submitted = False
        extra_headers = {**self._auth_headers, "Accept": "text/html,application/xhtml+xml"}
        context = self._browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=extra_headers,
        )
        try:
            page = context.new_page()
            page.add_init_script(console_init_script())

            page.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in {"image", "media", "font", "stylesheet"}
                else route.continue_(),
            )

            def _on_dialog(dialog):
                nonlocal confirmed, method, detail
                if payload_submitted:
                    confirmed = True
                    method = "dialog"
                    detail = f"alert() dialog triggered — message: {dialog.message!r}"
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", _on_dialog)

            def _on_console(msg):
                nonlocal confirmed, method, detail
                if payload_submitted and not confirmed and is_execution_console_text(msg.text):
                    confirmed = True
                    method = "console"
                    detail = (
                        f"console.{msg.type}() fired — "
                        f"text: {strip_execution_console_text(msg.text)!r}"
                    )

            page.on("console", _on_console)

            def _on_request(req):
                nonlocal confirmed, method, detail
                if payload_submitted and not confirmed and _BEACON_HOST in req.url:
                    confirmed = True
                    method = "network"
                    detail = f"OOB network request detected: {req.url!r}"

            page.on("request", _on_request)

            ok, phases, nav_exc = goto_with_edge_recovery(
                page,
                source_page_url,
                timeout_ms=_NAV_TIMEOUT_MS,
            )
            if not ok and nav_exc is not None:
                log.debug("fire_upload: source page load error for %s after %s: %s", source_page_url, phases, nav_exc)

            for field_name, field_value in companion_overrides.items():
                try:
                    page.fill(f'[name="{field_name}"]', field_value, timeout=3000)
                except Exception as fill_exc:
                    log.debug("fire_upload: companion fill failed for %s: %s", field_name, fill_exc)

            file_spec = _upload_file_spec(file_name, file_content)
            for file_field_name in file_field_names or ["file"]:
                try:
                    page.set_input_files(f'[name="{file_field_name}"]', file_spec, timeout=3000)
                except Exception as set_exc:
                    log.debug("fire_upload: file set failed for %s: %s", file_field_name, set_exc)
                    return ExecutionResult(
                        confirmed=False,
                        method="",
                        detail="",
                        transform_name=transform_name,
                        payload=file_name,
                        param_name=file_field_name,
                        fired_url=source_page_url,
                        error=f"file set failed: {set_exc}",
                    )

            payload_submitted = True
            try:
                submit_btn = page.locator('[type="submit"]').first
                if submit_btn.count() > 0:
                    submit_btn.click(timeout=3000)
                else:
                    page.evaluate("document.forms[0] && document.forms[0].submit()")
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=_NAV_TIMEOUT_MS)
                except Exception:
                    pass
            except Exception as submit_exc:
                log.debug("fire_upload: submit error: %s", submit_exc)
                payload_submitted = False

            if not confirmed:
                origin_root = same_origin_root(source_page_url)
                follow_ups = list(dict.fromkeys(
                    ([sink_url] if sink_url else [])
                    + [source_page_url, action_url, origin_root]
                ))
                for follow_up_url in follow_ups:
                    if confirmed:
                        break
                    ok, phases, nav_exc = goto_with_edge_recovery(
                        page,
                        follow_up_url,
                        timeout_ms=_NAV_TIMEOUT_MS,
                    )
                    if not ok and nav_exc is not None:
                        log.debug("fire_upload: follow-up nav error for %s after %s: %s", follow_up_url, phases, nav_exc)

        except Exception as exc:
            return ExecutionResult(
                confirmed=False,
                method="",
                detail="",
                transform_name=transform_name,
                payload=file_name,
                param_name=file_field_names[0] if file_field_names else "file",
                fired_url=source_page_url,
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
            payload=file_name,
            param_name=file_field_names[0] if file_field_names else "file",
            fired_url=source_page_url,
        )


def _strategy_value(strategy: Any, key: str) -> str:
    if strategy is None:
        return ""
    if isinstance(strategy, dict):
        return str(strategy.get(key, "") or "").strip()
    return str(getattr(strategy, key, "") or "").strip()


def _candidate_follow_up_target(url: str, payload_candidate: Any = None, sink_url: str | None = None) -> str:
    if sink_url:
        return sink_url
    follow_up_hint = str(getattr(getattr(payload_candidate, "strategy", None), "follow_up_hint", "") or "").strip()
    if not follow_up_hint:
        return ""
    parsed = urllib.parse.urlparse(follow_up_hint)
    if parsed.scheme and parsed.netloc:
        return follow_up_hint
    if follow_up_hint.startswith("/"):
        base = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(base._replace(path=follow_up_hint, query="", fragment=""))
    return ""


def _parse_test_vector(test_vector: str) -> tuple[dict[str, str], str]:
    test_vector = (test_vector or "").strip()
    if not test_vector:
        return {}, ""
    if test_vector.startswith("#"):
        return {}, test_vector[1:]
    query = test_vector
    fragment = ""
    if query.startswith("?"):
        query = query[1:]
    elif "?" in query:
        parsed = urllib.parse.urlparse(query)
        query = parsed.query
        fragment = parsed.fragment
    elif query.startswith("/"):
        parsed = urllib.parse.urlparse(query)
        query = parsed.query
        fragment = parsed.fragment
    elif "#" in query:
        query, fragment = query.split("#", 1)
    return dict(urllib.parse.parse_qsl(query, keep_blank_values=True)), fragment


def _build_delivery_plan(
    *,
    url: str,
    param_name: str,
    payload: str,
    all_params: dict[str, str],
    payload_overrides: dict[str, str] | None = None,
    payload_candidate: Any = None,
) -> DeliveryPlan:
    strategy = getattr(payload_candidate, "strategy", None)
    test_vector = str(getattr(payload_candidate, "test_vector", "") or "")
    delivery_hint = _strategy_value(strategy, "delivery_mode_hint").lower()
    session_hint = _strategy_value(strategy, "session_hint").lower()
    coordination_hint = _strategy_value(strategy, "coordination_hint").lower()

    overrides = dict(payload_overrides or {})
    vector_params, vector_fragment = _parse_test_vector(test_vector)
    if vector_params and (coordination_hint == "multi_param" or len(vector_params) > 1):
        overrides.update(vector_params)
    elif vector_params:
        overrides.update(vector_params)

    parsed = urllib.parse.urlparse(url)
    params = {**all_params, param_name: payload}
    params.update(overrides)
    fragment = parsed.fragment
    if vector_fragment:
        fragment = vector_fragment
    elif delivery_hint in {"fragment", "fragment_only"}:
        fragment = payload

    new_query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    fired_url = urllib.parse.urlunparse(parsed._replace(query=new_query, fragment=fragment))
    preflight_urls: list[str] = []
    follow_up_urls: list[str] = []
    if session_hint in {"navigate_then_fire", "authenticated_follow_up"}:
        preflight_urls.append(same_origin_root(url))
    if session_hint in {"authenticated_follow_up"}:
        follow_up = _candidate_follow_up_target(url, payload_candidate)
        if follow_up:
            follow_up_urls.append(follow_up)
    return DeliveryPlan(
        fired_url=fired_url,
        payload_value=str(params.get(param_name, payload)),
        param_overrides=params,
        preflight_urls=list(dict.fromkeys(preflight_urls)),
        follow_up_urls=list(dict.fromkeys(follow_up_urls)),
    )


def _build_post_delivery_plan(
    *,
    source_page_url: str,
    param_name: str,
    payload: str,
    payload_overrides: dict[str, str] | None = None,
    payload_candidate: Any = None,
    sink_url: str | None = None,
) -> DeliveryPlan:
    strategy = getattr(payload_candidate, "strategy", None)
    coordination_hint = _strategy_value(strategy, "coordination_hint").lower()
    session_hint = _strategy_value(strategy, "session_hint").lower()
    test_vector = str(getattr(payload_candidate, "test_vector", "") or "")

    overrides = {param_name: payload}
    if payload_overrides:
        overrides.update(payload_overrides)
    vector_params, _ = _parse_test_vector(test_vector)
    if vector_params and (coordination_hint == "multi_param" or len(vector_params) >= 1):
        overrides.update(vector_params)
    follow_up_urls: list[str] = []
    if session_hint in {"post_then_sink", "authenticated_follow_up"}:
        follow_up = _candidate_follow_up_target(source_page_url, payload_candidate, sink_url)
        if follow_up:
            follow_up_urls.append(follow_up)
    return DeliveryPlan(
        fired_url="",
        payload_value=str(overrides.get(param_name, payload)),
        param_overrides=overrides,
        follow_up_urls=list(dict.fromkeys(follow_up_urls)),
    )


def _upload_file_spec(filename: str, content: str, mime_type: str = "image/svg+xml") -> dict[str, Any]:
    return {
        "name": filename,
        "mimeType": mime_type,
        "buffer": content.encode("utf-8"),
    }


def _build_url(
    url: str,
    param_name: str,
    payload: str,
    all_params: dict[str, str],
    payload_overrides: dict[str, str] | None = None,
) -> str:
    """Return *url* with *param_name* replaced by *payload*, others preserved."""
    parsed = urllib.parse.urlparse(url)
    params = {**all_params, param_name: payload}
    if payload_overrides:
        params.update(payload_overrides)
    new_query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))
