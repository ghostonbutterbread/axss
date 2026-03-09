"""Per-URL active scanner worker — runs as an isolated multiprocessing.Process.

Full lifecycle per URL:
  1. WAF detect (reuse existing helper)
  2. Fetch + surface-map the target page
  3. Probe all query parameters for reflection + surviving chars
  4. For each injectable param: fire Phase 1 mechanical transforms via Playwright
  5. If Phase 1 exhausted with no execution confirmed:
       - Run local model to get AI payloads; fire those
       - If still unconfirmed: escalate directly to cloud model
  6. Write confirmed findings to the findings store (process-safe via lock)
  7. Return WorkerResult to orchestrator via result_queue
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from multiprocessing.managers import DictProxy
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import multiprocessing

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ConfirmedFinding:
    """A single confirmed XSS execution."""
    url: str
    param_name: str
    context_type: str
    sink_context: str
    payload: str
    transform_name: str
    execution_method: str    # "dialog" | "console" | "network"
    execution_detail: str
    waf: str | None
    surviving_chars: str
    fired_url: str
    source: str             # "phase1_transform" | "local_model" | "cloud_model"
    cloud_escalated: bool


@dataclass
class WorkerResult:
    """Returned by a worker to the orchestrator via the result queue."""
    url: str
    status: str             # "confirmed" | "no_execution" | "no_reflection" | "no_params" | "error"
    confirmed_findings: list[ConfirmedFinding] = field(default_factory=list)
    transforms_tried: int = 0
    cloud_escalated: bool = False
    waf: str | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    # Summary counts for the report
    params_tested: int = 0
    params_reflected: int = 0


# ---------------------------------------------------------------------------
# Deduplication key — includes endpoint + param so different endpoints/params
# are always treated as new targets even when WAF + filter profile match.
# ---------------------------------------------------------------------------

def _escalation_key(
    url: str,
    param_name: str,
    waf: str | None,
    surviving_chars: frozenset[str],
    context_type: str,
    failed_transform_names: list[str],
) -> str:
    parsed = urllib.parse.urlparse(url)
    endpoint = f"{parsed.netloc}{parsed.path}"
    fingerprint = {
        "endpoint": endpoint,
        "param": param_name,
        "waf": waf or "none",
        "chars": sorted(surviving_chars),
        "context": context_type,
        "failed": sorted(failed_transform_names),
    }
    return hashlib.sha256(
        json.dumps(fingerprint, sort_keys=True).encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# Worker entry point
# ---------------------------------------------------------------------------

def run_worker(
    url: str,
    rate: float,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    result_queue: "multiprocessing.Queue",
    dedup_registry: DictProxy,
    dedup_lock: Any,
    findings_lock: Any,
) -> None:
    """Target function for multiprocessing.Process.

    All results are communicated back via *result_queue*.
    Exceptions are caught and returned as error WorkerResults — workers
    must never crash silently.
    """
    start_time = time.monotonic()

    def _put_result(result: WorkerResult) -> None:
        result.duration_seconds = time.monotonic() - start_time
        result_queue.put(result)

    try:
        _run(
            url=url,
            rate=rate,
            waf_hint=waf_hint,
            model=model,
            cloud_model=cloud_model,
            use_cloud=use_cloud,
            timeout_seconds=timeout_seconds,
            result_queue=result_queue,
            dedup_registry=dedup_registry,
            dedup_lock=dedup_lock,
            findings_lock=findings_lock,
            start_time=start_time,
            put_result=_put_result,
        )
    except Exception as exc:
        log.exception("Worker crashed for %s", url)
        _put_result(WorkerResult(url=url, status="error", error=str(exc)))


def _run(
    *,
    url: str,
    rate: float,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    result_queue: Any,
    dedup_registry: DictProxy,
    dedup_lock: Any,
    findings_lock: Any,
    start_time: float,
    put_result: Any,
) -> None:
    deadline = start_time + timeout_seconds

    def _timed_out() -> bool:
        return time.monotonic() > deadline

    # ── Step 1: Parse URL params — early exit if none ─────────────────────────
    parsed = urllib.parse.urlparse(url)
    raw_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not raw_params:
        put_result(WorkerResult(url=url, status="no_params", waf=waf_hint))
        return

    flat_params = {k: v[0] for k, v in raw_params.items()}

    # ── Step 2: Probe all params for reflection + char survival ──────────────
    from ai_xss_generator.probe import probe_url
    probe_results = probe_url(url, rate=rate)

    injectable = [r for r in probe_results if r.is_injectable]
    reflected  = [r for r in probe_results if r.is_reflected]

    if not reflected:
        put_result(WorkerResult(
            url=url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(flat_params),
        ))
        return

    if not injectable:
        put_result(WorkerResult(
            url=url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(flat_params),
            params_reflected=len(reflected),
        ))
        return

    # ── Step 3: Start Playwright executor (shared for all payload attempts) ──
    from ai_xss_generator.active.executor import ActiveExecutor
    executor = ActiveExecutor()
    try:
        executor.start()
    except Exception as exc:
        put_result(WorkerResult(url=url, status="error", error=f"Playwright start failed: {exc}", waf=waf_hint))
        return

    confirmed_findings: list[ConfirmedFinding] = []
    total_transforms_tried = 0
    cloud_escalated = False

    try:
        from ai_xss_generator.active.transforms import all_variants_for_probe

        # ── Step 4: Phase 1 — mechanical transforms per injectable param ──────
        for probe_result in injectable:
            if _timed_out():
                break

            param_name = probe_result.param_name
            param_variants = all_variants_for_probe(probe_result)

            for _pname, context_type, variants in param_variants:
                if _timed_out():
                    break

                failed_transform_names: list[str] = []

                for variant in variants:
                    if _timed_out():
                        break

                    total_transforms_tried += 1
                    result = executor.fire(
                        url=url,
                        param_name=param_name,
                        payload=variant.payload,
                        all_params=flat_params,
                        transform_name=variant.transform_name,
                    )

                    if result.confirmed:
                        finding = _make_finding(
                            url=url,
                            probe_result=probe_result,
                            context_type=context_type,
                            result=result,
                            waf=waf_hint,
                            source="phase1_transform",
                            cloud_escalated=False,
                        )
                        confirmed_findings.append(finding)
                        _save_finding_safe(finding, findings_lock)
                        break  # confirmed for this context — move to next param
                    else:
                        failed_transform_names.append(variant.transform_name)

                # ── Step 5: No Phase 1 confirmation — try local model ─────────
                if not confirmed_findings and not _timed_out():
                    local_payloads = _get_local_payloads(
                        url=url,
                        probe_result=probe_result,
                        model=model,
                        waf=waf_hint,
                    )

                    for lp in local_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=lp,
                            all_params=flat_params,
                            transform_name="local_model",
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=url,
                                probe_result=probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="local_model",
                                cloud_escalated=False,
                            )
                            confirmed_findings.append(finding)
                            _save_finding_safe(finding, findings_lock)
                            break
                        else:
                            failed_transform_names.append("local_model")

                # ── Step 6: Still nothing — escalate to cloud ─────────────────
                if not confirmed_findings and use_cloud and not _timed_out():
                    # Each unique (endpoint + param + waf + char profile + context)
                    # combination gets exactly one cloud call.
                    surviving_chars = frozenset().union(
                        *(ctx.surviving_chars for ctx in probe_result.reflections)
                    )
                    ekey = _escalation_key(
                        url=url,
                        param_name=param_name,
                        waf=waf_hint,
                        surviving_chars=surviving_chars,
                        context_type=context_type,
                        failed_transform_names=failed_transform_names,
                    )

                    cloud_payloads = _get_cloud_payloads(
                        url=url,
                        probe_result=probe_result,
                        cloud_model=cloud_model,
                        waf=waf_hint,
                        ekey=ekey,
                        dedup_registry=dedup_registry,
                        dedup_lock=dedup_lock,
                    )

                    if cloud_payloads:
                        cloud_escalated = True

                    for cp in cloud_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=cp,
                            all_params=flat_params,
                            transform_name="cloud_model",
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=url,
                                probe_result=probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="cloud_model",
                                cloud_escalated=True,
                            )
                            confirmed_findings.append(finding)
                            _save_finding_safe(finding, findings_lock)
                            break

    finally:
        executor.stop()

    status = "confirmed" if confirmed_findings else "no_execution"
    put_result(WorkerResult(
        url=url,
        status=status,
        confirmed_findings=confirmed_findings,
        transforms_tried=total_transforms_tried,
        cloud_escalated=cloud_escalated,
        waf=waf_hint,
        params_tested=len(flat_params),
        params_reflected=len(reflected),
    ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    url: str,
    probe_result: Any,
    context_type: str,
    result: Any,
    waf: str | None,
    source: str,
    cloud_escalated: bool,
) -> ConfirmedFinding:
    surviving = "".join(sorted(
        c for ctx in probe_result.reflections for c in ctx.surviving_chars
    ))
    return ConfirmedFinding(
        url=url,
        param_name=probe_result.param_name,
        context_type=context_type,
        sink_context=context_type,
        payload=result.payload,
        transform_name=result.transform_name,
        execution_method=result.method,
        execution_detail=result.detail,
        waf=waf,
        surviving_chars=surviving,
        fired_url=result.fired_url,
        source=source,
        cloud_escalated=cloud_escalated,
    )


def _get_local_payloads(
    url: str,
    probe_result: Any,
    model: str,
    waf: str | None,
) -> list[str]:
    """Ask the local model for payloads. Returns raw payload strings."""
    try:
        from ai_xss_generator.probe import enrich_context
        from ai_xss_generator.parser import parse_target
        from ai_xss_generator.models import generate_payloads

        context = parse_target(url=url, html_value=None, waf=waf)
        context = enrich_context(context, [probe_result])
        payloads, *_ = generate_payloads(
            context=context,
            model=model,
            waf=waf,
            use_cloud=False,  # local only at this step
        )
        return [p.payload for p in payloads if p.payload]
    except Exception as exc:
        log.debug("Local model failed for %s param=%s: %s", url, probe_result.param_name, exc)
        return []


def _get_cloud_payloads(
    url: str,
    probe_result: Any,
    cloud_model: str,
    waf: str | None,
    ekey: str,
    dedup_registry: DictProxy,
    dedup_lock: Any,
) -> list[str]:
    """Check dedup registry; call cloud model if this is a novel fingerprint."""
    with dedup_lock:
        if ekey in dedup_registry:
            log.debug("Dedup hit — reusing cloud result for key %s", ekey[:12])
            return dedup_registry[ekey]

    try:
        from ai_xss_generator.probe import enrich_context
        from ai_xss_generator.parser import parse_target
        from ai_xss_generator.models import generate_cloud_payloads

        context = parse_target(url=url, html_value=None, waf=waf)
        context = enrich_context(context, [probe_result])
        payloads, _ = generate_cloud_payloads(
            context=context,
            cloud_model=cloud_model,
            waf=waf,
        )
        result_strings = [p.payload for p in payloads if p.payload]
    except Exception as exc:
        log.debug("Cloud escalation failed for %s: %s", url, exc)
        result_strings = []

    with dedup_lock:
        dedup_registry[ekey] = result_strings

    return result_strings


def _save_finding_safe(finding: ConfirmedFinding, findings_lock: Any) -> None:
    """Write to findings store with process-safe lock."""
    try:
        with findings_lock:
            from ai_xss_generator.findings import Finding, save_finding, infer_bypass_family
            f = Finding(
                sink_type=f"probe:{finding.context_type}",
                context_type=finding.context_type,
                surviving_chars=finding.surviving_chars,
                bypass_family=infer_bypass_family(finding.payload, []),
                payload=finding.payload,
                test_vector=f"?{finding.param_name}={finding.payload}",
                model=finding.source,
                explanation=(
                    f"Active scan confirmed via {finding.execution_method}. "
                    f"Transform: {finding.transform_name}. WAF: {finding.waf or 'none'}."
                ),
                target_host=urllib.parse.urlparse(finding.url).netloc,
                tags=[finding.source, finding.execution_method, finding.transform_name],
                verified=True,
            )
            save_finding(f)
    except Exception as exc:
        log.debug("Failed to save finding: %s", exc)
