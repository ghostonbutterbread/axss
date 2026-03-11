from __future__ import annotations

import urllib.parse
from typing import Any

from ai_xss_generator.findings import (
    Finding,
    MEMORY_TIER_EXPERIMENTAL,
    MEMORY_TIER_VERIFIED_RUNTIME,
    REVIEW_STATUS_APPROVED,
    REVIEW_STATUS_PENDING,
    TARGET_SCOPE_GLOBAL,
    TARGET_SCOPE_HOST,
    infer_bypass_family,
)


def build_memory_profile(
    *,
    context: Any | None = None,
    waf_name: str | None = None,
    delivery_mode: str = "",
    target_host: str = "",
    target_scope: str = "",
) -> dict[str, Any]:
    frameworks = []
    auth_required = False
    source = ""
    inferred_delivery_mode = delivery_mode.lower()
    if context is not None:
        frameworks = [str(item).lower() for item in getattr(context, "frameworks", []) if str(item).strip()]
        auth_required = bool(getattr(context, "auth_notes", []))
        source = str(getattr(context, "source", "") or "")
        if not inferred_delivery_mode:
            parsed = urllib.parse.urlparse(source)
            if parsed.query:
                inferred_delivery_mode = "get"
            elif getattr(context, "forms", []):
                inferred_delivery_mode = "post"
            elif getattr(context, "dom_sinks", []):
                inferred_delivery_mode = "dom"
    host = target_host or urllib.parse.urlparse(source).netloc
    scope = target_scope.lower().strip()
    if scope not in {TARGET_SCOPE_GLOBAL, TARGET_SCOPE_HOST}:
        scope = TARGET_SCOPE_HOST if host and inferred_delivery_mode != "offline" else TARGET_SCOPE_GLOBAL
    return {
        "target_host": host,
        "target_scope": scope,
        "waf_name": (waf_name or "").lower(),
        "delivery_mode": inferred_delivery_mode,
        "frameworks": list(dict.fromkeys(frameworks)),
        "auth_required": auth_required,
    }


def build_verified_runtime_finding(
    confirmed: Any,
    *,
    delivery_mode: str = "get",
    frameworks: list[str] | None = None,
    auth_required: bool = False,
) -> Finding:
    target_host = urllib.parse.urlparse(getattr(confirmed, "url", "")).netloc
    param_name = getattr(confirmed, "param_name", "")
    payload = getattr(confirmed, "payload", "")
    test_vector = (
        f"POST:{param_name}={payload}"
        if delivery_mode == "post"
        else f"?{param_name}={payload}"
    )
    return Finding(
        sink_type=f"probe:{getattr(confirmed, 'context_type', '')}",
        context_type=getattr(confirmed, "context_type", ""),
        surviving_chars=getattr(confirmed, "surviving_chars", ""),
        bypass_family=infer_bypass_family(payload, []),
        payload=payload,
        test_vector=test_vector,
        model=getattr(confirmed, "source", "verified-runtime"),
        explanation=(
            f"Active scan confirmed via {getattr(confirmed, 'execution_method', 'unknown')}. "
            f"Transform: {getattr(confirmed, 'transform_name', 'unknown')}. "
            f"WAF: {getattr(confirmed, 'waf', 'none') or 'none'}."
        ),
        target_host=target_host,
        tags=[
            getattr(confirmed, "source", "verified-runtime"),
            getattr(confirmed, "execution_method", "unknown"),
            getattr(confirmed, "transform_name", "unknown"),
        ],
        verified=True,
        memory_tier=MEMORY_TIER_VERIFIED_RUNTIME,
        evidence_type="active_scan",
        evidence_detail=(
            f"confirmed on {getattr(confirmed, 'fired_url', '') or getattr(confirmed, 'url', '')} "
            f"via {getattr(confirmed, 'execution_method', 'unknown')}: "
            f"{getattr(confirmed, 'execution_detail', '')}"
        ).strip(),
        provenance=getattr(confirmed, "url", ""),
        success_count=1,
        target_scope=TARGET_SCOPE_HOST if target_host else TARGET_SCOPE_GLOBAL,
        waf_name=str(getattr(confirmed, "waf", "") or "").lower(),
        delivery_mode=delivery_mode.lower(),
        frameworks=[item.lower() for item in (frameworks or [])],
        auth_required=auth_required,
        review_status=REVIEW_STATUS_APPROVED,
    )


def build_experimental_finding(
    *,
    payload: str,
    sink_type: str,
    context_type: str,
    surviving_chars: str,
    model: str,
    explanation: str,
    test_vector: str,
    target_host: str,
    tags: list[str],
    evidence_type: str,
    evidence_detail: str,
    provenance: str,
    target_scope: str = TARGET_SCOPE_GLOBAL,
    waf_name: str = "",
    delivery_mode: str = "",
    frameworks: list[str] | None = None,
    auth_required: bool = False,
) -> Finding:
    return Finding(
        sink_type=sink_type,
        context_type=context_type,
        surviving_chars=surviving_chars,
        bypass_family=infer_bypass_family(payload, tags),
        payload=payload,
        test_vector=test_vector,
        model=model,
        explanation=explanation,
        target_host=target_host,
        tags=tags,
        verified=False,
        memory_tier=MEMORY_TIER_EXPERIMENTAL,
        evidence_type=evidence_type,
        evidence_detail=evidence_detail,
        provenance=provenance,
        success_count=0,
        target_scope=target_scope,
        waf_name=waf_name.lower(),
        delivery_mode=delivery_mode.lower(),
        frameworks=[item.lower() for item in (frameworks or [])],
        auth_required=auth_required,
        review_status=REVIEW_STATUS_PENDING,
    )
