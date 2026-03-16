"""SARIF 2.1.0 output writer for active scan results.

Produces output compatible with GitHub Advanced Security, DefectDojo,
and any SARIF-aware security tooling.

Usage:
    from ai_xss_generator.sarif import write_sarif
    write_sarif(results, Path("results.sarif.json"))
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from ai_xss_generator.active.worker import WorkerResult

# Rule definitions — one per XSS variant class
_RULES: list[dict[str, Any]] = [
    {
        "id": "XSS001",
        "name": "ReflectedXSS",
        "shortDescription": {"text": "Reflected Cross-Site Scripting"},
        "fullDescription": {
            "text": (
                "User-controlled input is reflected into the response without sufficient encoding "
                "and can be used to execute arbitrary JavaScript in the victim's browser."
            )
        },
        "helpUri": "https://owasp.org/www-community/attacks/xss/",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "xss", "reflected"]},
    },
    {
        "id": "XSS002",
        "name": "StoredXSS",
        "shortDescription": {"text": "Stored Cross-Site Scripting"},
        "fullDescription": {
            "text": (
                "User-controlled input is stored and later rendered without encoding, "
                "allowing persistent JavaScript execution for any visitor."
            )
        },
        "helpUri": "https://owasp.org/www-community/attacks/xss/",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "xss", "stored"]},
    },
    {
        "id": "XSS003",
        "name": "DomBasedXSS",
        "shortDescription": {"text": "DOM-Based Cross-Site Scripting"},
        "fullDescription": {
            "text": (
                "Attacker-controlled data flows from a DOM source (e.g. location.hash) "
                "into a dangerous sink (e.g. innerHTML) without sanitization."
            )
        },
        "helpUri": "https://owasp.org/www-community/attacks/DOM_Based_XSS",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "xss", "dom-based"]},
    },
]

_RULE_INDEX: dict[str, int] = {r["id"]: i for i, r in enumerate(_RULES)}


def _rule_for_finding(finding: Any) -> str:
    exec_method = (getattr(finding, "execution_method", "") or "").lower()
    source = (getattr(finding, "source", "") or "").lower()
    if "dom" in exec_method or "dom" in source:
        return "XSS003"
    kind = (getattr(finding, "kind", "") or "").lower()
    if "stored" in kind or "post" in source:
        return "XSS002"
    return "XSS001"


def _finding_to_result(finding: Any) -> dict[str, Any]:
    rule_id = _rule_for_finding(finding)
    url = getattr(finding, "url", "") or ""
    param = getattr(finding, "param_name", "") or ""
    payload = getattr(finding, "payload", "") or ""
    context = getattr(finding, "context_type", "") or ""
    bypass = getattr(finding, "bypass_family", "") or ""
    exec_method = getattr(finding, "execution_method", "") or ""
    csp_note = getattr(finding, "csp_note", "") or ""

    msg_parts = [
        f"XSS confirmed via parameter '{param}'" if param else "XSS confirmed",
        f"in context '{context}'" if context else "",
        f"using {bypass} bypass" if bypass else "",
        f"(confirmed via {exec_method})" if exec_method else "",
    ]
    message = " ".join(p for p in msg_parts if p) + "."
    if csp_note:
        message += f" Note: {csp_note}"

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": _RULE_INDEX.get(rule_id, 0),
        "level": "error",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": url, "uriBaseId": "%SRCROOT%"},
                }
            }
        ],
        "properties": {
            "param": param,
            "payload": payload,
            "context_type": context,
            "bypass_family": bypass,
            "execution_method": exec_method,
            "fired_url": getattr(finding, "fired_url", "") or "",
            "waf": getattr(finding, "waf", "") or "",
            "ai_engine": getattr(finding, "ai_engine", "") or "",
        },
    }

    # Redact empty property keys to keep SARIF clean
    result["properties"] = {k: v for k, v in result["properties"].items() if v}
    return result


def _sanitize_uri(url: str) -> str:
    """Ensure URL is safe for SARIF artifactLocation.uri."""
    return re.sub(r"[\x00-\x1f\x7f]", "", url)


def write_sarif(
    results: Sequence[Any],
    output_path: Path,
    *,
    tool_version: str = "0.1.0",
) -> None:
    """Write SARIF 2.1.0 output from a list of WorkerResult objects."""
    sarif_results: list[dict[str, Any]] = []

    for worker_result in results:
        for finding in getattr(worker_result, "confirmed_findings", []):
            sarif_results.append(_finding_to_result(finding))

    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "axss",
                        "version": tool_version,
                        "informationUri": "https://github.com/Ryushe/axss",
                        "rules": _RULES,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "results": sarif_results,
            }
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
