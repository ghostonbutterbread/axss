from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from ai_xss_generator.types import ParsedContext, WafKnowledgeProfile


_TEXT_EXTENSIONS = {
    ".conf", ".config", ".rules", ".rule", ".yaml", ".yml", ".json",
    ".lua", ".py", ".js", ".ts", ".go", ".java", ".rb", ".txt", ".md",
}
_MAX_FILES = 120
_MAX_BYTES_PER_FILE = 256 * 1024
_REMOTE_CACHE_ROOT = Path(tempfile.gettempdir()) / "axss_waf_sources"


def _iter_text_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]

    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _TEXT_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > _MAX_BYTES_PER_FILE:
                continue
        except OSError:
            continue
        files.append(path)
        if len(files) >= _MAX_FILES:
            break
    return files


def _read_files(paths: list[Path]) -> tuple[str, int]:
    chunks: list[str] = []
    count = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        chunks.append(text)
        count += 1
    return "\n".join(chunks), count


def _detect_engine(text: str, root: Path) -> tuple[str, float]:
    lower = text.lower()
    name = root.name.lower()
    if "secrule" in lower:
        if "coraza" in lower or "crs-setup.conf" in lower:
            return "coraza", 0.8
        return "modsecurity", 0.8
    candidates: list[tuple[str, int]] = [
        ("modsecurity", sum((
            "modsecurity" in lower,
            "secrule" in lower,
            "ctl:" in lower,
            "tx.anomaly_score" in lower,
        ))),
        ("coraza", sum((
            "coraza" in lower,
            "secrule" in lower,
            "crs-setup.conf" in lower,
        ))),
        ("naxsi", sum((
            "naxsi" in lower,
            "mainrule" in lower,
            "libinjection" in lower,
        ))),
        ("openresty_lua", sum((
            "ngx." in lower,
            "resty" in lower,
            "access_by_lua" in lower,
            ".lua" in name,
        ))),
        ("custom_regex_filter", sum((
            "re.compile" in lower or "regexp.compile" in lower or "preg_match" in lower,
            "onerror" in lower or "onclick" in lower or "javascript:" in lower,
            "deny" in lower or "block" in lower,
        ))),
    ]
    engine_name, score = max(candidates, key=lambda item: item[1])
    confidence = min(0.95, 0.35 + (0.15 * score)) if score > 0 else 0.2
    if score <= 0:
        engine_name = "unknown_filter_stack"
    return engine_name, confidence


def _bool_score(text: str, *patterns: str) -> bool:
    lower = text.lower()
    return any(pattern in lower for pattern in patterns)


def _first_int_match(text: str, patterns: list[tuple[str, int]]) -> int:
    lower = text.lower()
    detected = 0
    for pattern, value in patterns:
        if pattern in lower:
            detected = max(detected, value)
    return detected


def _is_remote_source(source_path: str) -> bool:
    source = source_path.strip()
    return source.startswith(("http://", "https://", "git@")) or source.endswith(".git")


def _materialize_source_path(source_path: str) -> tuple[Path, str]:
    if not _is_remote_source(source_path):
        root = Path(source_path).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"WAF source path does not exist: {source_path}")
        return root, "local_repo"

    git_path = shutil.which("git")
    if not git_path:
        raise RuntimeError(
            "git is required to use a remote --waf-source repository URL. "
            "Install git or provide a local cloned path instead."
        )

    _REMOTE_CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    cache_key = hashlib.sha256(source_path.encode("utf-8")).hexdigest()[:16]
    clone_dir = _REMOTE_CACHE_ROOT / cache_key

    if not clone_dir.exists():
        subprocess.run(
            [git_path, "clone", "--depth", "1", source_path, str(clone_dir)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    return clone_dir.resolve(), "remote_git_clone"


def analyze_waf_source(source_path: str) -> WafKnowledgeProfile:
    root, source_type = _materialize_source_path(source_path)

    files = _iter_text_files(root)
    if not files:
        raise ValueError(f"No supported text files found under {root}")
    text, file_count = _read_files(files)
    lower = text.lower()

    engine_name, confidence = _detect_engine(text, root)

    url_decode_passes = _first_int_match(lower, [
        ("double urldecode", 2),
        ("double_url_decode", 2),
        ("urldecode(urldecode", 2),
        ("url decode", 1),
        ("urldecode", 1),
        ("decodeuri", 1),
        ("decodeuricomponent", 1),
    ])

    normalization = {
        "url_decode_passes": url_decode_passes,
        "html_entity_decode": _bool_score(lower, "html entity decode", "htmlentitydecode", "html.unescape", "decode_entities"),
        "unicode_escape_decode": _bool_score(lower, "\\u00", "unicode escape", "decodeunicodeescape"),
        "case_fold": "lower" if _bool_score(lower, ".lower()", "tolower(", "nocase", "transform:lowercase", "t:lowercase") else "none",
        "whitespace_collapse": _bool_score(lower, r"\\s+", "collapse whitespace", "trimspace", "stripspace"),
        "comment_stripping": _bool_score(lower, "strip comments", "remove comments", "html comments"),
    }

    matching = {
        "rule_style": (
            "signature_rules"
            if _bool_score(lower, "secrule", "mainrule", "rx ", "@rx", "operator:rx")
            else "custom_logic"
        ),
        "case_sensitive": not _bool_score(lower, "nocase", "re.ignorecase", "ignorecase", "tolower("),
        "token_based": _bool_score(lower, "token", "lexer", "parser", "libinjection"),
        "attribute_aware": _bool_score(lower, "onerror", "onclick", "href", "src=", "srcdoc", "formaction"),
        "javascript_scheme_focus": _bool_score(lower, "javascript:", "js scheme", "href", "formaction"),
        "event_handler_focus": _bool_score(lower, "onerror", "onload", "onclick", "onfocus", "event handler"),
    }

    likely_pressure_points: list[str] = []
    if matching["javascript_scheme_focus"]:
        likely_pressure_points.append("plain_javascript_uri")
    if matching["event_handler_focus"]:
        likely_pressure_points.append("raw_event_handler_literals")
    if _bool_score(lower, "<script", "</script>", "script tag"):
        likely_pressure_points.append("script_tag_literals")
    if normalization["case_fold"] == "lower":
        likely_pressure_points.append("mixed_case_markup")

    likely_blind_spots: list[str] = []
    if matching["javascript_scheme_focus"] and not normalization["html_entity_decode"]:
        likely_blind_spots.append("entity_encoded_scheme")
    if matching["javascript_scheme_focus"] and not normalization["whitespace_collapse"]:
        likely_blind_spots.append("whitespace_broken_scheme")
    if matching["event_handler_focus"] and not matching["token_based"]:
        likely_blind_spots.append("same_tag_attribute_pivot")
    if normalization["case_fold"] == "none":
        likely_blind_spots.append("mixed_case_tag_event")
    if url_decode_passes <= 1:
        likely_blind_spots.append("double_encoded_delivery")

    preferred_strategies: list[str] = []
    if "entity_encoded_scheme" in likely_blind_spots:
        preferred_strategies.append("entity_encoding")
    if "whitespace_broken_scheme" in likely_blind_spots:
        preferred_strategies.append("scheme_fragmentation")
    if "same_tag_attribute_pivot" in likely_blind_spots:
        preferred_strategies.append("quote_closure")
        preferred_strategies.append("same_tag_attribute_injection")
    if "mixed_case_tag_event" in likely_blind_spots:
        preferred_strategies.append("mixed_case_markup")
    if "double_encoded_delivery" in likely_blind_spots:
        preferred_strategies.append("double_url_encoding")

    avoid_strategies: list[str] = []
    if "plain_javascript_uri" in likely_pressure_points:
        avoid_strategies.append("plain_javascript_uri")
    if "raw_event_handler_literals" in likely_pressure_points:
        avoid_strategies.append("raw_event_handler_literals")
    if "script_tag_literals" in likely_pressure_points:
        avoid_strategies.append("plain_script_tag")

    notes: list[str] = []
    notes.append(f"Analyzed {file_count} source file(s) from {root.name}.")
    if engine_name != "unknown_filter_stack":
        notes.append(f"Detected likely engine family: {engine_name}.")
    if url_decode_passes:
        notes.append(f"Likely URL decode passes: {url_decode_passes}.")
    if normalization["case_fold"] == "lower":
        notes.append("Case folding appears to happen before matching.")
    if matching["token_based"]:
        notes.append("Matching appears to include parser/token-aware logic, not only regex signatures.")

    return WafKnowledgeProfile(
        source_type=source_type,
        source_ref=str(root),
        engine_name=engine_name,
        confidence=round(confidence, 2),
        normalization=normalization,
        matching=matching,
        likely_pressure_points=likely_pressure_points[:5],
        likely_blind_spots=likely_blind_spots[:5],
        preferred_strategies=preferred_strategies[:5],
        avoid_strategies=avoid_strategies[:5],
        notes=notes[:5],
    )


def attach_waf_knowledge(
    context: ParsedContext | None,
    profile: WafKnowledgeProfile | dict[str, Any] | None,
) -> ParsedContext | None:
    if context is None or profile is None:
        return context
    payload = profile.to_dict() if hasattr(profile, "to_dict") else dict(profile)
    return replace(context, waf_knowledge=payload)
