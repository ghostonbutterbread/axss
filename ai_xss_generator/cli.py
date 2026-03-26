from __future__ import annotations

import argparse
import math
import sys
import warnings
from pathlib import Path
from typing import Callable

from ai_xss_generator import __version__
from ai_xss_generator.config import (
    APP_NAME,
    CONFIG_PATH,
    DEFAULT_MODEL,
    load_config,
    resolve_ai_config,
)
from ai_xss_generator.console import header, info, step, success, warn, waf_label
from ai_xss_generator.findings import (
    export_yaml,
    import_yaml,
    load_findings,
    memory_stats,
)
from ai_xss_generator.models import check_api_keys, generate_payloads, list_ollama_models, search_ollama_models
from ai_xss_generator.output import render_batch_json, render_heat, render_json, render_list, render_summary
from ai_xss_generator.parser import BatchParseError, parse_target, parse_targets, read_url_list
from ai_xss_generator.plugin_system import PluginRegistry
from ai_xss_generator.public_payloads import FetchResult, fetch_public_payloads, select_reference_payloads
from ai_xss_generator.types import GenerationResult, ParsedContext
from ai_xss_generator.waf_detect import SUPPORTED_WAFS, detect_waf


class _HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    def _get_help_string(self, action: argparse.Action) -> str:
        help_text = action.help or ""
        if "%(default)" in help_text:
            return help_text
        default = action.default
        if default in (None, False, argparse.SUPPRESS):
            return help_text
        return super()._get_help_string(action)


_TRACE_HANDLER_NAME = "axss-trace-handler"


def _remove_trace_handlers(logger: object) -> None:
    import logging as _logging

    if not isinstance(logger, _logging.Logger):
        return
    for handler in list(logger.handlers):
        if handler.get_name() == _TRACE_HANDLER_NAME:
            logger.removeHandler(handler)
            handler.close()


def _configure_logging(verbose_level: int) -> None:
    import logging as _logging

    app_loggers = (
        _logging.getLogger("ai_xss_generator"),
        _logging.getLogger("xssy"),
    )
    noisy_loggers = (
        "scrapling",
        "urllib3",
        "playwright",
        "asyncio",
    )

    for logger in app_loggers:
        _remove_trace_handlers(logger)
        logger.propagate = True
        logger.setLevel(_logging.NOTSET)

    if verbose_level >= 2:
        for logger in app_loggers:
            handler = _logging.StreamHandler()
            handler.set_name(_TRACE_HANDLER_NAME)
            handler.setFormatter(_logging.Formatter("[%(name)s] %(message)s"))
            logger.addHandler(handler)
            logger.setLevel(_logging.DEBUG)
            logger.propagate = False

    for name in noisy_loggers:
        _logging.getLogger(name).setLevel(_logging.WARNING)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


# ---------------------------------------------------------------------------
# Subcommand builder helpers
# ---------------------------------------------------------------------------

def _add_shared_args(p: argparse.ArgumentParser, config_default_model: str) -> None:
    """Flags available on both 'generate' and 'scan' subcommands."""
    # ── AI / model ────────────────────────────────────────────────────────
    p.add_argument(
        "-m", "--model",
        default=None,
        help=(
            f"Override the AI model. Default comes from {CONFIG_PATH} "
            f"or falls back to {DEFAULT_MODEL}."
        ),
    )
    p.add_argument(
        "--no-cloud",
        action="store_true",
        help="Never escalate to a cloud LLM. Guarantees offline-only operation.",
    )
    p.add_argument(
        "--backend",
        metavar="BACKEND",
        choices=("api", "cli"),
        default=None,
        help=(
            "AI backend for cloud escalation: 'api' (OpenRouter/OpenAI keys) or "
            "'cli' (Claude/Codex subprocess — uses subscription auth, no per-token billing)."
        ),
    )
    p.add_argument(
        "--cli-tool",
        metavar="TOOL",
        choices=("claude", "codex"),
        default=None,
        help="CLI tool when --backend cli is set (default: claude).",
    )
    p.add_argument(
        "--cli-model",
        metavar="MODEL",
        default=None,
        help="Model passed to the CLI tool. Omit to use the tool's default.",
    )
    # ── Auth ─────────────────────────────────────────────────────────────
    p.add_argument(
        "--header",
        metavar="'Name: Value'",
        dest="headers",
        action="append",
        default=[],
        help=(
            "Add a custom request header (repeatable). "
            "e.g. --header 'Authorization: Bearer TOKEN' --header 'X-API-Key: secret'"
        ),
    )
    p.add_argument(
        "--cookies",
        metavar="FILE",
        help="Load session cookies from a Netscape-format cookies.txt file.",
    )
    p.add_argument(
        "--profile",
        metavar="PROGRAM/NAME",
        help="Use a saved auth profile. Explicit --header/--cookies values override on conflicts.",
    )
    # ── WAF ──────────────────────────────────────────────────────────────
    p.add_argument(
        "--waf",
        metavar="NAME",
        choices=SUPPORTED_WAFS,
        help=(
            f"Target WAF ({', '.join(SUPPORTED_WAFS)}). "
            "Auto-detected when not set; use to override."
        ),
    )
    p.add_argument(
        "--waf-source",
        metavar="PATH",
        help=(
            "Analyze a WAF/filter codebase and add a knowledge profile to model reasoning. "
            "Accepts a local directory/file path or a Git repository URL."
        ),
    )
    # ── Output ───────────────────────────────────────────────────────────
    p.add_argument(
        "--display",
        choices=["list", "heat", "interactive"],
        default="list",
        help="Terminal display style (default: list).",
    )
    p.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Output file format when saving with -o (default: json).",
    )
    p.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Save results to a file. e.g. -o result.json",
    )
    p.add_argument(
        "--sarif",
        metavar="PATH",
        help=(
            "Write a SARIF 2.1.0 report. "
            "Compatible with GitHub Advanced Security, DefectDojo, and most security pipelines."
        ),
    )
    p.add_argument(
        "-t", "--top",
        metavar="N",
        type=int,
        default=20,
        help="Limit ranked payloads in output (default: 20).",
    )
    p.add_argument(
        "--threshold",
        metavar="N",
        type=int,
        default=60,
        help=(
            "Minimum risk_score to include in output (default: 60). "
            "Always shows at least 5 payloads even if all are below threshold."
        ),
    )
    # ── Probe ────────────────────────────────────────────────────────────
    p.add_argument(
        "--no-probe",
        action="store_true",
        help=(
            "Skip active parameter probing. By default, axss sends probe requests "
            "per query parameter to confirm reflection contexts and char survival."
        ),
    )
    p.add_argument(
        "--no-live",
        action="store_true",
        help="Run probing silently. Probe results still enrich payload generation.",
    )
    # ── Misc ─────────────────────────────────────────────────────────────
    p.add_argument(
        "--fresh",
        action="store_true",
        default=False,
        help="Ignore cached sitemap/probe results and re-collect from scratch.",
    )
    p.add_argument(
        "-r", "--rate",
        metavar="N",
        type=float,
        default=25.0,
        help=(
            "Max requests per second (default: 25). "
            "Use 0 for uncapped. e.g. -r 5 for 5 req/sec."
        ),
    )
    p.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="-v for verbose output; -vv for full debug trace.",
    )


def _build_memory_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    mem = subparsers.add_parser(
        "memory",
        help="Manage the curated XSS knowledge base.",
        description="View, import, and export the curated findings knowledge base.",
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    mem.add_argument("-h", "--help", action="help", help="Show this help message and exit.")
    actions = mem.add_subparsers(dest="memory_action", metavar="ACTION")
    actions.add_parser("show",  help="List all knowledge base entries.")
    actions.add_parser("stats", help="Show entry counts by category.")
    imp = actions.add_parser("import", help="Import curated findings from a YAML file.")
    imp.add_argument("path", metavar="PATH", help="YAML file to import.")
    exp = actions.add_parser("export", help="Export the knowledge base to a YAML file.")
    exp.add_argument("path", metavar="PATH", help="Destination YAML file.")
    return mem


def _build_models_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    mod = subparsers.add_parser(
        "models",
        help="Manage and inspect AI models.",
        description="List available models, search Ollama, and validate API keys.",
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    mod.add_argument("-h", "--help", action="help", help="Show this help message and exit.")
    mod.add_argument(
        "--test-triage",
        action="store_true",
        default=False,
        help=(
            "Fire a synthetic example through the local model triage prompt and "
            "print the raw response and parsed result. "
            "Use to verify your local model handles the triage input correctly."
        ),
    )
    actions = mod.add_subparsers(dest="models_action", metavar="ACTION")
    actions.add_parser("list",       help="Show locally available Ollama models.")
    search = actions.add_parser("search", help="Search Ollama model names.")
    search.add_argument("query", metavar="QUERY", help="Search term.")
    actions.add_parser("check-keys", help="Validate all configured API keys.")
    return mod


def _build_generate_parser(
    subparsers: argparse._SubParsersAction,
    common: argparse.ArgumentParser,
    config_default_model: str,
) -> argparse.ArgumentParser:
    gen = subparsers.add_parser(
        "generate",
        parents=[common],
        help="Generate AI-ranked XSS payloads for a target.",
        description=(
            "Parse a target and produce a ranked list of XSS payloads. "
            "Use 'axss scan' to actively inject and confirm them in a browser."
        ),
        epilog=(
            "Examples:\n"
            "  axss generate -u https://example.com\n"
            "  axss generate -u https://example.com --public --waf cloudflare\n"
            "  axss generate -u urls.txt --merge-batch -o payloads.json\n"
            "  axss generate -i page.html --display heat\n"
            "  axss generate --public --waf modsecurity         (no target — dump public payloads)\n"
            f"  axss generate -u https://example.com -m {config_default_model} -t 15"
        ),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    gen.add_argument("-h", "--help", action="help", help="Show this help message and exit.")

    target = gen.add_mutually_exclusive_group()
    target.add_argument(
        "-u", "--urls",
        metavar="TARGET",
        dest="urls",
        help=(
            "Target URL, comma-separated list of URLs, or path to a file of URLs (one per line). "
            "e.g. -u https://example.com  or  -u targets.txt  or  -u https://a.com,https://b.com"
        ),
    )
    target.add_argument(
        "-i", "--input",
        metavar="FILE_OR_SNIPPET",
        help="Parse a local HTML file or raw HTML snippet.",
    )
    gen.add_argument(
        "--public",
        action="store_true",
        help=(
            "Fetch known XSS payloads from public/community sources and inject them as "
            "reference context. Can be used standalone (no target) to dump a payload list."
        ),
    )
    gen.add_argument(
        "--merge-batch",
        action="store_true",
        help="Combine all URLs from --urls into one payload set.",
    )
    return gen


def _build_scan_parser(
    subparsers: argparse._SubParsersAction,
    common: argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    scan = subparsers.add_parser(
        "scan",
        parents=[common],
        help="Actively scan a target and confirm XSS execution.",
        description=(
            "Crawl a target, inject payloads into a real browser, and confirm XSS execution. "
            "Defaults to testing all XSS types: reflected, stored, DOM, and uploads."
        ),
        epilog=(
            "Examples:\n"
            "  axss scan -u https://example.com\n"
            "  axss scan -u https://example.com --deep\n"
            "  axss scan -u urls.txt --reflected --stored\n"
            "  axss scan -u https://a.com,https://b.com\n"
            "  axss scan --interesting targets.txt\n"
            "  axss scan -u https://example.com --dry-run\n"
            "  axss scan -u https://example.com --scope h1:myprogram\n"
            "  axss scan -u https://example.com --blind-callback https://oast.pro/abc123"
        ),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    scan.add_argument("-h", "--help", action="help", help="Show this help message and exit.")

    target = scan.add_mutually_exclusive_group()
    target.add_argument(
        "-u", "--urls",
        metavar="TARGET",
        dest="urls",
        help=(
            "Target URL, comma-separated list of URLs, or path to a file of URLs (one per line). "
            "A single URL triggers crawl; multiple URLs skip crawl (use --crawl to override). "
            "e.g. -u https://example.com  or  -u targets.txt  or  -u https://a.com,https://b.com"
        ),
    )
    scan.add_argument(
        "--interesting",
        nargs="?",
        const=True,
        metavar="FILE|URL",
        help=(
            "Rank URLs by XSS potential using the AI backend and write a markdown triage report. "
            "Pass a file of URLs (one per line) or a single URL directly. "
            "Combine with --urls to rank that URL list without repeating the filename."
        ),
    )

    # ── Scan mode ─────────────────────────────────────────────────────────
    scan.add_argument(
        "--fast",
        action="store_true",
        default=False,
        help=(
            "Reflected XSS only. HTTP pre-filter fires payloads via curl_cffi; "
            "Playwright only opens when reflection is confirmed. Fastest mode, "
            "ideal for large URL lists (e.g. GAU output)."
        ),
    )
    scan.add_argument(
        "--deep",
        action="store_true",
        default=False,
        help=(
            "Full probe + AI-targeted payload generation per param. "
            "Best for 1–2 focused targets. Slowest mode."
        ),
    )
    scan.add_argument(
        "--obliterate",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,   # hidden deprecated alias for normal mode
    )

    # ── XSS type selectors ────────────────────────────────────────────────
    scan.add_argument("--reflected", action="store_true", help="Test for reflected XSS (GET params).")
    scan.add_argument("--stored",    action="store_true", help="Test for stored/POST XSS (form fields).")
    scan.add_argument("--uploads",   action="store_true", help="Test file-upload and artifact workflows.")
    scan.add_argument("--dom",       action="store_true", help="Test for DOM-based XSS (source→sink analysis + runtime hooking).")

    # ── Crawl control ─────────────────────────────────────────────────────
    scan.add_argument(
        "--depth",
        metavar="N",
        type=int,
        default=2,
        help="BFS crawl depth (default: 2). depth=1 follows links from the seed only.",
    )
    scan.add_argument(
        "--no-crawl",
        action="store_true",
        default=False,
        help="Skip crawling and test only the provided URL directly.",
    )
    scan.add_argument(
        "--crawl",
        action="store_true",
        default=False,
        help=(
            "Force crawl even when multiple URLs are provided. "
            "Crawls from each URL in the list and merges discovered endpoints."
        ),
    )
    scan.add_argument(
        "--scope",
        nargs="?",
        const="auto",
        default=None,
        metavar="SPEC",
        help=(
            "Control crawl scope. Without SPEC, auto-derives from seed URL. SPEC options:\n"
            "  h1:HANDLE / hackerone:HANDLE   — HackerOne scope (needs H1_API_USERNAME + H1_API_TOKEN)\n"
            "  bc:SLUG / bugcrowd:SLUG        — Bugcrowd scope (needs BUGCROWD_API_KEY)\n"
            "  ig:HANDLE / intigriti:HANDLE   — Intigriti scope (needs INTIGRITI_API_TOKEN)\n"
            "  https://...                    — LLM-parse a scope page\n"
            "  domain.com,*.other.com         — manual comma-separated domain list"
        ),
    )

    # ── Pre-flight ────────────────────────────────────────────────────────
    scan.add_argument(
        "--live",
        action="store_true",
        default=False,
        help=(
            "Force pre-flight liveness check even for --urls lists. "
            "By default, liveness checking is skipped for --urls (large pre-enumerated lists) "
            "and runs automatically for -u (crawler-discovered URLs)."
        ),
    )

    # ── Active scan tuning ────────────────────────────────────────────────
    scan.add_argument(
        "--workers",
        metavar="N",
        type=int,
        default=1,
        help="Maximum parallel scan workers (default: 1). Also auto-scales with --rate.",
    )
    scan.add_argument(
        "--timeout",
        metavar="N",
        type=int,
        default=300,
        help="Per-URL timeout in seconds (default: 300).",
    )
    scan.add_argument(
        "--attempts",
        metavar="N",
        type=int,
        default=1,
        help=(
            "Cloud reasoning rounds per injection context (default: 1). "
            "Each round tests returned payloads and feeds execution outcome into the next prompt."
        ),
    )
    scan.add_argument(
        "--keep-searching",
        action="store_true",
        default=False,
        help="After the first confirmed hit, keep searching for additional exploit classes.",
    )
    scan.add_argument(
        "--deep-model",
        metavar="MODEL",
        default=None,
        help="Override the reasoning model used in --deep mode. e.g. openai/o3-mini",
    )
    scan.add_argument(
        "--deep-limit",
        metavar="N",
        type=int,
        default=None,
        help="Cap deep reasoning to the top N injection points. 0 = unlimited.",
    )

    # ── Stored XSS / blind ────────────────────────────────────────────────
    scan.add_argument(
        "--sink-url",
        metavar="URL",
        default=None,
        help="After each injection, navigate to URL to check for stored XSS execution.",
    )
    scan.add_argument(
        "--blind-callback",
        metavar="URL",
        default=None,
        help=(
            "Enable blind XSS detection. Injects OOB payloads that call back to URL when "
            "executed. URL must be a server you control (Interactsh, Burp Collaborator, "
            "xsshunter, webhook.site). Saves a blind_tokens.json manifest."
        ),
    )
    scan.add_argument(
        "--poll-blind",
        metavar="FILE",
        default=None,
        help="Poll a previously saved blind_tokens.json for callbacks that have fired.",
    )

    # ── Session / lifecycle ───────────────────────────────────────────────
    scan.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Discover attack surface without firing payloads. Prints endpoints then exits.",
    )
    scan.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume a previous interrupted scan for the same target.",
    )
    scan.add_argument(
        "--session-check-url",
        metavar="URL",
        default=None,
        help="Probe URL before scanning to verify the session is still valid.",
    )

    # ── Debug / triage ────────────────────────────────────────────────────
    scan.add_argument(
        "--skip-triage",
        action="store_true",
        default=False,
        help=(
            "Deep mode only: bypass the local model triage gate and escalate directly "
            "to cloud mutation after Tier 1 + Tier 1.5 miss. "
            "Use when the local model is unavailable or producing unreliable decisions."
        ),
    )

    # ── Suppressed legacy flags ───────────────────────────────────────────
    scan.add_argument("--extreme", action="store_true", default=False, help=argparse.SUPPRESS)
    scan.add_argument("--research", "--patient", dest="research", action="store_true", default=False, help=argparse.SUPPRESS)
    scan.add_argument("--browser-crawl", action="store_true", default=False, help=argparse.SUPPRESS)
    scan.add_argument("-a", "--active", action="store_true", default=False, help=argparse.SUPPRESS)

    return scan


# Defaults injected into args when a flag belongs to a different subcommand.
_ARG_DEFAULTS: dict[str, object] = {
    "generate": False,
    "url": None,
    "urls": None,
    "input": None,
    "interesting": None,
    "public": False,
    "merge_batch": False,
    "reflected": False,
    "stored": False,
    "dom": False,
    "uploads": False,
    "active": False,
    "fast": False,
    "deep": False,
    "obliterate": False,
    "deep_model": None,
    "deep_limit": None,
    "dry_run": False,
    "resume": False,
    "crawl": False,
    "no_crawl": False,
    "scope": None,
    "depth": 2,
    "workers": 1,
    "timeout": 300,
    "attempts": 1,
    "keep_searching": False,
    "sink_url": None,
    "blind_callback": None,
    "poll_blind": None,
    "session_check_url": None,
    "extreme": False,
    "research": False,
    "browser_crawl": False,
    "no_probe": False,
    "no_live": False,
    "threshold": 60,
    "waf": None,
    "waf_source": None,
    "fresh": False,
    "display": "list",
    "format": "json",
    "output": None,
    "sarif": None,
    "top": 20,
    "model": None,
    "no_cloud": False,
    "backend": None,
    "cli_tool": None,
    "cli_model": None,
    "headers": [],
    "cookies": None,
    "profile": None,
    "rate": 25.0,
    "verbose": 0,
    "skip_triage": False,
    # Legacy utility flags (always False/None after subcommand dispatch)
    "list_models": False,
    "search_models": None,
    "check_keys": False,
    "clear_reports": False,
    "memory_list": False,
    "memory_stats": False,
    "memory_export": None,
    "memory_import": None,
}


def _normalize_args(args: argparse.Namespace) -> None:
    """Fill in defaults for attributes not defined by the active subcommand."""
    for key, default in _ARG_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, default)


def build_parser(config_default_model: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(
            "AI-assisted XSS scanner.\n"
            "Run 'axss COMMAND --help' for detailed usage of each command."
        ),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit.")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--clear-reports",
        action="store_true",
        help="Delete all saved scan reports from ~/.axss/reports/.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
        title="commands",
        description="",
    )

    _common = argparse.ArgumentParser(add_help=False)
    _add_shared_args(_common, config_default_model)

    _build_memory_parser(subparsers)
    _build_generate_parser(subparsers, _common, config_default_model)
    _build_scan_parser(subparsers, _common)
    _build_models_parser(subparsers)

    return parser


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _render_table(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "No results."
    headers = list(rows[0].keys())
    widths = {
        header: max(len(header), *(len(str(row.get(header, ""))) for row in rows))
        for header in headers
    }
    header_line = "  ".join(f"{header:<{widths[header]}}" for header in headers)
    separator = "  ".join("-" * widths[header] for header in headers)
    body = [
        "  ".join(f"{str(row.get(header, '')):<{widths[header]}}" for header in headers)
        for row in rows
    ]
    return "\n".join([header_line, separator, *body])


def _render_finding(f: object) -> str:
    from ai_xss_generator.findings import finding_id
    fid = finding_id(f)  # type: ignore[arg-type]
    lines = [
        f"{'id':>14}: {fid}",
        f"{'context':>14}: {getattr(f, 'context_type', '') or '-'}",
        f"{'sink':>14}: {getattr(f, 'sink_type', '') or '-'}",
        f"{'bypass_family':>14}: {getattr(f, 'bypass_family', '') or '-'}",
        f"{'waf':>14}: {getattr(f, 'waf_name', '') or '-'}",
        f"{'delivery':>14}: {getattr(f, 'delivery_mode', '') or '-'}",
        f"{'frameworks':>14}: {','.join(getattr(f, 'frameworks', [])) or '-'}",
        f"{'confidence':>14}: {getattr(f, 'confidence', 1.0):.2f}",
        f"{'source':>14}: {getattr(f, 'source', '') or '-'}",
        f"{'payload':>14}: {getattr(f, 'payload', '')}",
    ]
    explanation = getattr(f, "explanation", "")
    if explanation:
        lines.append(f"{'explanation':>14}: {explanation}")
    return "\n".join(lines)


def _handle_memory_stats() -> int:
    stats = memory_stats()
    print(_render_table([{
        "store": "curated_findings",
        "total": str(stats["total"]),
    }]))
    return 0


def _handle_memory_list() -> int:
    findings = load_findings()
    if not findings:
        info("No curated findings in the knowledge base.")
        return 0
    rows = []
    for f in findings:
        rows.append({
            "context": f.context_type or "-",
            "bypass_family": f.bypass_family or "-",
            "waf": f.waf_name or "-",
            "delivery": f.delivery_mode or "-",
            "confidence": f"{f.confidence:.2f}",
            "payload": f.payload[:60],
        })
    print(_render_table(rows))
    return 0


def _handle_memory_export(path_str: str) -> int:
    path = Path(path_str)
    count = export_yaml(path)
    success(f"Exported {count} curated findings to {path}.")
    return 0


def _handle_memory_import(path_str: str) -> int:
    path = Path(path_str)
    if not path.exists():
        warn(f"File not found: {path}")
        return 1
    inserted, skipped = import_yaml(path)
    success(f"Imported {inserted} findings ({skipped} skipped as duplicates) from {path}.")
    return 0


def _print_context_banner(result: GenerationResult, waf: str | None = None) -> None:
    context = result.context
    waf_str = f" | waf={waf_label(waf)}" if waf else ""
    print(
        f"Target: {context.source} ({context.source_type}) | "
        f"engine={result.engine} | model={result.model} | fallback={result.used_fallback}"
        f"{waf_str}"
    )
    print(
        f"title={context.title or '-'} | frameworks={','.join(context.frameworks) or '-'} | "
        f"forms={len(context.forms)} | inputs={len(context.inputs)} | "
        f"handlers={len(context.event_handlers)} | sinks={len(context.dom_sinks)}"
    )
    if context.notes:
        print("notes:", " ".join(context.notes))


def _vlog(message: str, *, enabled: bool) -> None:
    """Verbose-only sub-step messages (indented, dimmed)."""
    if enabled:
        info(f"  {message}")


def _apply_threshold(
    payloads: list,
    threshold: int,
    top: int,
) -> list:
    """Return payloads above *threshold*, always keeping at least min(5, len(payloads))."""
    above = [p for p in payloads if p.risk_score >= threshold]
    if not above:
        above = payloads[:5]
    return above[:top]


def _make_live_callback(
    threshold: int,
    output_mode: str,
) -> "Callable":
    """Return an on_result callback for the active prober that streams live output."""
    from ai_xss_generator.probe import ProbeResult, payloads_for_probe_result

    def _on_result(result: ProbeResult) -> None:
        if result.error:
            warn(f"[probe] {result.param_name}: {result.error}")
            return
        if not result.is_reflected:
            info(f"[probe] {result.param_name}: not reflected")
            return

        for ctx in result.reflections:
            chars = "".join(sorted(ctx.surviving_chars)) if ctx.surviving_chars else "?"
            status = "INJECTABLE" if ctx.is_exploitable else "no useful chars"
            msg = f"[probe] {result.param_name!r} → {ctx.short_label} | chars={chars!r} | {status}"
            if ctx.is_exploitable:
                success(msg)
            else:
                info(msg)

        if output_mode == "json":
            return

        live_payloads = payloads_for_probe_result(result)
        to_show = [p for p in live_payloads if p.risk_score >= threshold]
        if to_show:
            print()
            print(render_list(to_show[:5]))
            print()

    return _on_result


def _merge_contexts(contexts: list[ParsedContext], source: str) -> ParsedContext:
    waf_knowledge = next((context.waf_knowledge for context in contexts if context.waf_knowledge), None)
    return ParsedContext(
        source=source,
        source_type="batch",
        title=" | ".join(context.title for context in contexts if context.title)[:200],
        frameworks=list(dict.fromkeys(framework for context in contexts for framework in context.frameworks)),
        forms=[form for context in contexts for form in context.forms],
        inputs=[field for context in contexts for field in context.inputs],
        event_handlers=sorted(
            set(handler for context in contexts for handler in context.event_handlers)
        ),
        dom_sinks=[sink for context in contexts for sink in context.dom_sinks],
        variables=[variable for context in contexts for variable in context.variables],
        objects=sorted(set(obj for context in contexts for obj in context.objects)),
        inline_scripts=[script for context in contexts for script in context.inline_scripts],
        notes=[
            f"Merged {len(contexts)} URL contexts.",
            *list(dict.fromkeys(note for context in contexts for note in context.notes)),
        ],
        waf_knowledge=waf_knowledge,
    )


def _build_result(
    context: ParsedContext,
    *,
    model: str,
    registry: PluginRegistry,
    verbose: bool,
    reference_payloads: list | None = None,
    waf: str | None = None,
    use_cloud: bool = True,
    cloud_model: str = "anthropic/claude-3-5-sonnet",
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    deep: bool = False,
) -> GenerationResult:
    payloads, engine, used_fallback, resolved_model = generate_payloads(
        context=context,
        model=model,
        mutator_plugins=registry.mutators,
        progress=lambda message: _vlog(message, enabled=verbose),
        reference_payloads=reference_payloads,
        waf=waf,
        use_cloud=use_cloud,
        cloud_model=cloud_model,
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model,
        deep=deep,
    )
    return GenerationResult(
        engine=engine,
        model=resolved_model,
        used_fallback=used_fallback,
        context=context,
        payloads=payloads,
    )


def _load_waf_knowledge_profile(waf_source: str | None, verbose: bool) -> dict | None:
    if not waf_source:
        return None
    from ai_xss_generator.waf_knowledge import analyze_waf_source

    step(f"Analyzing WAF source: {waf_source}")
    profile = analyze_waf_source(waf_source)
    success(
        "WAF knowledge loaded: "
        f"{profile.engine_name or 'unknown'}"
        + (f" (confidence {profile.confidence:.2f})" if profile.confidence else "")
    )
    _vlog(f"WAF knowledge notes: {profile.notes}", enabled=verbose)
    return profile.to_dict()


def _attach_waf_knowledge_to_context(context: ParsedContext, waf_knowledge: dict | None) -> ParsedContext:
    if not waf_knowledge:
        return context
    from ai_xss_generator.waf_knowledge import attach_waf_knowledge
    return attach_waf_knowledge(context, waf_knowledge) or context


def _format_ai_role(role: object) -> str:
    backend = getattr(role, "backend", "") or "?"
    tool = getattr(role, "tool", "") or "?"
    model = getattr(role, "model", None)
    fallback_models = tuple(getattr(role, "fallback_models", ()) or ())
    parts = [f"{backend}:{tool}"]
    if model:
        parts.append(f"model={model}")
    if fallback_models:
        parts.append(f"fallbacks={','.join(fallback_models)}")
    return " | ".join(parts)


def _print_single_result(result: GenerationResult, output_mode: str, top: int, waf: str | None = None) -> None:
    _print_context_banner(result, waf=waf)
    if output_mode == "interactive":
        from ai_xss_generator.interactive import run_interactive
        run_interactive(result.payloads[:top], title=result.context.source)
        return
    if output_mode == "json":
        print(render_json(result))
    elif output_mode == "heat":
        print(render_summary(result, limit=min(top, 10)))
        print()
        print(render_heat(result.payloads, limit=top))
    else:
        print(render_list(result.payloads, limit=top, source=result.context.source))


def _print_batch_results(
    results: list[GenerationResult],
    *,
    output_mode: str,
    top: int,
    errors: list[BatchParseError],
    waf: str | None = None,
) -> None:
    if output_mode == "interactive":
        from ai_xss_generator.interactive import run_interactive
        all_payloads = [p for r in results for p in r.payloads][:top]
        run_interactive(all_payloads, title=f"batch ({len(results)} targets)")
        if errors:
            print()
            print("Errors:")
            for error in errors:
                print(f"- {error.url}: {error.error}")
        return
    if output_mode == "json":
        print(render_batch_json(results, errors=[error.to_dict() for error in errors]))
        return

    for index, result in enumerate(results, start=1):
        if index > 1:
            print()
        print(f"[{index}/{len(results)}] {result.context.source}")
        _print_context_banner(result, waf=waf)
        if output_mode == "heat":
            print(render_summary(result, limit=min(top, 10)))
            print()
            print(render_heat(result.payloads, limit=top))
        else:
            print(render_list(result.payloads, limit=top))

    if errors:
        print()
        print("Errors:")
        for error in errors:
            print(f"- {error.url}: {error.error}")


def _try_detect_waf(url: str, verbose: bool) -> str | None:
    """Attempt WAF detection from a live URL's response headers."""
    try:
        import requests as _req
        resp = _req.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; axss-waf-probe)"},
        )
        detected = detect_waf(resp)
        return detected
    except Exception as exc:
        _vlog(f"WAF probe failed: {exc}", enabled=verbose)
        return None


def _print_interesting_results(results: list[object], output_mode: str, top: int) -> None:
    if output_mode == "json":
        import json as _json
        print(_json.dumps([getattr(item, "to_dict")() for item in results[:top]], indent=2))
        return

    rows = []
    for item in results[:top]:
        rows.append({
            "score": str(getattr(item, "score", "")),
            "verdict": getattr(item, "verdict", ""),
            "candidate_params": ",".join(getattr(item, "candidate_params", []) or []) or "-",
            "likely_xss": ",".join(getattr(item, "likely_xss_types", []) or []) or "-",
            "recommended_mode": getattr(item, "recommended_mode", "") or "-",
            "url": getattr(item, "url", ""),
        })
    print(_render_table(rows))
    print()
    for item in results[:top]:
        print(f"- {item.url}")
        print(f"  score={item.score} verdict={item.verdict} engine={item.ai_engine or '-'}")
        print(f"  reason: {item.reason or '-'}")
        if getattr(item, "next_step", ""):
            print(f"  next: {item.next_step}")
        print()


def _handle_public_payloads(
    fetch_result: FetchResult,
    output_mode: str,
    top: int,
    json_out: str | None,
) -> int:
    """Print standalone --public payload dump (no target, no AI call)."""
    payloads = fetch_result.payloads[:top]
    if not payloads:
        warn("No public payloads fetched.")
        return 1

    header(f"\n=== Public XSS Payload Dump ({len(payloads)} shown of {fetch_result.total()}) ===")

    if output_mode == "heat":
        print(render_heat(payloads, limit=top))
    elif output_mode == "json":
        import json as _json
        print(_json.dumps([p.to_dict() for p in payloads], indent=2))
    else:
        print(render_list(payloads, limit=top))

    if json_out:
        import json as _json
        Path(json_out).write_text(
            _json.dumps([p.to_dict() for p in payloads], indent=2),
            encoding="utf-8",
        )
        success(f"JSON written to {json_out}")

    return 0


# ---------------------------------------------------------------------------
# Active scan entry point
# ---------------------------------------------------------------------------

def _run_active_scan(
    args: Any,
    config: Any,
    resolved_waf: str | None,
    resolved_ai_config: Any | None = None,
    auth_headers: dict[str, str] | None = None,
    auth_profile_ref: str = "",
    waf_knowledge: dict | None = None,
    scan_reflected: bool = True,
    scan_stored: bool = True,
    scan_uploads: bool = True,
    scan_dom: bool = True,
) -> int:
    """Route active scans through the orchestrator."""
    from ai_xss_generator.active.orchestrator import ActiveScanConfig, run_active_scan
    from ai_xss_generator.active.reporter import write_report
    from ai_xss_generator.parser import resolve_url_input

    ai_config = resolved_ai_config or resolve_ai_config(config, args=args)

    try:
        urls = resolve_url_input(args.urls)
    except Exception as exc:
        print(f"Error reading URL list: {exc}")
        return 1

    no_crawl = getattr(args, "no_crawl", False)
    force_crawl = getattr(args, "crawl", False)
    if force_crawl and no_crawl:
        print("Error: --crawl and --no-crawl are mutually exclusive")
        return 1
    crawl_enabled = (force_crawl or len(urls) == 1) and not no_crawl

    upload_only_batch_discovery = bool(
        len(urls) > 1
        and scan_uploads
        and not scan_reflected
        and not scan_stored
        and not scan_dom
        and not no_crawl
    )

    # WAF auto-detect from first URL — only when not crawling (the crawl will
    # detect WAF from its seed fetch, saving a redundant round-trip).
    waf = resolved_waf
    # (no_crawl, force_crawl, crawl_enabled already defined above)
    if not waf and urls and (not crawl_enabled and not upload_only_batch_discovery):
        step(f"Probing for WAF on {urls[0]}...")
        detected = _try_detect_waf(urls[0], getattr(args, "verbose", False))
        if detected:
            waf = detected
            success(f"WAF detected: {waf_label(detected)}")
        else:
            info("No WAF fingerprint detected.")

    # ── Scope resolution ──────────────────────────────────────────────────────
    _scan_scope = None
    try:
        from ai_xss_generator.scope import resolve_scope

        _scope_arg = getattr(args, "scope", None)
        # Default: auto-derive from seed URL (same behaviour as before)
        if _scope_arg is None:
            _scope_arg = "auto"

        _source_label = _scope_arg if _scope_arg != "auto" else "seed URL"
        step(f"Resolving scope: {_source_label}")
        _scan_scope = resolve_scope(_scope_arg, urls)

        _src = _scan_scope.source
        _allowed = len(_scan_scope.allowed_patterns)
        _excluded = len(_scan_scope.excluded_patterns)
        if _src == "auto":
            info(f"Auto scope ({len(_scan_scope.allowed_patterns) // 2} domain(s)): "
                 f"{', '.join(p for p in _scan_scope.allowed_patterns if not p.startswith('*'))}")
        elif _src == "page":
            success(
                f"Page scope loaded: {_allowed} in-scope, {_excluded} out-of-scope"
            )
        else:
            success(
                f"{_src.upper()} scope loaded: {_allowed} allowed, {_excluded} excluded"
            )
    except Exception as _scope_err:
        warn(f"Scope resolution failed: {_scope_err} — proceeding without scope enforcement")

    # Crawl to discover testable endpoints — only for single-URL mode.
    # When --urls is given the user already knows what they want to test.
    crawl_depth = getattr(args, "depth", 2)
    use_browser_crawl = getattr(args, "browser_crawl", False)
    post_forms: list = []
    upload_targets: list = []
    crawled_pages: list = []
    if scan_uploads and len(urls) > 1 and not upload_only_batch_discovery:
        info(
            "Upload scanning in batch mode only tests upload forms already discovered "
            "from crawlable entry pages; raw URL lists do not discover upload endpoints on their own."
        )
    if scan_uploads and not crawl_enabled and len(urls) == 1:
        info(
            "Upload scanning with crawl disabled needs a known upload target; the scanner will not "
            "discover multipart forms when crawling is disabled."
        )
    def _crawl_seed(seed_url: str, *, status_label: str | None = None) -> Any:
        from ai_xss_generator.console import (
            clear_status_bar, fmt_duration, set_status_bar,
            spin_char, update_status_bar,
        )
        import time as _time

        crawl_start = _time.monotonic()
        crawl_tick = [0]

        def _crawl_progress(visited: int, targets: int, depth: int) -> None:
            crawl_tick[0] += 1
            elapsed = _time.monotonic() - crawl_start
            sp = spin_char(crawl_tick[0])
            update_status_bar(
                f"\033[2m[~] {sp} Crawling | depth {depth}/{crawl_depth} | "
                f"{visited} pages visited | {targets} target(s) found | "
                f"{fmt_duration(elapsed)} elapsed\033[0m"
            )

        if use_browser_crawl:
            from ai_xss_generator.browser_crawler import browser_crawl
            step(status_label or f"Browser-crawling {seed_url} (depth={crawl_depth}, Playwright)...")
            set_status_bar(
                f"\033[2m[~] ⠋ Browser crawl | depth 0/{crawl_depth} | "
                f"0 pages visited | 0 target(s) found\033[0m"
            )
            try:
                return browser_crawl(
                    seed_url,
                    depth=crawl_depth,
                    auth_headers=auth_headers,
                    on_progress=_crawl_progress,
                )
            finally:
                clear_status_bar()

        from ai_xss_generator.crawler import crawl as crawl_site
        step(status_label or f"Crawling {seed_url} (depth={crawl_depth})...")
        set_status_bar(
            f"\033[2m[~] ⠋ Crawling | depth 0/{crawl_depth} | "
            f"0 pages visited | 0 target(s) found\033[0m"
        )
        try:
            return crawl_site(
                seed_url,
                depth=crawl_depth,
                rate=args.rate,
                waf=waf,
                auth_headers=auth_headers,
                on_progress=_crawl_progress,
                scope=_scan_scope,
            )
        finally:
            clear_status_bar()

    if upload_only_batch_discovery:
        info("Uploads-only batch mode: crawling each seed URL to discover multipart workflows.")
        seen_upload_keys: set[str] = set()
        for idx, seed_url in enumerate(urls, 1):
            crawl_result = _crawl_seed(
                seed_url,
                status_label=f"Crawling upload seed {idx}/{len(urls)}: {seed_url}",
            )
            crawled_pages.extend(crawl_result.visited_urls)
            for target in getattr(crawl_result, "upload_targets", []):
                key = (
                    target.action_url,
                    tuple(sorted(target.file_field_names)),
                    tuple(sorted(target.companion_field_names)),
                )
                if key in seen_upload_keys:
                    continue
                seen_upload_keys.add(key)
                upload_targets.append(target)
            if not waf and crawl_result.detected_waf:
                waf = crawl_result.detected_waf
        if upload_targets:
            success(
                f"Upload discovery complete: {len(upload_targets)} upload form(s) "
                f"across {len(urls)} seed URL(s)"
            )
        else:
            info("Upload discovery found no multipart forms on the provided seed URLs.")
    elif crawl_enabled:
        from ai_xss_generator.cache import get_sitemap, put_sitemap, sitemap_age_minutes, cache_sweep
        cache_sweep()
        _scope_spec = getattr(args, "scope", None) or "auto"
        _fresh = getattr(args, "fresh", False)

        if len(urls) == 1:
            # Single-URL crawl path (existing logic)
            _cached_crawl = None if _fresh else get_sitemap(urls[0], _scope_spec)
            if _cached_crawl is not None:
                crawl_result = _cached_crawl
                _age_min = sitemap_age_minutes(urls[0], _scope_spec) or 0
                step(
                    f"Sitemap cache hit — skipping crawl "
                    f"({len(crawl_result.get_urls)} URL(s), "
                    f"{len(crawl_result.post_forms)} form(s), "
                    f"~{_age_min}m old). Use --fresh to re-crawl."
                )
            else:
                crawl_result = _crawl_seed(urls[0])
                try:
                    put_sitemap(urls[0], _scope_spec, crawl_result)
                except Exception:
                    pass

            post_forms = crawl_result.post_forms
            upload_targets = getattr(crawl_result, "upload_targets", [])
            crawled_pages = crawl_result.visited_urls
            if crawl_result.get_urls:
                msg = f"Crawl complete: {len(crawl_result.get_urls)} GET URL(s) with testable params"
                if post_forms:
                    msg += f" + {len(post_forms)} POST form(s) discovered"
                if upload_targets:
                    msg += f" + {len(upload_targets)} upload form(s) discovered"
                success(msg)
                urls = crawl_result.get_urls
            elif post_forms or upload_targets:
                parts = []
                if post_forms:
                    parts.append(f"{len(post_forms)} POST form(s) discovered")
                if upload_targets:
                    parts.append(f"{len(upload_targets)} upload form(s) discovered")
                success(f"Crawl complete: {' + '.join(parts)} (no GET params)")
            else:
                info("Crawl found no URLs with testable params — testing provided URL directly")
                post_forms = []
                upload_targets = []

            if not waf and crawl_result.detected_waf:
                waf = crawl_result.detected_waf
                success(f"WAF detected: {waf_label(waf)}")

        else:
            # Multi-URL crawl (--crawl flag explicitly set)
            all_get_urls: list[str] = []
            for idx, seed in enumerate(urls, 1):
                crawl_result = _crawl_seed(seed, status_label=f"({idx}/{len(urls)})")
                if crawl_result:
                    post_forms.extend(crawl_result.post_forms)
                    upload_targets.extend(getattr(crawl_result, "upload_targets", []))
                    all_get_urls.extend(crawl_result.get_urls)
                    crawled_pages.extend(crawl_result.visited_urls)
                    if not waf and crawl_result.detected_waf:
                        waf = crawl_result.detected_waf
                        success(f"WAF detected: {waf_label(waf)}")
            if all_get_urls:
                success(
                    f"Crawl complete: {len(all_get_urls)} GET URL(s) across {len(urls)} seed(s)"
                )
                urls = all_get_urls
            else:
                info("Crawl found no URLs with testable params — testing provided URLs directly")

    # ── Dry-run: print attack surface and exit ────────────────────────────────
    if getattr(args, "dry_run", False):
        return _print_dry_run_surface(urls, post_forms, upload_targets)

    sink_url = getattr(args, "sink_url", None)
    if sink_url:
        info(f"Sink URL: {sink_url} (checking this page after each injection)")
    if auth_profile_ref:
        info(f"Active scan auth profile: {auth_profile_ref}")
    if getattr(args, "extreme", False):
        info("Active scan profile: extreme")
    if getattr(args, "research", False):
        info("Active scan profile: research")
    if getattr(args, "keep_searching", False):
        info("Post-confirmation mode: keep searching for distinct variants")
    if getattr(args, "waf_source", None):
        info(f"WAF source knowledge: {args.waf_source}")
        if waf_knowledge:
            info(f"WAF source engine: {waf_knowledge.get('engine_name', 'unknown')}")

    # Session management: detect an existing in-progress/paused session for this
    # exact target + scan type combination; offer to resume or start fresh.
    session = _resolve_session(
        args=args,
        urls=list(urls),
        post_forms=list(post_forms),
        upload_targets=list(upload_targets),
        scan_reflected=scan_reflected,
        scan_stored=scan_stored,
        scan_uploads=scan_uploads,
        scan_dom=scan_dom,
        rate=args.rate,
    )

    # Derive scan mode from flags (obliterate is deprecated alias for normal)
    if getattr(args, "obliterate", False):
        warnings.warn(
            "--obliterate is deprecated and will be removed in a future release. "
            "Normal mode (no flag) now provides the same broad-spectrum coverage.",
            DeprecationWarning, stacklevel=2,
        )
        _mode = "normal"
    elif getattr(args, "deep", False):
        _mode = "deep"
    elif getattr(args, "fast", False):
        _mode = "fast"
    else:
        _mode = "normal"

    info(f"Scan mode: {_mode}")

    scan_config = ActiveScanConfig(
        rate=args.rate,
        workers=getattr(args, "workers", 1),
        model=ai_config.model,
        cloud_model=ai_config.cloud_model,
        use_cloud=ai_config.use_cloud,
        waf=waf,
        timeout_seconds=getattr(args, "timeout", 300),
        output_path=getattr(args, "output", None),
        auth_headers=auth_headers or {},
        sink_url=sink_url,
        scan_reflected=scan_reflected,
        scan_stored=scan_stored,
        scan_uploads=scan_uploads,
        scan_dom=scan_dom,
        ai_backend=ai_config.ai_backend,
        cli_tool=ai_config.cli_tool,
        cli_model=ai_config.cli_model,
        cloud_attempts=getattr(args, "attempts", 1),
        mode=_mode,
        fresh=getattr(args, "fresh", False),
        waf_source=getattr(args, "waf_source", None),
        keep_searching=getattr(args, "keep_searching", False),
        extreme=getattr(args, "extreme", False),
        research=getattr(args, "research", False),
        # multi-URL input = pre-enumerated list: skip liveness by default, --live overrides
        # single-URL input = crawler will discover URLs: always check (list is small and fresh)
        skip_liveness=len(urls) > 1 and not getattr(args, "live", False),
        skip_triage=getattr(args, "skip_triage", False),
    )

    # ── Pre-scan session validity check ──────────────────────────────────────
    _session_check_url = getattr(args, "session_check_url", None)
    if _session_check_url and auth_headers:
        from ai_xss_generator.session_guard import SessionGuard, SessionExpiredWarning
        _guard = SessionGuard(session_check_url=_session_check_url)
        try:
            step(f"Checking session against {_session_check_url}...")
            _guard.pre_scan_check(auth_headers)
            success("Session check passed — credentials appear valid.")
        except SessionExpiredWarning as _session_exc:
            warn(str(_session_exc))
            warn("Continuing anyway — pass --no-session-check to suppress this check.")

    config_summary = (
        f"rate={args.rate:g} req/s | workers={scan_config.workers} | "
        f"model={scan_config.model} | waf={waf or 'none'} | "
        f"cloud_attempts={scan_config.cloud_attempts}"
        + (f" | mode={scan_config.mode}" if scan_config.mode != "fast" else "")
        + (" | profile=extreme" if getattr(args, "extreme", False) else "")
        + (" | profile=research" if getattr(args, "research", False) else "")
        + (" | keep_searching=true" if getattr(args, "keep_searching", False) else "")
        + (f" | waf_source={Path(args.waf_source).name}" if getattr(args, "waf_source", None) else "")
    )
    auth_summary = auth_profile_ref or ("ad hoc headers/cookies" if auth_headers else "none")

    results, live_base = run_active_scan(
        urls, scan_config,
        post_forms=post_forms,
        upload_targets=upload_targets,
        crawled_pages=crawled_pages,
        session=session,
        config_summary=config_summary,
        auth_summary=auth_summary,
    )

    report_path = write_report(
        results,
        config_summary=config_summary,
        auth_summary=auth_summary,
        base_path=live_base,
    )
    success(f"Report written to: {report_path}")
    success(f"HTML report written to: {Path(report_path).with_suffix('.html')}")

    sarif_out = getattr(args, "sarif", None)
    if sarif_out:
        try:
            from ai_xss_generator.sarif import write_sarif
            sarif_path = Path(sarif_out)
            write_sarif(results, sarif_path)
            success(f"SARIF report written to: {sarif_path}")
        except Exception as _sarif_err:
            warn(f"SARIF write failed: {_sarif_err}")

    return 0


def _print_dry_run_surface(
    urls: list[str],
    post_forms: list,
    upload_targets: list,
) -> int:
    """Print discovered attack surface and exit without firing any payloads."""
    import urllib.parse as _up

    info("DRY-RUN mode — no payloads will be fired.\n")

    if urls:
        info(f"GET endpoints ({len(urls)} with testable query parameters):")
        for u in urls:
            parsed = _up.urlparse(u)
            params = list(_up.parse_qs(parsed.query).keys())
            param_str = ", ".join(params) if params else "(no query params)"
            print(f"  {u}  [{param_str}]")
        print()

    if post_forms:
        info(f"POST forms ({len(post_forms)}):")
        for form in post_forms:
            action = getattr(form, "action_url", "") or getattr(form, "action", "") or "-"
            fields = getattr(form, "field_names", None) or getattr(form, "param_names", [])
            field_str = ", ".join(fields) if fields else "(unknown fields)"
            print(f"  {action}  [{field_str}]")
        print()

    if upload_targets:
        info(f"Upload targets ({len(upload_targets)}):")
        for t in upload_targets:
            action = getattr(t, "action_url", "") or "-"
            file_fields = getattr(t, "file_field_names", [])
            print(f"  {action}  [file fields: {', '.join(file_fields) or 'unknown'}]")
        print()

    total = len(urls) + len(post_forms) + len(upload_targets)
    if total == 0:
        warn("No testable attack surface discovered. Try --deep on the seed URL for SPA targets.")
    else:
        success(
            f"Dry-run complete: {len(urls)} GET endpoint(s), "
            f"{len(post_forms)} POST form(s), "
            f"{len(upload_targets)} upload target(s) discovered."
        )
        info("Remove --dry-run to start the active scan.")
    return 0


def _resolve_session(
    args: Any,
    urls: list[str],
    post_forms: list,
    upload_targets: list,
    scan_reflected: bool,
    scan_stored: bool,
    scan_uploads: bool,
    scan_dom: bool,
    rate: float,
) -> Any:
    """Create or resume a scan session.

    Default behaviour (no flags): always create a fresh session so the run is
    checkpointed, but never auto-resume a prior one.

    --resume: look for an existing in-progress/paused session and resume it.
    """
    from ai_xss_generator.session import (
        compute_seed_hash,
        create_session,
        find_existing_session,
    )

    auto_resume = getattr(args, "resume", False)

    seed_hash = compute_seed_hash(
        urls=urls,
        post_forms=post_forms,
        upload_targets=upload_targets,
        scan_reflected=scan_reflected,
        scan_stored=scan_stored,
        scan_uploads=scan_uploads,
        scan_dom=scan_dom,
    )

    # Only look for an existing session when --resume is explicitly passed.
    if auto_resume:
        existing = find_existing_session(seed_hash)
        if existing is not None:
            n_done = len(existing.get("completed", {}))
            n_total = existing.get("total_items", "?")
            status_label = "paused" if existing.get("status") == "paused" else "interrupted"
            prior_confirmed = sum(
                len(e.get("confirmed_findings", []))
                for e in existing.get("completed", {}).values()
                if e.get("status") == "confirmed"
            )
            created = existing.get("created_at", "")[:16].replace("T", " ")
            info(
                f"Resuming {status_label} session from {created} UTC — "
                f"{n_done}/{n_total} item(s) done"
                + (f", {prior_confirmed} finding(s) so far" if prior_confirmed else "")
                + "."
            )
            existing["status"] = "in_progress"
            return existing
        else:
            info("--resume: no prior session found for this target — starting fresh.")

    # Default path: create a new session for this run.
    config_summary = (
        f"target={urls[0] if urls else '?'} | "
        f"rate={rate:g} req/s | "
        f"reflected={scan_reflected} stored={scan_stored} uploads={scan_uploads} dom={scan_dom}"
    )
    total_items = (
        (len(urls) if scan_reflected else 0)
        + (len(post_forms) if scan_stored else 0)
        + (len(upload_targets) if scan_uploads else 0)
        + (len(urls) if scan_dom else 0)
    )
    session = create_session(
        seed_hash=seed_hash,
        config_summary=config_summary,
        total_items=total_items,
    )
    info(f"New session: {seed_hash[:16]}")
    return session


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    if argv and argv[0] == "auth":
        from ai_xss_generator.auth_cli import handle_auth_command
        return handle_auth_command(argv[1:])
    if argv and argv[0] == "ai":
        from ai_xss_generator.ai_capabilities import handle_ai_command
        return handle_ai_command(argv[1:])
    if argv and argv[0] == "setup":
        from ai_xss_generator.config import migrate_config
        msg = migrate_config()
        print(msg)
        return 0

    config = load_config()
    parser = build_parser(config.default_model)
    args = parser.parse_args(argv)

    # ── No subcommand → show help ─────────────────────────────────────────
    if not args.command:
        # Still handle --clear-reports at top level even with no subcommand
        if args.clear_reports:
            from ai_xss_generator.config import CONFIG_DIR
            reports_dir = CONFIG_DIR / "reports"
            if not reports_dir.exists():
                info("No reports directory found — nothing to clear.")
                return 0
            files = sorted(reports_dir.glob("*.md"))
            if not files:
                info("No reports found.")
                return 0
            for f in files:
                f.unlink()
            success(f"Cleared {len(files)} report(s) from {reports_dir}")
            return 0
        parser.print_help()
        return 0

    # ── memory subcommand ─────────────────────────────────────────────────
    if args.command == "memory":
        if not args.memory_action:
            # print memory subparser help
            for action in parser._subparsers._group_actions:
                sub = action.choices.get("memory")
                if sub:
                    sub.print_help()
                    break
            return 0
        if args.memory_action == "show":
            return _handle_memory_list()
        if args.memory_action == "stats":
            return _handle_memory_stats()
        if args.memory_action == "export":
            return _handle_memory_export(args.path)
        if args.memory_action == "import":
            return _handle_memory_import(args.path)
        return 0

    # ── models subcommand ─────────────────────────────────────────────────
    if args.command == "models":
        if getattr(args, "test_triage", False):
            import json as _json
            from ai_xss_generator.models import triage_probe_result

            _triage_input = {
                "context_type": "html_attr_url",
                "surviving_chars": ['"', " ", "javascript:"],
                "waf": None,
                "delivery_mode": "get",
            }
            _triage_model = config.default_model
            print("=== Triage Test ===")
            print("Input:", _json.dumps(_triage_input, indent=2))
            try:
                _triage_result = triage_probe_result(
                    context_type=_triage_input["context_type"],
                    surviving_chars=frozenset(_triage_input["surviving_chars"]),
                    waf=_triage_input["waf"],
                    delivery_mode=_triage_input["delivery_mode"],
                    model=_triage_model,
                )
            except Exception as _triage_exc:
                print(f"Error: {_triage_exc}")
                return 1
            print("Result:", _json.dumps(_triage_result, indent=2))
            _score = _triage_result.get("score")
            if not isinstance(_score, int) or not (1 <= _score <= 10):
                print(f"WARNING: score {_score!r} is outside valid range 1-10 — local model may be misconfigured.")
                return 1
            return 0
        if not args.models_action:
            for action in parser._subparsers._group_actions:
                sub = action.choices.get("models")
                if sub:
                    sub.print_help()
                    break
            return 0
        if args.models_action == "list":
            try:
                rows, source = list_ollama_models()
            except Exception as exc:
                parser.exit(1, f"Error: {exc}\n")
            print(f"Local Ollama models ({source})")
            print(_render_table(rows))
            return 0
        if args.models_action == "search":
            try:
                rows, source = search_ollama_models(args.query)
            except Exception as exc:
                parser.exit(1, f"Error: {exc}\n")
            print(f"Ollama model search for {args.query!r} ({source})")
            print(_render_table(rows))
            return 0
        if args.models_action == "check-keys":
            from ai_xss_generator.config import KEYS_PATH
            print(f"Checking API keys (keys file: {KEYS_PATH})\n")
            results = check_api_keys()
            _STATUS_ICON = {"ok": "[+]", "invalid": "[!]", "missing": "[-]", "error": "[!]", "unreachable": "[!]"}
            col_w = max(len(r["service"]) for r in results)
            src_w = max(len(r["source"]) for r in results)
            for r in results:
                icon = _STATUS_ICON.get(r["status"], "[?]")
                print(f"  {icon}  {r['service']:<{col_w}}  {r['source']:<{src_w}}  {r['detail']}")
            print()
            any_invalid = any(r["status"] in {"invalid", "error"} for r in results)
            return 1 if any_invalid else 0
        return 0

    # ── generate / scan subcommands ───────────────────────────────────────
    # Print subcommand help when invoked with no arguments.
    if args.command in ("scan", "generate"):
        has_any_arg = bool(
            getattr(args, "url", None)
            or getattr(args, "urls", None)
            or getattr(args, "input", None)
            or getattr(args, "interesting", None)
            or getattr(args, "public", False)
        )
        if not has_any_arg:
            for action in parser._subparsers._group_actions:
                sub = action.choices.get(args.command)
                if sub:
                    sub.print_help()
                    break
            return 0

    # Normalize: fill in defaults for attributes defined only on the other subcommand.
    _normalize_args(args)

    # generate command always routes to payload generation mode.
    if args.command == "generate":
        args.generate = True

    # Apply suppressed profile modifiers (--extreme / --research).
    if getattr(args, "extreme", False):
        if args.attempts == 1:
            args.attempts = 3
        if args.timeout == 300:
            args.timeout = 600
    if getattr(args, "research", False):
        if args.attempts <= 3:
            args.attempts = 5
        if args.timeout <= 600:
            args.timeout = 1200
    if args.attempts < 1:
        parser.error("--attempts must be >= 1")

    verbose_level: int = getattr(args, "verbose", 0) or 0

    # Configure console verbosity level (inherited by worker subprocesses via fork)
    from ai_xss_generator.console import set_verbose_level as _set_verbose
    _set_verbose(verbose_level)
    _configure_logging(verbose_level)

    has_target = bool(args.url or args.urls or args.input or (args.interesting is not None))

    # Validate: need at least a target or --public
    if not has_target and not args.public:
        if args.command == "generate":
            parser.error("axss generate requires -u/--url, --urls, -i/--input, or --public")
        else:
            parser.error("axss scan requires -u/--url, --urls, or --interesting")

    # --- Validate rate ---
    if not math.isfinite(args.rate) or args.rate < 0:
        parser.error("--rate must be a finite number >= 0 (use 0 for uncapped)")
    # Only display rate info when we will actually make HTTP requests
    if has_target and (args.url or args.urls):
        rate_label = "uncapped" if args.rate == 0 else f"{args.rate:g} req/sec"
        info(f"Rate limit: {rate_label}")

    # --- Build auth headers from --header / --cookies ---
    auth_headers: dict[str, str] = {}
    auth_profile_ref = ""
    if args.headers or args.cookies or args.profile:
        from ai_xss_generator.auth import describe_auth
        from ai_xss_generator.auth_profiles import (
            merge_scan_auth_headers,
            resolve_scan_profile,
            touch_profile_last_used,
        )

        target_hint = str(args.url or "")
        if not target_hint and args.urls:
            try:
                _targets = read_url_list(args.urls)
                target_hint = _targets[0] if _targets else ""
            except Exception:
                target_hint = ""

        try:
            selected_profile, profile_source = resolve_scan_profile(
                explicit_profile=args.profile,
                target_url=target_hint or None,
            )
            auth_headers = merge_scan_auth_headers(
                profile=selected_profile,
                extra_headers=args.headers or [],
                cookies_path=args.cookies,
            )
        except ValueError as exc:
            parser.error(str(exc))

        if selected_profile is not None and profile_source:
            auth_profile_ref = selected_profile.ref
            touch_profile_last_used(selected_profile.ref)
            info(f"Auth profile: {selected_profile.ref} ({profile_source})")
        if auth_headers:
            _auth_desc = describe_auth(auth_headers)
            info("Auth: " + "; ".join(_auth_desc))

    # --- Resolve WAF (auto-detect or manual) ---
    resolved_waf: str | None = args.waf  # may be None; will be filled by auto-detect below
    _waf_manual = args.waf is not None    # True when user explicitly passed --waf

    # --- Fetch public payloads if requested ---
    fetch_result: FetchResult | None = None
    reference_payloads: list | None = None

    if args.public:
        step("Fetching public XSS payloads...")
        fetch_result = fetch_public_payloads(
            waf=resolved_waf,
            include_social=True,
            progress=lambda msg: _vlog(msg, enabled=args.verbose),
        )
        counts_str = ", ".join(f"{k}={v}" for k, v in fetch_result.counts.items())
        cached_note = f" ({len(fetch_result.cached_keys)} cached)" if fetch_result.cached_keys else ""
        success(f"Loaded {fetch_result.total()} public payloads{cached_note} — {counts_str}")
        if fetch_result.errors:
            for err in fetch_result.errors:
                warn(f"Source error: {err}")
        reference_payloads = select_reference_payloads(fetch_result.payloads, limit=20)

    # --- Standalone --public mode (no target) ---
    if args.public and not has_target:
        if fetch_result is None:
            parser.error("--public fetch produced no result; check network connectivity")
        return _handle_public_payloads(fetch_result, args.display, args.top, args.output)

    # --- Target-based modes below ---
    ai_config = resolve_ai_config(config, args=args)
    selected_model = ai_config.model
    use_cloud = ai_config.use_cloud
    cloud_model = ai_config.cloud_model
    ai_backend = ai_config.ai_backend
    cli_tool = ai_config.cli_tool
    cli_model = ai_config.cli_model
    if use_cloud and ai_backend == "cli":
        from ai_xss_generator.ai_capabilities import choose_generation_tool, reasoning_role_warning

        resolved_tool, tool_note = choose_generation_tool(
            ai_config.xss_generation_model,
            model=cli_model,
            auto_check=True,
        )
        if tool_note:
            warn(tool_note)
        cli_tool = resolved_tool
        reasoning_note = reasoning_role_warning(
            backend="cli",
            tool=ai_config.xss_reasoning_model,
            model=cli_model,
            auto_check=True,
        )
        if reasoning_note:
            warn(reasoning_note)
    elif use_cloud and ai_backend == "api":
        from ai_xss_generator.ai_capabilities import choose_api_generation_model, reasoning_role_warning

        resolved_api_model, model_note = choose_api_generation_model(
            cloud_model,
            fallback_models=ai_config.api_fallback_models,
            auto_check=True,
        )
        if model_note:
            warn(model_note)
        cloud_model = resolved_api_model
        reasoning_note = reasoning_role_warning(
            backend="api",
            model=ai_config.reasoning_role.model or ai_config.cloud_model,
            auto_check=True,
        )
        if reasoning_note:
            warn(reasoning_note)
    from dataclasses import replace as _dc_replace
    ai_config = _dc_replace(
        ai_config,
        cloud_model=cloud_model,
        cli_tool=cli_tool,
        xss_generation_model=cli_tool if ai_backend == "cli" else ai_config.xss_generation_model,
        generation_role=_dc_replace(
            ai_config.generation_role,
            backend=ai_backend,
            tool=cli_tool if ai_backend == "cli" else "api",
            model=cli_model if ai_backend == "cli" else cloud_model,
            fallback_models=ai_config.api_fallback_models if ai_backend == "api" else (),
        ),
    )
    registry = PluginRegistry()
    registry.load_from(Path(__file__).resolve().parent.parent)
    waf_knowledge = _load_waf_knowledge_profile(getattr(args, "waf_source", None), args.verbose)

    # --- Interesting URL triage mode ---
    if args.interesting is not None:
        from ai_xss_generator.interesting import analyze_interesting_urls, write_interesting_report

        # Resolve the URL source: explicit file, inline URL, or fall back to --urls
        if args.interesting is True:
            if not args.urls:
                parser.error(
                    "--interesting without a FILE or URL argument requires --urls FILE"
                )
            source_label = args.urls
            step(f"Reading URL list: {args.urls}")
            try:
                urls = read_url_list(args.urls)
            except Exception as exc:
                parser.error(str(exc))
        elif isinstance(args.interesting, str) and args.interesting.startswith(("http://", "https://")):
            source_label = args.interesting
            urls = [args.interesting]
            step(f"Interesting triage for URL: {args.interesting}")
        else:
            source_label = args.interesting
            step(f"Reading URL list: {args.interesting}")
            try:
                urls = read_url_list(args.interesting)
            except Exception as exc:
                parser.error(str(exc))

        if ai_config.ai_backend == "api":
            warn(
                "Interesting-URL triage is using the API backend. This mode may issue multiple "
                "paid model requests depending on how many URLs are in the file."
            )
        info(f"XSS generation role: {_format_ai_role(ai_config.generation_role)}")
        info(f"XSS reasoning role: {_format_ai_role(ai_config.reasoning_role)}")

        step(f"Ranking {len(urls)} URL(s) for deep XSS follow-up...")
        try:
            interesting_results = analyze_interesting_urls(
                urls,
                ai_config,
                progress=lambda message: _vlog(message, enabled=args.verbose),
            )
        except Exception as exc:
            parser.error(str(exc))

        success(f"Interesting triage complete. {len(interesting_results)} URL(s) scored.")
        print()
        _print_interesting_results(interesting_results, args.display, args.top)

        report_path = write_interesting_report(
            interesting_results,
            source_file=source_label,
            ai_config=ai_config,
        )
        success(f"Report written to: {report_path}")

        if args.output:
            import json as _json

            Path(args.output).write_text(
                _json.dumps([item.to_dict() for item in interesting_results], indent=2),
                encoding="utf-8",
            )
            success(f"JSON written to {args.output}")
        return 0

    # --- Determine effective scan mode ---
    _want_generate  = getattr(args, "generate",  False)
    _want_reflected = getattr(args, "reflected", False)
    _want_stored    = getattr(args, "stored",    False)
    _want_uploads   = getattr(args, "uploads",   False)
    _want_dom       = getattr(args, "dom",       False)
    _want_active    = getattr(args, "active",    False)  # legacy flag

    _any_xss_type = _want_reflected or _want_stored or _want_uploads or _want_dom
    _is_active_mode = _want_active or _any_xss_type

    # --active alone (legacy): enable all types
    if _want_active and not _any_xss_type:
        _want_reflected = True
        _want_stored    = True
        _want_uploads   = True
        _want_dom       = True

    # Default: no explicit flag → active scan all types.
    # --fast is reflected-only by design; don't enable DOM/stored unless explicitly requested.
    # --generate takes explicit precedence; XSS type flags also activate the scanner.
    if not _want_generate and not _is_active_mode:
        _is_active_mode = True
        if getattr(args, "fast", False):
            # Fast mode defaults to reflected-only; user must add --dom/--stored explicitly.
            _want_reflected = True
        else:
            _want_reflected = True
            _want_stored    = True
            _want_uploads   = True
            _want_dom       = True

    # --- Active scan mode ---
    # --generate always wins: if explicitly requested, route to payload generation
    # even when XSS type flags are also present.
    if _is_active_mode and not _want_generate:
        info(f"XSS generation role: {_format_ai_role(ai_config.generation_role)}")
        info(f"XSS reasoning role: {_format_ai_role(ai_config.reasoning_role)}")
        if not (args.url or args.urls):
            parser.error(
                "active scanning requires -u/--url or --urls — "
                "use -i/--input with --generate for local file payload generation"
            )
        return _run_active_scan(
            args, config, resolved_waf,
            resolved_ai_config=ai_config,
            auth_headers=auth_headers,
            auth_profile_ref=auth_profile_ref,
            waf_knowledge=waf_knowledge,
            scan_reflected=_want_reflected,
            scan_stored=_want_stored,
            scan_uploads=_want_uploads,
            scan_dom=_want_dom,
        )

    # --- Payload generation mode (--generate or fallback) ---

    # --- Batch URLs mode ---
    if args.urls:
        step(f"Reading URL list: {args.urls}")
        try:
            urls = read_url_list(args.urls)
        except Exception as exc:
            parser.error(str(exc))

        # WAF auto-detect from first URL if not manually set
        if not resolved_waf and urls:
            step(f"Probing for WAF on {urls[0]}...")
            detected = _try_detect_waf(urls[0], args.verbose)
            if detected:
                resolved_waf = detected
                success(f"WAF detected: {waf_label(detected)}")
            else:
                info("No WAF fingerprint detected.")

        # If WAF was auto-detected (not manually set), add its bypass payloads now
        if args.public and resolved_waf and fetch_result is not None and not _waf_manual:
            from ai_xss_generator.public_payloads import _waf_candidates
            waf_extra = _waf_candidates(resolved_waf)
            if waf_extra:
                fetch_result.add(f"waf_{resolved_waf}", waf_extra)
                reference_payloads = select_reference_payloads(fetch_result.payloads, limit=20)

        step(f"Fetching and parsing {len(urls)} URL(s)...")
        try:
            contexts, errors = parse_targets(urls=urls, parser_plugins=registry.parsers, rate=args.rate, waf=resolved_waf, auth_headers=auth_headers or None)
        except Exception as exc:
            parser.error(str(exc))

        contexts = [_attach_waf_knowledge_to_context(context, waf_knowledge) for context in contexts]

        if not contexts and errors:
            parser.error(errors[0].error)

        step(f"Generating payloads with {selected_model}...")
        info(f"XSS generation role: {_format_ai_role(ai_config.generation_role)}")
        info(f"XSS reasoning role: {_format_ai_role(ai_config.reasoning_role)}")
        results = [
            _build_result(
                context,
                model=selected_model,
                registry=registry,
                verbose=args.verbose,
                reference_payloads=reference_payloads,
                waf=resolved_waf,
                use_cloud=use_cloud,
                cloud_model=cloud_model,
                ai_backend=ai_backend,
                cli_tool=cli_tool,
                cli_model=cli_model,
                deep=getattr(args, "deep", False),
            )
            for context in contexts
        ]

        merged_result: GenerationResult | None = None
        if args.merge_batch and contexts:
            step("Merging batch contexts...")
            merged_context = _merge_contexts(contexts, source=f"batch:{args.urls}")
            merged_result = _build_result(
                merged_context,
                model=selected_model,
                registry=registry,
                verbose=args.verbose,
                reference_payloads=reference_payloads,
                waf=resolved_waf,
                use_cloud=use_cloud,
                cloud_model=cloud_model,
                ai_backend=ai_backend,
                cli_tool=cli_tool,
                cli_model=cli_model,
                deep=getattr(args, "deep", False),
            )

        success(f"Done. {sum(len(r.payloads) for r in results)} total payloads ranked.")
        print()

        if args.merge_batch and merged_result is not None:
            _print_single_result(merged_result, args.display, args.top, waf=resolved_waf)
            if errors:
                print()
                print("Errors:")
                for error in errors:
                    print(f"- {error.url}: {error.error}")
        else:
            _print_batch_results(
                results,
                output_mode=args.display,
                top=args.top,
                errors=errors,
                waf=resolved_waf,
            )

        if args.output:
            json_body = render_batch_json(
                results,
                errors=[error.to_dict() for error in errors],
                merged_result=merged_result,
            )
            Path(args.output).write_text(json_body, encoding="utf-8")
            success(f"JSON written to {args.output}")
        return 0

    # --- Single target mode (-u / -i) ---
    target = args.url or args.input or ""

    # WAF auto-detect for live URL
    if args.url and not resolved_waf:
        step(f"Probing for WAF on {args.url}...")
        detected = _try_detect_waf(args.url, args.verbose)
        if detected:
            resolved_waf = detected
            success(f"WAF detected: {waf_label(detected)}")
        else:
            info("No WAF fingerprint detected — use --waf to set manually.")

    # If WAF was auto-detected (not manually set), add its bypass payloads now
    if args.public and resolved_waf and fetch_result is not None and not _waf_manual:
        from ai_xss_generator.public_payloads import _waf_candidates
        waf_extra = _waf_candidates(resolved_waf)
        if waf_extra:
            fetch_result.add(f"waf_{resolved_waf}", waf_extra)
            reference_payloads = select_reference_payloads(fetch_result.payloads, limit=20)

    step(f"Fetching/parsing target: {target}")
    try:
        context = parse_target(url=args.url, html_value=args.input, parser_plugins=registry.parsers, rate=args.rate, waf=resolved_waf, auth_headers=auth_headers or None)
    except Exception as exc:
        parser.error(str(exc))

    context = _attach_waf_knowledge_to_context(context, waf_knowledge)

    # --- Active probing (default for live URLs with query params) ---
    probe_enabled = args.url and not args.no_probe and "?" in args.url
    if probe_enabled:
        step("Active probing query parameters...")

        live_cb = (
            None
            if args.no_live
            else _make_live_callback(args.threshold, args.display)
        )

        from ai_xss_generator.probe import enrich_context, probe_url

        probe_results = probe_url(args.url, rate=args.rate, waf=resolved_waf, on_result=live_cb, auth_headers=auth_headers or None)
        param_count = len(probe_results)
        injectable = sum(1 for r in probe_results if r.is_injectable)
        reflected = sum(1 for r in probe_results if r.is_reflected)

        if injectable:
            success(
                f"Probing complete: {injectable}/{param_count} parameter(s) injectable, "
                f"{reflected} reflected."
            )
        elif reflected:
            info(f"Probing complete: {reflected}/{param_count} parameter(s) reflected (chars filtered).")
        elif param_count:
            info(f"Probing complete: no reflection found in {param_count} parameter(s).")
        else:
            info("Probing complete: all parameters were tracking/analytics noise — nothing to probe.")

        context = _attach_waf_knowledge_to_context(enrich_context(context, probe_results), waf_knowledge)

    step(f"Generating payloads with {selected_model}...")
    info(f"XSS generation role: {_format_ai_role(ai_config.generation_role)}")
    info(f"XSS reasoning role: {_format_ai_role(ai_config.reasoning_role)}")
    if resolved_waf:
        info(f"WAF context: {waf_label(resolved_waf)}")
    if reference_payloads:
        info(f"Reference payloads: {len(reference_payloads)} examples loaded into prompt.")

    result = _build_result(
        context,
        model=selected_model,
        registry=registry,
        verbose=args.verbose,
        reference_payloads=reference_payloads,
        waf=resolved_waf,
        use_cloud=use_cloud,
        cloud_model=cloud_model,
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model,
        deep=getattr(args, "deep", False),
    )

    # Apply threshold filter to final payloads
    filtered_payloads = _apply_threshold(result.payloads, args.threshold, args.top)
    below_count = len(result.payloads) - len(
        [p for p in result.payloads if p.risk_score >= args.threshold]
    )
    success(
        f"Done. {len(filtered_payloads)} payloads above threshold {args.threshold} "
        f"({below_count} below threshold, {len(result.payloads)} total)."
    )
    if below_count > 0:
        info(f"Use --threshold {max(1, args.threshold - 20)} to see more, or --threshold 1 for all.")
    print()

    from dataclasses import replace as _dc_replace
    result = _dc_replace(result, payloads=filtered_payloads)
    _print_single_result(result, args.display, args.top, waf=resolved_waf)

    if args.output:
        Path(args.output).write_text(render_json(result), encoding="utf-8")
        success(f"JSON written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
