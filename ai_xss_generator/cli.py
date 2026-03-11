from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Callable

from ai_xss_generator import __version__
from ai_xss_generator.config import APP_NAME, CONFIG_PATH, DEFAULT_MODEL, load_config
from ai_xss_generator.console import header, info, step, success, warn, waf_label
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


def build_parser(config_default_model: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(
            "Parse local or live HTML, identify likely XSS execution points, and rank payloads "
            "with Ollama-first generation."
        ),
        epilog=(
            "Common combos:\n"
            "  axss -u https://example.com -t 10 -o list\n"
            "  axss -u https://example.com --public --waf cloudflare -o heat\n"
            "  axss --public --waf modsecurity -o list          (standalone — no target needed)\n"
            "  axss --public -o list                            (all public payloads)\n"
            "  axss --urls urls.txt -t 5 -o list\n"
            "  axss --urls urls.txt --merge-batch -o json -j result.json\n"
            f"  axss -u https://example.com -m {config_default_model} -o list -t 3\n"
            "  axss -v -i sample_target.html -o heat\n"
            "  axss -l\n"
            "  axss -s qwen3.5\n"
            "  axss -u https://example.com -m qwen3.5:4b -j result.json"
        ),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit.")

    # Action group — no longer required=True because --public can be standalone
    action_group = parser.add_mutually_exclusive_group(required=False)
    action_group.add_argument(
        "-u",
        "--url",
        metavar="TARGET",
        help="--url TARGET (fetch live HTML), e.g. -u https://example.com",
    )
    action_group.add_argument(
        "--urls",
        metavar="FILE",
        help="--urls FILE (fetch one URL per line), e.g. --urls urls.txt",
    )
    action_group.add_argument(
        "-i",
        "--input",
        metavar="FILE_OR_SNIPPET",
        help="--input FILE_OR_SNIPPET (parse a local file or raw HTML), e.g. -i sample_target.html",
    )
    action_group.add_argument(
        "-l",
        "--list-models",
        action="store_true",
        help="--list-models (show locally available Ollama models), e.g. -l",
    )
    action_group.add_argument(
        "-s",
        "--search-models",
        metavar="QUERY",
        help="--search-models QUERY (search Ollama model names), e.g. -s qwen3.5",
    )
    action_group.add_argument(
        "--check-keys",
        action="store_true",
        help=(
            "--check-keys  Validate all configured API keys (Ollama, OpenRouter, OpenAI). "
            "Reads from ~/.axss/keys and environment variables, makes a lightweight "
            "probe request to each service, and reports status."
        ),
    )

    # Payload sourcing flags
    parser.add_argument(
        "--public",
        action="store_true",
        help=(
            "--public  Fetch known XSS payloads from public/community sources and inject "
            "them as reference context into the model prompt. Can be used standalone "
            "(no target required) to dump a payload list."
        ),
    )
    parser.add_argument(
        "--waf",
        metavar="NAME",
        choices=SUPPORTED_WAFS,
        help=(
            f"--waf NAME  Target WAF ({', '.join(SUPPORTED_WAFS)}). "
            "Auto-detected from response headers when -u/--urls is used; "
            "use this flag to override or set manually. "
            "Loads WAF-specific bypass payloads and primes the model."
        ),
    )

    parser.add_argument(
        "-m",
        "--model",
        default=None,
        help=(
            "--model MODEL (override the Ollama model), e.g. -m qwen3.5:4b. "
            f"Default comes from {CONFIG_PATH} or falls back to {DEFAULT_MODEL}."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "list", "heat", "interactive"],
        default="list",
        help="--output {json,list,heat,interactive} (choose terminal format), e.g. -o interactive",
    )
    parser.add_argument(
        "-t",
        "--top",
        metavar="N",
        type=int,
        default=20,
        help="--top N (limit ranked payloads), e.g. -t 10",
    )
    parser.add_argument(
        "-j",
        "--json-out",
        metavar="PATH",
        help="--json-out PATH (always write the full JSON result), e.g. -j result.json",
    )
    parser.add_argument(
        "-r",
        "--rate",
        metavar="N",
        type=float,
        default=25.0,
        help=(
            "--rate N  Max requests per second against the target (default: 25). "
            "Use 0 to run uncapped. Lower values help avoid rate-limit bans on strict platforms, "
            "e.g. -r 5 for 5 req/sec, -r 0 for no limit."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="--verbose (print detailed sub-step progress), e.g. -v -i sample_target.html",
    )
    parser.add_argument(
        "--merge-batch",
        action="store_true",
        help="--merge-batch (combine batch contexts into one payload set), e.g. --urls urls.txt --merge-batch",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help=(
            "--no-probe  Skip active parameter probing. By default, axss sends two "
            "probe requests per query parameter to confirm reflection contexts and "
            "which characters survive filtering before generating payloads."
        ),
    )
    parser.add_argument(
        "--no-live",
        action="store_true",
        help=(
            "--no-live  Run probing silently (no live output per parameter). "
            "Probe results still enrich the final payload generation."
        ),
    )
    parser.add_argument(
        "--threshold",
        metavar="N",
        type=int,
        default=60,
        help=(
            "--threshold N  Minimum risk_score to include in final output (default: 60). "
            "Filters out generic payloads that don't match the detected context. "
            "Always shows at least 5 payloads even if all are below threshold."
        ),
    )
    parser.add_argument(
        "--no-cloud",
        action="store_true",
        help=(
            "--no-cloud  Never escalate to a cloud LLM, even if an API key is set "
            "and the local model output is weak. Use this to guarantee offline-only operation."
        ),
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    # ── Authentication ────────────────────────────────────────────────────────
    parser.add_argument(
        "--header",
        metavar="'Name: Value'",
        dest="headers",
        action="append",
        default=[],
        help=(
            "--header 'Name: Value'  Add a custom request header (repeatable). "
            "Use for Authorization tokens, API keys, or any session header. "
            "e.g. --header 'Authorization: Bearer TOKEN' --header 'X-API-Key: secret'"
        ),
    )
    parser.add_argument(
        "--cookies",
        metavar="FILE",
        help=(
            "--cookies FILE  Load session cookies from a Netscape-format cookies.txt file. "
            "Combine with browser export tools (e.g. 'Export Cookies' extension) to scan "
            "authenticated pages. e.g. --cookies cookies.txt"
        ),
    )

    # ── Active scanner ────────────────────────────────────────────────────────
    parser.add_argument(
        "--generate",
        action="store_true",
        help=(
            "--generate  Generate AI-ranked XSS payloads without active browser testing. "
            "Parses the target, identifies XSS surface, and returns a ranked payload list. "
            "Works with -u, --urls, and -i/--input. "
            "Pass this flag when you want payloads only, not active confirmation."
        ),
    )
    parser.add_argument(
        "--reflected",
        action="store_true",
        help=(
            "--reflected  Test for reflected XSS. Injects payloads into GET query "
            "parameters and confirms JS execution in a real Playwright browser. "
            "Implies active scanning. Combine with --stored/--dom to test multiple types."
        ),
    )
    parser.add_argument(
        "--stored",
        action="store_true",
        help=(
            "--stored  Test for stored/POST XSS. Injects payloads into POST form fields "
            "and checks follow-up pages for confirmed execution. "
            "Requires a crawlable target. Implies active scanning."
        ),
    )
    parser.add_argument(
        "--dom",
        action="store_true",
        help=(
            "--dom  Test for DOM-based XSS (coming soon). Will analyze client-side JS "
            "for source→sink flows and inject payloads via URL fragments and DOM sources. "
            "Implies active scanning."
        ),
    )
    parser.add_argument(
        "-a",
        "--active",
        action="store_true",
        help=(
            "--active  Enable active scanning of all XSS types (reflected + stored + DOM). "
            "Equivalent to passing --reflected --stored --dom together. "
            "Fires payloads into a real Playwright browser and detects confirmed execution "
            "(alert() dialogs, console output, network beacons). Requires -u or --urls. "
            "Writes a markdown report to ~/.axss/reports/. "
            "Legacy flag — prefer using --reflected/--stored/--dom directly, "
            "or omit all flags to default to testing all types."
        ),
    )
    parser.add_argument(
        "--workers",
        metavar="N",
        type=int,
        default=1,
        help=(
            "--workers N  Maximum parallel active-scan workers (default: 1). "
            "Each worker is an isolated process scanning one URL at a time. "
            "Workers also auto-scale with --rate (floor(rate/5)), but never exceed N. "
            "Increase only when scanning multiple distinct domains simultaneously."
        ),
    )
    parser.add_argument(
        "--timeout",
        metavar="N",
        type=int,
        default=300,
        help=(
            "--timeout N  Per-URL timeout in seconds for active scan workers (default: 300). "
            "Workers that exceed this are marked inconclusive and terminated cleanly."
        ),
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        default=False,
        help=(
            "--no-crawl  Skip site crawling and only test the provided URL directly. "
            "By default, --active crawls the site first to discover all endpoints "
            "with testable query parameters before scanning."
        ),
    )
    parser.add_argument(
        "--browser-crawl",
        action="store_true",
        default=False,
        help=(
            "--browser-crawl  Use a real Playwright browser for crawling instead of "
            "the default HTTP crawler. Renders JavaScript so Angular/React/Vue "
            "client-side routes are discovered. Also intercepts XHR/fetch requests "
            "to surface API endpoints with injectable query parameters. "
            "Slower than the default crawler but finds far more surface on SPAs."
        ),
    )
    parser.add_argument(
        "--depth",
        metavar="N",
        type=int,
        default=2,
        help=(
            "--depth N  BFS crawl depth when crawling is enabled (default: 2). "
            "depth=1 follows links from the seed page only; depth=2 follows "
            "links from those pages too. Higher values discover more surface "
            "but take longer."
        ),
    )
    parser.add_argument(
        "--sink-url",
        metavar="URL",
        default=None,
        help=(
            "--sink-url URL  After each injection, navigate to URL to check for "
            "XSS execution there. Use when the injected value is stored server-side "
            "and rendered on a different page (e.g. username shown on /profile after "
            "being set via a POST form). Checked before auto-discovered follow-up pages."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help=(
            "--resume  Automatically resume a previous interrupted or paused scan "
            "for the same target without prompting. If no prior session exists, "
            "starts a new scan."
        ),
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        default=False,
        help=(
            "--no-resume  Ignore any existing session and start a fresh scan. "
            "Prior session data is not deleted — use this when you intentionally "
            "want to re-scan from the beginning."
        ),
    )
    parser.add_argument(
        "--backend",
        metavar="BACKEND",
        choices=("api", "cli"),
        default=None,
        help=(
            "--backend api|cli  AI backend for cloud escalation. "
            "'api' uses OpenRouter/OpenAI API keys (default). "
            "'cli' invokes the claude or codex CLI subprocess — uses subscription auth, "
            "no per-token billing. Overrides the config.json value."
        ),
    )
    parser.add_argument(
        "--cli-tool",
        metavar="TOOL",
        choices=("claude", "codex"),
        default=None,
        help=(
            "--cli-tool claude|codex  Which CLI tool to use when --backend cli is set. "
            "Defaults to 'claude'. Requires the tool to be on PATH and logged in."
        ),
    )
    parser.add_argument(
        "--cli-model",
        metavar="MODEL",
        default=None,
        help=(
            "--cli-model MODEL  Model passed to the CLI tool (e.g. claude-opus-4-6). "
            "Omit to use the CLI tool's default model."
        ),
    )

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
    )
    return GenerationResult(
        engine=engine,
        model=resolved_model,
        used_fallback=used_fallback,
        context=context,
        payloads=payloads,
    )


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
    auth_headers: dict[str, str] | None = None,
    scan_reflected: bool = True,
    scan_stored: bool = True,
    scan_dom: bool = True,
) -> int:
    """Route active scans through the orchestrator."""
    from ai_xss_generator.active.orchestrator import ActiveScanConfig, run_active_scan
    from ai_xss_generator.active.reporter import write_report
    from ai_xss_generator.parser import read_url_list

    use_cloud = config.use_cloud and not getattr(args, "no_cloud", False)

    if args.urls:
        try:
            urls = read_url_list(args.urls)
        except Exception as exc:
            print(f"Error reading URL list: {exc}")
            return 1
    else:
        urls = [args.url]

    # WAF auto-detect from first URL — only when not crawling (the crawl will
    # detect WAF from its seed fetch, saving a redundant round-trip).
    waf = resolved_waf
    no_crawl = getattr(args, "no_crawl", False)
    if not waf and urls and (no_crawl or not args.url):
        step(f"Probing for WAF on {urls[0]}...")
        detected = _try_detect_waf(urls[0], getattr(args, "verbose", False))
        if detected:
            waf = detected
            success(f"WAF detected: {waf_label(detected)}")
        else:
            info("No WAF fingerprint detected.")

    # Crawl to discover testable endpoints — only for single-URL mode.
    # When --urls is given the user already knows what they want to test.
    crawl_depth = getattr(args, "depth", 2)
    use_browser_crawl = getattr(args, "browser_crawl", False)
    post_forms: list = []
    crawled_pages: list = []
    if args.url and not no_crawl:
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
            step(f"Browser-crawling {urls[0]} (depth={crawl_depth}, Playwright)...")
            set_status_bar(
                f"\033[2m[~] ⠋ Browser crawl | depth 0/{crawl_depth} | "
                f"0 pages visited | 0 target(s) found\033[0m"
            )
            try:
                crawl_result = browser_crawl(
                    urls[0],
                    depth=crawl_depth,
                    auth_headers=auth_headers,
                    on_progress=_crawl_progress,
                )
            finally:
                clear_status_bar()
        else:
            from ai_xss_generator.crawler import crawl as crawl_site, CrawlResult
            step(f"Crawling {urls[0]} (depth={crawl_depth})...")
            set_status_bar(
                f"\033[2m[~] ⠋ Crawling | depth 0/{crawl_depth} | "
                f"0 pages visited | 0 target(s) found\033[0m"
            )
            try:
                crawl_result = crawl_site(
                    urls[0],
                    depth=crawl_depth,
                    rate=args.rate,
                    waf=waf,
                    auth_headers=auth_headers,
                    on_progress=_crawl_progress,
                )
            finally:
                clear_status_bar()

        post_forms = crawl_result.post_forms
        crawled_pages = crawl_result.visited_urls
        if crawl_result.get_urls:
            msg = f"Crawl complete: {len(crawl_result.get_urls)} GET URL(s) with testable params"
            if post_forms:
                msg += f" + {len(post_forms)} POST form(s) discovered"
            success(msg)
            urls = crawl_result.get_urls
        elif post_forms:
            success(f"Crawl complete: {len(post_forms)} POST form(s) discovered (no GET params)")
            # urls stays as [args.url] — original URL is still needed for report labeling
        else:
            info("Crawl found no URLs with testable params — testing provided URL directly")
            post_forms = []

        # Use WAF detected from crawl seed if auto-detect hasn't found one yet
        if not waf and crawl_result.detected_waf:
            waf = crawl_result.detected_waf
            success(f"WAF detected: {waf_label(waf)}")

    sink_url = getattr(args, "sink_url", None)
    if sink_url:
        info(f"Sink URL: {sink_url} (checking this page after each injection)")

    # Resolve CLI backend settings: CLI flag > config.json > hardcoded default
    ai_backend = getattr(args, "backend", None) or config.ai_backend
    cli_tool = getattr(args, "cli_tool", None) or config.cli_tool
    cli_model = getattr(args, "cli_model", None) or config.cli_model

    # Session management: detect an existing in-progress/paused session for this
    # exact target + scan type combination; offer to resume or start fresh.
    session = _resolve_session(
        args=args,
        urls=list(urls),
        post_forms=list(post_forms),
        scan_reflected=scan_reflected,
        scan_stored=scan_stored,
        scan_dom=scan_dom,
        rate=args.rate,
    )

    scan_config = ActiveScanConfig(
        rate=args.rate,
        workers=getattr(args, "workers", 1),
        model=args.model or config.default_model,
        cloud_model=config.cloud_model,
        use_cloud=use_cloud,
        waf=waf,
        timeout_seconds=getattr(args, "timeout", 300),
        output_path=getattr(args, "json_out", None),
        auth_headers=auth_headers or {},
        sink_url=sink_url,
        scan_reflected=scan_reflected,
        scan_stored=scan_stored,
        scan_dom=scan_dom,
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model,
    )

    results = run_active_scan(
        urls, scan_config,
        post_forms=post_forms,
        crawled_pages=crawled_pages,
        session=session,
    )

    config_summary = (
        f"rate={args.rate:g} req/s | workers={scan_config.workers} | "
        f"model={scan_config.model} | waf={waf or 'none'}"
    )
    report_path = write_report(results, config_summary=config_summary)
    success(f"Report written to: {report_path}")

    return 0


def _resolve_session(
    args: Any,
    urls: list[str],
    post_forms: list,
    scan_reflected: bool,
    scan_stored: bool,
    scan_dom: bool,
    rate: float,
) -> Any:
    """Detect an existing resumable session and return it, or create a new one.

    Returns the session dict (to be passed to run_active_scan) or None when
    --no-resume is set.
    """
    from ai_xss_generator.session import (
        compute_seed_hash,
        create_session,
        find_existing_session,
    )

    no_resume = getattr(args, "no_resume", False)
    auto_resume = getattr(args, "resume", False)

    if no_resume:
        return None

    seed_hash = compute_seed_hash(
        urls=urls,
        post_forms=post_forms,
        scan_reflected=scan_reflected,
        scan_stored=scan_stored,
        scan_dom=scan_dom,
    )

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

        if auto_resume:
            do_resume = True
        else:
            created = existing.get("created_at", "")[:16].replace("T", " ")
            info(
                f"Found a {status_label} session from {created} UTC — "
                f"{n_done}/{n_total} item(s) done"
                + (f", {prior_confirmed} finding(s)" if prior_confirmed else "")
                + "."
            )
            try:
                answer = input("  Resume from checkpoint? [Y/n] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"
                print()
            do_resume = answer in ("", "y", "yes")

        if do_resume:
            existing["status"] = "in_progress"
            info(f"Resuming — skipping {n_done} already-completed item(s).")
            return existing

    # No existing session or user declined — create a fresh one
    config_summary = (
        f"target={urls[0] if urls else '?'} | "
        f"rate={rate:g} req/s | "
        f"reflected={scan_reflected} stored={scan_stored}"
    )
    total_items = (len(urls) if scan_reflected else 0) + (len(post_forms) if scan_stored else 0)
    session = create_session(
        seed_hash=seed_hash,
        config_summary=config_summary,
        total_items=total_items,
    )
    log.debug("New session: %s", seed_hash[:16])
    return session


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    config = load_config()
    parser = build_parser(config.default_model)
    args = parser.parse_args(argv)

    has_target = bool(args.url or args.urls or args.input)
    is_utility = args.list_models or args.search_models or args.check_keys

    # Validate: need at least one of: target, --public, or a utility action
    if not has_target and not args.public and not is_utility:
        parser.error(
            "one of the arguments -u/--url --urls -i/--input -l/--list-models "
            "-s/--search-models --check-keys --public is required"
        )

    # --- Utility: check API keys ---
    if args.check_keys:
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

    # --- Utility: list / search models ---
    if args.list_models:
        try:
            rows, source = list_ollama_models()
        except Exception as exc:
            parser.exit(1, f"Error: {exc}\n")
        print(f"Local Ollama models ({source})")
        print(_render_table(rows))
        return 0

    if args.search_models:
        try:
            rows, source = search_ollama_models(args.search_models)
        except Exception as exc:
            parser.exit(1, f"Error: {exc}\n")
        print(f"Ollama model search for {args.search_models!r} ({source})")
        print(_render_table(rows))
        return 0

    # --- Validate rate ---
    if not math.isfinite(args.rate) or args.rate < 0:
        parser.error("--rate must be a finite number >= 0 (use 0 for uncapped)")
    # Only display rate info when we will actually make HTTP requests
    if has_target and (args.url or args.urls):
        rate_label = "uncapped" if args.rate == 0 else f"{args.rate:g} req/sec"
        info(f"Rate limit: {rate_label}")

    # --- Build auth headers from --header / --cookies ---
    auth_headers: dict[str, str] = {}
    if args.headers or args.cookies:
        from ai_xss_generator.auth import build_auth_headers, describe_auth
        try:
            auth_headers = build_auth_headers(
                headers=args.headers or [],
                cookies_path=args.cookies,
            )
        except ValueError as exc:
            parser.error(str(exc))
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
        return _handle_public_payloads(fetch_result, args.output, args.top, args.json_out)

    # --- Target-based modes below ---
    selected_model = args.model or config.default_model
    use_cloud = config.use_cloud and not getattr(args, "no_cloud", False)
    cloud_model = config.cloud_model
    ai_backend = getattr(args, "backend", None) or config.ai_backend
    cli_tool = getattr(args, "cli_tool", None) or config.cli_tool
    cli_model = getattr(args, "cli_model", None) or config.cli_model
    registry = PluginRegistry()
    registry.load_from(Path(__file__).resolve().parent.parent)

    # --- Determine effective scan mode ---
    _want_generate  = getattr(args, "generate",  False)
    _want_reflected = getattr(args, "reflected", False)
    _want_stored    = getattr(args, "stored",    False)
    _want_dom       = getattr(args, "dom",       False)
    _want_active    = getattr(args, "active",    False)  # legacy flag

    _any_xss_type = _want_reflected or _want_stored or _want_dom
    _is_active_mode = _want_active or _any_xss_type

    # --active alone (legacy): enable all types
    if _want_active and not _any_xss_type:
        _want_reflected = True
        _want_stored    = True
        _want_dom       = True

    # Default: no explicit flag → active scan all types
    # --generate takes explicit precedence; XSS type flags also activate the scanner.
    if not _want_generate and not _is_active_mode:
        _want_reflected = True
        _want_stored    = True
        _want_dom       = True
        _is_active_mode = True

    # --- Active scan mode ---
    # --generate always wins: if explicitly requested, route to payload generation
    # even when XSS type flags are also present.
    if _is_active_mode and not _want_generate:
        if not (args.url or args.urls):
            parser.error(
                "active scanning requires -u/--url or --urls — "
                "use -i/--input with --generate for local file payload generation"
            )
        return _run_active_scan(
            args, config, resolved_waf,
            auth_headers=auth_headers,
            scan_reflected=_want_reflected,
            scan_stored=_want_stored,
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

        if not contexts and errors:
            parser.error(errors[0].error)

        step(f"Generating payloads with {selected_model}...")
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
            )

        success(f"Done. {sum(len(r.payloads) for r in results)} total payloads ranked.")
        print()

        if args.merge_batch and merged_result is not None:
            if args.output == "json":
                rendered = render_batch_json(
                    results,
                    errors=[error.to_dict() for error in errors],
                    merged_result=merged_result,
                )
                print(rendered)
            else:
                _print_single_result(merged_result, args.output, args.top, waf=resolved_waf)
                if errors:
                    print()
                    print("Errors:")
                    for error in errors:
                        print(f"- {error.url}: {error.error}")
        else:
            _print_batch_results(
                results,
                output_mode=args.output,
                top=args.top,
                errors=errors,
                waf=resolved_waf,
            )

        if args.json_out:
            json_body = render_batch_json(
                results,
                errors=[error.to_dict() for error in errors],
                merged_result=merged_result,
            )
            Path(args.json_out).write_text(json_body, encoding="utf-8")
            success(f"JSON written to {args.json_out}")
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

    # --- Active probing (default for live URLs with query params) ---
    probe_enabled = args.url and not args.no_probe and "?" in args.url
    if probe_enabled:
        step("Active probing query parameters...")

        live_cb = (
            None
            if args.no_live or args.output == "json"
            else _make_live_callback(args.threshold, args.output)
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

        context = enrich_context(context, probe_results)

    step(f"Generating payloads with {selected_model}...")
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
    _print_single_result(result, args.output, args.top, waf=resolved_waf)

    if args.json_out:
        Path(args.json_out).write_text(render_json(result), encoding="utf-8")
        success(f"JSON written to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
