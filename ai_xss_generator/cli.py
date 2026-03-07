from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Callable

from ai_xss_generator import __version__
from ai_xss_generator.config import APP_NAME, CONFIG_PATH, DEFAULT_MODEL, load_config
from ai_xss_generator.console import header, info, step, success, warn, waf_label
from ai_xss_generator.models import generate_payloads, list_ollama_models, search_ollama_models
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
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
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
) -> GenerationResult:
    payloads, engine, used_fallback, resolved_model = generate_payloads(
        context=context,
        model=model,
        mutator_plugins=registry.mutators,
        progress=lambda message: _vlog(message, enabled=verbose),
        reference_payloads=reference_payloads,
        waf=waf,
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
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    config = load_config()
    parser = build_parser(config.default_model)
    args = parser.parse_args(argv)

    has_target = bool(args.url or args.urls or args.input)
    is_utility = args.list_models or args.search_models

    # Validate: need at least one of: target, --public, or a utility action
    if not has_target and not args.public and not is_utility:
        parser.error(
            "one of the arguments -u/--url --urls -i/--input -l/--list-models "
            "-s/--search-models --public is required"
        )

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
    registry = PluginRegistry()
    registry.load_from(Path(__file__).resolve().parent.parent)

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
            contexts, errors = parse_targets(urls=urls, parser_plugins=registry.parsers, rate=args.rate)
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
        context = parse_target(url=args.url, html_value=args.input, parser_plugins=registry.parsers, rate=args.rate)
    except Exception as exc:
        parser.error(str(exc))

    # --- Active probing (default for live URLs with query params) ---
    probe_enabled = args.url and not args.no_probe and "?" in args.url
    if probe_enabled:
        param_count = len(args.url.split("?", 1)[-1].split("&")) if "?" in args.url else 0
        step(f"Active probing: {param_count} parameter(s) × 2 requests each...")

        live_cb = (
            None
            if args.no_live or args.output == "json"
            else _make_live_callback(args.threshold, args.output)
        )

        from ai_xss_generator.probe import enrich_context, probe_url

        probe_results = probe_url(args.url, rate=args.rate, on_result=live_cb)
        injectable = sum(1 for r in probe_results if r.is_injectable)
        reflected = sum(1 for r in probe_results if r.is_reflected)

        if injectable:
            success(
                f"Probing complete: {injectable}/{param_count} parameter(s) injectable, "
                f"{reflected} reflected."
            )
        elif reflected:
            info(f"Probing complete: {reflected}/{param_count} parameter(s) reflected (chars filtered).")
        else:
            info(f"Probing complete: no reflection found in {param_count} parameter(s).")

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
