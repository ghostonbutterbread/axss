#!/usr/bin/env python3
"""axss-learn — offline XSS learning from xssy.uk labs.

Fetches every published XSS lab, parses its live HTML, runs the axss payload
generator, then asks the configured AI backend to extract and save a curated
Finding for each lab — capturing the bypass technique, context type, and
filter behaviour into the SQLite knowledge store at ~/.axss/knowledge.db.

The same ai_backend / cli_tool / cloud_model config used for scanning is used
here: no separate key or service needed.

Usage examples
--------------
# Run all labs (Novice → Impossible), curate findings
python xssy/learn.py

# Only Novice + Intermediate (rating 1-2)
python xssy/learn.py --max-rating 2

# Only labs whose objective mentions "cookie"
python xssy/learn.py --objective cookie

# Use your xssy.uk JWT to get isolated instances instead of the demo token
python xssy/learn.py --xssy-token <paste token from localStorage>

# Dry-run: list labs without fetching HTML or generating payloads
python xssy/learn.py --list

# Skip curation (generate + print only, nothing saved)
python xssy/learn.py --no-curate

# Save a JSON report of all generated payloads
python xssy/learn.py --json-out xssy_results.json

# Use a specific local Ollama model for generation
python xssy/learn.py --model qwen3.5:4b
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Ensure the project root is on the path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_xss_generator.config import DEFAULT_MODEL, load_api_key, load_config
from ai_xss_generator.console import (
    _ensure_utf8,
    dim_line,
    error,
    header,
    info,
    step,
    success,
    warn,
)
from ai_xss_generator.models import generate_payloads
from ai_xss_generator.parser import parse_target
from ai_xss_generator.plugin_system import PluginRegistry
from ai_xss_generator.types import PayloadCandidate
from xssy.client import (
    RATING_LABELS,
    XssyLab,
    fetch_lab_html,
    get_lab_instance,
    load_labs,
)
from xssy.curate import curate_lab_finding

_ensure_utf8()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_lab_result(
    lab: XssyLab,
    payloads: list[PayloadCandidate],
    engine: str,
    curated: int,
    top: int,
) -> None:
    top_payloads = sorted(payloads, key=lambda p: -p.risk_score)[:top]
    print()
    header(f"  ── {lab.name}  [{lab.difficulty}]  {lab.lab_url}")
    info(
        f"     objective: {lab.objective}  |  engine: {engine}  |  "
        f"{len(payloads)} payloads  |  {curated} curated"
    )
    for p in top_payloads:
        score_str = f"[{p.risk_score:3d}]"
        print(f"     {score_str}  {p.payload[:120]}")
        if p.explanation:
            dim_line(f"            {p.explanation[:100]}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="axss-learn",
        description=(
            "Offline XSS learning from xssy.uk labs — generates payloads and "
            "curates findings into the SQLite knowledge base."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--xssy-token",
        metavar="JWT",
        default=None,
        help=(
            "xssy.uk JWT from localStorage['userData'].token. "
            "If given, creates a fresh isolated lab instance for each lab. "
            "Without it, the static demo token is used."
        ),
    )
    p.add_argument(
        "--min-rating",
        metavar="N",
        type=int,
        default=None,
        help="Only include labs with difficulty rating >= N (1=Novice … 35=Impossible).",
    )
    p.add_argument(
        "--max-rating",
        metavar="N",
        type=int,
        default=None,
        help="Only include labs with difficulty rating <= N.",
    )
    p.add_argument(
        "--objective",
        metavar="STR",
        default=None,
        help="Case-insensitive filter on lab objective, e.g. 'cookie', 'alert'.",
    )
    p.add_argument(
        "--model",
        metavar="MODEL",
        default=None,
        help=f"Ollama model to use for generation. Defaults to config / {DEFAULT_MODEL}.",
    )
    p.add_argument(
        "--top",
        metavar="N",
        type=int,
        default=5,
        help="How many top payloads to print per lab (default: 5).",
    )
    p.add_argument(
        "--delay",
        metavar="SEC",
        type=float,
        default=0.5,
        help="Seconds between lab requests (default: 0.5).",
    )
    p.add_argument(
        "--no-generate",
        action="store_true",
        help="Skip payload generation — only fetch and parse lab HTML.",
    )
    p.add_argument(
        "--no-curate",
        action="store_true",
        help="Skip curation step — generate payloads but do not save findings.",
    )
    p.add_argument(
        "--list",
        action="store_true",
        help="List matching labs and exit without fetching HTML or generating payloads.",
    )
    p.add_argument(
        "--json-out",
        metavar="PATH",
        default=None,
        help="Write a JSON report of all results to this file.",
    )
    p.add_argument(
        "--no-cloud",
        action="store_true",
        help="Never escalate to a cloud LLM for payload generation.",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print extra detail during lab fetching and curation.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    config = load_config()
    args = build_parser().parse_args(argv)

    model = args.model or config.default_model
    use_cloud = config.use_cloud and not args.no_cloud
    xssy_token = args.xssy_token or load_api_key("xssy_jwt") or None

    registry = PluginRegistry()
    registry.load_from(Path(__file__).resolve().parent)

    # ── Fetch lab list ────────────────────────────────────────────────────────
    step("Fetching xssy.uk lab catalogue...")
    try:
        labs = load_labs(
            jwt=xssy_token,
            min_rating=args.min_rating,
            max_rating=args.max_rating,
            objective_filter=args.objective,
            delay=args.delay,
            progress=lambda msg: info(f"  {msg}") if args.verbose else None,
        )
    except Exception as exc:
        error(f"Failed to fetch lab list: {exc}")
        return 1

    if not labs:
        warn("No labs matched your filters.")
        return 0

    success(f"Loaded {len(labs)} labs.")

    # ── --list mode ───────────────────────────────────────────────────────────
    if args.list:
        print()
        header(f"{'#':>4}  {'ID':>5}  {'Difficulty':<14}  {'Objective':<22}  Name")
        print("─" * 80)
        for i, lab in enumerate(labs, 1):
            obj = lab.objective[:20] if lab.objective else "-"
            print(f"{i:>4}  {lab.id:>5}  {lab.difficulty:<14}  {obj:<22}  {lab.name}")
        print()
        info(f"Total: {len(labs)} labs.")
        return 0

    # ── Per-lab pipeline ──────────────────────────────────────────────────────
    all_results: list[dict] = []
    total_curated = 0
    failures = 0

    print()
    header(f"=== xssy.uk learn session — {len(labs)} labs | model={model} ===")
    print()

    for idx, lab in enumerate(labs, 1):
        step(f"[{idx}/{len(labs)}] {lab.name}  ({lab.difficulty})  {lab.lab_url}")

        # ── Optionally get a fresh isolated instance ──────────────────────────
        effective_token = lab.token
        if xssy_token:
            try:
                effective_token = get_lab_instance(lab.id, xssy_token)
                if args.verbose:
                    info(f"  Fresh instance token: {effective_token}")
            except Exception as exc:
                warn(f"  getInstance failed ({exc}), falling back to demo token.")

        if not effective_token:
            warn("  No token available, skipping.")
            failures += 1
            continue

        lab_url = f"https://{effective_token}.xssy.uk/"

        # ── Fetch lab HTML ────────────────────────────────────────────────────
        try:
            if args.delay > 0 and idx > 1:
                time.sleep(args.delay)
            html = fetch_lab_html(effective_token)
        except Exception as exc:
            warn(f"  HTML fetch failed: {exc}")
            failures += 1
            continue

        if args.verbose:
            info(f"  HTML fetched: {len(html):,} bytes")

        # ── Parse context ─────────────────────────────────────────────────────
        try:
            context = parse_target(
                url=None,
                html_value=html,
                parser_plugins=registry.parsers,
            )
            context = context.__class__(
                source=lab_url,
                source_type="url",
                title=context.title or lab.name,
                frameworks=context.frameworks,
                forms=context.forms,
                inputs=context.inputs,
                event_handlers=context.event_handlers,
                dom_sinks=context.dom_sinks,
                variables=context.variables,
                objects=context.objects,
                inline_scripts=context.inline_scripts,
                notes=[
                    f"xssy.uk lab: {lab.name}",
                    f"difficulty: {lab.difficulty}",
                    f"objective: {lab.objective}",
                    *context.notes,
                ],
                parser_plugins=context.parser_plugins,
            )
        except Exception as exc:
            warn(f"  Parse failed: {exc}")
            failures += 1
            continue

        if args.no_generate:
            info(
                f"  sinks={len(context.dom_sinks)} forms={len(context.forms)} "
                f"inputs={len(context.inputs)} handlers={len(context.event_handlers)}"
            )
            all_results.append({
                "lab": {"id": lab.id, "name": lab.name, "url": lab_url, "difficulty": lab.difficulty},
                "context": {
                    "sinks": len(context.dom_sinks),
                    "forms": len(context.forms),
                    "inputs": len(context.inputs),
                },
                "payloads": [],
            })
            continue

        # ── Generate payloads ─────────────────────────────────────────────────
        try:
            payloads, engine, _, resolved_model = generate_payloads(
                context=context,
                model=model,
                mutator_plugins=registry.mutators,
                progress=lambda msg: info(f"  {msg}") if args.verbose else None,
                use_cloud=use_cloud,
                cloud_model=config.cloud_model,
                ai_backend=config.ai_backend,
                cli_tool=config.cli_tool,
                cli_model=config.cli_model,
            )
        except Exception as exc:
            warn(f"  Generation failed: {exc}")
            failures += 1
            all_results.append({
                "lab": {"id": lab.id, "name": lab.name, "url": lab_url, "difficulty": lab.difficulty},
                "error": str(exc),
                "payloads": [],
            })
            continue

        # ── Curate finding ────────────────────────────────────────────────────
        curated = 0
        if not args.no_curate:
            if args.verbose:
                info("  Curating finding via AI backend...")
            curated = curate_lab_finding(
                payloads=payloads,
                lab_name=lab.name,
                lab_objective=lab.objective or "",
                lab_url=lab_url,
                context=context,
                config=config,
                source=lab.lab_url,
                verbose=args.verbose,
            )
            total_curated += curated

        # ── Print result ──────────────────────────────────────────────────────
        _print_lab_result(lab, payloads, engine, curated, args.top)

        all_results.append({
            "lab": {
                "id": lab.id,
                "name": lab.name,
                "url": lab_url,
                "difficulty": lab.difficulty,
                "objective": lab.objective,
                "solution_url": lab.solution_url,
                "tags": lab.tags,
            },
            "engine": engine,
            "model": resolved_model,
            "payload_count": len(payloads),
            "curated": curated,
            "payloads": [p.to_dict() for p in sorted(payloads, key=lambda x: -x.risk_score)[:20]],
        })

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    header("=== Session complete ===")
    success(
        f"Labs processed: {len(labs) - failures}/{len(labs)}  |  "
        f"Findings curated: {total_curated}  |  "
        f"Failures: {failures}"
    )
    if total_curated:
        info(
            f"{total_curated} finding(s) saved to ~/.axss/knowledge.db — "
            "future axss scans will use them as few-shot examples."
        )
    elif not args.no_curate:
        info("No findings curated — check that your AI backend is configured (run: axss --check-keys).")

    # ── JSON output ───────────────────────────────────────────────────────────
    if args.json_out:
        try:
            Path(args.json_out).write_text(json.dumps(all_results, indent=2), encoding="utf-8")
            success(f"JSON report written to {args.json_out}")
        except Exception as exc:
            warn(f"Could not write JSON report: {exc}")

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
