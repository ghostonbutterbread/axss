from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ai_xss_generator import __version__
from ai_xss_generator.config import APP_NAME, CONFIG_PATH, DEFAULT_MODEL, load_config
from ai_xss_generator.models import generate_payloads, list_ollama_models, search_ollama_models
from ai_xss_generator.output import render_heat, render_json, render_list, render_summary
from ai_xss_generator.parser import parse_target
from ai_xss_generator.plugin_system import PluginRegistry
from ai_xss_generator.types import GenerationResult


class _HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def build_parser(config_default_model: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Context-aware XSS payload generator with Ollama-first AI fallback.",
        epilog=(
            "Examples:\n"
            "  axss -h sample_target.html -o list -t 10\n"
            "  axss -h '<div onclick=\"{{user}}\"></div>' -o heat\n"
            "  axss -l\n"
            "  axss -s qwen\n"
            f"  axss -u https://example.com -m {config_default_model} -o list -t 3"
        ),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    parser.add_argument("--help", action="help", help="Show this help message and exit.")
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "-u",
        "--url",
        metavar="TARGET",
        help="Fetch and parse a target URL. Example: -u https://example.com",
    )
    action_group.add_argument(
        "-h",
        "--html",
        metavar="FILE_OR_SNIPPET",
        help="Parse a local HTML file or a raw HTML snippet. Example: -h sample_target.html",
    )
    action_group.add_argument(
        "-l",
        "--list-models",
        action="store_true",
        help="List locally available Ollama models.",
    )
    action_group.add_argument(
        "-s",
        "--search-models",
        metavar="QUERY",
        help="Search Ollama models by name or keyword.",
    )
    parser.add_argument(
        "-m",
        "--model",
        default=None,
        help=(
            "Override the Ollama model for generation. "
            f"Default comes from {CONFIG_PATH} or falls back to {DEFAULT_MODEL}."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "list", "heat"],
        default="list",
        help="Output format. Example: -o list",
    )
    parser.add_argument(
        "-t",
        "--top",
        metavar="N",
        type=int,
        default=20,
        help="How many ranked payloads to show. Example: -t 5",
    )
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        help="Optional path to write the full JSON result regardless of terminal format. Example: --json-out result.json",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


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


def _print_context_banner(result: GenerationResult) -> None:
    context = result.context
    print(
        f"Target: {context.source} ({context.source_type}) | "
        f"engine={result.engine} | model={result.model} | fallback={result.used_fallback}"
    )
    print(
        f"title={context.title or '-'} | frameworks={','.join(context.frameworks) or '-'} | "
        f"forms={len(context.forms)} | inputs={len(context.inputs)} | "
        f"handlers={len(context.event_handlers)} | sinks={len(context.dom_sinks)}"
    )
    if context.notes:
        print("notes:", " ".join(context.notes))


def main(argv: list[str] | None = None) -> int:
    config = load_config()
    parser = build_parser(config.default_model)
    args = parser.parse_args(argv)

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

    selected_model = args.model or config.default_model
    registry = PluginRegistry()
    registry.load_from(Path(__file__).resolve().parent.parent)

    try:
        context = parse_target(url=args.url, html_value=args.html, parser_plugins=registry.parsers)
    except Exception as exc:
        parser.error(str(exc))

    payloads, engine, used_fallback, resolved_model = generate_payloads(
        context=context,
        model=selected_model,
        mutator_plugins=registry.mutators,
    )
    result = GenerationResult(
        engine=engine,
        model=resolved_model,
        used_fallback=used_fallback,
        context=context,
        payloads=payloads,
    )

    _print_context_banner(result)
    print(render_summary(result, limit=min(args.top, 10)))
    print()
    if args.output == "json":
        print(render_json(result))
    elif args.output == "heat":
        print(render_heat(result.payloads, limit=args.top))
    else:
        print(render_list(result.payloads, limit=args.top))

    if args.json_out:
        Path(args.json_out).write_text(render_json(result), encoding="utf-8")
        print(f"\nJSON written to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
