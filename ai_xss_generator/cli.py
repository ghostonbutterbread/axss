from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ai_xss_generator import __version__
from ai_xss_generator.models import generate_payloads
from ai_xss_generator.output import render_heat, render_json, render_list, render_summary
from ai_xss_generator.parser import parse_target
from ai_xss_generator.plugin_system import PluginRegistry
from ai_xss_generator.types import GenerationResult


DEFAULT_MODEL = "qwen2.5-coder:7b-instruct-q5_K_M"


class _HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-xss-generator",
        description="Context-aware XSS payload generator with Ollama-first AI fallback.",
        epilog=(
            "Examples:\n"
            "  ai-xss-generator -h sample_target.html -o list -t 10\n"
            "  ai-xss-generator -h '<div onclick=\"{{user}}\"></div>' -o heat\n"
            "  ai-xss-generator -u https://example.com -o json --json-out result.json\n"
            f"  ai-xss-generator -u https://example.com -m {DEFAULT_MODEL} -o list -t 3"
        ),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    parser.add_argument("--help", action="help", help="Show this help message and exit.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "-u",
        "--url",
        metavar="TARGET",
        help="Fetch and parse a target URL. Example: -u https://example.com",
    )
    source_group.add_argument(
        "-h",
        "--html",
        metavar="FILE_OR_SNIPPET",
        help="Parse a local HTML file or a raw HTML snippet. Example: -h sample_target.html",
    )
    parser.add_argument(
        "-m",
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model name. Example: -m {DEFAULT_MODEL}",
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
    parser = build_parser()
    args = parser.parse_args(argv)
    registry = PluginRegistry()
    registry.load_from(Path(__file__).resolve().parent.parent)

    try:
        context = parse_target(url=args.url, html_value=args.html, parser_plugins=registry.parsers)
    except Exception as exc:
        parser.error(str(exc))

    payloads, engine, used_fallback = generate_payloads(
        context=context,
        model=args.model,
        mutator_plugins=registry.mutators,
    )
    result = GenerationResult(
        engine=engine,
        model=args.model if engine != "openai" else "gpt-4o-mini",
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
