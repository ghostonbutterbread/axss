from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ai_xss_generator import __version__
from ai_xss_generator.config import APP_NAME, CONFIG_PATH, DEFAULT_MODEL, load_config
from ai_xss_generator.models import generate_payloads, list_ollama_models, search_ollama_models
from ai_xss_generator.output import render_batch_json, render_heat, render_json, render_list, render_summary
from ai_xss_generator.parser import BatchParseError, parse_target, parse_targets, read_url_list
from ai_xss_generator.plugin_system import PluginRegistry
from ai_xss_generator.types import GenerationResult, ParsedContext


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
    action_group = parser.add_mutually_exclusive_group(required=True)
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
    parser.add_argument(
        "-m",
        "--model",
        default=None,
        help=(
            "--model MODEL (override the Ollama model), e.g. -m qwen3.5:4b. Supports "
            "qwen3.5 size tags such as "
            "qwen3.5:4b, qwen3.5:9b, qwen3.5:27b, or qwen3.5:35b. "
            f"Default comes from {CONFIG_PATH} or falls back to {DEFAULT_MODEL}."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "list", "heat"],
        default="list",
        help="--output {json,list,heat} (choose terminal format), e.g. -o list",
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
        "-v",
        "--verbose",
        action="store_true",
        help="--verbose (print stage-by-stage progress), e.g. -v -i sample_target.html",
    )
    parser.add_argument(
        "--merge-batch",
        action="store_true",
        help="--merge-batch (combine batch contexts into one payload set), e.g. --urls urls.txt --merge-batch",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
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


def _verbose(message: str, *, enabled: bool) -> None:
    if enabled:
        print(message, flush=True)


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
) -> GenerationResult:
    payloads, engine, used_fallback, resolved_model = generate_payloads(
        context=context,
        model=model,
        mutator_plugins=registry.mutators,
        progress=lambda message: _verbose(message, enabled=verbose),
    )
    return GenerationResult(
        engine=engine,
        model=resolved_model,
        used_fallback=used_fallback,
        context=context,
        payloads=payloads,
    )


def _print_single_result(result: GenerationResult, output_mode: str, top: int) -> None:
    _print_context_banner(result)
    print(render_summary(result, limit=min(top, 10)))
    print()
    if output_mode == "json":
        print(render_json(result))
    elif output_mode == "heat":
        print(render_heat(result.payloads, limit=top))
    else:
        print(render_list(result.payloads, limit=top))


def _print_batch_results(
    results: list[GenerationResult],
    *,
    output_mode: str,
    top: int,
    errors: list[BatchParseError],
) -> None:
    if output_mode == "json":
        print(render_batch_json(results, errors=[error.to_dict() for error in errors]))
        return

    for index, result in enumerate(results, start=1):
        if index > 1:
            print()
        print(f"[{index}/{len(results)}] {result.context.source}")
        _print_context_banner(result)
        print(render_summary(result, limit=min(top, 10)))
        print()
        if output_mode == "heat":
            print(render_heat(result.payloads, limit=top))
        else:
            print(render_list(result.payloads, limit=top))

    if errors:
        print()
        print("Errors:")
        for error in errors:
            print(f"- {error.url}: {error.error}")


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

    if args.urls:
        try:
            urls = read_url_list(args.urls)
            _verbose("Fetching/parsing targets...", enabled=args.verbose)
            _verbose(f"Fetching {len(urls)} URLs from {args.urls}...", enabled=args.verbose)
            contexts, errors = parse_targets(urls=urls, parser_plugins=registry.parsers)
        except Exception as exc:
            parser.error(str(exc))

        if not contexts and errors:
            parser.error(errors[0].error)

        _verbose("Loading model...", enabled=args.verbose)
        results = [_build_result(context, model=selected_model, registry=registry, verbose=args.verbose) for context in contexts]
        merged_result: GenerationResult | None = None
        if args.merge_batch and contexts:
            merged_context = _merge_contexts(contexts, source=f"batch:{args.urls}")
            merged_result = _build_result(
                merged_context,
                model=selected_model,
                registry=registry,
                verbose=args.verbose,
            )

        _verbose("Rendering output...", enabled=args.verbose)
        if args.merge_batch and merged_result is not None:
            if args.output == "json":
                rendered = render_batch_json(
                    results,
                    errors=[error.to_dict() for error in errors],
                    merged_result=merged_result,
                )
                print(rendered)
            else:
                _print_single_result(merged_result, args.output, args.top)
                if errors:
                    print()
                    print("Errors:")
                    for error in errors:
                        print(f"- {error.url}: {error.error}")
        else:
            _print_batch_results(results, output_mode=args.output, top=args.top, errors=errors)

        if args.json_out:
            json_body = render_batch_json(
                results,
                errors=[error.to_dict() for error in errors],
                merged_result=merged_result,
            )
            Path(args.json_out).write_text(json_body, encoding="utf-8")
            print(f"\nJSON written to {args.json_out}")
        return 0

    try:
        target = args.url or args.input or ""
        _verbose("Fetching/parsing target...", enabled=args.verbose)
        _verbose("Fetching target: {}...".format(target), enabled=args.verbose)
        context = parse_target(url=args.url, html_value=args.input, parser_plugins=registry.parsers)
    except Exception as exc:
        parser.error(str(exc))

    _verbose("Loading model...", enabled=args.verbose)
    result = _build_result(context, model=selected_model, registry=registry, verbose=args.verbose)

    _verbose("Rendering output...", enabled=args.verbose)
    _print_single_result(result, args.output, args.top)

    if args.json_out:
        Path(args.json_out).write_text(render_json(result), encoding="utf-8")
        print(f"\nJSON written to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
