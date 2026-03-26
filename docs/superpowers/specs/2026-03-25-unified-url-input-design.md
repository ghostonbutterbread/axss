# Unified URL Input Design

**Date:** 2026-03-25
**Branch:** feat/payload-pipeline-restructure

## Problem

The current CLI has two separate target flags with different semantics:

- `-u`/`--url TARGET` — single URL, triggers crawl in `scan` mode
- `--urls FILE` — file of URLs, skips crawl

Users naturally reach for `-u` regardless of input type. `--url` (singular) is semantically awkward for a tool that accepts lists. The flags should unify.

## Design

### 1. Flag unification (`scan` and `generate`)

Remove `-u`/`--url` and `--urls` as separate flags. Replace with a single flag:

```
-u TARGET, --urls TARGET
```

`-u` is the short form of `--urls`. Both names accept the same value formats:

| Input | Example | Resolves to |
|-------|---------|-------------|
| Single URL | `-u https://example.com` | `["https://example.com"]` |
| CSV of URLs | `-u https://a.com,https://b.com` | `["https://a.com", "https://b.com"]` |
| File path | `-u targets.txt` or `--urls targets.txt` | lines from file |

The flag remains in the mutually-exclusive target group alongside `--input` (in `generate`) and `--interesting` (in `scan`).

### 2. Resolver — `resolve_url_input(value: str) -> list[str]`

New function in `parser.py`. Resolution order:

1. Starts with `http://` or `https://` **and** contains `,` → split on `,`, strip whitespace → list of URLs
2. Starts with `http://` or `https://` → `[value]`
3. Otherwise → treat as file path; delegate to existing `read_url_list()` logic
4. File not found → raise `ValueError`

`read_url_list` remains as the file-reading backend. All call sites currently using `read_url_list(args.urls)` switch to `resolve_url_input(args.urls)`.

### 3. Crawl inference (`scan` mode only)

Crawl is determined **after** URL resolution, based on count:

| Resolved count | Default crawl behavior |
|---------------|------------------------|
| 1 URL | Crawl **on** (existing single-URL behavior) |
| > 1 URL | Crawl **off** (pre-enumerated list, existing `--urls` behavior) |

**Override flags** (mutually exclusive with each other):
- `--crawl` — force crawl on regardless of URL count; crawls from each URL in the list
- `--no-crawl` — force crawl off regardless of URL count (existing flag, unchanged)

`--crawl` is new. It is added to the crawl control section of the `scan` parser.

### 4. `--interesting` fallback

`--interesting` accepts an optional file path. When invoked bare (`--interesting` with no argument), it falls back to the URL list already resolved from `-u`/`--urls`. No change to `--interesting` semantics beyond what is already in-flight on this branch.

### 5. Help text and examples

All epilog examples in both `scan` and `generate` parsers updated:
- Remove any reference to `--url` (singular)
- Use `-u` for single-URL examples
- Use `--urls` for file examples in scripts/CI context

`--url` removed from all help strings, error messages, and inline documentation.

## Affected Files

| File | Change |
|------|--------|
| `ai_xss_generator/cli.py` | Unify flags in `_build_scan_parser` and `_build_gen_parser`; update all `args.url`/`args.urls` references; add `--crawl` flag; update `has_target` check; update crawl decision logic; update epilog examples |
| `ai_xss_generator/parser.py` | Add `resolve_url_input()`; keep `read_url_list()` as internal backend |
| `tests/test_cli_help.py` | Update assertions to use `--urls` / `-u` metavar |
| Any test referencing `args.url` or `--url` flag | Update to `args.urls` / `--urls` |

## Backwards Compatibility

- `-u https://example.com` — unchanged
- `--urls file.txt` — unchanged
- `--url https://example.com` — **breaks** (flag removed). Acceptable: tool is not widely distributed.
- `--no-crawl` — unchanged

## Non-Goals

- No change to crawl implementation itself
- No change to `generate` crawl behavior (generate doesn't crawl)
- No change to `--interesting` triage logic beyond the fallback already in-flight
