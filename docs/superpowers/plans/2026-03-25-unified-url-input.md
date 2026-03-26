# Unified URL Input Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the separate `-u`/`--url` and `--urls` flags with a single `-u`/`--urls` flag that accepts a URL, CSV of URLs, or a file path, with count-based crawl inference.

**Architecture:** Add `resolve_url_input()` to `parser.py` as the single resolver for all URL input. All CLI paths call this function after argparse. Crawl is inferred from resolved URL count (`== 1` → crawl on, `> 1` → crawl off) with `--crawl`/`--no-crawl` as explicit overrides.

**Tech Stack:** Python 3, argparse, existing `read_url_list()` as file-reading backend.

---

## File Map

| File | Change |
|------|--------|
| `ai_xss_generator/parser.py` | Add `resolve_url_input()` — wraps `read_url_list()`, handles URL/CSV/file |
| `ai_xss_generator/cli.py` | Unify flags in both parsers; add `--crawl`; replace all `args.url` references; update crawl logic |
| `tests/test_cli_help.py` | Update flag assertions; add `--crawl` assertion; add resolver unit tests |

---

### Task 1: Add `resolve_url_input()` to `parser.py`

**Files:**
- Modify: `ai_xss_generator/parser.py` (after `read_url_list`, ~line 658)
- Test: `tests/test_cli_help.py` (add new `TestResolveUrlInput` class)

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli_help.py`:

```python
class TestResolveUrlInput(unittest.TestCase):
    def test_single_url(self):
        from ai_xss_generator.parser import resolve_url_input
        result = resolve_url_input("https://example.com")
        self.assertEqual(result, ["https://example.com"])

    def test_csv_of_urls(self):
        from ai_xss_generator.parser import resolve_url_input
        result = resolve_url_input("https://a.com, https://b.com , https://c.com")
        self.assertEqual(result, ["https://a.com", "https://b.com", "https://c.com"])

    def test_file_path(self, tmp_path=None):
        import tempfile, os
        from ai_xss_generator.parser import resolve_url_input
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("https://x.com\nhttps://y.com\n# comment\n\n")
            path = f.name
        try:
            result = resolve_url_input(path)
            self.assertEqual(result, ["https://x.com", "https://y.com"])
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        from ai_xss_generator.parser import resolve_url_input
        with self.assertRaises(ValueError):
            resolve_url_input("/nonexistent/path/urls.txt")

    def test_http_url_not_treated_as_file(self):
        from ai_xss_generator.parser import resolve_url_input
        # A URL that looks like it might be a path — must not hit the filesystem
        result = resolve_url_input("http://example.com/path/to/resource")
        self.assertEqual(result, ["http://example.com/path/to/resource"])
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && python -m pytest tests/test_cli_help.py::TestResolveUrlInput -v
```

Expected: `ImportError: cannot import name 'resolve_url_input'`

- [ ] **Step 3: Implement `resolve_url_input()` in `parser.py`**

Add after `read_url_list` (after line 658):

```python
def resolve_url_input(value: str) -> list[str]:
    """Resolve a URL input value to a list of URLs.

    Accepts:
    - A single URL: "https://example.com"
    - A CSV of URLs: "https://a.com,https://b.com"
    - A file path: "targets.txt" (one URL per line)
    """
    if value.startswith(("http://", "https://")):
        if "," in value:
            return [u.strip() for u in value.split(",") if u.strip()]
        return [value]
    return read_url_list(value)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_cli_help.py::TestResolveUrlInput -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add ai_xss_generator/parser.py tests/test_cli_help.py
git commit -m "feat: add resolve_url_input() — unified URL/CSV/file resolver"
```

---

### Task 2: Unify flag in `_build_gen_parser`

**Files:**
- Modify: `ai_xss_generator/cli.py` lines ~339–368
- Test: `tests/test_cli_help.py` — `test_generate_help`

- [ ] **Step 1: Update the test assertions**

In `tests/test_cli_help.py`, change `test_generate_help`:

```python
# REMOVE these two lines:
self.assertIn("-u TARGET, --url TARGET", help_text)
self.assertIn("--urls FILE", help_text)

# ADD this line:
self.assertIn("-u TARGET, --urls TARGET", help_text)
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
python -m pytest tests/test_cli_help.py::CliHelpTest::test_generate_help -v
```

Expected: `AssertionError: '-u TARGET, --urls TARGET' not found in help text`

- [ ] **Step 3: Update `_build_gen_parser` in `cli.py`**

Replace the two separate `target.add_argument` calls for `-u`/`--url` and `--urls` (~lines 340–349) with one unified flag:

```python
target.add_argument(
    "-u", "--urls",
    metavar="TARGET",
    dest="urls",
    help=(
        "Target URL, comma-separated list of URLs, or path to a file of URLs (one per line). "
        "e.g. -u https://example.com  or  -u targets.txt  or  -u https://a.com,https://b.com"
    ),
)
```

Also update the `--merge-batch` help text (~line 364):

```python
    help="Combine all URLs from --urls into one payload set.",
```

(No change needed — it already says `--urls`.)

Also update epilog examples (~lines 327–330):

```python
epilog=(
    "Examples:\n"
    "  axss generate -u https://example.com\n"
    "  axss generate -u https://example.com --public --waf cloudflare\n"
    "  axss generate -u urls.txt --merge-batch -o payloads.json\n"
    "  axss generate -i page.html --display heat\n"
    "  axss generate --public --waf modsecurity         (no target — dump public payloads)\n"
),
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_cli_help.py::CliHelpTest::test_generate_help -v
```

Expected: PASS.

- [ ] **Step 5: Run full suite to check for regressions**

```bash
python -m pytest tests/test_cli_help.py -v
```

Expected: same pass count as before (minus the two assertions changed).

- [ ] **Step 6: Commit**

```bash
git add ai_xss_generator/cli.py tests/test_cli_help.py
git commit -m "feat: unify -u/--urls in generate parser"
```

---

### Task 3: Unify flag in `_build_scan_parser` + add `--crawl`

**Files:**
- Modify: `ai_xss_generator/cli.py` lines ~398–420, ~454–490
- Test: `tests/test_cli_help.py` — `test_scan_help`

- [ ] **Step 1: Update test assertions**

In `test_scan_help`:

```python
# REMOVE:
self.assertIn("-u TARGET, --url TARGET", help_text)
self.assertIn("--urls FILE", help_text)

# ADD:
self.assertIn("-u TARGET, --urls TARGET", help_text)
self.assertIn("--crawl", help_text)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_cli_help.py::CliHelpTest::test_scan_help -v
```

Expected: `AssertionError`

- [ ] **Step 3: Replace the two separate target flags with the unified flag**

Replace `-u`/`--url` + `--urls` add_argument calls (~lines 399–408) with:

```python
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
```

- [ ] **Step 4: Add `--crawl` flag to the crawl control section** (~line 462, after `--no-crawl`)

Find the existing `--no-crawl` block and add `--crawl` immediately after it:

```python
scan.add_argument(
    "--crawl",
    action="store_true",
    default=False,
    help=(
        "Force crawl even when multiple URLs are provided. "
        "Crawls from each URL in the list and merges discovered endpoints."
    ),
)
```

`--crawl` and `--no-crawl` are not made mutually exclusive via argparse (they're both booleans); validation happens at runtime in `_run_active_scan`.

- [ ] **Step 5: Update scan epilog examples** (~line 383)

```python
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
```

- [ ] **Step 6: Update default args dict** (~line 626)

Find the `_SCAN_DEFAULTS` dict (or equivalent) and add:
```python
"crawl": False,
```
alongside the existing `"no_crawl": False`.

- [ ] **Step 7: Run tests**

```bash
python -m pytest tests/test_cli_help.py -v
```

Expected: all passing (including the updated `test_scan_help`).

- [ ] **Step 8: Commit**

```bash
git add ai_xss_generator/cli.py tests/test_cli_help.py
git commit -m "feat: unify -u/--urls in scan parser, add --crawl flag"
```

---

### Task 4: Update `_run_active_scan` — URL resolution and crawl logic

**Files:**
- Modify: `ai_xss_generator/cli.py` — `_run_active_scan` function (~lines 1127–1430)

This is the most involved task. Work through it section by section.

- [ ] **Step 1: Replace URL resolution at the top of `_run_active_scan`** (~lines 1129–1140)

```python
# BEFORE:
from ai_xss_generator.parser import read_url_list
...
if args.urls:
    try:
        urls = read_url_list(args.urls)
    except Exception as exc:
        print(f"Error reading URL list: {exc}")
        return 1
else:
    urls = [args.url]

# AFTER:
from ai_xss_generator.parser import resolve_url_input
...
try:
    urls = resolve_url_input(args.urls)
except Exception as exc:
    print(f"Error reading URL list: {exc}")
    return 1
```

- [ ] **Step 2: Update `upload_only_batch_discovery`** (~line 1142)

```python
# BEFORE:
upload_only_batch_discovery = bool(
    args.urls
    and scan_uploads
    and not scan_reflected
    and not scan_stored
    and not scan_dom
    and not getattr(args, "no_crawl", False)
)

# AFTER:
no_crawl = getattr(args, "no_crawl", False)
force_crawl = getattr(args, "crawl", False)
crawl_enabled = (force_crawl or len(urls) == 1) and not no_crawl

upload_only_batch_discovery = bool(
    len(urls) > 1
    and scan_uploads
    and not scan_reflected
    and not scan_stored
    and not scan_dom
    and crawl_enabled
)
```

- [ ] **Step 3: Update the WAF probe condition** (~line 1154)

```python
# BEFORE:
waf = resolved_waf
no_crawl = getattr(args, "no_crawl", False)
if not waf and urls and (no_crawl or (not args.url and not upload_only_batch_discovery)):

# AFTER:
waf = resolved_waf
# (no_crawl, force_crawl, crawl_enabled already set above)
if not waf and urls and (not crawl_enabled and not upload_only_batch_discovery):
```

- [ ] **Step 4: Update upload-mode warning messages** (~lines 1202–1210)

```python
# BEFORE:
if scan_uploads and args.urls and not upload_only_batch_discovery:
    info("Upload scanning in --urls batch mode only tests upload forms already discovered ...")
if scan_uploads and args.url and no_crawl:
    info("Upload scanning with --no-crawl needs a known upload target ...")

# AFTER:
if scan_uploads and len(urls) > 1 and not upload_only_batch_discovery:
    info(
        "Upload scanning in batch mode only tests upload forms already discovered "
        "from crawlable entry pages; raw URL lists do not discover upload endpoints on their own."
    )
if scan_uploads and not crawl_enabled:
    info(
        "Upload scanning with crawl disabled needs a known upload target; the scanner will not "
        "discover multipart forms when crawling is disabled."
    )
```

- [ ] **Step 5: Update the crawl branch** (~line 1296)

```python
# BEFORE:
elif args.url and not no_crawl:
    from ai_xss_generator.cache import get_sitemap, put_sitemap, sitemap_age_minutes, cache_sweep
    cache_sweep()
    _scope_spec = getattr(args, "scope", None) or "auto"
    _fresh = getattr(args, "fresh", False)
    _cached_crawl = None if _fresh else get_sitemap(urls[0], _scope_spec)
    if _cached_crawl is not None:
        ...
    else:
        crawl_result = _crawl_seed(urls[0])
        ...
    post_forms = crawl_result.post_forms
    upload_targets = getattr(crawl_result, "upload_targets", [])
    crawled_pages = crawl_result.visited_urls
    if crawl_result.get_urls:
        ...
        urls = crawl_result.get_urls
    ...

# AFTER:
elif crawl_enabled:
    from ai_xss_generator.cache import get_sitemap, put_sitemap, sitemap_age_minutes, cache_sweep
    cache_sweep()
    _scope_spec = getattr(args, "scope", None) or "auto"
    _fresh = getattr(args, "fresh", False)

    if len(urls) == 1:
        # Single-URL crawl path (unchanged logic)
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
```

- [ ] **Step 6: Update `skip_liveness`** (~line 1425)

```python
# BEFORE:
skip_liveness=bool(args.urls) and not getattr(args, "live", False),

# AFTER:
skip_liveness=len(urls) > 1 and not getattr(args, "live", False),
```

- [ ] **Step 7: Run the existing test suite**

```bash
python -m pytest tests/test_cli_help.py -v
```

Expected: all passing.

- [ ] **Step 8: Commit**

```bash
git add ai_xss_generator/cli.py
git commit -m "feat: count-based crawl inference in _run_active_scan, --crawl multi-seed support"
```

---

### Task 5: Update `main()` — validation and error messages

**Files:**
- Modify: `ai_xss_generator/cli.py` — `main()` function

- [ ] **Step 1: Update `has_target`** (~line 1794)

```python
# BEFORE:
has_target = bool(args.url or args.urls or args.input or (args.interesting is not None))

# AFTER:
has_target = bool(args.urls or args.input or (args.interesting is not None))
```

- [ ] **Step 2: Update error messages** (~lines 1799–1801)

```python
# BEFORE:
if args.command == "generate":
    parser.error("axss generate requires -u/--url, --urls, -i/--input, or --public")
else:
    parser.error("axss scan requires -u/--url, --urls, or --interesting")

# AFTER:
if args.command == "generate":
    parser.error("axss generate requires -u/--urls, -i/--input, or --public")
else:
    parser.error("axss scan requires -u/--urls or --interesting")
```

- [ ] **Step 3: Update rate info condition** (~line 1807)

```python
# BEFORE:
if has_target and (args.url or args.urls):

# AFTER:
if has_target and args.urls:
```

- [ ] **Step 4: Update `target_hint` resolution for auth profiles** (~lines 1822–1828)

```python
# BEFORE:
target_hint = str(args.url or "")
if not target_hint and args.urls:
    try:
        _targets = read_url_list(args.urls)
        target_hint = _targets[0] if _targets else ""
    except Exception:
        target_hint = ""

# AFTER:
target_hint = ""
if args.urls:
    try:
        _targets = resolve_url_input(args.urls)
        target_hint = _targets[0] if _targets else ""
    except Exception:
        target_hint = ""
```

Make sure `resolve_url_input` is imported at the top of `main()` or the local import block. Add to the existing import line near line 27:

```python
from ai_xss_generator.parser import BatchParseError, parse_target, parse_targets, read_url_list, resolve_url_input
```

- [ ] **Step 5: Update `--interesting` fallback** (~line 1949)

```python
# BEFORE:
if args.interesting is True:
    if not args.urls:
        parser.error("--interesting without a FILE or URL argument requires --urls FILE")
    source_label = args.urls
    step(f"Reading URL list: {args.urls}")
    try:
        urls = read_url_list(args.urls)
    except Exception as exc:
        parser.error(str(exc))

# AFTER:
if args.interesting is True:
    if not args.urls:
        parser.error("--interesting without a FILE argument requires -u/--urls")
    source_label = args.urls
    step(f"Reading URL list: {args.urls}")
    try:
        urls = resolve_url_input(args.urls)
    except Exception as exc:
        parser.error(str(exc))
```

- [ ] **Step 6: Update active scan validation** (~line 2048)

```python
# BEFORE:
if not (args.url or args.urls):
    parser.error(
        "active scanning requires -u/--url or --urls — "
        "use -i/--input with --generate for local file payload generation"
    )

# AFTER:
if not args.urls:
    parser.error(
        "active scanning requires -u/--urls — "
        "use -i/--input with --generate for local file payload generation"
    )
```

- [ ] **Step 7: Run tests**

```bash
python -m pytest tests/test_cli_help.py -v
```

Expected: all passing.

- [ ] **Step 8: Commit**

```bash
git add ai_xss_generator/cli.py
git commit -m "fix: update main() validation to use unified args.urls"
```

---

### Task 6: Update `main()` — generate mode URL handling

**Files:**
- Modify: `ai_xss_generator/cli.py` — generate mode section of `main()` (~lines 2068–2229)

This replaces the `if args.urls: ... # batch` / `# single target` split with a count-based split using `resolve_url_input`.

- [ ] **Step 1: Replace batch URLs block** (~lines 2068–2171)

```python
# BEFORE:
if args.urls:
    step(f"Reading URL list: {args.urls}")
    try:
        urls = read_url_list(args.urls)
    except Exception as exc:
        parser.error(str(exc))
    # ... (rest of batch processing using `urls`)

# AFTER:
if args.urls:
    try:
        _resolved = resolve_url_input(args.urls)
    except Exception as exc:
        parser.error(str(exc))

    if len(_resolved) > 1:
        urls = _resolved
        step(f"Fetching and parsing {len(urls)} URL(s)...")
        # ... (rest of batch processing — unchanged, but use `urls` variable)
        # Also update the merge-batch source label:
        merged_context = _merge_contexts(contexts, source=f"batch:{args.urls}")
        # ^ this line is unchanged — args.urls is still the raw input string, fine as label
```

The key change: resolve first, then branch on `len(_resolved) > 1` vs single URL.

- [ ] **Step 2: Update single target block** (~lines 2173–2229)

When `len(_resolved) == 1`, fall through to single URL handling. Replace `args.url` with `_resolved[0]` (or assign `_url = _resolved[0]` at the top for clarity):

```python
    else:
        # Single URL — fall through to single target mode
        _url = _resolved[0]

# --- Single target mode (-u / -i) ---
# (Previously entered when args.urls was None and args.url was set)
# Now: _url is the single URL from resolve_url_input, or "" if using -i
_url = locals().get("_url", "")  # set above or empty for -i mode
target = _url or args.input or ""

# WAF auto-detect for live URL
if _url and not resolved_waf:
    step(f"Probing for WAF on {_url}...")
    detected = _try_detect_waf(_url, args.verbose)
    if detected:
        resolved_waf = detected
        success(f"WAF detected: {waf_label(detected)}")
    else:
        info("No WAF fingerprint detected — use --waf to set manually.")

# ... (rest of single-URL handling, replacing args.url with _url)
context = parse_target(url=_url or None, html_value=args.input, ...)
probe_enabled = _url and not args.no_probe and "?" in _url
probe_results = probe_url(_url, ...)
```

**Note:** The `-i`/`--input` path doesn't go through `args.urls`, so the `else` block (single URL) should only execute when `args.urls` is set and resolved to 1 URL. The pure `-i` path still enters the single-target section directly (the `if args.urls:` block is skipped). Set `_url = ""` before the `if args.urls:` block for the `-i` case.

Full restructured flow:

```python
_url = ""  # set to resolved single URL below; empty for -i mode

if args.urls:
    try:
        _resolved = resolve_url_input(args.urls)
    except Exception as exc:
        parser.error(str(exc))

    if len(_resolved) > 1:
        # --- Batch mode ---
        urls = _resolved
        # WAF auto-detect from first URL if not manually set
        if not resolved_waf and urls:
            step(f"Probing for WAF on {urls[0]}...")
            detected = _try_detect_waf(urls[0], args.verbose)
            if detected:
                resolved_waf = detected
                success(f"WAF detected: {waf_label(detected)}")
            else:
                info("No WAF fingerprint detected.")

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

    else:
        # Single URL from -u/--urls
        _url = _resolved[0]

# --- Single target mode (_url from -u/--urls, or args.input) ---
target = _url or args.input or ""

if _url and not resolved_waf:
    step(f"Probing for WAF on {_url}...")
    detected = _try_detect_waf(_url, args.verbose)
    if detected:
        resolved_waf = detected
        success(f"WAF detected: {waf_label(detected)}")
    else:
        info("No WAF fingerprint detected — use --waf to set manually.")

if args.public and resolved_waf and fetch_result is not None and not _waf_manual:
    from ai_xss_generator.public_payloads import _waf_candidates
    waf_extra = _waf_candidates(resolved_waf)
    if waf_extra:
        fetch_result.add(f"waf_{resolved_waf}", waf_extra)
        reference_payloads = select_reference_payloads(fetch_result.payloads, limit=20)

step(f"Fetching/parsing target: {target}")
try:
    context = parse_target(url=_url or None, html_value=args.input, parser_plugins=registry.parsers, rate=args.rate, waf=resolved_waf, auth_headers=auth_headers or None)
except Exception as exc:
    parser.error(str(exc))

context = _attach_waf_knowledge_to_context(context, waf_knowledge)

probe_enabled = _url and not args.no_probe and "?" in _url
if probe_enabled:
    step("Active probing query parameters...")
    live_cb = (
        None
        if args.no_live
        else _make_live_callback(args.threshold, args.display)
    )
    from ai_xss_generator.probe import enrich_context, probe_url
    probe_results = probe_url(_url, rate=args.rate, waf=resolved_waf, on_result=live_cb, auth_headers=auth_headers or None)
    # ... (rest of probe handling unchanged)
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/test_cli_help.py -v
```

Expected: all passing.

- [ ] **Step 4: Quick smoke test**

```bash
python axss.py generate -u https://example.com --dry-run 2>/dev/null || echo "no dry-run for generate, that's fine"
python axss.py scan --help | grep -E "^\s+-u"
```

Expected second line shows: `-u TARGET, --urls TARGET`

- [ ] **Step 5: Commit**

```bash
git add ai_xss_generator/cli.py
git commit -m "feat: count-based URL routing in generate mode, remove args.url"
```

---

### Task 7: Full test sweep + cleanup

**Files:**
- Modify: `tests/test_cli_help.py` — update any remaining `args.url` references in test stubs

- [ ] **Step 1: Run the full test suite**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && python -m pytest tests/ -v --tb=short 2>&1 | tail -40
```

- [ ] **Step 2: Fix any remaining `args.url` references in tests**

Search for any test that still passes `"--url"` or checks `args.url`:

```bash
grep -n "args\.url\b\|\"--url\"\|'--url'" tests/test_cli_help.py
```

Update any found references. Tests using `cli.main(["scan", "-u", "..."])` are fine — `-u` is the short form of `--urls` and still works.

- [ ] **Step 3: Check for any remaining `args.url` in cli.py**

```bash
grep -n "args\.url\b" ai_xss_generator/cli.py
```

Expected: zero results. Fix any that remain.

- [ ] **Step 4: Run tests again**

```bash
python -m pytest tests/ -v --tb=short 2>&1 | tail -20
```

Expected: same pass count as before this branch started (270 passing, 2 skipped, 1 pre-existing failure in test_probe_browser.py).

- [ ] **Step 5: Final commit**

```bash
git add ai_xss_generator/cli.py tests/test_cli_help.py
git commit -m "fix: remove remaining args.url references, full test sweep"
```
