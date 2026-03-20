# `-v` / `-vv` Pipeline Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add structured `-v` (one summary line per param/context on completion) and `-vv` (inline per-tier lines as scan progresses) output to the payload pipeline so scan misses are diagnosable without adding print statements.

**Architecture:** Two new output levels gate on the existing `VERBOSE_LEVEL` global in `console.py`. A `console.verbose()` function handles `-v` output (`[>]` dim). The existing `console.debug()` handles `-vv` (`[.]` dim). In `worker.py`, a `_v_steps: list[str]` accumulates outcome tokens per (param, context_type) iteration and prints as a single summary line at loop exit. Inline `console.debug()` calls fire at each tier boundary in real time.

**Tech Stack:** Python, `ai_xss_generator/console.py`, `ai_xss_generator/active/worker.py`. No new dependencies.

---

### Task 1: Add `console.verbose()` to console.py

**Files:**
- Modify: `ai_xss_generator/console.py` (after the existing `debug()` function, ~line 119)

- [ ] **Step 1: Add `verbose()` function**

Open `ai_xss_generator/console.py`. After the `debug()` function (which ends around line 119), insert:

```python
def verbose(message: str) -> None:
    """[>] Verbose output — printed at -v (VERBOSE_LEVEL >= 1)."""
    if VERBOSE_LEVEL < 1:
        return
    _before_print()
    prefix = _c(DIM, "[>]") if _tty() else "[>]"
    print(f"{prefix} {message}", flush=True)
    _after_print()
```

- [ ] **Step 2: Verify it works at both levels**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate
python3 -c "
from ai_xss_generator import console
console.set_verbose_level(0)
console.verbose('should be silent')
console.set_verbose_level(1)
console.verbose('should appear with [>] prefix')
console.set_verbose_level(2)
console.verbose('should also appear at -vv')
"
```

Expected: first call produces no output; second and third each print `[>] should appear`.

- [ ] **Step 3: Verify existing 242 tests still pass**

```bash
pytest tests/ -x -q --ignore=tests/test_network_live.py
```

Expected: 242 passed.

- [ ] **Step 4: Commit**

```bash
git add ai_xss_generator/console.py
git commit -m "feat: add console.verbose() for -v pipeline summary output"
```

---

### Task 2: Add `_trunc()` helper and `console` import to worker.py

**Files:**
- Modify: `ai_xss_generator/active/worker.py` (top of file, around line 33 where `log` is defined)

- [ ] **Step 1: Add `console` import and `_trunc()` helper**

Find the line `log = logging.getLogger(__name__)` (around line 33). Directly after it, add:

```python
from ai_xss_generator import console as _console


def _trunc(s: str, n: int = 50) -> str:
    """Truncate *s* to *n* chars for display, appending '…' if clipped."""
    return s if len(s) <= n else s[:n] + "…"
```

- [ ] **Step 2: Verify import is clean**

```bash
python3 -c "from ai_xss_generator.active import worker; print('ok')"
```

Expected: `ok` with no errors.

- [ ] **Step 3: Commit**

```bash
git add ai_xss_generator/active/worker.py
git commit -m "feat: add _trunc helper and console import to worker.py"
```

---

### Task 3: GET path — `-vv` lines for Tier 1 and Tier 1.5

**Files:**
- Modify: `ai_xss_generator/active/worker.py` — GET context loop (lines ~1287–1428)

All insertions go inside the `if mode in ("normal", "deep") and context_type != "fast_omni"` block.

- [ ] **Step 1: Add `-vv` line after `payloads_for_context()` returns (~line 1321)**

Find the call to `payloads_for_context(...)` that assigns `tier1_candidates`. Immediately after it (before the `if mode == "normal" and tier1_candidates:` pre-rank block), insert:

```python
                    # -vv: Tier 1 dispatch
                    if tier1_candidates:
                        _t1_top = _trunc(_payload_text(tier1_candidates[0]) or "", 50)
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Tier 1: {len(tier1_candidates)} candidates | top: \"{_t1_top}\""
                        )
                    else:
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Tier 1: 0 candidates — context not dispatched"
                        )
```

- [ ] **Step 2: Add `-vv` line after HTTP pre-rank loop (~line 1353)**

Find where `tier1_candidates = _ranked + _non_reflecting + tier1_candidates[10:]` is assigned. After that line (still inside the `try` block for pre-rank), add:

```python
                            # -vv: pre-rank result
                            _prerank_top = ""
                            if _ranked:
                                _prerank_top = _trunc(_payload_text(_ranked[0]) or "", 50)
                                _console.debug(
                                    f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                                    f"Pre-rank: {len(_ranked)}/{len(_check_candidates)} reflect | "
                                    f"top: \"{_prerank_top}\""
                                )
                            else:
                                _console.debug(
                                    f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                                    f"Pre-rank: 0/{len(_check_candidates)} reflect — order unchanged"
                                )
```

- [ ] **Step 3: Add `-vv` line after Tier 1 fire loop (~line 1393)**

Find the end of the `for t1_cand in tier1_candidates:` fire loop. After the loop (before the `# ── Tier 1.5` comment), add:

```python
                    # -vv: Tier 1 results
                    _t1_confirmed = 1 if context_done else 0
                    _console.debug(
                        f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                        f"Tier 1: fired {len(tier1_candidates)} → {_t1_confirmed} confirmed"
                    )
```

- [ ] **Step 4: Add `-vv` lines for Tier 1.5 (~lines 1396–1428)**

Find the line `tier15_mutations = mutate_seeds(tier1_seeds, _t1_surviving)`. After it, add:

```python
                        # -vv: Tier 1.5 mutations
                        _t15_top = _trunc(tier15_mutations[0] if tier15_mutations else "", 50)
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Tier 1.5: {len(tier15_mutations)} mutations from {len(tier1_seeds)} seeds | "
                            f"top: \"{_t15_top}\""
                        )
```

Then after the `for t15_text in tier15_mutations:` fire loop ends (look for `_tier15_failed_payloads.append(t15_text)`), add:

```python
                        # -vv: Tier 1.5 results
                        _t15_confirmed = 1 if context_done else 0
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Tier 1.5: fired {len(tier15_mutations)} → {_t15_confirmed} confirmed"
                        )
```

- [ ] **Step 5: Smoke-run to verify no errors introduced**

```bash
python3 -c "from ai_xss_generator.active import worker; print('ok')"
```

- [ ] **Step 6: Commit**

```bash
git add ai_xss_generator/active/worker.py
git commit -m "feat: add -vv Tier 1 and Tier 1.5 debug lines to GET path"
```

---

### Task 4: GET path — `-vv` lines for triage and Tier 3

**Files:**
- Modify: `ai_xss_generator/active/worker.py` — GET context loop (lines ~1430–1770)

- [ ] **Step 1: Add `-vv` triage lines (~line 1448)**

The triage section has four code paths. Add a debug line after each:

**After `_triage_with_local_model()` returns** (find `_triage_approved = _triage.should_escalate`):
```python
                        # -vv: triage result
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Triage: score={_triage.score} escalate={'YES' if _triage_approved else 'NO'} | "
                            f"{_trunc(_triage.reason, 60)}"
                        )
```

**After `skip_triage=True` deep mode bypass** (find `_append_reason(escalation_reasons, "skip_triage=True — triage gate bypassed")`):
```python
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Triage: skipped (--skip-triage) — auto-escalate"
                        )
```

**For fast-mode short-circuit:** The `_triage_with_local_model()` function itself returns immediately with `reason="fast mode — triage skipped"` when `fast_mode=True`. This case is already caught by the triage result debug line above (score=5, reason shows "fast mode"). No separate insertion needed.

**For `fast_omni` bypass** — this is handled in Task 5 via the `_v_steps` tracker token `triage:skip(omni)`, not a separate `-vv` line (the fast_omni path goes directly to cloud with its own debug lines there).

- [ ] **Step 2: Add `-vv` lines for normal mode Tier 3 scout (~lines 1634–1682)**

Find `_scout_payloads = generate_normal_scout(...)`. After the call returns, add:
```python
                        # -vv: normal scout returned
                        _scout_top = _trunc(_scout_payloads[0] if _scout_payloads else "", 50)
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Tier 3 scout: {len(_scout_payloads)} payloads | top: \"{_scout_top}\""
                        )
```

After the `for _scout_text in _scout_new:` fire loop ends (find the last `_ai_tried_payloads.append` in the scout block), add:
```python
                        # -vv: normal scout fire result
                        _scout_confirmed = 1 if context_done else 0
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Tier 3 scout: fired {len(_scout_new)} → {_scout_confirmed} confirmed"
                        )
```

- [ ] **Step 3: Add `-vv` lines for deep Tier 3 (~lines 1596–1770)**

Find the `_deep_strategy_hint = "\n".join(_hint_parts)` assignment. After it, add:
```python
                        # -vv: deep T3 hint assembled
                        _blocked_chars = sorted({
                            _blocked_on_char(p, _probe_surviving)
                            for p in _all_failed_strs
                            if _blocked_on_char(p, _probe_surviving)
                        })
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Deep Tier 3: {len(_all_failed)} failures → top 5 to cloud "
                            f"(blocked on {_blocked_chars or 'unknown'})"
                        )
```

After the deep cloud `for cp in cloud_payloads:` fire loop ends (find `cloud_feedback_lessons = _build_cloud_feedback_lessons`), add:
```python
                        # -vv: deep cloud fire result
                        _deep_confirmed = 1 if context_done else 0
                        _console.debug(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                            f"Deep Tier 3: fired {len(cloud_payloads)} → {_deep_confirmed} confirmed"
                        )
```

- [ ] **Step 4: Smoke-run**

```bash
python3 -c "from ai_xss_generator.active import worker; print('ok')"
```

- [ ] **Step 5: Commit**

```bash
git add ai_xss_generator/active/worker.py
git commit -m "feat: add -vv triage and Tier 3 debug lines to GET path"
```

---

### Task 5: GET path — `-v` summary via `_v_steps` tracker

**Files:**
- Modify: `ai_xss_generator/active/worker.py` — GET context loop (lines ~1260–1931)

- [ ] **Step 1: Initialize `_v_steps` at the top of the context loop**

Find the line `context_done = False` (around line 1259, inside `for _pname, context_type, variants`). After it, add:

```python
                _v_steps: list[str] = []  # -v summary tokens for this context
```

- [ ] **Step 2: Append Tier 1 token**

After the Tier 1 fire loop (same location as the `-vv` Tier 1 results line added in Task 3 Step 3), add:

```python
                    # -v: Tier 1 outcome token
                    if not tier1_candidates:
                        _v_steps.append("T1:skip(no-cands)")
                    elif context_done:
                        _v_steps.append("T1:CONFIRMED")
                    else:
                        _v_steps.append("T1:miss")
```

- [ ] **Step 3: Append Tier 1.5 token**

After the `-vv` Tier 1.5 results line (Task 3 Step 4, second insertion), add:

```python
                        # -v: Tier 1.5 outcome token
                        if context_done:
                            _v_steps.append("T1.5:CONFIRMED")
                        else:
                            _v_steps.append("T1.5:miss")
```

- [ ] **Step 4: Append triage tokens**

For the **`fast_omni` bypass** (before the cloud block, at `if context_type == "fast_omni":`), add before the `cloud_escalated = True` line:
```python
                    # -v: fast_omni skips triage entirely
                    if context_type == "fast_omni":
                        _v_steps.append("triage:skip(omni)")
```

For the **local model ran** case (after the `-vv` triage result line from Task 4 Step 1):
```python
                        # -v: triage outcome token
                        if _triage_approved:
                            # distinguish fast-mode short-circuit from real escalation
                            if mode in ("fast", "normal"):
                                _v_steps.append("triage:skip(fast)")
                            else:
                                _v_steps.append("triage:escalate")
                        else:
                            _v_steps.append(f"triage:block(score={_triage.score})")
```

For the **`skip_triage=True` deep mode** case (after the `-vv` skip line from Task 4 Step 1):
```python
                        # -v: skip_triage token
                        _v_steps.append("triage:skip(flag)")
```

- [ ] **Step 5: Append normal scout and deep T3 tokens**

After the `-vv` normal scout fire result line (Task 4 Step 2):
```python
                        # -v: normal scout token
                        _v_steps.append("T3-scout:CONFIRMED" if context_done else "T3-scout:miss")
```

After the `-vv` deep cloud fire result line (Task 4 Step 3):
```python
                        # -v: deep T3 token
                        _v_steps.append("Deep-T3:CONFIRMED" if context_done else "Deep-T3:miss")
```

- [ ] **Step 6: Print `-v` summary at bottom of context loop body**

The context loop body ends with the seed pool promotion block (around line 1930, the `try: ... SeedPool()...except Exception: pass` block). Add the following **after** that entire try/except block, as the last statement inside `for _pname, context_type, variants`:

```python
                # -v: emit per-context summary line
                if _v_steps:
                    # Append timeout token when a timeout cut the context short mid-tier.
                    # Only append when the last token implies more tiers should have followed.
                    # NOTE: wrap both sub-conditions in _timed_out() — operator precedence
                    # means `and` binds tighter than `or`, so the entire OR must be inside.
                    if _timed_out() and (
                        _v_steps[-1] in ("T1:miss", "T1.5:miss")
                        or _v_steps[-1].startswith("triage:")
                    ):
                        _v_steps.append("timeout")
                    _v_label = f"GET ?{_trunc(param_name, 20)} [{context_type}]"
                    _console.verbose(f"{_v_label} {' → '.join(_v_steps)}")
```

- [ ] **Step 7: Smoke-run**

```bash
python3 -c "from ai_xss_generator.active import worker; print('ok')"
```

- [ ] **Step 8: Commit**

```bash
git add ai_xss_generator/active/worker.py
git commit -m "feat: add -v per-context summary (_v_steps tracker) to GET path"
```

---

### Task 6: POST path — mirror Tasks 3–5

**Files:**
- Modify: `ai_xss_generator/active/worker.py` — POST context loop (lines ~4050–4360)

The POST path is structurally identical to GET. The anchor variables have `post_` prefixes:
- `post_tier1_candidates` instead of `tier1_candidates`
- `post_tier15_mutations` instead of `tier15_mutations`
- `_post_tier1_failed_payloads`, `_post_tier15_failed_payloads`
- Target label: `POST {_trunc(post_form.action_url.split("?")[0].rsplit("/", 2)[-1] or post_form.action_url, 30)}` — use the last path segment of the action URL as the display label, e.g. `POST /search`

- [ ] **Step 1: Add all `-vv` Tier 1 lines to POST path**

Replicate the same insertions from Task 3 Steps 1–4, substituting `post_tier1_candidates`, `post_tier15_mutations`, `_post_t1_surviving`, `tier1_seeds` (same variable name in POST), and the `POST` prefix in all debug strings.

- [ ] **Step 2: Add all `-vv` triage and Tier 3 lines to POST path**

Find the POST triage gate (around line 4198: `# Local model triage gate for POST params`). Replicate the insertions from Task 4 Steps 1–3 with `POST` prefix.

Find the POST normal scout call (around line 4300 — look for `generate_normal_scout` inside the POST block). Add the same scout debug lines from Task 4 Step 2.

Find the POST deep T3 hint block (look for `_post_deep_strategy_hint` or the `_post_tier1_failed_payloads + _post_tier15_failed_payloads` assembly). Add deep T3 debug lines from Task 4 Step 3.

- [ ] **Step 3: Add `_v_steps` tracker to POST context loop**

Find the top of the POST context loop (look for `for _pname, context_type, variants in post_param_variants:` — the POST equivalent of the GET loop). Initialize `_v_steps: list[str] = []` there.

Replicate all token-append steps from Task 5 Steps 2–5, using `post_tier1_candidates`, `post_tier15_mutations`, and the `POST` label prefix.

For the **`fast_omni` bypass** in POST: search for `if context_type == "fast_omni":` inside the POST context loop. Add `_v_steps.append("triage:skip(omni)")` just before `cloud_escalated = True` in that block — same as Task 5 Step 4 first bullet.

Print the summary line at the end of the POST context loop body using the same corrected timeout guard from Task 5 Step 6:
```python
                if _v_steps:
                    if _timed_out() and (
                        _v_steps[-1] in ("T1:miss", "T1.5:miss")
                        or _v_steps[-1].startswith("triage:")
                    ):
                        _v_steps.append("timeout")
                    _v_label = f"POST {_trunc(_post_label, 30)} [{context_type}]"
                    _console.verbose(f"{_v_label} {' → '.join(_v_steps)}")
```
Where `_post_label` is computed once before the context loop: `_post_label = post_form.action_url.split("?")[0].rsplit("/", 1)[-1] or post_form.action_url`.

- [ ] **Step 4: Smoke-run**

```bash
python3 -c "from ai_xss_generator.active import worker; print('ok')"
```

- [ ] **Step 5: Commit**

```bash
git add ai_xss_generator/active/worker.py
git commit -m "feat: add -v/-vv pipeline debug lines to POST path"
```

---

### Task 7: DOM path — `-vv` taint discovery and `-v` URL summary

**Files:**
- Modify: `ai_xss_generator/active/worker.py` — `_run_dom()` function (lines ~2876–3200)

The DOM path is architecturally different: there is no Tier 1/1.5 (no reflection probing). Instead: taint discovery runs once per URL, then per-hit local model → triage → cloud.

- [ ] **Step 1: Add `-vv` taint discovery line after `discover_dom_taint_paths()` returns (~line 2948)**

Find `dom_hits = sorted(dom_hits, key=_dom_hit_priority)`. After it, add:

```python
    # -vv: taint discovery result
    _dom_url_label = _trunc(url.split("?")[0].rsplit("/", 1)[-1] or url, 30)
    if dom_hits:
        _console.debug(
            f"DOM {_dom_url_label} Taint discovery: {len(dom_hits)} paths found"
        )
    else:
        _console.debug(
            f"DOM {_dom_url_label} Taint discovery: 0 paths — no DOM XSS surface"
        )
```

- [ ] **Step 2: Initialize per-URL `-v` tracking**

Just before the `for hit in dom_hits:` loop (around line 3013), add:

```python
    _dom_v_confirmed = False
    _dom_v_taint_count = len(dom_hits)
```

- [ ] **Step 3: Add per-hit `-vv` triage and cloud lines inside `for hit in dom_hits:`**

Inside the hit loop, find where the local model is called (`_get_dom_local_payloads`). After it returns, add:
```python
                # -vv: DOM local model result
                _hit_label = f"{_trunc(hit.source_name or hit.source_type, 15)}→{_trunc(hit.sink, 15)}"
                _dom_local_top = _trunc(local_payloads[0] if local_payloads else "", 50)
                _console.debug(
                    f"DOM {_hit_label} Local: {len(local_payloads)} payloads | top: \"{_dom_local_top}\""
                )
```

Find where `_triage_with_local_model` is called in the DOM path. After it, add triage debug lines (same pattern as Task 4 Step 1, with `DOM {_hit_label}` prefix).

Find where `_get_dom_cloud_payloads` is called. After it returns, add:
```python
                # -vv: DOM cloud payloads
                _dom_cloud_top = _trunc(cloud_payloads[0] if cloud_payloads else "", 50)
                _console.debug(
                    f"DOM {_hit_label} Cloud: {len(cloud_payloads)} payloads | top: \"{_dom_cloud_top}\""
                )
```

After the DOM cloud fire loop, add:
```python
                # -vv: DOM cloud fire result
                _dom_cloud_confirmed_n = 1 if confirmed else 0
                _console.debug(
                    f"DOM {_hit_label} Cloud: fired {len(cloud_payloads)} → {_dom_cloud_confirmed_n} confirmed"
                )
                if confirmed:
                    _dom_v_confirmed = True
```

- [ ] **Step 4: Print `-v` URL-level summary after `for hit in dom_hits:` loop ends**

After the `for hit in dom_hits:` loop (before the `findings` result assembly), add:

```python
    # -v: DOM URL-level summary
    _dom_outcome = "CONFIRMED" if _dom_v_confirmed else ("miss" if _dom_v_taint_count else "0 paths")
    _console.verbose(f"DOM {_dom_url_label} taint:{_dom_v_taint_count} paths → {_dom_outcome}")
```

- [ ] **Step 5: Smoke-run**

```bash
python3 -c "from ai_xss_generator.active import worker; print('ok')"
```

- [ ] **Step 6: Commit**

```bash
git add ai_xss_generator/active/worker.py
git commit -m "feat: add -v/-vv pipeline debug lines to DOM path"
```

---

### Task 8: Full verification pass

- [ ] **Step 1: Run the full test suite**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate
pytest tests/ -x -q --ignore=tests/test_network_live.py
```

Expected: 242 passed, 0 failed.

- [ ] **Step 2: Manual `-v` smoke test against a known target**

```bash
python3 axss.py scan -u "https://euhyngyk.xssy.uk/target.ftl" -v --deep
```

Expected: `[>] GET ?... [...] T1:miss → T1.5:miss → triage:escalate → Deep-T3:...` style lines appear after each param/context finishes. No `[.]` debug lines.

- [ ] **Step 3: Manual `-vv` smoke test**

```bash
python3 axss.py scan -u "https://euhyngyk.xssy.uk/target.ftl" -vv --deep
```

Expected: `[.] GET ?... [...] Tier 1: N candidates | top: "..."` style lines appear in real time as each tier fires. `[>]` summary lines also appear (since `-vv` implies VERBOSE_LEVEL=2 which is ≥ 1).

- [ ] **Step 4: Final commit if any fixups needed**

```bash
git add -p
git commit -m "fix: -v/-vv verbosity fixups from manual verification"
```
