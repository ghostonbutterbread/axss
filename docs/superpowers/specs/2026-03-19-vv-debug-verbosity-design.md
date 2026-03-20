# Design: `-v` / `-vv` Pipeline Visibility

**Date:** 2026-03-19
**Branch:** feat/payload-pipeline-restructure
**Status:** Approved

## Problem

The payload pipeline tiers (Tier 1 deterministic, Tier 1.5 mutations, Tier 2 local triage, Tier 3 cloud scout) produce almost no visible output during a scan. Only error paths are logged. The happy path — payloads fired, seeds ranked, triage decision, escalation to cloud — is completely silent.

When a scan produces no findings, there is no way to tell whether the issue is:
- The context dispatch returned zero candidates (bad context detection)
- All payloads were char-filtered before firing (surviving_chars too restrictive)
- Triage blocked escalation (local model scored too low)
- Cloud was reached but returned weak payloads
- Payloads fired but the WAF blocked them all

This makes iterative debugging require code instrumentation. The fix is structured per-tier output at `-v` and `-vv`.

## Goals

- `-v`: High-level tier progression and escalation outcome per param/context. One line per context on completion. No payload content. Good for a quick audit of what happened.
- `-vv`: Full real-time stream at each tier boundary. Includes payload counts, top seed shown (truncated to ~50 chars), triage score/reason, blocked_on chars for deep mode. Good for live debugging in a split terminal (tmux).
- No logic changes — purely additive display lines.
- No new tests required — display-only output.

## Console Infrastructure

### New function: `console.verbose()`

Add to `ai_xss_generator/console.py`:

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

Uses `[>]` in DIM — visually distinct from the existing `[~]` magenta used by `info()` and the `[.]` dim used by `debug()`. DIM groups it visually as secondary output (less prominent than `[*]`/`[+]` but more prominent than `[.]`).

The existing `console.debug()` is already gated at `VERBOSE_LEVEL >= 2` and prints `[.]` in dim. No changes needed there.

`VERBOSE_LEVEL` is set in the main process before workers are forked (Linux fork inherits global state), so both functions work correctly inside worker processes without any additional wiring.

### Helper: `_trunc(s, n)`

Add to `worker.py` as a module-level private helper:

```python
def _trunc(s: str, n: int = 50) -> str:
    return s if len(s) <= n else s[:n] + "…"
```

Applied to: payload strings (n=50), param names (n=20), URL path components (n=30), triage reason strings (n=60). Keeps lines readable in narrow tmux panes.

## `-v` Output: Per-Context Summary Line

Printed once per (param, context_type) combination when that context's loop exits — after all tiers have run for that context.

A local list `_v_steps` is built during the context loop, appending tier outcome tokens as they complete. Joined with ` → ` and printed via `console.verbose()` at exit. Using a list avoids fragile string concatenation across many conditionals.

### Format

```
[>] GET ?{param} [{context_type}] {tier_chain}
[>] POST {path} [{context_type}] {tier_chain}
[>] DOM {source}→{sink} {tier_chain}
```

### `tier_chain` examples

```
T1:CONFIRMED
T1:miss → T1.5:miss → triage:block(score=3)
T1:miss → T1.5:miss → triage:skip(fast) → T3-scout:miss
T1:miss → T1.5:miss → triage:skip(flag) → Deep-T3:miss
T1:miss → T1.5:miss → triage:escalate → T3-scout:CONFIRMED
T1:miss → T1.5:miss → triage:escalate → Deep-T3:miss
T1:miss → timeout
```

For DOM:
```
taint:0 paths
triage:block(score=2)
triage:escalate → cloud:CONFIRMED
triage:escalate → cloud:miss
```

### State tracking rules

A local list `_v_steps: list[str]` is initialized at the top of each (param, context_type) loop iteration.

**Tier 1:** Append `"T1:CONFIRMED"` if any Tier 1 payload confirmed, else `"T1:miss"`. If `payloads_for_context()` returned empty, append `"T1:skip(no-cands)"` and do not append Tier 1.5 or triage tokens. `T1:skip(no-cands)` is a terminal token — suppress the timeout append (see below) when this is the last step.

**Tier 1.5:** Append `"T1.5:CONFIRMED"` or `"T1.5:miss"`. Skip if not reached.

**Triage:** Four variants:
- `context_type == "fast_omni"` → append `"triage:skip(omni)"` — this path bypasses the triage gate entirely and goes straight to cloud (line 1434: `if context_type != "fast_omni" and escalation_policy.use_local`). Same applies in the POST path.
- `_triage_with_local_model()` ran → append `"triage:escalate"` or `"triage:block(score=N)"`
- `fast_mode=True` caused the internal short-circuit (normal mode) → append `"triage:skip(fast)"`
- `skip_triage=True` in deep mode → append `"triage:skip(flag)"`

**Normal Tier 3 scout:** Append `"T3-scout:CONFIRMED"` or `"T3-scout:miss"`.

**Deep Tier 3 cloud:** Append `"Deep-T3:CONFIRMED"` or `"Deep-T3:miss"`.

**Timeout:** Check `_timed_out()` just before printing the summary line. If true AND the last token in `_v_steps` is one that implies more tiers should have followed (i.e., `"T1:miss"`, `"T1.5:miss"`, or any `"triage:*"` token), append `"timeout"`. Do NOT append `"timeout"` when the last token is `"T1:skip(no-cands)"`, `"T1:CONFIRMED"`, `"T1.5:CONFIRMED"`, `"T3-scout:CONFIRMED/miss"`, or `"Deep-T3:CONFIRMED/miss"` — those are already terminal outcomes.

**Print placement:** Place the `console.verbose()` call at the bottom of the `for (param_name, context_type, variants)` loop body, outside all tier `if` blocks, so it executes on every iteration including early exits via `context_done`. Do not rely on a `finally` block — none exists at this scope. Build the output as two parts joined with a space (not ` → `):

```python
_label = f"GET ?{_trunc(param_name, 20)} [{context_type}]"
_chain = " → ".join(_v_steps)
console.verbose(f"{_label} {_chain}")
```

The label prefix is a fixed string; only `_v_steps` tokens are joined with ` → `.

## `-vv` Output: Inline Per-Tier Lines

Printed via `console.debug()` at each tier boundary. These fire in real time as the scan progresses — suitable for watching in a tmux split.

All variable-length fields are truncated via `_trunc()` to stay readable in narrow panes.

### GET path

| Trigger | Line emitted |
|---|---|
| After `payloads_for_context()` | `[.] GET ?{param} [{ctx}] Tier 1: {n} candidates \| top: "{top50}"` |
| After `payloads_for_context()` returns empty | `[.] GET ?{param} [{ctx}] Tier 1: 0 candidates — context not dispatched` |
| After HTTP pre-rank loop | `[.] GET ?{param} [{ctx}] Pre-rank: {r}/{c} reflect \| top: "{top50}"` |
| After pre-rank with 0 reflecting | `[.] GET ?{param} [{ctx}] Pre-rank: 0/{c} reflect — order unchanged` |
| After Tier 1 fire loop | `[.] GET ?{param} [{ctx}] Tier 1: fired {n} → {confirmed} confirmed` |
| After `mutate_seeds()` | `[.] GET ?{param} [{ctx}] Tier 1.5: {n} mutations from {s} seeds \| top: "{top50}"` |
| After Tier 1.5 fire loop | `[.] GET ?{param} [{ctx}] Tier 1.5: fired {n} → {confirmed} confirmed` |
| After triage (`_triage_with_local_model()` ran) | `[.] GET ?{param} [{ctx}] Triage: score={score} escalate={YES/NO} \| {reason60}` |
| After triage fast-mode short-circuit | `[.] GET ?{param} [{ctx}] Triage: skipped (fast mode) — auto-escalate` |
| After triage `skip_triage` flag (deep mode) | `[.] GET ?{param} [{ctx}] Triage: skipped (--skip-triage) — auto-escalate` |
| After `generate_normal_scout()` | `[.] GET ?{param} [{ctx}] Tier 3 scout: {n} payloads \| top: "{top50}"` |
| After scout fire loop | `[.] GET ?{param} [{ctx}] Tier 3 scout: fired {n} → {confirmed} confirmed` |
| After `_deep_strategy_hint` assembled | `[.] GET ?{param} [{ctx}] Deep Tier 3: {n} failures → top 5 to cloud (blocked on {chars})` |
| After deep cloud fire loop | `[.] GET ?{param} [{ctx}] Deep Tier 3: fired {n} → {confirmed} confirmed` |

### POST path

Identical structure to GET. Prefix is `POST {path}` where `{path}` is the action URL path component (truncated to 30 chars).

### DOM path

DOM does not have Tier 1/1.5 — different architecture (taint path analysis, not reflection probing).

| Trigger | Line emitted |
|---|---|
| After `discover_dom_taint_paths()` returns | `[.] DOM {url30} Taint discovery: {n} paths found` |
| When `n == 0` (no taint paths) | `[.] DOM {url30} Taint discovery: 0 paths — no DOM XSS surface` |
| After local model call per taint path | `[.] DOM {source}→{sink} Local: {n} payloads \| top: "{top50}"` |
| After triage per taint path | `[.] DOM {source}→{sink} Triage: score={score} escalate={YES/NO} \| {reason60}` |
| After cloud model call | `[.] DOM {source}→{sink} Cloud: {n} payloads \| top: "{top50}"` |
| After cloud fire loop | `[.] DOM {source}→{sink} Cloud: fired {n} → {confirmed} confirmed` |

The DOM `-v` summary line is emitted once per URL (not per taint path), after all taint paths are processed:
```
[>] DOM {url30} taint:{n} paths → {overall_outcome}
```
Where `overall_outcome` is `CONFIRMED` if any taint path confirmed, else `miss` or `0 paths`.

## Files Changed

| File | Change |
|---|---|
| `ai_xss_generator/console.py` | Add `verbose()` function using `[>]` DIM prefix |
| `ai_xss_generator/active/worker.py` | Add `console` import; add `_trunc()` helper; add `console.debug()` calls at each tier boundary in GET/POST/DOM paths; add `_v_steps` list tracker + `console.verbose()` summary at context exit |

## Out of Scope

- Upload worker path — lower priority, can be added later
- Modifying existing `log.debug()` calls — those go to Python's logging system (file handler at `-vv`), not the terminal. They stay as-is.
- Any logic change to tier firing, triage, or escalation decisions
- DOM exception-exit path (`discover_dom_taint_paths()` throws before any taint paths are processed) — the error is already surfaced via `WorkerResult(status="error")`. No additional verbose line needed there.
