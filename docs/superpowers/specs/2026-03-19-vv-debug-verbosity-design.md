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
    """[~] Verbose output — printed at -v (VERBOSE_LEVEL >= 1)."""
    if VERBOSE_LEVEL < 1:
        return
    _before_print()
    prefix = _c(MAGENTA, "[~]") if _tty() else "[~]"
    print(f"{prefix} {message}", flush=True)
    _after_print()
```

The existing `console.debug()` is already gated at `VERBOSE_LEVEL >= 2` and prints `[.]` in dim. No changes needed there.

`VERBOSE_LEVEL` is set in the main process before workers are forked (Linux fork inherits global state), so both functions work correctly inside worker processes without any additional wiring.

## `-v` Output: Per-Context Summary Line

Printed once per (param, context_type) combination when that context's loop exits — after all tiers have run for that context.

A small state string is assembled during the context loop, appending tier outcomes as they complete. Printed via `console.verbose()` at exit.

### Format

```
[~] GET ?{param} [{context_type}] {tier_chain}
[~] POST {action_url} [{context_type}] {tier_chain}
[~] DOM {source}→{sink} {tier_chain}
```

### `tier_chain` examples

```
T1:CONFIRMED
T1:miss → T1.5:miss → triage:block(score=3)
T1:miss → T1.5:miss → triage:escalate → T3-scout:miss
T1:miss → T1.5:miss → triage:escalate → T3-scout:CONFIRMED
T1:miss → T1.5:miss → triage:escalate → Deep-T3:miss
T1:miss → T1.5:CONFIRMED
```

For DOM:
```
triage:escalate → cloud:miss
triage:block(score=2)
cloud:CONFIRMED
```

### State tracking

A local string variable (e.g. `_v_chain`) is built up in the context loop:
- Append `"T1:CONFIRMED"` or `"T1:miss"` after the Tier 1 fire loop
- Append `"→ T1.5:CONFIRMED"` or `"→ T1.5:miss"` after the Tier 1.5 fire loop
- Append `"→ triage:block(score=N)"` or `"→ triage:escalate"` after triage
- Append `"→ T3-scout:CONFIRMED"` / `"→ T3-scout:miss"` after normal scout fire loop
- Append `"→ Deep-T3:CONFIRMED"` / `"→ Deep-T3:miss"` after deep cloud fire loop
- Print `console.verbose(f"GET ?{param_name} [{context_type}] {_v_chain}")` at context loop exit

Early exit (context_done mid-tier) still prints the chain built so far — the confirmed tier is visible.

## `-vv` Output: Inline Per-Tier Lines

Printed via `console.debug()` at each tier boundary. These fire in real time as the scan progresses — suitable for watching in a tmux split.

Payload strings are truncated to 50 characters to stay readable in narrow panes.

### GET path

| Trigger | Line emitted |
|---|---|
| After `payloads_for_context()` | `[.] GET ?{param} [{ctx}] Tier 1: {n} candidates \| top: "{top50}"` |
| After HTTP pre-rank loop | `[.] GET ?{param} [{ctx}] Pre-rank: {r}/{c} reflect \| top reflecting: "{top50}"` |
| After Tier 1 fire loop | `[.] GET ?{param} [{ctx}] Tier 1: fired {n} → {confirmed} confirmed` |
| After `mutate_seeds()` | `[.] GET ?{param} [{ctx}] Tier 1.5: {n} mutations from {s} seeds \| top: "{top50}"` |
| After Tier 1.5 fire loop | `[.] GET ?{param} [{ctx}] Tier 1.5: fired {n} → {confirmed} confirmed` |
| After `_triage_with_local_model()` | `[.] GET ?{param} [{ctx}] Triage: score={score} escalate={YES/NO} \| {reason}` |
| After `generate_normal_scout()` | `[.] GET ?{param} [{ctx}] Tier 3 scout: {n} payloads \| top: "{top50}"` |
| After scout fire loop | `[.] GET ?{param} [{ctx}] Tier 3 scout: fired {n} → {confirmed} confirmed` |
| After `_deep_strategy_hint` assembled | `[.] GET ?{param} [{ctx}] Deep Tier 3: {n} failures → top 5 to cloud (blocked on {chars})` |
| After deep cloud fire loop | `[.] GET ?{param} [{ctx}] Deep Tier 3: fired {n} → {confirmed} confirmed` |

When pre-rank produces zero reflecting payloads: `Pre-rank: 0/{c} reflect — no HTTP pre-filter applied`.

When `payloads_for_context()` returns empty: `Tier 1: 0 candidates (context not dispatched)`.

### POST path

Identical structure to GET. Prefix is `POST` and target label uses the action URL's path component (e.g. `POST /search`).

### DOM path

DOM does not have Tier 1/1.5 — different architecture (taint path analysis, not reflection probing).

| Trigger | Line emitted |
|---|---|
| After local model call | `[.] DOM {source}→{sink} Local: {n} payloads \| top: "{top50}"` |
| After triage | `[.] DOM {source}→{sink} Triage: score={score} escalate={YES/NO} \| {reason}` |
| After cloud model call | `[.] DOM {source}→{sink} Cloud: {n} payloads \| top: "{top50}"` |
| After cloud fire loop | `[.] DOM {source}→{sink} Cloud: fired {n} → {confirmed} confirmed` |

## Files Changed

| File | Change |
|---|---|
| `ai_xss_generator/console.py` | Add `verbose()` function (~5 lines) |
| `ai_xss_generator/active/worker.py` | Add `console` import; add `console.debug()` calls at each tier boundary in GET/POST/DOM paths; add `_v_chain` state tracker + `console.verbose()` summary at context exit |

## Out of Scope

- Upload worker path — lower priority, can be added later
- Modifying existing `log.debug()` calls — those go to Python's logging system (file handler at `-vv`), not the terminal. They stay as-is.
- Any logic change to tier firing, triage, or escalation decisions
