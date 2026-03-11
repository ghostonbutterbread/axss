# Verified Learning Architecture

## Goal

Make `axss` learn from evidence without poisoning future generations with unverified guesses.

The system now has two complementary memory paths:

- findings memory
  Exact payload evidence and exploit outcomes.
- lesson memory
  Reusable logic, filter, and mapping observations.

## Memory tiers

- `curated`
  Hand-authored or manually reviewed findings. Highest trust.
- `verified-runtime`
  Payloads confirmed during active scans or other browser-verified execution paths.
- `experimental`
  Offline-generated or otherwise unverified candidates. Useful for review, not trusted retrieval.

## Promotion rules

- Active scan confirmations are promoted directly into `verified-runtime`.
- Offline `xssy/learn.py` generations are stored as `experimental`.
- Duplicate findings are merged.
  Higher-trust tiers upgrade lower-trust entries instead of creating parallel records.

## Retrieval rules

- Default retrieval only uses `curated` and `verified-runtime`.
- `experimental` findings are excluded from normal prompt context unless a caller explicitly opts in.
- Retrieval stays hybrid and structured:
  exact sink/context matches first, surviving-char overlap second, tier confidence last.
- Retrieval is target-aware:
  host-scoped findings only apply back to the same host, while global findings can transfer across targets.
- Retrieval also scores landscape matches:
  WAF, delivery mode, framework hints, and auth context all influence ranking.

## Lesson memory

Lesson memory lives in `~/.axss/lessons/` and stores three kinds of reusable observations:

- `xss_logic`
  Reflection logic such as `html_attr_url`, `js_string_dq`, or `html_body`.
- `filter`
  Surviving and blocked probe characters for a confirmed reflection.
- `mapping`
  Non-payload application hints: forms, authenticated workflows, framework-rendered surfaces, and DOM-source presence.

Active probe observations are trusted runtime lessons because they describe what the application actually did, even when no payload executed. Offline lab parsing writes experimental mapping lessons.

## Memory fingerprint

Each finding can carry a reusable fingerprint:

- sink type
- context type
- surviving chars
- target scope (`host` or `global`)
- WAF name
- delivery mode (`get`, `post`, `offline`, etc.)
- framework hints
- auth requirement

## File ownership

- `xssy/learn.py`
  Offline lab runner. Generates experimental findings and mapping lessons.
- `ai_xss_generator/active/worker.py`
  Runtime promotion path for verified findings and probe-derived logic/filter lessons.
- `ai_xss_generator/findings.py`
  Persistent store, merge rules, retrieval policy.
- `ai_xss_generator/learning.py`
  Shared constructors for promoted findings.
- `ai_xss_generator/lessons.py`
  Lesson storage, extraction, and retrieval for logic/filter/mapping memory.

## Review workflow

- `axss --memory-review`
  Open the interactive review inbox for pending experimental memory items.
- `axss --memory-list`
  Show the current pending queue as a table without entering the interactive flow.
- `--memory-review [all|labs|targets]`
  The source filter is inline on the review command and defaults to `all`.
- `--memory-list [all|labs|targets]`
  The source filter is inline on the list command and defaults to `all`.
- `--memory-stats [all|labs|targets]`
  The source filter is inline on the stats command and defaults to `all`.
- `axss --memory-show <id>`
  Inspect one memory item in full.
- `axss --memory-promote <id> --memory-tier curated --memory-scope global`
  Promote a reviewed memory item into trusted memory.
- `axss --memory-reject <id>`
  Mark a memory item as rejected so it leaves the queue.

## Re-entry guidance

Future work should preserve these invariants:

`generated payload != learned fact`

`observed reflection/filter behavior == valid lesson`

Only verified execution or curated review should produce trusted memory.
