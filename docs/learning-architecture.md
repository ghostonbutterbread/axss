# Learning Architecture

## Design goals

- Learn generalizable XSS bypass patterns across scans without accumulating noise
- Keep scan performance fast — no disk I/O on the hot path
- No manual review queue — only deliberately curated findings enter the knowledge base

## Two-tier model

### Curated findings (persisted, global)

Stored in SQLite at `~/.axss/knowledge.db`.
All entries are globally scoped — no per-host partitioning.
Indexed by `context_type`, `bypass_family`, `waf_name`, `delivery_mode` for fast retrieval.

Populated two ways:
1. **Seed scripts** (`xssy/seed_*.py`) — hand-curated lab knowledge written directly to the store
2. **Curation pipeline** (`xssy/curate.py`) — LLM extracts a structured finding from lab payloads and saves it

Retrieval scores candidates by: context_type / sink_type match, surviving chars overlap,
WAF name, delivery mode, framework hints, and auth context.

### Session lessons (ephemeral, in-memory)

`Lesson` objects built by `ai_xss_generator/lessons.py` from probe results during a scan.
They carry three kinds of observations:

- `xss_logic` — reflection context type detected by probing (e.g. `html_attr_value`, `js_string_dq`)
- `filter` — surviving and blocked probe characters for a confirmed reflection sink
- `mapping` — application hints: forms, authenticated surfaces, framework-rendered DOM, source presence

Lessons are passed directly into the payload generation prompt as context and discarded
when the scan ends. Nothing is written to disk.

## Curation pipeline (`xssy/curate.py`)

```
lab HTML → parse_target() → generate_payloads() → curate_lab_finding()
                                                          │
                                              configured AI backend
                                         (cli_tool=claude/codex or api)
                                                          │
                                              structured Finding JSON
                                                          │
                                              save_finding() → SQLite
```

`curate_lab_finding()` sends the top candidate payloads + parsed page context to the
configured AI backend (same `ai_backend` / `cli_tool` / `cloud_model` as scanning),
asks it to describe the best bypass technique as a structured finding, and saves the
result with a confidence < 1.0 (not browser-confirmed).

## Storage layout

```
~/.axss/
  knowledge.db          SQLite — curated_findings table (WAL mode)
  config.json           AppConfig (ai_backend, cli_tool, cloud_model, ...)
  keys                  API keys (openrouter_api_key, openai_api_key, xssy_jwt, ...)
  .jsonl_migrated       Sentinel: one-time migration of old JSONL partitions complete
  findings/             (legacy JSONL backup — not used after migration)
```

## CLI memory commands

| Command | Description |
|---------|-------------|
| `axss --memory-list` | Show all curated findings |
| `axss --memory-stats` | Count findings by context type |
| `axss --memory-export PATH` | Export all findings to JSON file |
| `axss --memory-import PATH` | Import findings from JSON file |

## File ownership

| File | Role |
|------|------|
| `ai_xss_generator/store.py` | SQLite backend (schema, CRUD, migration) |
| `ai_xss_generator/findings.py` | `Finding` dataclass, retrieval scoring, public API |
| `ai_xss_generator/lessons.py` | Ephemeral `Lesson` objects, prompt formatting |
| `ai_xss_generator/learning.py` | `build_memory_profile()` — context fingerprinting |
| `xssy/curate.py` | LLM curation pipeline — extracts Finding from lab payloads |
| `xssy/learn.py` | Lab runner — fetch → parse → generate → curate |
| `xssy/seed_*.py` | Hand-curated seed findings written directly to the store |
| `ai_xss_generator/active/worker.py` | Builds session lessons from probe results, passes to generation |

## Invariants

- `generated payload ≠ curated fact` — only LLM-extracted structured findings enter the store
- `observed filter behaviour == valid session lesson` — probe results inform generation immediately
- Confirmed XSS goes to the scan report, not the knowledge base
- All curated findings are global — no target-host contamination
