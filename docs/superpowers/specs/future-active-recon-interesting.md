# Future Spec: Active Recon Mode (`--interesting --fetch`)

**Status:** Future — not yet designed or implemented
**Depends on:** Payload pipeline restructure (2026-03-19 spec)

---

## Problem

The current `--interesting` flag does static URL string analysis only. The AI
scores URLs based on parameter names and path shape — no ground truth about
what the application actually does. This produces educated guesses, not evidence.

---

## Vision

A lightweight active recon pass that gives both the scanner and manual researchers
a full contextual picture of the target before any payload work begins.

**Dual purpose:**
1. **Automated:** Pre-filter large URL lists so normal/deep mode works on
   high-value targets only. Fast → interesting → normal is the intended workflow.
2. **Manual research aid:** Produce a recon report rich enough that a human
   researcher can immediately understand the application's XSS surface — frameworks
   detected, reflected params, sink types, form structures, likely stored XSS paths.

---

## Proposed Behavior (`--interesting FILE --fetch`)

For each URL in the input list:

1. **Fetch** the page via HTTP (Scrapling, no Playwright — fast and cheap)
2. **Parse** the response with `parser.py` — detect sinks, input fields, param names
3. **Canary reflection check** — fire a short unique canary string into each param,
   check if it appears in the response body (lightweight, no execution detection)
4. **Enrich the AI scorer** with real context:
   - Detected frameworks
   - Confirmed reflected params + reflection context type
   - Sink types found in page (innerHTML, document.write, etc.)
   - Form actions and field names
   - WAF detected (if any)

**Output additions to `InterestingUrl`:**
- `reflected_params: list[str]` — params confirmed to reflect
- `reflection_contexts: dict[str, str]` — param → context_type
- `sinks_detected: list[str]` — sink types found in page
- `frameworks: list[str]` — detected frameworks
- `forms: int` — number of forms detected
- `waf: str | None` — detected WAF

---

## Recon Report

Beyond the scored URL list, produce a separate recon summary:
- Per-domain sink inventory
- Reflected parameter map across all URLs
- Framework/technology fingerprint
- Recommended scan strategy per URL cluster

This report should be useful to a manual researcher picking up the tool's
output — they should be able to read it and immediately know where to look.

---

## Implementation Notes

- Canary reflection check can reuse `probe.py` logic (stripped down, no char probing)
- Parser already handles sink/form detection — just needs to be called per URL
- WAF detection already in `waf_detect.py`
- Rate limiting: respect `--rate` flag — this mode can be slow on large lists;
  consider a `--fetch-workers N` flag for parallelism
- Playwright not needed for the fetch phase — only for JS-heavy SPAs (opt-in)
