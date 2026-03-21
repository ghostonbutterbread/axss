---
name: Future Feature — Active Recon Mode
description: Planned enhancement to --interesting flag for active page fetching, sink detection, and canary reflection — serves both automated pre-filtering and manual researcher recon reports
type: project
---

Enhance `--interesting` from static URL string scoring to active recon pass.

**Why:** Current --interesting scores URLs from URL strings only (parameter names, path shape). No ground truth. Active mode would fetch pages, run parser.py, fire canary strings, and feed real context to the AI scorer.

**Dual purpose:**
1. Automated pre-filter: fast → interesting --fetch → normal mode workflow for large URL lists
2. Manual research aid: recon report with framework fingerprint, reflected params, sink inventory, form surfaces — enough for a human researcher to immediately understand the XSS surface

**How to apply:** When user asks about recon, pre-scanning, or improving --interesting, reference this feature. Spec stub at `docs/superpowers/specs/future-active-recon-interesting.md`.

**Why deferred:** Out of scope for payload pipeline restructure. Standalone spec needed.
