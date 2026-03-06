# axss

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![Ollama](https://img.shields.io/badge/Ollama-local%20runtime-111111?logo=ollama&logoColor=white)
![Qwen3.5](https://img.shields.io/badge/Qwen3.5-4B%20%7C%209B%20%7C%2027B%20%7C%2035B-0F766E)

`axss` is a context-aware XSS recon CLI that parses target HTML, detects likely DOM sinks and framework fingerprints, then generates ranked payloads with an Ollama-first Qwen3.5 workflow plus heuristic fallback.

Live crawling now uses a quiet Scrapy spider with selector-based parsing, which makes multi-URL recon less noisy and scales better than the earlier BeautifulSoup fetch path.

## Why Qwen3.5

Qwen3.5 is a strong default for this project because the task is not just "write an XSS string." It has to read HTML, follow JavaScript context, notice framework clues, and mutate payloads toward likely execution paths.

- Better reasoning fit for multi-step DOM sink analysis and source-to-sink tracing.
- Better coding fit for JavaScript-heavy targets, inline handlers, and framework-specific payload mutation.
- Strong local-model range: `4b` for low-memory laptops, `9b` as the balanced default, `27b` for higher-quality reasoning, and `35b` when you have real GPU headroom.
- Works locally through Ollama, with heuristic fallback if Ollama is unavailable and optional OpenAI fallback via `OPENAI_API_KEY`.

## Features

- Parses a live URL with `-u, --url TARGET`, a batch file with `--urls FILE`, or local HTML/snippets with `-i, --input FILE_OR_SNIPPET`.
- Detects forms, inputs, inline scripts, DOM sinks, variables, objects, and framework fingerprints.
- Uses Scrapy selectors for HTML extraction and a quiet `AxssSpider` for larger live recon runs.
- Uses Ollama-first generation with Qwen3.5 model overrides via `-m, --model`.
- Lists local models with `-l, --list-models` and searches model names with `-s, --search-models QUERY`.
- Ranks payloads in `list`, `heat`, or `json` output modes.
- Ships with `setup.sh`, which installs Ollama with the official curl script when needed, auto-selects a Qwen3.5 tier, pulls it, creates `~/.axss/config.json`, builds the venv, and symlinks `~/.local/bin/axss`.

## Setup

### Fast path

```bash
./setup.sh
axss --help
```

`setup.sh` does all of the following:

- Installs Ollama automatically with `curl -fsSL https://ollama.com/install.sh | sh` when `ollama` is missing.
- Detects RAM and NVIDIA VRAM, then selects a Qwen3.5 tier.
- Starts `ollama serve` if needed and runs `ollama pull` for the selected model.
- Writes `~/.axss/config.json` with `default_model`.
- Creates or refreshes `venv`, installs `requirements.txt`, and symlinks `axss` to `~/.local/bin/axss`.

### Manual Ollama setup

If you want to control the install yourself:

1. Install Ollama.

```bash
# official installer
curl -fsSL https://ollama.com/install.sh | sh

# then start the local runtime
ollama serve
```

`setup.sh` uses that same official installer automatically when `ollama` is missing.

2. Pull the Qwen3.5 size that matches your machine.

```bash
# low-memory / smallest local footprint
ollama pull qwen3.5:4b

# standard default for most systems
ollama pull qwen3.5:9b

# higher quality if you have 32 GB+ RAM
ollama pull qwen3.5:27b

# highest tier here, intended for systems with 24 GB+ NVIDIA VRAM
ollama pull qwen3.5:35b
```

Sizing guidance used by `setup.sh`:

| Tier | Model | Recommended hardware |
| --- | --- | --- |
| Low | `qwen3.5:4b` | Less than 8 GB RAM |
| Standard | `qwen3.5:9b` | 8 GB to under 32 GB RAM |
| High | `qwen3.5:27b` | 32 GB+ RAM |
| GPU high | `qwen3.5:35b` | 24 GB+ NVIDIA VRAM |

3. Create `~/.axss/config.json`.

```json
{
  "default_model": "qwen3.5:9b"
}
```

4. Install the CLI locally.

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
./axss --help
```

If `~/.local/bin` is not on your `PATH`, add:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

### Common examples

List local Ollama models:

```bash
axss -l
```

Search for Qwen3.5 tags available through your Ollama setup:

```bash
axss -s qwen3.5
```

Scan the included sample target and print the top payloads:

```bash
axss -i sample_target.html -o list -t 10
```

Probe an inline HTML snippet and render the heat view:

```bash
axss -i '<div onclick="{{user}}"></div><script>eval(location.hash.slice(1))</script>' -o heat
```

Fetch a live target and write the full JSON result to disk:

```bash
axss -u https://example.com -m qwen3.5:9b -o json -j result.json
```

Scan a batch list and print the top payloads for each URL:

```bash
axss --urls urls.txt -t 5 -o list
```

Merge a batch into one combined payload set while still writing per-URL JSON:

```bash
axss --urls urls.txt --merge-batch -o json -j batch.json
```

Force the smaller Qwen3.5 model when you want lower memory usage:

```bash
axss -u https://example.com -m qwen3.5:4b -o list -t 5
```

Show stage-by-stage progress while scanning a local target:

```bash
axss -v -i sample_target.html -t 5 -o list
```

Run the bundled demo:

```bash
./demo_top5.sh
```

### Help excerpt

```text
$ axss --help
usage: axss [-h] (-u TARGET | --urls FILE | -i FILE_OR_SNIPPET | -l | -s QUERY)
            [-m MODEL] [-o {json,list,heat}] [-t N] [-j PATH] [-v]
            [--merge-batch] [-V]

Parse local or live HTML, identify likely XSS execution points, and rank payloads with Ollama-first generation.

options:
  -h, --help            Show this help message and exit.
  -u, --url TARGET      --url TARGET (fetch live HTML), e.g. -u
                        https://example.com
  --urls FILE           --urls FILE (fetch one URL per line), e.g. --urls
                        urls.txt
  -i, --input FILE_OR_SNIPPET
                        --input FILE_OR_SNIPPET (parse a local file or raw
                        HTML), e.g. -i sample_target.html
  -l, --list-models     --list-models (show locally available Ollama models),
                        e.g. -l
  -s, --search-models QUERY
                        --search-models QUERY (search Ollama model names),
                        e.g. -s qwen3.5
  -m, --model MODEL     --model MODEL (override the Ollama model), e.g. -m
                        qwen3.5:4b
  -o, --output {json,list,heat}
                        --output {json,list,heat} (choose terminal format),
                        e.g. -o list (default: list)
  -t, --top N           --top N (limit ranked payloads), e.g. -t 10 (default:
                        20)
  -j, --json-out PATH   --json-out PATH (always write the full JSON result),
                        e.g. -j result.json
  -v, --verbose         --verbose (print stage-by-stage progress), e.g. -v -i
                        sample_target.html
  --merge-batch         --merge-batch (combine batch contexts into one payload
                        set), e.g. --urls urls.txt --merge-batch
  -V, --version         show program's version number and exit

Common combos:
  axss -u https://example.com -t 10 -o list
  axss --urls urls.txt -t 5 -o list
  axss --urls urls.txt --merge-batch -o json -j result.json
  axss -u https://example.com -m qwen3.5:9b -o list -t 3
  axss -v -i sample_target.html -o heat
  axss -l
```

## Output Modes

- `list`: ranked table with payload, tags, and rationale.
- `heat`: compact risk heat view.
- `json`: full structured output, suitable for automation or post-processing.

## Terminal Preview

Sample run against `sample_target.html`:

```text
$ ./axss -v -i sample_target.html -o heat -t 8
Fetching/parsing target...
Fetching target: sample_target.html...
Loading model...
Generating payloads...
Ranking/mutating...
Rendering output...
Target: file:sample_target.html (html) | engine=heuristic | model=qwen3.5:9b | fallback=True
title=XSS Demo Target | frameworks=React | forms=1 | inputs=3 | handlers=0 | sinks=4
notes: Parsed HTML with Scrapy selectors. Parsed scripts with esprima AST.
# | Risk | Payload                                      | Focus                | Title
--+------+----------------------------------------------+----------------------+-------------------------
1 | 72   | <form id=forms><input name=innerHTML value=… | innerHTML            | DOM clobber + property …
2 | 62   | <svg><animate onbegin=alert(1) attributeNam… | innerHTML            | innerHTML SVG animate
3 | 60   | {"__html":"<img src=x onerror=alert(1)>"}    | dangerouslySetInner… | React dangerouslySetInn…
4 | 52   | "><svg/onload=alert(document.domain)>        | polyglot,attribute-… | SVG onload break-out
5 | 52   | ';document.body.innerHTML='<img src=x onerr… | chain,innerHTML      | Script-to-DOM chain
6 | 52   | <math><mtext><img src=x onerror=alert(1)>    | mathml,polyglot      | MathML wrapper
7 | 52   | <svg><script>alert(1)</script>               | svg,script-tag       | SVG script block
8 | 47   | alert?.(1)//                                 | setTimeout           | Timer string execution …

 1.  72 ##################        DOM clobber + property si… <form id=forms><input name=innerHTM…
 2.  62 ################          innerHTML SVG animate      <svg><animate onbegin=alert(1) attr…
 3.  60 ###############           React dangerouslySetInner… {"__html":"<img src=x onerror=alert…
 4.  52 #############             SVG onload break-out       "><svg/onload=alert(document.domain…
 5.  52 #############             Script-to-DOM chain        ';document.body.innerHTML='<img src…
```

### Payload table preview

```text
+----+------+----------------------------------------------+------------------------------+
| #  | Risk | Payload                                      | Tags                         |
+----+------+----------------------------------------------+------------------------------+
| 1  | 72   | <form id=forms><input name=innerHTML value=… | dom-clobber, chain, innerHTML|
| 2  | 62   | <svg><animate onbegin=alert(1) attributeNam… | innerHTML, svg, animate      |
| 3  | 60   | {"__html":"<img src=x onerror=alert(1)>"}    | react, dangerouslySetInner…  |
| 4  | 52   | "><svg/onload=alert(document.domain)>        | polyglot, attribute-breakout |
+----+------+----------------------------------------------+------------------------------+
```

## Model Notes

- The default model comes from `~/.axss/config.json`; if that file is missing, `axss` falls back to `qwen3.5:9b`.
- Supported Qwen3.5 sizes in this project are `qwen3.5:4b`, `qwen3.5:9b`, `qwen3.5:27b`, and `qwen3.5:35b`.
- `axss -l` wraps `ollama list` and formats the results as a table.
- `axss -s qwen3.5` prefers `ollama search qwen3.5` and falls back to Ollama web search if the installed CLI does not support local search.
- Live crawling suppresses Scrapy logs by default and can rotate request user-agents or proxies with `AXSS_USER_AGENTS` and `AXSS_PROXIES`.
- Without Ollama, the CLI still runs with heuristic generation. If `OPENAI_API_KEY` is set, it can also use `gpt-4o-mini` as a fallback path.
