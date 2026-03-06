# axss

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![Ollama](https://img.shields.io/badge/Ollama-local%20runtime-111111?logo=ollama&logoColor=white)
![Qwen3.5](https://img.shields.io/badge/Qwen3.5-4B%20%7C%209B%20%7C%2027B%20%7C%2035B-0F766E)

`axss` is a context-aware XSS recon CLI that parses target HTML, detects likely DOM sinks and framework fingerprints, then generates ranked payloads with an Ollama-first Qwen3.5 workflow plus heuristic fallback.

## Why Qwen3.5

Qwen3.5 is a strong default for this project because the task is not just "write an XSS string." It has to read HTML, follow JavaScript context, notice framework clues, and mutate payloads toward likely execution paths.

- Better reasoning fit for multi-step DOM sink analysis and source-to-sink tracing.
- Better coding fit for JavaScript-heavy targets, inline handlers, and framework-specific payload mutation.
- Strong local-model range: `4b` for low-memory laptops, `9b` as the balanced default, `27b` for higher-quality reasoning, and `35b` when you have real GPU headroom.
- Works locally through Ollama, with heuristic fallback if Ollama is unavailable and optional OpenAI fallback via `OPENAI_API_KEY`.

## Features

- Parses a live URL with `-u, --url TARGET` or local HTML/snippets with `-h, --html FILE_OR_SNIPPET`.
- Detects forms, inputs, inline scripts, DOM sinks, variables, objects, and framework fingerprints.
- Uses Ollama-first generation with Qwen3.5 model overrides via `-m, --model`.
- Lists local models with `-l, --list-models` and searches model names with `-s, --search-models QUERY`.
- Ranks payloads in `list`, `heat`, or `json` output modes.
- Ships with `setup.sh`, which auto-selects a Qwen3.5 tier, pulls it, creates `~/.axss/config.json`, builds the venv, and symlinks `~/.local/bin/axss`.

## Setup

### Fast path

```bash
./setup.sh
axss --help
```

`setup.sh` does all of the following:

- Installs Ollama automatically on Homebrew-based systems when `ollama` is missing.
- Detects RAM and NVIDIA VRAM, then selects a Qwen3.5 tier.
- Starts `ollama serve` if needed and runs `ollama pull` for the selected model.
- Writes `~/.axss/config.json` with `default_model`.
- Creates or refreshes `venv`, installs `requirements.txt`, and symlinks `axss` to `~/.local/bin/axss`.

### Manual Ollama setup

If you want to control the install yourself:

1. Install Ollama.

```bash
# macOS with Homebrew
brew install ollama

# then start the local runtime
ollama serve
```

If you are not using Homebrew, install Ollama with the official package for your OS first, then start `ollama serve`.

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
axss -h sample_target.html -o list -t 10
```

Probe an inline HTML snippet and render the heat view:

```bash
axss -h '<div onclick="{{user}}"></div><script>eval(location.hash.slice(1))</script>' -o heat
```

Fetch a live target and write the full JSON result to disk:

```bash
axss -u https://example.com -m qwen3.5:9b -o json --json-out result.json
```

Force the smaller Qwen3.5 model when you want lower memory usage:

```bash
axss -u https://example.com -m qwen3.5:4b -o list -t 5
```

Run the bundled demo:

```bash
./demo_top5.sh
```

## Output Modes

- `list`: ranked table with payload, tags, and rationale.
- `heat`: compact risk heat view.
- `json`: full structured output, suitable for automation or post-processing.

## Terminal Preview

Sample run against `sample_target.html`:

```text
$ ./axss -h sample_target.html -o heat -t 8
Target: file:sample_target.html (html) | engine=heuristic | model=qwen3.5:9b | fallback=True
title=XSS Demo Target | frameworks=React | forms=1 | inputs=3 | handlers=0 | sinks=4
notes: Parsed HTML with BeautifulSoup. Parsed scripts with esprima AST.
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
- Without Ollama, the CLI still runs with heuristic generation. If `OPENAI_API_KEY` is set, it can also use `gpt-4o-mini` as a fallback path.
