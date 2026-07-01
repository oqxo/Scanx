# Scanx

**An autonomous, LLM-powered security scanning agent for source code repositories.**

Point Scanx at a git URL or a local path. It clones/verifies it, figures out
which files are actually worth auditing, runs each one through an LLM
concurrently, and hands you back a structured vulnerability report — no
per-file babysitting required.

```
$ uv run scanx --url https://github.com/org/some-repo --provider openai --model gpt-4o-mini

Scan complete in 25.19s
Findings — critical: 4, high: 11, medium: 2, low: 0, info: 0
Reports written to: reports/scanx-report.{json,md}
```

---

## Features

- **Autonomous pipeline** — clone/verify → discover → analyze → report, end to end, no interaction required once started
- **Smart file discovery** — allowlist-first source-code filtering, layered with `.gitignore` awareness (git-native `git ls-files` when available, a dependency-free fallback matcher otherwise) and a broad, extensible exclusion policy for build output, vendored deps, tests, docs, and dependency manifests
- **Concurrent analysis** — an `asyncio` worker pool bounded by `--concurrency`, so N files get analyzed in parallel instead of one at a time
- **AST-aware chunking** — large files are split on function/class boundaries (Python today, easy to extend to other languages) so the model sees coherent units instead of arbitrary line cuts
- **Pluggable model backend** — OpenAI by default; local Ollama models supported for fully offline/private scanning
- **Structured, auditable output** — every finding is a validated Pydantic object (severity, CWE, file/line, remediation), rendered to both JSON and Markdown, plus a full rotating log of what was scanned, skipped, and found

## How it works

```
1. Acquire repo     clone (GitPython) or verify a local path
2. Discover files    git ls-files --exclude-standard, or a manual walk +
                      hand-rolled .gitignore matcher — both layered with
                      an allow/deny policy for source code vs. everything else
3. Chunk large files  Python: AST-split on function/class boundaries
                      Other languages: line-window chunking with overlap
4. Analyze            asyncio.Semaphore-bounded worker pool, one LLM call
                      per chunk, strict-JSON output, retried on failure
5. Report              scanx-report.json (full fidelity) +
                      scanx-report.md  (human-readable, severity-grouped)
```

Every stage lives in its own module under `src/scanx/tools/`, independently
callable and testable, orchestrated deterministically by
`scanx.workflow.ScanxWorkflow`. The pipeline itself is intentionally
deterministic — the LLM's job is judging *whether code is vulnerable*, not
deciding what to look at, which keeps a security tool's behavior
predictable and its logs auditable.

## Quick start

**Requirements:** Python 3.14+, [uv](https://docs.astral.sh/uv/), and an OpenAI API key.

```bash
git clone https://github.com/<you>/scanx.git
cd scanx
uv sync
```

Set your API key for the session:

```bash
# macOS/Linux
export OPENAI_API_KEY="sk-..."

# Windows PowerShell
$env:OPENAI_API_KEY = "sk-..."
```

Run it:

```bash
# Interactive — prompts for a repo URL or local path
uv run scanx --provider openai --model gpt-4o-mini

# Scan a remote repo directly
uv run scanx --url https://github.com/org/some-repo --provider openai --model gpt-4o-mini

# Scan a local path
uv run scanx --path ../some-project --provider openai --model gpt-4o-mini --concurrency 8
```

### Using a local model instead

Scanx also supports fully local, offline scanning via
[Ollama](https://ollama.com) — useful for private codebases you don't want
leaving your machine, at the cost of speed (local inference is typically
one request at a time, versus real parallelism with a hosted API).

```bash
ollama pull <your-model-tag>
uv run scanx --path ../some-project --provider ollama --model <your-model-tag> --concurrency 1
```

## CLI reference

| Flag | Default | Description |
|---|---|---|
| `--url` | — | Git URL to clone and scan |
| `--path` | — | Local path to scan |
| `--provider` | `ollama` | Model backend: `openai` or `ollama` |
| `--model` | `ornith:9b` | Model name — e.g. `gpt-4o-mini` for OpenAI, or an Ollama tag |
| `--api-key` | — | OpenAI API key (falls back to `OPENAI_API_KEY` env var) |
| `--ollama-host` | `http://localhost:11434` | Ollama server URL |
| `--output-dir` | `reports` | Where reports + logs are written |
| `--concurrency` | `4` | Max concurrent worker-pool tasks hitting the model |
| `--timeout` | `120` | Per-chunk model call timeout, in seconds |
| `--max-retries` | `2` | Retries per chunk on timeout/failure |
| `--include-tests` | off | Scan test directories/files too |
| `--verbose` | off | Debug-level console logging |

> Note: `--provider` currently defaults to `ollama` for backward compatibility;
> pass `--provider openai` explicitly (as in the examples above) until the
> default flips in a future release. See [Roadmap](#roadmap).

## What gets scanned

**Allowlist-first**: a file is only scanned if it's recognized source code,
IaC, or CI/CD config (`.py`, `.js`, `.go`, `.rs`, `.tf`, `.yaml`,
`Dockerfile`, etc — see `src/scanx/config.py::INCLUDED_EXTENSIONS`).

**Always excluded**, regardless of language or ecosystem:

- VCS internals (`.git`) and hidden dirs/files — except `.github`/CI
  folders and `.env*`, which are security-relevant
- Virtual envs & package caches: `.venv`, `node_modules`, `__pycache__`, `.tox` …
- Build/compile output: `target`, `dist`, `build`, `bin`, `obj`, `.gradle`,
  `cmake-build-*` …
- Vendored/dependency trees: `vendor`, `Pods`, `bower_components` …
- IaC tool caches: `.terraform`, `cdk.out`, `.serverless`, `.pulumi` …
- `docs/`, `tests/` (tests are configurable via `--include-tests`)
- Dependency manifests/lockfiles: `package.json`, `pom.xml`, `Cargo.lock`,
  `go.sum`, `requirements.txt`, etc — this is a SAST tool, not SCA
- Binaries, media, fonts, archives, `.md`/`.rst`/`.txt` docs
- Anything matched by the repo's own `.gitignore`

The full, commented policy lives in `src/scanx/config.py` and is
deliberately easy to extend.

## Output

- `reports/scanx-report.md` — human-readable, grouped by severity, with
  file/line, description, and remediation for each finding
- `reports/scanx-report.json` — full structured findings for tooling/CI integration
- `reports/scanx.log` — full audit trail: everything discovered, skipped,
  scanned, and any errors encountered

## Project layout

```
src/scanx/
├── config.py            exclusion policy + runtime tunables (ScanConfig)
├── models.py              Pydantic schemas: Finding, FileAnalysisResult, ScanReport
├── logging_config.py      console + rotating file logging
├── workflow.py             ScanxWorkflow — orchestrates the pipeline
├── cli.py                   interactive + flag-based entry point
└── tools/
    ├── repo_tools.py         clone_repo / verify_local_path
    ├── discovery_tools.py     file discovery (git-native + gitignore fallback)
    ├── chunking.py             AST-aware + line-window chunking
    ├── analysis_tools.py       async worker pool, OpenAI/Ollama backend
    └── report_tools.py         JSON + Markdown report generation
```

## Responsible use

Scanx is a **defensive** security tool. Only run it against repositories
you own or are explicitly authorized to test. Findings are AI-generated —
review them before acting; false positives and missed issues are both
possible, and this tool is meant to assist a security review, not replace one.

## Roadmap

- [ ] Flip `--provider` default to `openai` once local-model UX is polished
- [ ] Per-severity model routing (cheap model for triage, stronger model to confirm high/critical findings)
- [ ] Rate-limit-aware backoff tuned specifically for hosted APIs
- [ ] AST-aware chunking for more languages (JS/TS, Go, Java)
- [ ] SARIF output for CI/PR-check integration
- [ ] Optional CVE/advisory cross-referencing for flagged dependency versions

## Contributing

Issues and PRs welcome. Before opening a PR:

```bash
uv sync --group dev
uv run ruff check src/
```

## License

MIT — see [LICENSE](LICENSE). (Swap this out if your org needs a different license.)
