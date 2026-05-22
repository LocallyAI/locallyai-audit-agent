# locallyai-audit-agent

A forensic-investigation agent over LocallyAI's tamper-evident
HMAC-chained audit log. The agent uses a local LLM (Qwen 2.5
family) to interpret human questions and route them to four
purpose-built tools: keyword search, time-windowed filtering,
chain-integrity verification, and per-bucket aggregation.

This codebase ships into the same regulated-industry deployments
LocallyAI itself serves. The agent's **runtime is fully
air-gapped** — no calls leave the firm's hardware. The eval
suite uses Claude as judge (cloud) but is dev-only tooling.

---

## Quick start

```bash
git clone <this repo> ~/locallyai-audit-agent       # or you already have it
cd ~/locallyai-audit-agent
./run.sh setup                                       # one-time
./run.sh start-mlx                                   # in one terminal — starts mlx_lm.server (default backend)
# in a second terminal:
./run.sh doctor                                      # pre-flight every dependency
./run.sh demo                                        # 5-query CLI demo
```

The default backend is **MLX** (`mlx_lm.server`) because it's the
lightest path on Apple Silicon. If you'd rather use LM Studio or
Ollama: `BACKEND=lmstudio ./run.sh demo` (and skip `start-mlx`).

If `doctor` reports anything red or yellow, jump to
[**Troubleshooting**](#troubleshooting) below.

---

## Table of contents

1. [What you need](#what-you-need)
2. [One-time setup](#one-time-setup)
3. [Daily run patterns](#daily-run-patterns)
4. [Configuration reference](#configuration-reference)
5. [Architecture in 30 seconds](#architecture-in-30-seconds)
6. [The four tools](#the-four-tools)
7. [Tracing](#tracing)
8. [Eval suite](#eval-suite)
9. [Troubleshooting](#troubleshooting) ← the long section
10. [Roadmap](#roadmap)
11. [Known drift risk](#known-drift-risk)

---

## What you need

| Component | Why | How to check |
|---|---|---|
| **Python ≥ 3.10** | the agent + eval are pure Python | `python3 -V` |
| **A LocallyAI checkout** with a populated audit log | the agent reads `logs/audit.log` from this path | `ls ~/locallyai/logs/audit*.log*` |
| **LocallyAI's `.env`** with `LOCALLYAI_AUDIT_HMAC_KEY` | `hmac_verify` needs it | `grep AUDIT_HMAC_KEY ~/locallyai/.env` |
| **One tool-capable backend** — LM Studio **or** Ollama **or** `mlx_lm.server` — with a Qwen 2.5 model loaded | the agent's LLM | `./run.sh doctor` probes all three |
| **`ANTHROPIC_API_KEY`** *(eval only)* | the Claude judge | `echo $ANTHROPIC_API_KEY` |

`./run.sh doctor` checks all of these in one shot and prints what
needs fixing.

## Choosing a backend

The agent talks to any OpenAI-compatible `/v1/chat/completions`
endpoint that emits tool-calls for Qwen 2.5. Three backends are
supported out of the box:

| Backend | Default URL | Default model | Pick when |
|---|---|---|---|
| **`mlx`** *(default)* | `http://localhost:8765/v1` | `mlx-community/Qwen2.5-7B-Instruct-4bit` | The lightest path: `mlx_lm.server` is one process, no GUI, MLX-native on Apple Silicon. Reuses LocallyAI's `mlx_lm.server` install if present. |
| **`lmstudio`** | `http://localhost:1234/v1` | `qwen2.5-coder-7b-instruct-mlx` | You want a GUI to manage models. The committed sitting-4 baseline used this. |
| **`ollama`** | `http://localhost:11434/v1` | `qwen2.5:14b` | You already use Ollama and have models pulled there. **Watch out** for the `llama runner process has terminated` Metal-shader bug on older Ollama builds (see Troubleshooting). |

### Switching backends

The default is `BACKEND=mlx`. To switch:

```bash
BACKEND=lmstudio ./run.sh demo
BACKEND=ollama   ./run.sh demo
BACKEND=auto     ./run.sh demo               # auto-detect (probes
                                             # lmstudio → ollama → mlx,
                                             # picks first responsive)
BACKEND=lmstudio MODEL=qwen2.5-14b-instruct ./run.sh ask "..."
```

Explicit `BASE_URL` / `MODEL` always win over the backend's defaults
— useful for remote backends:

```bash
BASE_URL=http://office-mac.local:11434/v1 MODEL=qwen2.5:14b ./run.sh eval
```

### Starting each backend

**LM Studio** — open the app, Developer tab, toggle **Status: Running**.

**Ollama** — `open -a Ollama` (or it auto-starts on login). Pull a model: `ollama pull qwen2.5:14b`. If `ollama --version` is older than 0.24, upgrade first: `brew install --cask ollama-app --force`.

**MLX** (`mlx_lm.server`) — `./run.sh start-mlx` in a separate terminal. Uses LocallyAI's `mlx_lm.server` install if available; otherwise install with `pip install mlx-lm`. Custom model: `./run.sh start-mlx mlx-community/Qwen2.5-14B-Instruct-4bit`.

---

## One-time setup

```bash
cd ~/locallyai-audit-agent
./run.sh setup            # creates .venv + installs openai pydantic pyyaml anthropic
./run.sh doctor           # confirms python, venv, deps, .env, audit log, LM Studio
```

Then start the model backend (LM Studio is the supported default;
Ollama works too):

1. Open **LM Studio**
2. Discover tab → search **`qwen2.5 14b instruct`** → download the GGUF or MLX build (~9 GB).  
   If you don't have 9 GB of bandwidth right now, **`qwen2.5-coder-7b-instruct-mlx`** is the fallback used by the committed baseline.
3. Left sidebar → **`</>`** (Developer / Local Server)
4. Select the model in the top dropdown
5. Toggle **Status: Running** (default port `1234`)

Re-run `./run.sh doctor` — every line should be green.

---

## Daily run patterns

| What | Command | Notes |
|---|---|---|
| Sanity-check everything | `./run.sh doctor` | Reads-only. Probes all three backends. Always safe. |
| Start MLX backend (separate terminal) | `./run.sh start-mlx [<model>]` | Foreground-runs `mlx_lm.server` on port 8765. Ctrl-C to stop. |
| 5-query CLI demo | `./run.sh demo` | ~30 s. Prints tool calls + answers + trace paths. |
| One ad-hoc question | `./run.sh ask "Is the chain intact?"` | Writes one trace to `traces/`. |
| Full eval (30 questions) | `./run.sh eval` | Needs `ANTHROPIC_API_KEY`. ~10–15 min on Coder 7B. |
| Eval without the judge | `./run.sh eval-dry` | Offline; captures agent answers, skips grading. |
| Resume an interrupted eval | `./run.sh eval-resume eval/runs/<file>.jsonl` | Auto-detects the first ungraded question. |
| Compare two runs | `./run.sh compare <base>.jsonl <new>.jsonl` | After a tweak, this is the only thing that tells you whether it helped. |
| Pretty-print a trace | `./run.sh trace [<file>]` | No arg = newest trace under `traces/`. |

All of the above auto-source LocallyAI's `.env`, activate the venv,
set sensible defaults, and run preflight checks before dispatching
to Python. To override any default for one invocation:

```bash
MODEL=qwen2.5:14b ./run.sh demo                      # different model
BASE_URL=http://office-mac.local:1234/v1 ./run.sh eval   # remote LM Studio
LOCALLYAI_REPO=/path/to/locallyai ./run.sh doctor    # non-default LocallyAI path
```

---

## Configuration reference

All env vars the agent and `run.sh` recognise.

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND` | `mlx` | Backend selection: `mlx` (default) \| `lmstudio` \| `ollama` \| `auto`. `auto` probes lmstudio → ollama → mlx and uses the first responsive one. |
| `BASE_URL` | (per backend) | OpenAI-compatible endpoint. Overrides `BACKEND`'s default. Examples: `http://localhost:1234/v1` (lmstudio), `http://localhost:11434/v1` (ollama), `http://localhost:8765/v1` (mlx). |
| `MODEL` | (per backend) | Model identifier. Defaults by backend: `qwen2.5-coder-7b-instruct-mlx` (lmstudio), `qwen2.5:14b` (ollama), `mlx-community/Qwen2.5-7B-Instruct-4bit` (mlx). |
| `MLX_PORT` | `8765` | Port `./run.sh start-mlx` binds to. Change if 8765 is taken. Remember to update `BASE_URL` to match. |
| `LOCALLYAI_REPO` | `$HOME/locallyai` | Where to find LocallyAI's `.env` + `logs/`. Override if your checkout lives elsewhere. |
| `LOCALLYAI_ENV` | `$LOCALLYAI_REPO/.env` | Path to LocallyAI's `.env`. Auto-sourced by `run.sh`. |
| `LOCALLYAI_AUDIT_LOG` | `$LOCALLYAI_REPO/logs/audit.log` | The active audit log. Walker also picks up sibling `audit-YYYY-MM-DD.log.gz` rotations automatically. |
| `LOCALLYAI_AUDIT_HMAC_KEY` | (from LocallyAI's `.env`) | HMAC secret used by `hmac_verify`. Must match what LocallyAI used to write the chain or every entry looks "tampered". |
| `LOCALLYAI_TRACE_DIR` | `traces/` (relative to cwd) | Where per-run JSONL traces are written. |
| `ANTHROPIC_API_KEY` | (unset) | Required for `./run.sh eval`. The judge — dev-only — never sees the audit log itself. |
| `JUDGE_MODEL` | `claude-haiku-4-5-20251001` | Override the judge model. Haiku is fine for structured grading; use Sonnet for closer calls. |
| `LOCALLYAI_AUDIT_LOG_SOURCE` | `/Users/emanuel/locallyai/logs/audit.log` | Source log used by `eval/fixtures.py` to build the eval fixtures. Set this if you're not the original developer. |

---

## Architecture in 30 seconds

```
┌──────────────────────────────────────────────────────────────┐
│  cli.py / agent.py                                           │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ run_agent(user_query):                                 │  │
│  │   OpenAI client → BASE_URL (LM Studio / Ollama / ...)  │  │
│  │   loop max 5 iterations:                               │  │
│  │     model emits tool_calls                             │  │
│  │     dispatch via AVAILABLE_TOOLS                       │  │
│  │     append tool result, recurse                        │  │
│  │   no more tool_calls → return final text               │  │
│  │   tracing.py writes one JSONL line per event           │  │
│  └────────────────────────────────────────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│  tools.py — four tools, each a plain Python fn:              │
│    log_search       — substring across metadata fields       │
│    time_range_query — ISO window + event_type + user filters │
│    hmac_verify      — chain integrity walk (vendored from    │
│                       LocallyAI api.py:_chain_hmac)          │
│    summary_stats    — counts bucketed by fixed enum          │
└──────────────────────────────────────────────────────────────┘
            │ reads
            ▼
   /path/to/locallyai/logs/audit.log + sibling .gz rotations
```

---

## The four tools

| Tool | Use for | Returns |
|---|---|---|
| `log_search(query, max_results)` | Keyword / substring content matching across metadata fields | Up to `max_results` entries, newest-first |
| `time_range_query(start, end, event_type, user, max_results)` | Precise ISO-8601 time window + structured filters (chat vs admin, user_hash substring) | Up to `max_results` entries in the window, sorted ascending |
| `hmac_verify(start_seq, end_seq)` | Chain integrity, tamper detection | `{chain_intact, verified_count, total_count, first_failure_seq, failures[≤10]}` |
| `summary_stats(group_by, start, end)` | Counts / top-N / distributions; `group_by` ∈ {`user`, `event_type`, `hour_of_day`, `day`} | `{group_by, total_events, buckets[{key,count}], time_range}` |

Routing decisions live in the **tool descriptions** themselves
(see `tools.py`). Each tool's description explicitly tells the
model when *not* to use it. Bad `group_by` values to `summary_stats`
return a clear error listing the valid options — the model
self-corrects on the next iteration rather than getting a silent
default.

---

## Tracing

Every `run_agent()` call writes one JSONL file to `traces/`
(gitignored). One line per event:

| Event | Fields |
|---|---|
| `user_query` | `content`, `timestamp` |
| `model_call` | `iteration`, `model`, `messages_count`, `latency_ms` |
| `tool_call` | `iteration`, `tool`, `args`, `latency_ms` |
| `tool_result` | `iteration`, `tool`, `result_summary` (capped 500 chars) |
| `error` | `iteration`, `where` (`model_call` \| `tool_call`), `exception`, `message` |
| `final_answer` | `content`, `total_iterations`, `total_latency_ms` |

Render any trace human-readably:

```bash
./run.sh trace                            # newest
./run.sh trace traces/<file>.jsonl        # specific
python trace_viewer.py - < trace.jsonl    # stdin pipe
```

Tool results are truncated to 500 chars in the trace and to 1500
chars when fed back into the next model call — bounds the context
against tool-chaining bloat.

---

## Eval suite

30 questions; Claude as judge; markdown summary per run; diff tool
for run-to-run comparison.

### Configuring the cloud judge

> **Important.** The agent runtime stays fully air-gapped. The
> eval **judge** is the **one place** where the air-gap rule is
> relaxed: it calls Claude at `api.anthropic.com` to grade the
> agent's answers against the dataset's ground-truth facts. This
> is **dev-only tooling** — the judge never ships into a
> regulated-industry deployment. The judge **never sees the audit
> log** — only the question, ground-truth facts, the agent's
> answer, and the tools the agent called.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./run.sh eval                 # full run
./run.sh eval-dry             # no judge, captures agent answers only
./run.sh eval-resume eval/runs/<file>.jsonl   # resume an interrupted run
./run.sh compare eval/runs/<a>.jsonl eval/runs/<b>.jsonl
```

Output lands in `eval/runs/`:

- `<stamp>.jsonl` — one line per question
- `<stamp>_summary.md` — overall + per-category + per-difficulty pass rates, failed-question list with judge rationales

### Dataset

`eval/dataset.yaml` — 30 questions across 5 categories
(log_search/time_range/aggregation/integrity/multi_tool) and 3
difficulty levels. Each has `expected_tools`, ground-truth facts,
required + forbidden substrings (hallucination guards), and
`log_fixture` (clean or tampered).

The tampered fixture is built by `eval/fixtures.py` from the live
LocallyAI audit log — `LOCALLYAI_AUDIT_LOG_SOURCE` controls which
file it copies. Fixtures live under `eval/fixtures/` (gitignored).

### Baseline (2026-05-21)

First baseline run at `eval/runs/2026-05-21T192709Z.jsonl` +
`_summary.md`. All 30 questions ran end-to-end against
`qwen2.5-coder-7b-instruct-mlx` via LM Studio; runtime 5.6 min.
**Anthropic credit ran out after question 8**, so 8/30 have valid
grades and 22/30 are `judge_error=true`. The agent's answers are
captured in the JSONL for all 30 — re-grading after a top-up is a
no-extra-agent-cost run via `./run.sh eval-resume`.

Honest numbers from the validly-graded subset:

| Axis | Rate (graded only) |
|---|---|
| Tool selection | 7 / 8 (87.5%) |
| Answer correctness | 2 / 8 (25.0%) |
| Both axes | 2 / 8 (25.0%) |

---

## Troubleshooting

Organised by symptom. If you don't see your symptom, run
`./run.sh doctor` — it surfaces 90% of issues with a clear fix
suggestion.

### Setup

#### `bash: ./run.sh: Permission denied`
`run.sh` lost its executable bit. Fix: `chmod +x ./run.sh`.

#### `python3: command not found`
You're on a system without Python 3. Fix on macOS:
`brew install python@3.12`. After install, verify with
`python3 -V` — needs 3.10 or newer.

#### `./run.sh setup` fails on pip install
Three common causes:
1. **Offline / proxy.** Set `HTTPS_PROXY` env if your network needs one.
2. **PyPI index unreachable.** Try `pip install -i https://pypi.org/simple openai` as a sanity check.
3. **Wrong venv.** If you have a global pip alias, your installs may land outside `.venv/`. After `./run.sh setup`, confirm with `./run.sh doctor` — the deps check looks inside `.venv/`.

#### `venv missing at .../venv. Run: ./run.sh setup`
You skipped setup. Run `./run.sh setup` exactly once.

#### `ModuleNotFoundError: No module named 'openai'` (or `yaml`, `anthropic`, `pydantic`)
The venv exists but a dep is missing. Re-run `./run.sh setup` —
it's idempotent and only installs what's missing.

### Backend (LM Studio / Ollama / MLX)

#### `BACKEND=<x> endpoint http://... is unreachable`
`./run.sh doctor` probes all three; pick whichever is responsive
and pin it: `BACKEND=ollama ./run.sh demo`. To switch to a
specific backend, follow its setup checklist:

**LM Studio**:
1. LM Studio open? Check the macOS Dock.
2. Developer tab → Status: Running? Default toggle is OFF on a fresh launch.
3. Model loaded? The dropdown at the top of the Developer pane must show a chat-capable model. Embedding-only won't serve `/v1/chat/completions`.
4. Port collision? `lsof -nP -iTCP:1234 -sTCP:LISTEN`.

**Ollama**:
1. App running? `open -a Ollama` (or `brew services restart ollama`).
2. Model pulled? `ollama list` should show `qwen2.5:14b` or similar.
3. Recent enough? `ollama --version` ≥ 0.24 avoids the Metal-shader crash. Fix: `brew install --cask ollama-app --force` (quit Ollama first).
4. Port collision? `lsof -nP -iTCP:11434 -sTCP:LISTEN`.

**MLX (`mlx_lm.server`)**:
1. Server started? `./run.sh start-mlx` in another terminal.
2. Model downloaded? First run downloads weights from HuggingFace; subsequent runs are cached at `~/.cache/huggingface/hub/`.
3. `mlx_lm.server: command not found`? Activate LocallyAI's venv first (`source ~/locallyai/.venv/bin/activate`) — it ships `mlx-lm`. Or `pip install mlx-lm` into the agent's venv.
4. Port collision? `lsof -nP -iTCP:8765 -sTCP:LISTEN`. Change with `MLX_PORT=8766 ./run.sh start-mlx` and `BASE_URL=http://localhost:8766/v1 ./run.sh demo`.

#### `Model 'qwen2.5-coder-7b-instruct-mlx' is NOT in the loaded model list`
Either load that model in LM Studio (Developer → top dropdown), or
override the agent's expected model name to match what's loaded:
```bash
MODEL=$(curl -sS http://localhost:1234/v1/models | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])') ./run.sh demo
```

#### Agent gets `400 ... messages: array too long` or `context length exceeded`
The conversation grew past the model's context window. Most often
during eval on questions that chain several tools. Mitigation
already in place: tool results are truncated to 1500 chars going
back into the messages array. If you still hit this on a question
that needs huge results, narrow the question or use a model with a
bigger context window.

#### Agent gets `llama runner process has terminated` (Ollama specifically)
Known Ollama issue on certain macOS / Metal version combinations —
the runner can't compile a Metal shader. **The agent's not at fault.**
Three fixes:
1. **Upgrade Ollama:** `brew install --cask ollama-app --force` (will replace `/Applications/Ollama.app`; quit Ollama first).
2. **Switch to LM Studio:** `BACKEND=lmstudio ./run.sh demo` after toggling LM Studio's server on.
3. **Switch to MLX:** `./run.sh start-mlx` in one terminal, `BACKEND=mlx ./run.sh demo` in another. Same Qwen 2.5 family, no Ollama dependency.

#### MLX backend: `mlx_lm.server not found`
The agent's venv doesn't have `mlx-lm` installed (it's a heavy
dep — PyTorch-equivalent + the model loader). Two fixes:
1. **Reuse LocallyAI's install:** `./run.sh start-mlx` auto-detects `~/locallyai/.venv/bin/mlx_lm.server` if LocallyAI is installed. This is the recommended path.
2. **Install into the agent's venv:** `source .venv/bin/activate && pip install mlx-lm`. Adds ~2 GB of deps.

#### MLX backend: model fetch hangs on first start
`mlx_lm.server` downloads the model from HuggingFace on first
launch (~5 GB for Qwen 2.5 7B 4bit). Watch the output of `./run.sh
start-mlx` — it shows `Fetching N files: ...`. Subsequent runs are
cached. If the download stalls: `~/.cache/huggingface/hub/.locks/`
may have orphan locks from a killed download; delete them and retry.

#### MLX backend: tool-call response is `null` content + no `tool_calls`
Qwen 2.5 + the bundled chat template supports tool-calling
natively. If `mlx_lm.server` returns plain text instead of a
`tool_calls` array, the model isn't applying the tool-call template.
Two checks:
1. **Model is Qwen 2.5 / 3 instruct?** Mistral / Llama 3.2 1B don't reliably emit OpenAI tool-call format.
2. **`mlx-lm` version is recent?** `pip show mlx-lm | grep Version` — needs a version that handles `tools` in the request body. If stuck, upgrade: `pip install -U mlx-lm`.

#### Model responds in seconds but tool args are nonsense
e.g. `hmac_verify(end_seq='<insert_last_sequence_number>')`. The
model is hallucinating placeholder syntax. Two retries usually
self-correct (the dispatch returns a tool error → model adjusts).
If the model gets stuck for more than 5 iterations, the agent's
hard cap kicks in and the final answer is prefixed with `[agent:
hit MAX_ITERATIONS=5 without settling]`. Swap to a stronger model
or tighten the system prompt for that question shape.

#### Model picks the wrong tool
Tool descriptions in `tools.py` carry the routing weight (the
system prompt is intentionally brief). The fix is to tighten the
specific tool's description, then re-run the eval and use
`./run.sh compare` to verify the change didn't regress other
questions.

### LocallyAI deployment / env

#### `LOCALLYAI_AUDIT_HMAC_KEY not set` / `HmacKeyMissing`
The agent couldn't find LocallyAI's `.env`. Three fixes:
1. **Standard location:** make sure `~/locallyai/.env` exists and has `LOCALLYAI_AUDIT_HMAC_KEY=...`. `run.sh` auto-sources it.
2. **Custom location:** `LOCALLYAI_ENV=/path/to/.env ./run.sh demo`.
3. **No LocallyAI install at all:** export the key directly: `export LOCALLYAI_AUDIT_HMAC_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')`. **Warning:** if you do this against an existing log, every `hmac_verify` will report `chain_intact=false` — the chain was written with a different key.

#### `LOCALLYAI_AUDIT_LOG=... does not exist`
LocallyAI hasn't been installed at `~/locallyai`, or it has but no
audit entries have been written yet, or it's at a custom path.
Fix one of:
- `LOCALLYAI_REPO=/path/to/locallyai ./run.sh demo`
- `LOCALLYAI_AUDIT_LOG=/explicit/path.log ./run.sh demo`
- Generate at least one audit entry: send any chat request to LocallyAI's `/v1/chat/completions` with admin auth.

#### Active log is empty (0 bytes) but doctor says it's fine
This is normal — LocallyAI rotates `logs/audit.log` to
`logs/audit-YYYY-MM-DD.log.gz` at midnight. The walker reads
both the active log AND sibling `.gz` rotations. As long as
`./run.sh doctor` shows ≥1 rotation, you have content.

#### Every `hmac_verify` returns `chain_intact=false, first_failure_seq=1`
The HMAC key the agent has doesn't match the one LocallyAI used.
Check that you're sourcing the right `.env`:
```bash
grep ^LOCALLYAI_AUDIT_HMAC_KEY ~/locallyai/.env
```
If LocallyAI ran a salt rotation, the *new* salt may be in
`LOCALLYAI_AUDIT_HMAC_KEY` but old entries were signed with a
prior era. Check LocallyAI's `LOCALLYAI_AUDIT_SALT_ERA_*` lines
and document which era you want to verify against (`tools.py`
currently uses the active key only — re-implementing era handling
is on the backlog).

#### `Permission denied: logs/audit.log`
Macs running LocallyAI under launchd often chmod the log dir to
`0700` for the install user. Read-only access requires either
running the agent as the same user, or copying the logs to a
location your user can read: `cp -R ~/locallyai/logs /tmp/audit-snapshot/ && LOCALLYAI_AUDIT_LOG=/tmp/audit-snapshot/audit.log ./run.sh demo`.

### Agent runtime

#### Agent prints `[Agent] Iteration 5 ... hit MAX_ITERATIONS=5 without settling`
The model never produced a no-tool-calls response within 5 turns.
Causes:
- The model keeps calling tools with bad args and not learning.
- The question really does need more iterations (genuinely complex).
- A tool keeps returning errors and the model keeps retrying.

Quickest debug: pretty-print the trace (`./run.sh trace`) and see
where the loop went wrong. The 5-cap is conservative; if you have
a question that legitimately needs more, edit `MAX_ITERATIONS` in
`agent.py` — but most legitimate questions settle in 2–3.

#### Trace file isn't being written
1. `traces/` doesn't exist: `mkdir traces`
2. Disk full: `df -h .`
3. Permission denied on `traces/`: `chmod u+w traces/`
4. `LOCALLYAI_TRACE_DIR` was set to an unwritable path.

#### `OSError: [Errno 24] Too many open files`
A long eval run can hit the file-descriptor limit if previous
runs left orphan tracer file handles. Restart your shell or
`ulimit -n 4096`.

### Eval — judge

#### `JudgeNotConfigured: ANTHROPIC_API_KEY not set`
Export the key before `./run.sh eval`:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
./run.sh eval
```
Or run without the judge: `./run.sh eval-dry`.

#### `BadRequestError ... Your credit balance is too low`
This is what happened in the baseline run. The judge errors are
not silently auto-failed — they're recorded as `judge_error=true`
with `tool_pass=null` / `answer_pass=null`, so the summary's
headline pass rate is computed only over the validly-graded
subset.

Recovery:
1. Top up at https://console.anthropic.com/settings/billing
2. `./run.sh eval-resume eval/runs/<that-jsonl>.jsonl`
3. The runner auto-detects the first ungraded question and only re-grades the remainder. Agent answers are not re-run.

#### Judge returns garbage / non-JSON
The judge tolerates a stray ```json fence and tries to extract the
first `{...}` from the response. If parsing fails entirely, the
question is recorded as failed with `rationale: "judge output
unparseable: ..."`. If this happens repeatedly:
1. Try a stronger judge: `JUDGE_MODEL=claude-sonnet-4-6-20251022 ./run.sh eval`
2. Inspect the JSONL — the failing rationale will quote the model's actual response.

#### `RateLimitError 429`
You're hitting Anthropic's per-minute rate limit. The eval runs
sequentially with no built-in throttle. Wait 60 s, then
`./run.sh eval-resume eval/runs/<file>.jsonl`. If this becomes
chronic, add a `time.sleep(2)` between judge calls in `eval/run.py`.

#### `AuthenticationError 401`
The `ANTHROPIC_API_KEY` is wrong (typo, expired, revoked, or you
copy-pasted with surrounding whitespace). Regenerate at the
Anthropic console.

### Eval — dataset / fixtures

#### `nothing to run` after `--start-from <id>`
Either the id is wrong (typo — they're `q01`..`q30`) or every
question with id >= that value has already been graded. Check
the JSONL: `python3 -c "import json; print([r['id'] for line in
open('eval/runs/<file>.jsonl') for r in [json.loads(line)] if
r['judge'].get('judge_error') or r['judge'].get('tool_pass') is
None])"`.

#### `KeyError: 'expected_tools'` or schema validation in dataset
Someone edited `dataset.yaml` and broke the per-question required
fields. The validator at the top of the dataset comment lists the
exact set: `id`, `category`, `question`, `expected_tools`,
`expected_answer_contains`, `expected_answer_excludes`,
`ground_truth_facts`, `difficulty`, `log_fixture`, `notes`.

#### Tampered fixture isn't broken (chain_intact=true)
The tamper is keyed off a specific seq number (default 5). If
the source LocallyAI log has fewer than 5 entries, the fixture
builder raises `RuntimeError: tamper target seq=5 not found`.
Either:
- Wait until LocallyAI accumulates more entries.
- Lower `TAMPER_TARGET_SEQ` in `eval/fixtures.py` to a seq that exists.

#### Eval pass rate suddenly drops to 0 across the board
Two prime suspects:
1. **LM Studio crashed mid-run** — every question gets a model error → tool-call-less answer. Restart LM Studio and re-run.
2. **Live LocallyAI log changed** — fixtures rebuilt with new entries that don't match the dataset's ground-truth facts. Either revert the change or update the dataset's `ground_truth_facts` to reflect the new reality.

#### Fixture build crashes with `unreadable archive`
The `.gz` files under `logs/.archived-pre-demo-reset/` aren't
walked by the fixture builder, but if a top-level `.gz` is corrupt
the builder errors out. Check with
`gunzip -t logs/audit-*.log.gz`.

### Comparison

#### `compare` output shows huge regressions that don't make sense
Most likely cause: the two runs used **different datasets** or
different LocallyAI log content. The comparator joins rows by
question `id`. If the dataset was edited between runs, two `q05`s
may have completely different ground truth.

Sanity check: were both runs from the same git commit?
```bash
git log --oneline eval/dataset.yaml | head -3
```

#### `ungraded on one side: base=N, new=M — skipped from rate deltas`
The comparator correctly filters rows that aren't validly graded
on both sides. If you want a full picture, regrade the ungraded
side first (`./run.sh eval-resume <file>`), then re-compare.

### Model behaviour quirks observed in practice

These are real failure modes from the committed baseline. None
are bugs in the agent or tools — they're model-quality issues
that the eval is meant to expose so they can be tuned against.

| Symptom | Example | Fix direction |
|---|---|---|
| Model searches with wrong-case keyword, gets 0 hits, confabulates "no entries found" instead of broadening | q02 searched `"MLX"`, got 0 hits (field is lowercase `"mlx-..."`), concluded no MLX entries | Tighten `log_search` description to mention case-insensitive matching; or add a system-prompt hint to retry with broader query on 0 hits |
| Model resolves "yesterday" to its training cutoff date, not actual yesterday | q04 with `start='2023-10-14T...'` | Inject current date in system prompt, or add a `today()` micro-tool |
| Model passes literal placeholder string as tool arg | `hmac_verify(end_seq='<insert_last_sequence_number>')` | Self-corrects on retry; if persistent, add an example invocation in the tool description |
| Model routes content question to `time_range_query` when the question carries both a content cue and a time window | q01 "admin events from the last 24 hours" → either tool is reasonable | Accept both routings in the dataset, or tighten one description to disambiguate |

The fix-and-measure loop for all of these:
1. Make the change.
2. `./run.sh eval-resume` (or full `./run.sh eval`).
3. `./run.sh compare eval/runs/2026-05-21T192709Z.jsonl eval/runs/<new>.jsonl`.
4. Check that the targeted question flipped fail → pass AND no other question flipped pass → fail.

### Operating system / disk

#### `OSError: [Errno 28] No space left on device`
The trace dir filled the disk (each trace is ~1 KB; would need
thousands for this). Clean: `rm -rf traces/*` (they're disposable
— the live audit log is the source of truth).

#### Eval run takes 3× longer than the README claims
- **Cold model load:** first call after starting LM Studio includes the model load (~10–30 s). Subsequent calls are fast.
- **Other Mac workloads competing for RAM:** Qwen 14B is ~9 GB resident. If LocallyAI is also running MLX models, you may swap. Quit one of them.
- **Network latency to Anthropic** for the judge: each call is ~1–2 s. Eval is sequential; 30 questions × 2 s ≈ 1 minute of judge time, plus agent latency.

#### Agent silently exits with no output
Likely a Python exception during a tool dispatch that the agent's
`try/except` caught and serialised as a `tool_result` with
`error` — but then the model produced an empty final answer. Read
the trace file (`./run.sh trace`) — every model + tool event is
logged, including any error.

---

## Roadmap

- ~~**Sitting 1** — `log_search` + the OpenAI-shaped agent loop.~~ ✓ shipped
- ~~**Sitting 2** — `hmac_verify` + system-prompt tool-routing + tamper-detection smoke test.~~ ✓ shipped
- ~~**Sitting 3** — `time_range_query`, `summary_stats`, per-run JSONL tracing + `trace_viewer.py`.~~ ✓ shipped
- ~~**Sitting 4** — 30-question eval suite + Claude judge + run comparator + baseline.~~ ✓ shipped
- **Sitting 5** — Prompt + tool-description tuning to lift the baseline. Use `./run.sh compare` to verify every change. Swap to Qwen 2.5 14B Instruct once a stable build is available; quantify the model-quality delta against the baseline. FastAPI server + per-firm deployment as a `/admin/forensics/ask` endpoint behind LocallyAI's `_admin_auth`.

---

## Known drift risk

`tools.py` re-implements LocallyAI's `_chain_hmac` walk (sitting 2)
and `_iter_entries_from` JSONL reader (sitting 1) locally rather
than importing from LocallyAI's `api.py` / `audit_reader.py`. This
is deliberate — the agent ships as a standalone codebase that
doesn't need the full LocallyAI dependency tree to install — but
if LocallyAI changes the chain algorithm (different canonicalisation,
different HMAC msg format, different genesis convention) the
verifier will silently return false positives or negatives.

Mitigation: re-run the tampering smoke test against the latest
LocallyAI archive after any LocallyAI release that touches
`api.py:_chain_hmac` or `api.py:_write_audit`. Sitting 5 will
introduce a thin `locallyai_adapter.py` that imports the canonical
functions when LocallyAI is installed in the same Python env.

---

## Dependencies

Pure-Python, four packages, no native compile:

```
openai     — talks to LM Studio / Ollama / LocallyAI via OpenAI-compatible API
pydantic   — typed schemas in later sittings
pyyaml     — eval/dataset.yaml
anthropic  — Claude judge (DEV-ONLY; see Eval suite cloud-judge disclosure)
```

Install via `./run.sh setup`. The judge dep ships in the same
venv as the agent itself; it's only used when you actually run
`./run.sh eval`.

---

## License

Same as the parent LocallyAI project.
