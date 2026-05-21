# locallyai-audit-agent

A forensic-audit agent for LocallyAI's tamper-evident HMAC-chained
audit log. The agent runs as a tool-use loop over a local LLM,
calling `log_search` (sitting 1) — and, in later sittings,
`hmac_verify`, `time_range_query`, `summary_stats` — to investigate
operator questions about who did what, when, against the firm's
deployment.

## Air-gapped by design

This agent ships into the same regulated-industry deployments
LocallyAI itself serves. It must run **without** any call to
`api.anthropic.com`, `api.openai.com`, or any other off-premises
inference endpoint. The implementation uses the OpenAI Python
client throughout, but its `base_url` is pointed at a local
Ollama (or LM Studio, or LocallyAI's own `/v1/chat/completions`)
endpoint — same protocol shape, on-prem hardware.

The default model is **Qwen 2.5 14B Instruct** (Q4_K_M, 32K context).
The Ollama tag is `qwen2.5:14b` — Ollama publishes Qwen 2.5's
default 14B tag as the instruct-tuned variant; this matches the
spec's `qwen2.5:14b-instruct`. Tool-use capability is native (the
`ollama show` capabilities list includes `tools`).

## Sitting 1 scope

One tool: `log_search`. One model: Qwen 2.5 14B. One CLI test.

## Sitting 2 scope

Adds `hmac_verify` — recomputes LocallyAI's `_chain_hmac` chain
and returns `{chain_intact, verified_count, total_count,
first_failure_seq, failures[]}`. With both tools the agent can
investigate audit-log **content** (sitting 1) AND verify
**chain integrity** (sitting 2).

## Sitting 3 scope

Fills out the tool surface to four and instruments the agent
loop with per-run JSONL tracing.

### The four tools

| Tool | Use for | Returns |
|---|---|---|
| `log_search(query, max_results)` | Keyword / substring content matching across metadata fields | Up to `max_results` entries, newest-first |
| `time_range_query(start, end, event_type, user, max_results)` | Precise ISO-8601 time window + structured filters (chat vs admin, user_hash substring) | Up to `max_results` entries in the window, sorted ascending |
| `hmac_verify(start_seq, end_seq)` | Chain integrity, tamper detection, "is this log valid" questions | `{chain_intact, verified_count, total_count, first_failure_seq, failures[≤10]}` |
| `summary_stats(group_by, start, end)` | Counts / top-N / distributions; `group_by` ∈ {`user`, `event_type`, `hour_of_day`, `day`} | `{group_by, total_events, buckets[{key,count}], time_range}` |

Routing decisions live in the tool **descriptions** (the system
prompt is just orientation). Each tool's description explicitly
tells the model when *not* to use it ("use `summary_stats` instead
when the question asks for counts"). If the model passes a
`group_by` not in the enum, `summary_stats` returns a clear error
listing the valid options — the model self-corrects on the next
iteration rather than getting a silent default.

### Tracing

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

Latencies use `time.perf_counter()`. Tool results are truncated to
500 chars in the trace and to 1500 chars when fed back into the
next model call — bounds the context against tool-chaining bloat.

`trace_viewer.py` renders any trace human-readably:

```bash
python trace_viewer.py traces/<file>.jsonl     # specific file
python trace_viewer.py traces/                 # picks the newest
python trace_viewer.py - < trace.jsonl         # stdin pipe
```

The traces directory is the eval-suite input for sitting 4.

## Demo

The CLI runs three sequential queries against the LocallyAI audit
log to exercise tool routing:

```bash
cd ~/locallyai-audit-agent && source .venv/bin/activate
set -a; source /path/to/locallyai/.env; set +a       # for LOCALLYAI_AUDIT_HMAC_KEY
export BASE_URL=http://localhost:1234/v1             # LM Studio
export MODEL=qwen2.5-coder-7b-instruct-mlx
export LOCALLYAI_AUDIT_LOG=/path/to/locallyai/logs/audit.log
python cli.py
```

| Query | Expected tools | Observed (sitting-3 run) |
|---|---|---|
| **Q1 — content** "Find all admin authentication events from the last 24 hours." | `log_search` or `time_range_query` (both reasonable readings) | ✓ `time_range_query(start='2026-05-21T00:00:00Z', end='2026-05-21T23:59:59Z', event_type='admin')` |
| **Q2 — integrity** "Is the audit log chain intact for the last 1000 entries?" | `hmac_verify` only | ✓ `hmac_verify(start_seq=1, end_seq=1000)` → `chain INTACT verified=10/10` |
| **Q3 — mixed** "Did anyone access privileged documents outside business hours, and is that part of the log tamper-free?" | both tools | ✓ `time_range_query(...)` + `hmac_verify(...)` parallelised in one iteration |
| **Q4 — time range** "How many failed login attempts happened between 9am and 5pm yesterday?" | `time_range_query` (possibly chained with `summary_stats`) | ✓ `time_range_query(start='...T09:00:00Z', end='...T17:00:00Z', event_type='non_chat')` |
| **Q5 — aggregation** "Which three users had the most admin actions this week?" | `summary_stats(group_by='user', ...)` | ✓ `summary_stats(group_by='user')` → `{8bcc65a8…: 10}` (the test corpus has one operator) |

### Sample trace

```
=== trace: traces/2026-05-21T190410Z_a91a290b.jsonl ===
  [2026-05-21T19:04:10Z] user_query: 'Which three users had the most admin actions this week?'

  --- iteration 1 ---
    model_call    model=qwen2.5-coder-7b-instruct-mlx  messages=2  latency_ms=3111
    tool_call     summary_stats(group_by='user')  latency_ms=2
    tool_result   summary_stats → {"group_by": "user", "total_events": 10, "buckets": [{"key": "8bcc65a8fac92c0f", "count": 10}], ...}

  --- iteration 2 ---
    model_call    model=qwen2.5-coder-7b-instruct-mlx  messages=4  latency_ms=3436

  === final_answer  iterations=2  total_latency_ms=6551 ===
  Based on the provided summary statistics, there was only one user
  (identified by the hash prefix `8bcc65a8fac92c0f`) who had any
  admin actions during the specified time range. ...

  summary: 2 model calls (6547 ms), 1 tool calls (2 ms)
```

### Tampering smoke test

The point of an HMAC-chained log is that any modification produces
a detectable break. To prove the agent surfaces it correctly, we
copy the live log to a temp directory, mutate one field
(`matter_code`) inside the third entry of an archive, and re-run
Q2 against the tampered copy:

```bash
# 1. Copy logs/audit.log + rotations to /tmp/sitting2-tamper.XXXX/
# 2. Mutate one entry's matter_code field inside the gz archive
# 3. Re-run query 2 against the copy
LOCALLYAI_AUDIT_LOG=/tmp/sitting2-tamper.XXXX/audit.log python cli.py
```

Real terminal output from the smoke test:

```
[Agent] Iteration 1
[Agent] Tool call: hmac_verify(end_seq=1000)
[Tool ] hmac_verify → chain BROKEN  verified=9/10  first_failure_seq=5
  - seq=5  ts=2026-05-15T16:08:17Z  stored=ab4aa6460d6c…  expected=00a6dbcdd2a2…

[Agent] Iteration 2

[Agent] Final answer (iter=2):
The audit log chain for the last 10 entries is not intact. The first
failure is at entry sequence number 5, which has an HMAC mismatch.
The expected HMAC for this entry is 00a6dbcdd2a2c0a5...010f5a5, but
the stored HMAC is ab4aa6460d6cdebb...869e24403b. The failure occurred
at timestamp 2026-05-15T16:08:17Z.
```

This is the demo moment: the chain is cryptographically verifiable
**by anyone holding `LOCALLYAI_AUDIT_HMAC_KEY`**, with no external
service required. The forensic agent reasons about both the
content of what happened *and* whether the log of what happened
has been altered since.

### Secret-key handling discipline

`LOCALLYAI_AUDIT_HMAC_KEY` is loaded from the environment by
`tools._load_hmac_key()`. **It is never accepted as a tool
argument** — the model is not in the loop on secrets, by design.
If the env var is unset, `hmac_verify` raises `HmacKeyMissing`
with a clear message rather than silently returning `chain_intact=False`.

## Audit log format (read from LocallyAI source)

LocallyAI writes JSONL to `logs/audit.log` with daily rotation
into `logs/audit-YYYY-MM-DD.log.gz`. Each entry is one JSON
object on one line. The schema (12 fields + `_chain_hmac`):

| Field | Notes |
|---|---|
| `timestamp` | ISO 8601 UTC, e.g. `2026-05-14T21:23:08Z` |
| `node_id` | hostname of the writing node |
| `data_region` | `UK` or `KSA` |
| `user_hash` | SHA-256 of (salt + username), 16-hex-char pseudonym (GDPR Art. 25) |
| `salt_era` | which `LOCALLYAI_AUDIT_SALT_ERA_N` produced `user_hash` |
| `model` | model ID for chat events; `-` for non-chat events |
| `sources` | number of retrieval sources used (0 for non-chat) |
| `latency_ms` | wall time of the action |
| `backend` | `mlx`, `ollama`, `lmstudio` |
| `query_hash` | SHA-256 of the query text (queries themselves are NEVER logged) |
| `matter_code` | client/matter identifier (free-text, may be empty) |
| `_chain_hmac` | HMAC-SHA256 over (prev_hmac \|\| canonical_json(entry)) — verifier checks this in sitting 2 |

Pseudonymisation note for the forensic agent: a question like
*"find admin events"* cannot literal-string-match a username —
the audit log carries hashes only. A well-designed agent answers
*"the log is pseudonymised by design; here are events in the
relevant time range / matching the relevant model field"*.

## Dependencies

```
openai     (Python client — talks to Ollama/LM Studio via OpenAI-compatible API)
pydantic   (kept for v2 schemas in later sittings)
pyyaml     (sitting 4 — eval/dataset.yaml)
anthropic  (sitting 4 — Claude judge, DEV-ONLY, see "Eval suite" below)
```

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install openai pydantic pyyaml anthropic
```

## Run

```bash
# default — points at logs/audit.log of the sibling LocallyAI checkout
python cli.py

# point at a specific log file or gzipped archive
LOCALLYAI_AUDIT_LOG=/path/to/audit-2026-05-16.log.gz python cli.py

# point at a different OpenAI-compatible endpoint
BASE_URL=https://office-mac.local:8000/v1 python cli.py
```

`cli.py` ships one hardcoded test query and prints each tool call,
each tool result, and the final answer.

## Eval suite

Sitting 4 added a 30-question eval suite over the four-tool agent.
Every change to the agent (prompt, model, tool description, fixture)
is now measurable rather than vibes-graded.

### Dataset

[`eval/dataset.yaml`](eval/dataset.yaml) — 30 questions distributed:

| Category | Count | What it tests |
|---|---|---|
| `log_search` | 8 | keyword routing, pseudonymisation tripwires, hallucination guards |
| `time_range` | 6 | precise ISO-8601 window filtering, event_type filter, ascending sort |
| `aggregation` | 6 | all four `group_by` values (`user`, `event_type`, `hour_of_day`, `day`); top-N edge cases |
| `integrity` | 5 | clean + tampered fixtures; range-scoped verify; citation precision |
| `multi_tool` | 5 | 2+ tool sequences including the hardest "busiest day + chain integrity for that day" case on a tampered fixture |

Each question carries `expected_tools`, ground-truth facts, required + forbidden substrings (hallucination guards), difficulty (easy/medium/hard), and `log_fixture` (clean or tampered). Ground truth is anchored to the **real** LocallyAI audit log on the developer machine — 10 entries, one pseudonymised user, 2 days, the chain intact on `clean` and broken at seq=5 on `tampered`.

Fixtures live under `eval/fixtures/` (gitignored — they contain timestamped data from the live LocallyAI deployment). [`eval/fixtures.py`](eval/fixtures.py) rebuilds them idempotently from the live log; the tamper at seq=5 is deterministic so the eval is reproducible.

### Configuring the cloud judge

> **Important.** The agent itself stays fully air-gapped at runtime. The eval **judge** is the **one place** in the codebase where the air-gap rule is relaxed: it calls Claude (`api.anthropic.com`) to grade the agent's answers against the dataset's ground-truth facts. This is **dev-only tooling** — the judge never ships into a regulated-industry deployment. The distinction is intentional and matters for the pitch: judging is a developer-side measurement activity, not part of the agent the firm runs.

The judge calls Claude Haiku 4.5 by default (cheap, fast, sufficient for the structured boolean grading the prompt asks for). To use it:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# Optional: switch to a stronger judge for closer calls
export JUDGE_MODEL=claude-sonnet-4-6-20251022
```

The judge **never sees the audit log** — it sees only the question, ground-truth facts, the agent's answer, and the tools the agent called. That separation is what keeps the eval deterministic across log changes.

### Running the eval

```bash
# full 30-question run (~10–15 min on Qwen 2.5 Coder 7B via LM Studio,
# 20–40 min on Qwen 2.5 14B via Ollama)
set -a; source /path/to/locallyai/.env; set +a       # LOCALLYAI_AUDIT_HMAC_KEY
export BASE_URL=http://localhost:1234/v1
export MODEL=qwen2.5-coder-7b-instruct-mlx
export ANTHROPIC_API_KEY=sk-ant-...
python -m eval.run

# or equivalently via the cli.py entry point
python cli.py --eval

# debug flags
python -m eval.run --limit 5                         # first 5 questions only
python -m eval.run --start-from q15 --resume-into eval/runs/<existing>.jsonl
python -m eval.run --no-judge                        # offline dry-run (no Claude call)
```

Output lands in [`eval/runs/`](eval/runs/):

- `<stamp>.jsonl` — one line per question (`id`, `category`, `tools_called`, `answer`, `judge:{tool_pass,answer_pass,rationale,…}`, `trace_path`, `agent_latency_ms`)
- `<stamp>_summary.md` — overall + per-category + per-difficulty pass rates, failed-question list with judge rationales, total runtime, judge token usage + estimated cost

### Comparing runs

```bash
python -m eval.compare eval/runs/<base>.jsonl eval/runs/<new>.jsonl
```

Surfaces (a) per-question status flips (pass → fail, fail → pass), (b) per-category pass-rate deltas, (c) overall per-axis deltas. This is the tool to reach for every time you tighten a prompt, swap a model, or refactor a tool description.

### Baseline (2026-05-21)

First baseline run committed at [`eval/runs/2026-05-21T192709Z.jsonl`](eval/runs/2026-05-21T192709Z.jsonl) + [`_summary.md`](eval/runs/2026-05-21T192709Z_summary.md). All 30 questions ran end-to-end against `qwen2.5-coder-7b-instruct-mlx` via LM Studio; runtime 5.6 min.

**The judge ran out of Anthropic credit after question 8.** 22 of 30 questions have valid grades; 22 have `judge_error=true` (the JSONL records the agent's answer + tool calls for every question, so re-grading after topping up is a no-cost run). Honest numbers from the validly-graded subset only:

| Axis | Rate (graded only) |
|---|---|
| Tool selection | 7 / 8 (87.5%) |
| Answer correctness | 2 / 8 (25.0%) |
| Both axes | 2 / 8 (25.0%) |

By category (graded subset is `log_search` only — the credit ran out before any other category got judged):

| Category | Both pass | Tool pass | Answer pass |
|---|---|---|---|
| `log_search` | 2/8 (25.0%) | 7/8 (87.5%) | 2/8 (25.0%) |
| `time_range` | — (no graded rows) | — | — |
| `aggregation` | — (no graded rows) | — | — |
| `integrity` | — (no graded rows) | — | — |
| `multi_tool` | — (no graded rows) | — | — |

**Honest read:** the agent reliably picks the right tool on simple content questions (7/8 tool-pass) but the model hallucinates content on questions where the answer requires reading the search results carefully (e.g. q02 — the agent searched for `"MLX"`, got 0 hits because the model field is `"mlx-community/..."` lowercased, and then **confabulated** "no entries used the MLX backend" instead of broadening the search). This is exactly the kind of failure mode the eval is meant to expose.

**Next-session task:** top up the Anthropic balance, re-grade the remaining 22 questions with `python -m eval.run --start-from q09 --resume-into eval/runs/2026-05-21T192709Z.jsonl`, then begin the prompt + tool-description tuning loop in sitting 5 with `python -m eval.compare` reporting deltas against this baseline.

### Honest limits

- One judge (Claude Haiku 4.5). No model-vs-model judge matrices.
- 30 questions, not 100. Quality of questions over count for v1.
- Markdown summary; no HTML dashboard, no charts.
- The dataset's ground truth is currently anchored to a 10-entry log on the developer machine. Re-generating the fixtures against a richer log requires updating `ground_truth_facts` in `dataset.yaml` for any quantitative claim that depends on counts.

---

## Roadmap

- ~~**Sitting 1** — `log_search` + the OpenAI-shaped agent loop.~~ ✓ shipped
- ~~**Sitting 2** — `hmac_verify` + system-prompt tool-routing + tamper-detection smoke test.~~ ✓ shipped
- ~~**Sitting 3** — `time_range_query`, `summary_stats`, per-run JSONL tracing + `trace_viewer.py`.~~ ✓ shipped
- ~~**Sitting 4** — 30-question eval suite + Claude judge + run comparator + baseline.~~ ✓ shipped
- **Sitting 5** — Prompt + tool-description tuning to lift the baseline. Use `eval/compare.py` to verify every change. Also: swap to Qwen 2.5 14B Instruct (or a stronger Coder variant) once a working build is available; quantify the model-quality delta against the baseline. FastAPI server + per-firm deployment as a `/admin/forensics/ask` endpoint behind `_admin_auth`.

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

## License

Same as the parent LocallyAI project.
