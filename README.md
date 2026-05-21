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
openai     (Python client — talks to Ollama via OpenAI-compatible API)
pydantic   (kept for v2 schemas in later sittings)
```

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install openai pydantic
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

## Roadmap

- ~~**Sitting 1** — `log_search` + the OpenAI-shaped agent loop.~~ ✓ shipped
- ~~**Sitting 2** — `hmac_verify` + system-prompt tool-routing + tamper-detection smoke test.~~ ✓ shipped
- ~~**Sitting 3** — `time_range_query`, `summary_stats`, per-run JSONL tracing + `trace_viewer.py`.~~ ✓ shipped
- **Sitting 4** — 30-question eval suite (the traces from sitting 3 are the input). Model swap to Qwen 2.5 14B Instruct once a working build is available; quantify the routing-quality / answer-quality delta vs Coder 7B on the eval.
- **Sitting 5** — FastAPI server + per-firm deployment as a `/admin/forensics/ask` endpoint behind `_admin_auth`.

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
