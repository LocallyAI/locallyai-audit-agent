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
**chain integrity** (sitting 2). See the **Demo** section below.

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

| Query | Expected tools | Observed (sitting-2 run) |
|---|---|---|
| **Q1 — content** "Find all admin authentication events from the last 24 hours." | `log_search` only | ✓ `log_search(query='admin', max_results=500)` |
| **Q2 — integrity** "Is the audit log chain intact for the last 1000 entries?" | `hmac_verify` only | ✓ `hmac_verify(end_seq=1000)` → `chain INTACT verified=10/10` |
| **Q3 — mixed** "Did anyone access privileged documents outside business hours, and is that part of the log tamper-free?" | both tools | ✓ `log_search(query='privileged documents non-business hours')` + `hmac_verify()` parallelised in one iteration |

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
- **Sitting 3** — `time_range_query`, `summary_stats`; 30-question eval suite. Also: swap to Qwen 2.5 14B Instruct once a working build is available, run the eval to quantify the routing-quality / answer-quality delta vs Coder 7B.
- **Sitting 4** — FastAPI server + per-firm deployment as a `/admin/forensics/ask` endpoint behind `_admin_auth`.

## License

Same as the parent LocallyAI project.
