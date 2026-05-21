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
That's it for tonight — see `cli.py` and run it.

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

- **Sitting 2** — `hmac_verify` tool that walks the chain offline; refactor `log_search` toward the real `audit_reader.py` shape.
- **Sitting 3** — `time_range_query`, `summary_stats`; 30-question eval suite.
- **Sitting 4** — FastAPI server + per-firm deployment as a `/admin/forensics/ask` endpoint behind `_admin_auth`.

## License

Same as the parent LocallyAI project.
