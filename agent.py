"""
agent.py — tool-use loop with per-run structured tracing (sitting 3).

OpenAI client pointed at a local Ollama / LM Studio / LocallyAI
endpoint, running a tool-capable Qwen 2.5 family model. The loop:

  - send the conversation + tool schemas
  - if the response carries tool_calls: dispatch each, append the
    assistant message + each tool result, recurse
  - if no tool_calls: return the assistant's text content

A hard 5-iteration cap prevents runaway recursion if the model
keeps calling tools or refuses to settle on a final answer.

Every invocation writes one JSONL trace file under `traces/` via the
`Tracer` from `tracing.py`. The path is returned via `on_event` as
the `trace_started` event so the CLI can print it. Trace events
cover user_query / model_call / tool_call / tool_result /
final_answer (+ error on exceptions). Latencies use perf_counter().

The OpenAI client + the OpenAI tool-call protocol are deliberate:
when this codebase ships into LocallyAI's own deployment, the only
thing that changes is `base_url`. Same code path, same protocol.
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from typing import Any

from openai import OpenAI

from tools import (
    AVAILABLE_TOOLS,
    HMAC_VERIFY_SCHEMA,
    LOG_SEARCH_SCHEMA,
    SUMMARY_STATS_SCHEMA,
    TIME_RANGE_QUERY_SCHEMA,
)
from tracing import Tracer

# ── Configuration ─────────────────────────────────────────────────────────

DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_MODEL = "qwen2.5:14b"          # = qwen2.5:14b-instruct on Ollama
MAX_ITERATIONS = 5

# Env override for the model identifier — LM Studio, vLLM, and
# LocallyAI's own /v1/chat/completions all use different `model` strings
# for what's nominally "Qwen 2.5 14B Instruct". Setting MODEL from the
# environment keeps the agent code portable.
ENV_MODEL = os.getenv("MODEL", "").strip() or None

SYSTEM_PROMPT = (
    "You are a forensic auditor for LocallyAI's tamper-evident, "
    "HMAC-chained audit log. You have four tools — pick by question "
    "shape (see each tool's description for details):\n"
    "  - log_search       — keyword / substring content matching\n"
    "  - time_range_query — precise ISO-8601 time window + filters\n"
    "  - hmac_verify      — chain integrity / tamper detection\n"
    "  - summary_stats    — counts and aggregations (group_by enum)\n"
    "Chain multiple tools if the question mixes shapes.\n\n"
    "The log is pseudonymised by design: usernames live as SHA-256 "
    "hashes in `user_hash`; query text is never stored, only its "
    "SHA-256 in `query_hash`. There is no `event_type` column — "
    "entries with model='-' are non-chat / admin actions, entries "
    "with a real model string are chat completions.\n\n"
    "Cite entries by timestamp + `user_hash[:12]`. For integrity "
    "findings, cite `first_failure_seq` and the affected timestamp. "
    "For aggregations, cite the top buckets with their counts. "
    "If a question can't be answered because the relevant data is "
    "intentionally absent (plain-text usernames, query text), say "
    "so explicitly rather than guess."
)


# ── Loop ──────────────────────────────────────────────────────────────────

def _make_client() -> OpenAI:
    return OpenAI(
        base_url=os.getenv("BASE_URL", DEFAULT_BASE_URL),
        api_key="ollama",  # placeholder — Ollama ignores it
    )


def _dispatch(name: str, args_json: str, available: dict[str, Callable]) -> str:
    """Run a tool by name, JSON-stringify the result for the assistant."""
    func = available.get(name)
    if func is None:
        return json.dumps({"error": f"unknown tool: {name}"})
    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid tool arguments JSON: {e}"})
    try:
        result = func(**args)
    except TypeError as e:
        return json.dumps({"error": f"bad arguments for {name}: {e}"})
    except Exception as e:
        return json.dumps({"error": f"{name} raised {type(e).__name__}: {e}"})
    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError) as e:
        return json.dumps({"error": f"result not JSON-serialisable: {e}"})


# Truncation budget for tool result strings going INTO the conversation
# messages (NOT the JSONL trace — the trace has its own 500-char cap).
# Keeps the context bounded when the model chains several tools across
# iterations; 1500 chars is enough for narrative continuity without
# bloating the next model call.
_TOOL_RESULT_MAX_CHARS_IN_CONTEXT = 1500


def _truncate_for_context(result_json: str) -> str:
    if len(result_json) <= _TOOL_RESULT_MAX_CHARS_IN_CONTEXT:
        return result_json
    return result_json[: _TOOL_RESULT_MAX_CHARS_IN_CONTEXT - 60] + (
        f' …[truncated; full result was {len(result_json)} chars]"}}'
    )


def run_agent(
    user_query: str,
    *,
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
    model: str | None = None,
) -> str:
    """Execute the agent loop for one user query. Returns the final
    assistant text. Writes one JSONL trace file per call to `traces/`.

    `on_event` (optional) receives interactive events for the CLI to
    print. Kinds: `trace_started`, `iteration`, `tool_call`,
    `tool_result`, `final`.
    """
    client = _make_client()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_query},
    ]
    tools = [
        LOG_SEARCH_SCHEMA,
        TIME_RANGE_QUERY_SCHEMA,
        HMAC_VERIFY_SCHEMA,
        SUMMARY_STATS_SCHEMA,
    ]
    model = model or ENV_MODEL or DEFAULT_MODEL
    tracer = Tracer.start(user_query)
    if on_event:
        on_event("trace_started", {"path": str(tracer.path)})

    try:
        for iteration in range(1, MAX_ITERATIONS + 1):
            if on_event:
                on_event("iteration", {"n": iteration})

            # ── Model call (timed) ──────────────────────────────
            t0 = time.perf_counter()
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                )
            except Exception as exc:
                tracer.error(iteration=iteration, where="model_call", exc=exc)
                raise
            model_latency_ms = int((time.perf_counter() - t0) * 1000)
            tracer.model_call(
                iteration=iteration, model=model,
                messages_count=len(messages), latency_ms=model_latency_ms,
            )
            msg = response.choices[0].message

            # No tool calls → final answer
            if not getattr(msg, "tool_calls", None):
                text = msg.content or ""
                tracer.final_answer(content=text, total_iterations=iteration)
                if on_event:
                    on_event("final", {"text": text, "iterations": iteration})
                return text

            # Append the assistant's tool-call message verbatim.
            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ],
            })

            for tc in msg.tool_calls:
                name = tc.function.name
                args_raw = tc.function.arguments
                try:
                    args_decoded = json.loads(args_raw) if args_raw else {}
                except json.JSONDecodeError:
                    args_decoded = {"_unparsed": args_raw}
                if on_event:
                    on_event("tool_call", {"name": name, "args_raw": args_raw, "id": tc.id})

                # ── Tool dispatch (timed) ──────────────────────
                t1 = time.perf_counter()
                result_json = _dispatch(name, args_raw, AVAILABLE_TOOLS)
                tool_latency_ms = int((time.perf_counter() - t1) * 1000)
                try:
                    decoded = json.loads(result_json)
                except json.JSONDecodeError:
                    decoded = result_json

                tracer.tool_call(iteration=iteration, tool=name,
                                 args=args_decoded, latency_ms=tool_latency_ms)
                tracer.tool_result(iteration=iteration, tool=name, result=decoded)

                if on_event:
                    on_event("tool_result", {"name": name, "id": tc.id, "result": decoded})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": _truncate_for_context(result_json),
                })

        # Iteration cap — return what we have with a diagnostic prefix.
        last_text = messages[-1].get("content", "") if messages else ""
        diag = f"[agent: hit MAX_ITERATIONS={MAX_ITERATIONS} without settling]"
        capped_answer = f"{diag}\n{last_text}"
        tracer.final_answer(content=capped_answer, total_iterations=MAX_ITERATIONS)
        if on_event:
            on_event("final", {"text": last_text, "iterations": MAX_ITERATIONS, "capped": True})
        return capped_answer
    finally:
        tracer.close()


# ── Module-CLI: run as `python agent.py "<query>"` for quick checks ──

if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "Show me the most recent audit entries."
    print(run_agent(q))
