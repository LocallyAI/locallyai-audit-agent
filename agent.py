"""
agent.py — tool-use loop, sitting 1.

OpenAI client pointed at a local Ollama endpoint (OpenAI-compatible),
running Qwen 2.5 14B Instruct. The loop is the standard pattern:

  - send the conversation + tool schemas
  - if the response carries tool_calls: dispatch each, append the
    assistant message + each tool result, recurse
  - if no tool_calls: return the assistant's text content

A hard 5-iteration cap prevents runaway recursion if the model
keeps calling tools or refuses to settle on a final answer.

The OpenAI client + the OpenAI tool-call protocol are deliberate:
when this codebase ships into LocallyAI's own deployment, the only
thing that changes is `base_url` (Ollama → LocallyAI's own
`/v1/chat/completions`). Same code path, same protocol.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable

from openai import OpenAI

from tools import AVAILABLE_TOOLS, HMAC_VERIFY_SCHEMA, LOG_SEARCH_SCHEMA


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
    "HMAC-chained audit log. You have two tools:\n"
    "  - `log_search` for CONTENT questions (what happened, who did "
    "    what, find entries matching X).\n"
    "  - `hmac_verify` for INTEGRITY questions (is the chain intact, "
    "    has the log been tampered with, verify range N to M).\n"
    "If a question mixes both — e.g. 'did X happen AND is that part "
    "of the log tamper-free?' — call both tools and combine the "
    "results in your answer.\n\n"
    "The log is pseudonymised by design: usernames are SHA-256 hashes "
    "in `user_hash`; query text is never stored, only its SHA-256 in "
    "`query_hash`. Cite specific entries by timestamp + `user_hash` "
    "prefix (first 12 chars). For integrity findings, cite the "
    "`first_failure_seq` and the affected entry's timestamp. If a "
    "question can't be answered because the relevant data is "
    "intentionally not in the log (plain-text usernames, query text), "
    "say so explicitly."
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


def run_agent(
    user_query: str,
    *,
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
    model: str | None = None,
) -> str:
    """Execute the agent loop for one user query. Returns the final
    assistant text. `on_event` (optional) receives observability events
    for the CLI to surface — kinds are 'tool_call', 'tool_result',
    'iteration', 'final'.

    The conversation lives in memory only; nothing is persisted by the
    agent itself. Auditing the agent's own calls is a sitting-3 concern.
    """
    client = _make_client()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_query},
    ]
    tools = [LOG_SEARCH_SCHEMA, HMAC_VERIFY_SCHEMA]
    model = model or ENV_MODEL or DEFAULT_MODEL

    for iteration in range(1, MAX_ITERATIONS + 1):
        if on_event:
            on_event("iteration", {"n": iteration})

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        msg = response.choices[0].message

        # No tool calls → we have our final answer
        if not getattr(msg, "tool_calls", None):
            text = msg.content or ""
            if on_event:
                on_event("final", {"text": text, "iterations": iteration})
            return text

        # Append the assistant's tool-call message verbatim (the OpenAI
        # protocol requires the same `tool_calls` block be present in
        # the conversation history before the corresponding tool roles).
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
            if on_event:
                on_event("tool_call", {"name": name, "args_raw": args_raw, "id": tc.id})

            result_json = _dispatch(name, args_raw, AVAILABLE_TOOLS)
            if on_event:
                # Decode for the CLI to pretty-print; the wire format
                # stays JSON-stringified.
                try:
                    decoded = json.loads(result_json)
                except json.JSONDecodeError:
                    decoded = result_json
                on_event("tool_result", {"name": name, "id": tc.id, "result": decoded})

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_json,
            })

    # Iteration cap reached — return whatever the last assistant message
    # carried as content, even if empty, with a diagnostic prefix so the
    # CLI surfaces the runaway condition rather than silently hiding it.
    last_text = messages[-1].get("content", "") if messages else ""
    diag = f"[agent: hit MAX_ITERATIONS={MAX_ITERATIONS} without settling]"
    if on_event:
        on_event("final", {"text": last_text, "iterations": MAX_ITERATIONS, "capped": True})
    return f"{diag}\n{last_text}"


# ── Module-CLI: run as `python agent.py "<query>"` for quick checks ──

if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "Show me the most recent audit entries."
    print(run_agent(q))
