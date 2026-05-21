"""
cli.py — sitting 1 end-to-end test.

Runs one hardcoded forensic question through the agent loop and prints
(a) each tool call with arguments, (b) each tool result truncated to
the first three entries for readability, (c) the final answer.

Exit code 0 on success, 1 if the agent errors out before producing a
final answer.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from agent import run_agent
from tools import _resolve_log_path

TEST_QUERY = "Find all admin authentication events from the last 24 hours."


def _truncate(result: Any, head: int = 3) -> Any:
    """Cap a list-of-dicts at `head` entries for terminal display."""
    if isinstance(result, list):
        suffix = f" ... [+{len(result) - head} more]" if len(result) > head else ""
        return result[:head], suffix
    return result, ""


def _emit(kind: str, payload: dict[str, Any]) -> None:
    if kind == "iteration":
        print(f"\n[Agent] Iteration {payload['n']}")
    elif kind == "tool_call":
        name = payload["name"]
        # The model's tool_calls.function.arguments is a JSON string;
        # decode it for display but don't choke on malformed JSON.
        try:
            args = json.loads(payload["args_raw"])
            args_repr = ", ".join(f"{k}={v!r}" for k, v in args.items())
        except json.JSONDecodeError:
            args_repr = f"<unparsed JSON: {payload['args_raw']!r}>"
        print(f"[Agent] Tool call: {name}({args_repr})")
    elif kind == "tool_result":
        result = payload["result"]
        head, suffix = _truncate(result, head=3)
        if isinstance(result, list):
            print(f"[Tool ] Returned {len(result)} entries:")
            for entry in head:
                # Compact one-line summary for terminal sanity
                ts = entry.get("timestamp", "?")
                uh = (entry.get("user_hash") or "")[:12]
                model = entry.get("model", "?")
                matter = entry.get("matter_code") or "-"
                print(f"  - {ts}  user={uh}  model={model}  matter={matter}")
            if suffix:
                print(f"  {suffix.strip()}")
        elif isinstance(result, dict) and "error" in result:
            print(f"[Tool ] ERROR: {result['error']}")
        else:
            print(f"[Tool ] {json.dumps(result, indent=2)[:500]}")
    elif kind == "final":
        capped = payload.get("capped")
        marker = " (capped at MAX_ITERATIONS)" if capped else ""
        print(f"\n[Agent] Final answer (after {payload['iterations']} iteration(s){marker}):")
        print(payload["text"])


def main() -> int:
    log_path = _resolve_log_path()
    print(f"=== locallyai-audit-agent — sitting 1 ===")
    print(f"  Audit log:   {log_path}  (exists={log_path.exists()})")
    print(f"  Base URL:    {os.getenv('BASE_URL', 'http://localhost:11434/v1')}")
    print(f"  Model:       {os.getenv('MODEL', 'qwen2.5:14b')}")
    print(f"  Query:       {TEST_QUERY!r}")
    print("=" * 50)

    try:
        run_agent(TEST_QUERY, on_event=_emit)
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
