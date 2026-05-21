"""
cli.py — sitting 2 end-to-end test.

Runs three hardcoded forensic questions through the agent loop and
prints (a) each tool call with arguments, (b) each tool result
truncated to the first three entries for readability, (c) the final
answer. Separator between queries.

Expected tool selection (the model's routing is the primary thing
being tested):

  Q1 (content)    → log_search only
  Q2 (integrity)  → hmac_verify only
  Q3 (mixed)      → both tools

Exit code 0 on success, 1 if any query errors out before producing a
final answer.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from agent import run_agent
from tools import _resolve_log_path

QUERIES = [
    ("Q1 — content",
     "Find all admin authentication events from the last 24 hours."),
    ("Q2 — integrity",
     "Is the audit log chain intact for the last 1000 entries?"),
    ("Q3 — mixed",
     "Did anyone access privileged documents outside business hours, "
     "and is that part of the log tamper-free?"),
    ("Q4 — time range",
     "How many failed login attempts happened between 9am and 5pm yesterday?"),
    ("Q5 — aggregation",
     "Which three users had the most admin actions this week?"),
]


def _truncate(result: Any, head: int = 3) -> tuple[Any, str]:
    if isinstance(result, list):
        suffix = f" ... [+{len(result) - head} more]" if len(result) > head else ""
        return result[:head], suffix
    return result, ""


def _format_log_entry(entry: dict) -> str:
    ts = entry.get("timestamp", "?")
    uh = (entry.get("user_hash") or "")[:12]
    model = entry.get("model", "?")
    matter = entry.get("matter_code") or "-"
    return f"  - {ts}  user={uh}  model={model}  matter={matter}"


def _format_failure(f: dict) -> str:
    return (f"  - seq={f.get('seq')}  ts={f.get('timestamp')}  "
            f"stored={f.get('stored_hmac','')[:12]}…  "
            f"expected={f.get('expected_hmac','')[:12]}…")


def _emit(kind: str, payload: dict[str, Any]) -> None:
    if kind == "trace_started":
        print(f"[Trace] Writing to {payload['path']}")
    elif kind == "iteration":
        print(f"\n[Agent] Iteration {payload['n']}")
    elif kind == "tool_call":
        name = payload["name"]
        try:
            args = json.loads(payload["args_raw"]) if payload["args_raw"] else {}
            args_repr = ", ".join(f"{k}={v!r}" for k, v in args.items()) or "<no args>"
        except json.JSONDecodeError:
            args_repr = f"<unparsed: {payload['args_raw']!r}>"
        print(f"[Agent] Tool call: {name}({args_repr})")
    elif kind == "tool_result":
        name = payload["name"]
        result = payload["result"]
        if isinstance(result, dict) and "error" in result:
            print(f"[Tool ] ERROR: {result['error']}")
            return
        if name == "log_search" and isinstance(result, list):
            head, suffix = _truncate(result, head=3)
            print(f"[Tool ] log_search → {len(result)} entries:")
            for e in head:
                print(_format_log_entry(e))
            if suffix:
                print(f"  {suffix.strip()}")
        elif name == "time_range_query" and isinstance(result, list):
            # The tool returns a single-element list with an error dict
            # when the timestamps are bad; render that distinctly.
            if result and isinstance(result[0], dict) and "error" in result[0]:
                print(f"[Tool ] time_range_query → ERROR: {result[0]}")
            else:
                head, suffix = _truncate(result, head=3)
                print(f"[Tool ] time_range_query → {len(result)} entries:")
                for e in head:
                    print(_format_log_entry(e))
                if suffix:
                    print(f"  {suffix.strip()}")
        elif name == "summary_stats" and isinstance(result, dict):
            if "error" in result:
                print(f"[Tool ] summary_stats → ERROR: {result['error']}: "
                      f"{result.get('detail','')[:200]}")
            else:
                buckets = result.get("buckets", [])
                print(f"[Tool ] summary_stats(group_by={result.get('group_by')}) → "
                      f"{result.get('total_events',0)} events across "
                      f"{len(buckets)} buckets")
                for b in buckets[:5]:
                    print(f"  - {b['key']}: {b['count']}")
                if len(buckets) > 5:
                    print(f"  ... [+{len(buckets) - 5} more buckets]")
        elif name == "hmac_verify" and isinstance(result, dict):
            v = result
            ok = "INTACT" if v.get("chain_intact") else "BROKEN"
            print(f"[Tool ] hmac_verify → chain {ok}  "
                  f"verified={v.get('verified_count')}/{v.get('total_count')}  "
                  f"first_failure_seq={v.get('first_failure_seq')}")
            if v.get("failures"):
                print(f"  failures ({len(v['failures'])} shown, capped at 10):")
                for f in v["failures"][:3]:
                    print(_format_failure(f))
        else:
            text = json.dumps(result, indent=2)
            print(f"[Tool ] {text[:500]}{' ...' if len(text) > 500 else ''}")
    elif kind == "final":
        capped = payload.get("capped")
        marker = " (capped at MAX_ITERATIONS)" if capped else ""
        print(f"\n[Agent] Final answer (after {payload['iterations']} "
              f"iteration(s){marker}):")
        print(payload["text"])


def main() -> int:
    log_path = _resolve_log_path()
    print("=" * 70)
    print("=== locallyai-audit-agent — sitting 3 ===")
    print(f"  Audit log:   {log_path}  (exists={log_path.exists()})")
    print(f"  Base URL:    {os.getenv('BASE_URL', 'http://localhost:11434/v1')}")
    print(f"  Model:       {os.getenv('MODEL', 'qwen2.5:14b')}")
    print(f"  HMAC key:    {'set' if os.environ.get('LOCALLYAI_AUDIT_HMAC_KEY') else 'NOT SET — hmac_verify will raise'}")
    print("=" * 70)

    rc = 0
    for label, query in QUERIES:
        print(f"\n{'-' * 70}")
        print(f"{label}: {query!r}")
        print("-" * 70)
        try:
            run_agent(query, on_event=_emit)
        except Exception as e:
            print(f"\n[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
            rc = 1

    print("\n" + "=" * 70)
    print("Done.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
