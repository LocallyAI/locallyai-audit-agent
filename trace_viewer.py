"""
trace_viewer.py — pretty-print one or more JSONL agent traces.

Usage:
    python trace_viewer.py traces/<file>.jsonl
    python trace_viewer.py traces/                  # picks the newest
    cat traces/<file>.jsonl | python trace_viewer.py -

Renders one event per line, indented under the iteration number,
with timings rolled up to a per-run summary at the end. Designed
for demos + debugging, not log-analysis at scale (that's eval's
job in sitting 4).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable


def _resolve_path(arg: str) -> Path | None:
    """`arg` can be a file, a directory (uses newest .jsonl in it), or '-'.
    Returns None for stdin mode."""
    if arg == "-":
        return None
    p = Path(arg)
    if p.is_dir():
        traces = sorted(p.glob("*.jsonl"), key=lambda f: f.stat().st_mtime)
        if not traces:
            raise FileNotFoundError(f"no .jsonl files under {p}")
        return traces[-1]
    if not p.exists():
        raise FileNotFoundError(arg)
    return p


def _iter_events(source: Iterable[str]) -> Iterable[dict[str, Any]]:
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            print(f"  ! malformed line skipped: {line[:80]}...", file=sys.stderr)
            continue


def _render(events: Iterable[dict[str, Any]], origin: str) -> None:
    print(f"=== trace: {origin} ===")
    current_iter: int | None = None
    tool_count = 0
    model_call_count = 0
    total_tool_ms = 0
    total_model_ms = 0

    for ev in events:
        kind = ev.get("event")
        if kind == "user_query":
            print(f'  [{ev.get("timestamp","?")}] user_query: {ev["content"]!r}')
        elif kind == "model_call":
            it = ev.get("iteration", 0)
            if it != current_iter:
                current_iter = it
                print(f"\n  --- iteration {it} ---")
            ms = ev.get("latency_ms", 0)
            total_model_ms += ms
            model_call_count += 1
            print(f'    model_call    model={ev.get("model","?")}  '
                  f'messages={ev.get("messages_count","?")}  '
                  f'latency_ms={ms}')
        elif kind == "tool_call":
            it = ev.get("iteration", 0)
            if it != current_iter:
                current_iter = it
                print(f"\n  --- iteration {it} ---")
            tool_count += 1
            ms = ev.get("latency_ms", 0)
            total_tool_ms += ms
            args = ev.get("args", {})
            args_repr = ", ".join(f"{k}={v!r}" for k, v in args.items()) or "<no args>"
            print(f'    tool_call     {ev["tool"]}({args_repr})  '
                  f'latency_ms={ms}')
        elif kind == "tool_result":
            print(f'    tool_result   {ev["tool"]} → {ev.get("result_summary","")[:200]}')
        elif kind == "error":
            print(f'    !! ERROR in {ev.get("where","?")}: '
                  f'{ev.get("exception","?")}: {ev.get("message","")[:200]}')
        elif kind == "final_answer":
            iters = ev.get("total_iterations", "?")
            ms = ev.get("total_latency_ms", "?")
            text = ev.get("content", "")
            print(f"\n  === final_answer  iterations={iters}  total_latency_ms={ms} ===")
            print(f"  {text[:600]}{' …' if len(text) > 600 else ''}")
        else:
            print(f"    (unknown event: {kind})  {ev}")

    print()
    print(f"  summary: {model_call_count} model calls "
          f"({total_model_ms} ms), {tool_count} tool calls "
          f"({total_tool_ms} ms)")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    arg = argv[1]
    if arg == "-":
        _render(_iter_events(sys.stdin), origin="<stdin>")
        return 0
    path = _resolve_path(arg)
    if path is None:
        return 1
    with open(path, "r", encoding="utf-8") as f:
        _render(_iter_events(f), origin=str(path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
