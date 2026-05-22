"""
tracing.py — structured per-run JSONL tracing for the agent loop.

One trace file per `run_agent()` invocation, written to `traces/`.
Filename format: `{ISO timestamp without colons}_{8-char uuid}.jsonl`
(colons stripped so the path survives Windows / S3 / shell globs).

Each line is one event:
    {"event": "user_query",    "content": str,           "timestamp": str}
    {"event": "model_call",    "iteration": int,         "model": str, "messages_count": int, "latency_ms": int}
    {"event": "tool_call",     "iteration": int,         "tool": str, "args": dict, "latency_ms": int}
    {"event": "tool_result",   "iteration": int,         "tool": str, "result_summary": str}
    {"event": "final_answer",  "content": str,           "total_iterations": int, "total_latency_ms": int}

Errors during model or tool calls produce an additional event:
    {"event": "error", "iteration": int, "where": "model_call"|"tool_call",
     "exception": str, "message": str}

The Tracer is a thin object the agent passes events to. It owns the
file handle so partial traces survive crashes (each write is flushed
+ fsynced immediately — at the cost of disk thrash, which is fine
for an interactive agent at human pace).
"""
from __future__ import annotations

import datetime
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

_TRACE_RESULT_TRUNCATE = 500   # chars per tool result going into the trace


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarise_result(result: Any) -> str:
    """Convert a tool result into a compact one-line summary for the
    trace. Keeps the trace human-scannable; full results are
    reconstructable from the audit log itself."""
    try:
        s = json.dumps(result, default=str)
    except (TypeError, ValueError):
        s = repr(result)
    if isinstance(result, list):
        s = f"list[{len(result)}] {s}"
    elif isinstance(result, dict) and "error" in result:
        s = f"ERROR {result.get('error')}: {result.get('detail','')[:200]}"
    if len(s) > _TRACE_RESULT_TRUNCATE:
        s = s[:_TRACE_RESULT_TRUNCATE - 1] + "…"
    return s


class Tracer:
    """Per-run trace writer. Construct via `Tracer.start(query)`; emit
    events via the typed helper methods; the destructor closes the
    file. The agent loop holds one tracer for the duration of a single
    `run_agent()` call."""

    def __init__(self, path: Path, started_at: float):
        self.path = path
        self._fp = open(path, "w", encoding="utf-8")
        self._started_at = started_at

    @classmethod
    def start(cls, query: str, trace_dir: Path | None = None) -> Tracer:
        d = trace_dir or Path(os.environ.get("LOCALLYAI_TRACE_DIR", "traces"))
        d.mkdir(parents=True, exist_ok=True)
        stamp = _now_iso().replace(":", "")
        path = d / f"{stamp}_{uuid.uuid4().hex[:8]}.jsonl"
        t = cls(path, time.perf_counter())
        t._emit({"event": "user_query", "content": query, "timestamp": _now_iso()})
        return t

    # ── private write primitive ──────────────────────────────────────

    def _emit(self, payload: dict[str, Any]) -> None:
        # default=str so timestamps / Paths / Pydantic objects don't
        # crash the tracer mid-run; lose-ily survives anything sane.
        self._fp.write(json.dumps(payload, default=str) + "\n")
        self._fp.flush()
        try:
            os.fsync(self._fp.fileno())
        except OSError:
            pass

    # ── typed helpers (agent.py calls these) ─────────────────────────

    def model_call(self, *, iteration: int, model: str, messages_count: int, latency_ms: int) -> None:
        self._emit({"event": "model_call", "iteration": iteration, "model": model,
                    "messages_count": messages_count, "latency_ms": latency_ms})

    def tool_call(self, *, iteration: int, tool: str, args: dict, latency_ms: int) -> None:
        self._emit({"event": "tool_call", "iteration": iteration, "tool": tool,
                    "args": args, "latency_ms": latency_ms})

    def tool_result(self, *, iteration: int, tool: str, result: Any) -> None:
        self._emit({"event": "tool_result", "iteration": iteration, "tool": tool,
                    "result_summary": _summarise_result(result)})

    def error(self, *, iteration: int, where: str, exc: BaseException) -> None:
        self._emit({"event": "error", "iteration": iteration, "where": where,
                    "exception": type(exc).__name__, "message": str(exc)[:500]})

    def final_answer(self, *, content: str, total_iterations: int) -> None:
        total_latency_ms = int((time.perf_counter() - self._started_at) * 1000)
        self._emit({"event": "final_answer", "content": content,
                    "total_iterations": total_iterations,
                    "total_latency_ms": total_latency_ms})

    def close(self) -> None:
        if not self._fp.closed:
            self._fp.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
