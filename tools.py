"""
tools.py — agent-callable tools, sitting 1.

Only `log_search` is implemented tonight. Schema + dispatch table
are exposed for the agent loop.

The reader is intentionally minimal and does NOT import LocallyAI —
that keeps the agent loose-coupled to the audit-log format and
makes this codebase shippable into firms whose LocallyAI checkout
isn't on the same machine. The format is JSONL (one JSON object
per line) with optional gzip-compressed rotations alongside the
active file. Refactor toward the real `audit_reader.py` shape in
sitting 2 once we know what the agent actually needs.
"""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
from typing import Any, Iterable


# ── Configuration ─────────────────────────────────────────────────────────

# Default active log path. Resolved relative to the sibling LocallyAI
# checkout if `LOCALLYAI_AUDIT_LOG` is not set explicitly. Operators
# point this at any JSONL audit log (plain or gzipped) when shipping.
_DEFAULT_LOG = Path.home() / "locallyai" / "logs" / "audit.log"


def _resolve_log_path() -> Path:
    env = os.environ.get("LOCALLYAI_AUDIT_LOG", "").strip()
    if env:
        return Path(env).expanduser()
    return _DEFAULT_LOG


# Fields the search compares against, in order of "most likely to carry a
# hit on a free-text query". `_chain_hmac` is excluded — matching against
# HMAC hex is noise, not signal.
_SEARCHABLE_FIELDS = (
    "matter_code",
    "model",
    "backend",
    "data_region",
    "node_id",
    "user_hash",
    "salt_era",
    "query_hash",
    "timestamp",
)


# ── Reader ────────────────────────────────────────────────────────────────

def _open_jsonl(path: Path):
    """Return a context-managed handle that yields decoded lines from
    `path`, transparently handling .gz rotation files."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")


def _iter_entries_from(path: Path) -> Iterable[dict[str, Any]]:
    """Yield every parseable JSON object in a single audit file."""
    if not path.exists():
        return
    with _open_jsonl(path) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError:
                # Skip malformed lines silently; a real auditor would
                # surface them via a separate diagnostic tool. For
                # log_search the failure mode is "don't poison the
                # result set with garbage lines".
                continue


def _candidate_files(active: Path) -> list[Path]:
    """Active log + sibling rotated .gz files in the same directory.
    Sorted newest-mtime first so the most recent entries appear in
    `max_results` early.

    This is the behaviour an operator expects from a forensic tool:
    "search across the last 7 days" should not need a separate
    invocation per rotated file.
    """
    files: list[Path] = []
    if active.exists():
        files.append(active)
    if active.parent.exists():
        # Sibling rotations follow the LocallyAI naming convention
        # `<stem>-YYYY-MM-DD.log.gz` next to the active file.
        rotations = sorted(
            active.parent.glob(f"{active.stem}-*.log.gz"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        files.extend(rotations)
    # Stable order: active first, then rotations newest-first.
    return files


# ── Tool implementation ──────────────────────────────────────────────────

def log_search(query: str, max_results: int = 20) -> list[dict[str, Any]]:
    """Case-insensitive substring search across audit-log entries.

    Args:
        query: text to look for in the searchable fields of each entry.
        max_results: cap on entries returned (default 20).

    Returns:
        Up to `max_results` matching entries, newest-first by timestamp.
        Each entry is the full JSON dict including `_chain_hmac`. If the
        log file is missing or empty, returns `[]`.

    Notes for the agent:
        - The audit log is **pseudonymised**. A query like "alice" will
          not match a username — the log stores SHA-256 of (salt + name)
          in `user_hash`. Search by `matter_code`, `model`, `backend`,
          `data_region`, `query_hash`, or by timestamp substring instead.
        - An empty query returns the most recent entries up to
          `max_results` — useful as a "give me a sense of the log" probe.
    """
    if not isinstance(max_results, int) or max_results < 1:
        max_results = 20
    if max_results > 500:
        max_results = 500  # bound the response size for the LLM context

    active = _resolve_log_path()
    files = _candidate_files(active)

    needle = (query or "").lower()
    matches: list[dict[str, Any]] = []
    for f in files:
        for entry in _iter_entries_from(f):
            if needle:
                blob = " ".join(
                    str(entry.get(k, "")) for k in _SEARCHABLE_FIELDS
                ).lower()
                if needle not in blob:
                    continue
            matches.append(entry)

    # Newest-first by timestamp. Entries lacking a parseable timestamp
    # sort last to keep the most-recent-first contract honest.
    matches.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return matches[:max_results]


# ── OpenAI tool schema ────────────────────────────────────────────────────

LOG_SEARCH_SCHEMA = {
    "type": "function",
    "function": {
        "name": "log_search",
        "description": (
            "Search LocallyAI's tamper-evident audit log by substring "
            "(case-insensitive) across the entry's metadata fields: "
            "matter_code, model, backend, data_region, node_id, "
            "user_hash, salt_era, query_hash, timestamp. "
            "The log is pseudonymised: usernames are SHA-256 hashes "
            "(field 'user_hash'); query text is never stored — only its "
            "SHA-256 ('query_hash'). Returns up to max_results entries "
            "newest-first. An empty query returns the most recent entries "
            "with no filter applied. Always cite specific entries by "
            "timestamp + user_hash prefix in your answer."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring to match. Pass empty string to get the "
                        "most recent entries with no filter."
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "description": "Cap on entries returned (default 20, max 500).",
                    "default": 20,
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["query"],
        },
    },
}


# ── Dispatch table for the agent loop ────────────────────────────────────

AVAILABLE_TOOLS = {
    "log_search": log_search,
}
