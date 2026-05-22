"""
tools.py — agent-callable tools.

Four tools as of sitting 3:
    log_search          — keyword/substring match across metadata fields
    hmac_verify         — HMAC chain-integrity walk (sitting 2)
    time_range_query    — precise ISO-timestamp window + structured filters
    summary_stats       — aggregations bucketed by a fixed enum

The reader is intentionally minimal and does NOT import LocallyAI —
that keeps the agent loose-coupled to the audit-log format and makes
this codebase shippable into firms whose LocallyAI checkout isn't on
the same machine. The format is JSONL (one JSON object per line) with
optional gzip-compressed rotations alongside the active file.

LocallyAI audit-log schema (12 fields + `_chain_hmac`):
    timestamp node_id data_region user_hash salt_era model sources
    latency_ms backend query_hash matter_code _chain_hmac
There is NO `event_type` column. This module maps the spec-level
concept of "event type" onto the real `model` field: entries with
`model == "-"` are non-chat administrative events (user CRUD, ACL
edits, conflict checks, etc.); entries with `model != "-"` are chat
completions. The tool descriptions surface this so the model routes
correctly.
"""
from __future__ import annotations

import datetime
import gzip
import hmac as _hmac
import json
import os
from collections import Counter
from collections.abc import Iterable
from hashlib import sha256
from pathlib import Path
from typing import Any

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
    return open(path, encoding="utf-8")


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


# ─────────────────────────────────────────────────────────────────────────
# hmac_verify — HMAC-chain integrity verification (sitting 2)
# ─────────────────────────────────────────────────────────────────────────
#
# Re-implements LocallyAI's _chain_hmac algorithm (api.py:556-559) here
# rather than importing api.py. The algorithm is 3 lines; vendoring it
# keeps this codebase importable on machines that don't have LocallyAI
# installed at all (the eventual deployment target for the agent).
#
# Canonical algorithm (matches api.py:2210-2223 verifier exactly):
#
#     prev = "0" * 64                                  # genesis
#     for line in chronological order across rotations + live log:
#         entry = json.loads(line)
#         stored = entry.pop("_chain_hmac", "")
#         if not stored: continue          # entries with no chain → skip
#         msg = prev + json.dumps(entry, sort_keys=True)
#         expected = HMAC-SHA256(key=AUDIT_HMAC_KEY, msg=msg).hex()
#         if not compare_digest(stored, expected): TAMPERED
#         prev = stored
#
# Notes for future-me:
#   - `entry.pop("_chain_hmac")` MUST run before json.dumps, since the
#     HMAC was computed over the dict before _chain_hmac was added.
#   - `sort_keys=True`, NO separators argument (default `(', ', ': ')`).
#   - `_AUDIT_HMAC_KEY` is whatever bytes the env var holds — NOT hex-
#     decoded (api.py does `.encode()` only, treating the hex string as
#     ASCII bytes). Verifier must match exactly.

_HMAC_KEY_ENV = "LOCALLYAI_AUDIT_HMAC_KEY"
_GENESIS_PREV = "0" * 64


class HmacKeyMissing(RuntimeError):
    """Raised when the HMAC key isn't configured. Surfaces clearly to
    the caller instead of silently returning chain_intact=False."""


def _load_hmac_key() -> bytes:
    """Read the HMAC key from env (matches LocallyAI's convention)."""
    raw = os.environ.get(_HMAC_KEY_ENV, "").strip()
    if not raw:
        raise HmacKeyMissing(
            f"{_HMAC_KEY_ENV} not set in environment. Source LocallyAI's "
            f".env (e.g. `set -a; . /path/to/locallyai/.env; set +a`) "
            f"before running the agent. The secret is never accepted as "
            f"a tool argument."
        )
    return raw.encode("utf-8")


def _expected_chain_hmac(entry_without_field: dict, prev: str, key: bytes) -> str:
    """Vendored from LocallyAI api.py:_chain_hmac. Returns hex digest."""
    entry_json = json.dumps(entry_without_field, sort_keys=True)
    return _hmac.new(key, f"{prev}{entry_json}".encode(), sha256).hexdigest()


def _iter_log_entries_with_seq(active: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    """Yield (seq, entry) across rotations + active log in chronological
    order. seq is 1-indexed across the full chain.

    Walk order matches LocallyAI's audit_verify endpoint (api.py:2236-2248):
    `sorted(LOG_DIR.glob("audit-*.log.gz"))` first, then the active log.
    """
    if not active.parent.exists():
        return
    archives = sorted(active.parent.glob(f"{active.stem}-*.log.gz"))
    seq = 0
    for f in archives + ([active] if active.exists() else []):
        for entry in _iter_entries_from(f):
            seq += 1
            yield seq, entry


def hmac_verify(start_seq: int | None = None, end_seq: int | None = None) -> dict[str, Any]:
    """Verify the LocallyAI audit-log HMAC chain.

    Args:
        start_seq: 1-indexed first entry to record results for. None = 1.
        end_seq: 1-indexed last entry to record results for. None = the
            last entry on disk.

    Returns the shape the agent-side cli + system prompt expect:
        {
          "verified_count": int,            # entries that hashed correctly in range
          "total_count":    int,            # entries inspected in range
          "first_failure_seq": int | None,  # earliest break in range, if any
          "failures": [                     # truncated to first 10
            {"seq", "expected_hmac", "stored_hmac", "timestamp"}, ...
          ],
          "chain_intact":   bool,           # True iff failures == [] in range
        }

    Important: chain-of-trust extends from genesis. To verify entry N
    correctly, we MUST recompute entries 1..N-1 (their `_chain_hmac`
    becomes the `prev` for entry N). Narrowing via start_seq does not
    skip that walk — it only narrows the failure-reporting window. This
    is a correctness > performance choice; at 50K+ entries we'd add an
    explicit `unsafe_skip_to_start` opt-in.
    """
    # Bounds + normalisation. None-and-zero both mean "no constraint".
    lo = max(1, int(start_seq)) if start_seq else 1
    hi = int(end_seq) if end_seq else None
    if hi is not None and hi < lo:
        return {
            "verified_count": 0, "total_count": 0,
            "first_failure_seq": None, "failures": [],
            "chain_intact": True,
            "error": f"end_seq ({hi}) < start_seq ({lo})",
        }

    key = _load_hmac_key()           # raises HmacKeyMissing if unset
    active = _resolve_log_path()

    prev = _GENESIS_PREV
    verified_count = 0
    total_count = 0
    first_failure_seq: int | None = None
    failures: list[dict[str, Any]] = []
    _FAILURE_CAP = 10

    for seq, entry in _iter_log_entries_with_seq(active):
        if hi is not None and seq > hi:
            break
        # Mutate-on-copy: don't disturb the iterator's view of the entry.
        e = dict(entry)
        stored = e.pop("_chain_hmac", "")
        if not stored:
            # Entries without _chain_hmac happen when LOCALLYAI_AUDIT_HMAC_KEY
            # was empty at write time. The canonical verifier skips them
            # without advancing `prev` either — preserve that semantics.
            continue

        in_range = seq >= lo
        expected = _expected_chain_hmac(e, prev, key)

        if in_range:
            total_count += 1
        match = _hmac.compare_digest(stored, expected)
        if match:
            if in_range:
                verified_count += 1
        else:
            if in_range:
                if first_failure_seq is None:
                    first_failure_seq = seq
                if len(failures) < _FAILURE_CAP:
                    failures.append({
                        "seq": seq,
                        "expected_hmac": expected,
                        "stored_hmac": stored,
                        "timestamp": entry.get("timestamp", ""),
                    })
        # Advance prev with what's STORED on disk, not with `expected`.
        # Otherwise a single tampered entry only breaks that one seq;
        # the canonical chain semantics is "everything after the break
        # also fails", which only happens when prev follows the stored
        # value (so the next entry's recomputation diverges).
        prev = stored

    return {
        "verified_count": verified_count,
        "total_count": total_count,
        "first_failure_seq": first_failure_seq,
        "failures": failures,
        "chain_intact": first_failure_seq is None,
    }


HMAC_VERIFY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "hmac_verify",
        "description": (
            "Verify the cryptographic integrity of LocallyAI's audit log "
            "by recomputing the HMAC-SHA256 chain and comparing against "
            "the stored `_chain_hmac` per entry. USE THIS TOOL for any "
            "question about: tampering, chain integrity, log validity, "
            "whether the log has been modified, whether entries N-M are "
            "intact, or whether you can trust the audit trail. "
            "Returns `chain_intact: true` if every entry's recomputed "
            "HMAC matches the stored value, or `chain_intact: false` "
            "with `first_failure_seq` pointing at the earliest break. "
            "Always cite `first_failure_seq` and the timestamp of the "
            "first failed entry in your answer when chain_intact is "
            "false. Pass start_seq + end_seq to narrow the result "
            "window (the walk still starts from genesis to preserve "
            "chain-of-trust). Do NOT use this tool to find log content; "
            "use `log_search` for that."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "start_seq": {
                    "type": "integer",
                    "description": (
                        "1-indexed sequence number of the first entry to "
                        "record results for. Omit or pass 1 to verify "
                        "from the start of the chain."
                    ),
                    "minimum": 1,
                },
                "end_seq": {
                    "type": "integer",
                    "description": (
                        "1-indexed sequence number of the last entry to "
                        "record results for. Omit to verify to the end "
                        "of the chain."
                    ),
                    "minimum": 1,
                },
            },
            # Both optional — the model can call hmac_verify({}) to verify everything.
            "required": [],
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────
# time_range_query — precise structured filtering by timestamp + fields
# ─────────────────────────────────────────────────────────────────────────
#
# Distinct from log_search by design: log_search is a free-text
# substring scan, time_range_query is a structured filter. The
# different tool descriptions are what route the model correctly.


def _parse_iso(ts: str) -> datetime.datetime | None:
    """Parse an ISO-8601 timestamp tolerating trailing `Z`. Returns None
    on parse failure (caller decides whether to error or skip)."""
    if not ts:
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.UTC)
    return dt


def time_range_query(
    start: str,
    end: str,
    event_type: str | None = None,
    user: str | None = None,
    max_results: int = 50,
) -> list[dict[str, Any]]:
    """Return audit entries with `start <= timestamp <= end`, optionally
    filtered by event_type / user. Sorted ascending by timestamp.

    Args:
        start, end: ISO-8601 timestamps (e.g. `2026-05-20T14:00:00Z`).
        event_type: one of `chat` (entries with model != "-"),
            `non_chat` / `admin` (entries with model == "-"), or a
            substring matched case-insensitively against the `model`
            field (so `event_type="mlx-community/Qwen"` works).
        user: substring matched case-insensitively against `user_hash`.
            (The audit log pseudonymises usernames; pass the hash
            prefix, not the plain-text name.)
        max_results: cap on entries returned (default 50, max 500).
    """
    if not isinstance(max_results, int) or max_results < 1:
        max_results = 50
    if max_results > 500:
        max_results = 500

    start_dt = _parse_iso(start)
    end_dt = _parse_iso(end)
    if start_dt is None or end_dt is None:
        return [{
            "error": "invalid_timestamp",
            "detail": f"start={start!r} end={end!r} — expected ISO-8601 (e.g. '2026-05-20T14:00:00Z').",
        }]
    if end_dt < start_dt:
        return [{"error": "invalid_range", "detail": f"end ({end}) precedes start ({start})."}]

    et = (event_type or "").strip().lower()
    user_needle = (user or "").strip().lower()

    active = _resolve_log_path()
    files = _candidate_files(active)
    matches: list[tuple[datetime.datetime, dict[str, Any]]] = []
    for f in files:
        for entry in _iter_entries_from(f):
            ts_dt = _parse_iso(entry.get("timestamp", ""))
            if ts_dt is None or ts_dt < start_dt or ts_dt > end_dt:
                continue
            if et:
                model = (entry.get("model") or "").strip()
                if et in ("chat",):
                    if model == "-" or not model:
                        continue
                elif et in ("non_chat", "non-chat", "admin"):
                    if model and model != "-":
                        continue
                else:
                    # Free-text substring match against the model field.
                    if et not in model.lower():
                        continue
            if user_needle:
                if user_needle not in (entry.get("user_hash") or "").lower():
                    continue
            matches.append((ts_dt, entry))

    matches.sort(key=lambda t: t[0])           # ascending by timestamp
    return [m[1] for m in matches[:max_results]]


TIME_RANGE_QUERY_SCHEMA = {
    "type": "function",
    "function": {
        "name": "time_range_query",
        "description": (
            "Return audit-log entries whose `timestamp` falls inside a "
            "precise ISO-8601 window, optionally narrowed by event_type "
            "and user. USE THIS TOOL when the question carries a "
            "time window or a structured filter ('between 9 and 5', "
            "'yesterday', 'last week', 'all chat events on 2026-05-15'). "
            "Use `log_search` instead for free-text keyword matching "
            "with no time constraint. Use `summary_stats` instead when "
            "the question asks for counts or aggregations rather than "
            "individual entries.\n"
            "event_type values:\n"
            "  - `chat`     — entries with model != '-' (chat completions)\n"
            "  - `non_chat` / `admin` — entries with model == '-' "
            "(user CRUD, ACL edits, conflict checks, document compare)\n"
            "  - any other string — substring-matched against `model`\n"
            "user must be a substring of `user_hash` (the audit log "
            "pseudonymises usernames; pass the hash prefix, not the "
            "plain-text name)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "start": {"type": "string", "description": "ISO-8601 start (inclusive), e.g. '2026-05-20T09:00:00Z'."},
                "end":   {"type": "string", "description": "ISO-8601 end (inclusive), e.g. '2026-05-20T17:00:00Z'."},
                "event_type": {"type": "string", "description": "Optional. `chat` | `non_chat` | `admin` | substring of model."},
                "user":  {"type": "string", "description": "Optional. Substring of `user_hash`."},
                "max_results": {"type": "integer", "default": 50, "minimum": 1, "maximum": 500},
            },
            "required": ["start", "end"],
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────
# summary_stats — aggregations on a fixed enum (NOT a query language)
# ─────────────────────────────────────────────────────────────────────────

_VALID_GROUP_BY = ("user", "event_type", "hour_of_day", "day")


def summary_stats(
    group_by: str,
    start: str | None = None,
    end: str | None = None,
) -> dict[str, Any]:
    """Bucket audit entries by one of a fixed set of dimensions and
    return per-bucket counts sorted descending.

    Args:
        group_by: one of `user`, `event_type`, `hour_of_day`, `day`.
            ANY other value returns an explicit error — the model is
            expected to self-correct on the next iteration. We do NOT
            silently coerce to a default.
        start, end: optional ISO-8601 time window. Both inclusive.

    Return shape:
        {
          "group_by":     str,
          "total_events": int,
          "buckets":      [{"key": str, "count": int}, ...],
          "time_range":   {"start": str | None, "end": str | None},
        }
    """
    gb = (group_by or "").strip().lower()
    if gb not in _VALID_GROUP_BY:
        return {
            "error": "invalid_group_by",
            "detail": (f"group_by={group_by!r} is not supported. "
                       f"Valid values: {list(_VALID_GROUP_BY)}."),
            "valid_group_by": list(_VALID_GROUP_BY),
        }

    start_dt = _parse_iso(start) if start else None
    end_dt = _parse_iso(end) if end else None
    if start and start_dt is None:
        return {"error": "invalid_timestamp", "detail": f"start={start!r} — expected ISO-8601."}
    if end and end_dt is None:
        return {"error": "invalid_timestamp", "detail": f"end={end!r} — expected ISO-8601."}

    active = _resolve_log_path()
    files = _candidate_files(active)
    counter: Counter[str] = Counter()
    total = 0
    for f in files:
        for entry in _iter_entries_from(f):
            ts_dt = _parse_iso(entry.get("timestamp", ""))
            if ts_dt is None:
                continue
            if start_dt and ts_dt < start_dt:
                continue
            if end_dt and ts_dt > end_dt:
                continue
            total += 1
            if gb == "user":
                key = (entry.get("user_hash") or "")[:16] or "(no user_hash)"
            elif gb == "event_type":
                model = (entry.get("model") or "").strip()
                key = "non_chat" if (model == "-" or not model) else "chat"
            elif gb == "hour_of_day":
                key = f"{ts_dt.hour:02d}"
            elif gb == "day":
                key = ts_dt.date().isoformat()
            else:                                        # pragma: no cover
                key = "(unreachable)"
            counter[key] += 1

    buckets = [{"key": k, "count": c} for k, c in counter.most_common()]
    return {
        "group_by":     gb,
        "total_events": total,
        "buckets":      buckets,
        "time_range":   {"start": start, "end": end},
    }


SUMMARY_STATS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "summary_stats",
        "description": (
            "Aggregate the audit log into per-bucket counts, sorted "
            "desc by count. USE THIS TOOL for any question asking "
            "'how many', 'top N', 'distribution', 'breakdown', "
            "'busiest hour', or 'which users had the most ...'. "
            "Use `time_range_query` or `log_search` instead when the "
            "question asks for individual entries rather than counts.\n"
            "group_by is a fixed enum (any other value is an error):\n"
            "  - `user`        — count per `user_hash` prefix\n"
            "  - `event_type`  — `chat` vs `non_chat` (model is '-')\n"
            "  - `hour_of_day` — bucketed 00..23 from timestamp\n"
            "  - `day`         — bucketed by calendar date\n"
            "Pass start + end as ISO-8601 timestamps to narrow the "
            "time window."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "group_by": {
                    "type": "string",
                    "enum": list(_VALID_GROUP_BY),
                    "description": "Dimension to bucket by.",
                },
                "start": {"type": "string", "description": "Optional ISO-8601 start (inclusive)."},
                "end":   {"type": "string", "description": "Optional ISO-8601 end (inclusive)."},
            },
            "required": ["group_by"],
        },
    },
}


# ── Dispatch table for the agent loop ────────────────────────────────────

AVAILABLE_TOOLS = {
    "log_search":       log_search,
    "hmac_verify":      hmac_verify,
    "time_range_query": time_range_query,
    "summary_stats":    summary_stats,
}
