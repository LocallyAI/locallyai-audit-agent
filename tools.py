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
import hmac as _hmac
import json
import os
from hashlib import sha256
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
    return _hmac.new(key, f"{prev}{entry_json}".encode("utf-8"), sha256).hexdigest()


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


# ── Dispatch table for the agent loop ────────────────────────────────────

AVAILABLE_TOOLS = {
    "log_search":  log_search,
    "hmac_verify": hmac_verify,
}
