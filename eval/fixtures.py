"""
eval/fixtures.py — build + maintain the eval log fixtures.

Two fixtures live under eval/fixtures/:

  clean/audit.log + clean/audit-YYYY-MM-DD.log.gz
      copy of the live LocallyAI audit log on this machine. Used by
      every clean-fixture eval question.

  tampered/audit.log + tampered/audit-YYYY-MM-DD.log.gz
      same content but with one entry's `matter_code` field mutated.
      The tamper is deterministic so re-running the eval against the
      same fixture produces the same hmac_verify result every run.

Fixtures are gitignored — they hold timestamped data from the live
LocallyAI deployment on this machine and shouldn't bloat the repo.
The fixture-builder runs idempotently at the top of eval/run.py so a
clean checkout reproduces the fixtures from the live log.
"""
from __future__ import annotations

import gzip
import json
import os
import shutil
from pathlib import Path

# Source: the live LocallyAI audit log + its sibling rotations.
SRC_LOG = Path(os.environ.get(
    "LOCALLYAI_AUDIT_LOG_SOURCE",
    "/Users/emanuel/locallyai/logs/audit.log",
))

CLEAN_DIR    = Path(__file__).resolve().parent / "fixtures" / "clean"
TAMPERED_DIR = Path(__file__).resolve().parent / "fixtures" / "tampered"

# Tamper target: which seq position to mutate (1-indexed across all
# entries chronologically). Sitting 2's smoke test used seq=5, which
# falls inside the second archive (audit-2026-05-16.log.gz, line 3).
# Keeping that to match the README's worked example.
TAMPER_TARGET_SEQ = 5


def _gather_source_files() -> list[Path]:
    """Active log + sibling .gz rotations, sorted chronologically.
    Mirrors tools._candidate_files but stable for the fixture builder."""
    if not SRC_LOG.parent.exists():
        raise FileNotFoundError(
            f"audit log directory {SRC_LOG.parent} not found; "
            "set LOCALLYAI_AUDIT_LOG_SOURCE to point at your LocallyAI "
            "checkout's logs/audit.log path."
        )
    files: list[Path] = []
    # Sort archives chronologically (oldest first) so the chain walks
    # in the same order the canonical verifier uses.
    rotations = sorted(SRC_LOG.parent.glob(f"{SRC_LOG.stem}-*.log.gz"))
    files.extend(rotations)
    if SRC_LOG.exists():
        files.append(SRC_LOG)
    return files


def _copy_into(dest_dir: Path) -> list[Path]:
    """Wipe + repopulate dest_dir from the source files. Returns the
    list of destination paths in chronological order."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for old in list(dest_dir.iterdir()):
        if old.is_file():
            old.unlink()
    out: list[Path] = []
    for src in _gather_source_files():
        dst = dest_dir / src.name
        shutil.copy2(src, dst)
        out.append(dst)
    return out


def _iter_lines(path: Path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                yield line.rstrip("\n")
    else:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                yield line.rstrip("\n")


def _rewrite_lines(path: Path, lines: list[str]) -> None:
    body = "\n".join(lines) + ("\n" if lines else "")
    if path.suffix == ".gz":
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write(body)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)


def _apply_tamper(files: list[Path], target_seq: int) -> dict:
    """Locate entry #`target_seq` across the (chronologically ordered)
    files, mutate one field, and write back. Returns a small record
    describing the tamper for eval ground-truth references."""
    cur_seq = 0
    for f in files:
        lines = list(_iter_lines(f))
        for i, raw in enumerate(lines):
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            cur_seq += 1
            if cur_seq != target_seq:
                continue
            # Mutate matter_code — chosen because it doesn't change the
            # semantic interpretation of the entry but does change the
            # HMAC. This is the same tamper sitting 2's smoke test used.
            before = entry.get("matter_code", "")
            entry["matter_code"] = "M-TAMPER-EVAL"
            lines[i] = json.dumps(entry)
            _rewrite_lines(f, lines)
            return {
                "tampered_seq":   target_seq,
                "tampered_file":  str(f.name),
                "tampered_field": "matter_code",
                "value_before":   before,
                "value_after":    "M-TAMPER-EVAL",
            }
    raise RuntimeError(
        f"tamper target seq={target_seq} not found across "
        f"{sum(1 for f in files)} fixture files (only {cur_seq} entries available)"
    )


def build(force: bool = False) -> dict:
    """Build both fixtures from the live LocallyAI audit log.
    Idempotent: returns the existing fixture's tamper-record if files
    already exist and `force=False`.
    Returns metadata about the fixtures for run.py to log."""
    marker = TAMPERED_DIR / ".tamper_record.json"
    if not force and CLEAN_DIR.exists() and marker.exists():
        try:
            return json.loads(marker.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass  # fall through and rebuild

    _copy_into(CLEAN_DIR)
    tampered_files = _copy_into(TAMPERED_DIR)
    record = _apply_tamper(tampered_files, TAMPER_TARGET_SEQ)
    marker.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def fixture_log_path(fixture_name: str) -> Path:
    """Return the active log path the agent's LOCALLYAI_AUDIT_LOG env
    var should point at for a given fixture. The walker in tools.py
    follows the .gz siblings automatically."""
    if fixture_name == "clean":
        return CLEAN_DIR / SRC_LOG.name
    if fixture_name == "tampered":
        return TAMPERED_DIR / SRC_LOG.name
    raise ValueError(f"unknown fixture: {fixture_name!r}")


if __name__ == "__main__":  # pragma: no cover
    rec = build(force=True)
    print(json.dumps(rec, indent=2))
