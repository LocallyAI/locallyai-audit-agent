"""
eval/compare.py — diff two eval-run JSONL files.

The fix-and-measure loop. Without this you're guessing whether a
prompt tweak / tool description tightening / model swap actually
helped or just shifted noise around.

Three things it surfaces:

  1. Per-question status flips (pass → fail or fail → pass)
  2. Per-category pass-rate deltas
  3. Overall pass-rate delta on each axis (tool / answer / both)

A passing question is one where both `judge.tool_pass` and
`judge.answer_pass` are true.

Usage:
    python -m eval.compare <base>.jsonl <new>.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows[row.get("id", f"<no-id-{len(rows)}>")] = row
    return rows


def _passed(row: dict[str, Any]) -> tuple[bool, bool, bool]:
    """(tool, answer, both) — None means ungraded; we treat it as
    fail here for tallying purposes but the caller can filter via
    `_is_graded` first to avoid mixing ungraded into per-axis rates."""
    j = row.get("judge", {}) or {}
    tp = bool(j.get("tool_pass"))
    ap = bool(j.get("answer_pass"))
    return tp, ap, (tp and ap)


def _is_graded(row: dict[str, Any]) -> bool:
    j = row.get("judge", {}) or {}
    if j.get("judge_error"):
        return False
    if (j.get("rationale") or "").startswith("skipped"):
        return False
    # treat explicit None on both axes as ungraded too
    return j.get("tool_pass") is not None and j.get("answer_pass") is not None


def _rate(numer: int, denom: int) -> str:
    if denom == 0:
        return "—"
    return f"{numer}/{denom} ({numer / denom * 100:.1f}%)"


def _delta(new: int, old: int, denom: int) -> str:
    if denom == 0:
        return "—"
    diff = new - old
    sign = "+" if diff > 0 else ""
    pct_diff = (new - old) / denom * 100
    return f"{sign}{diff}  ({sign}{pct_diff:+.1f}%)"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="diff two eval-run JSONL files")
    ap.add_argument("base", help="baseline JSONL")
    ap.add_argument("new",  help="new JSONL to compare against baseline")
    args = ap.parse_args(argv)

    base_path = Path(args.base)
    new_path = Path(args.new)
    if not base_path.exists():
        print(f"baseline not found: {base_path}", file=sys.stderr)
        return 1
    if not new_path.exists():
        print(f"new file not found: {new_path}", file=sys.stderr)
        return 1

    base = _load(base_path)
    new = _load(new_path)

    common_all = sorted(set(base) & set(new))
    only_base = sorted(set(base) - set(new))
    only_new = sorted(set(new) - set(base))

    # Restrict per-axis comparisons to rows where BOTH sides were
    # validly graded. Mixing ungraded into a rate produces misleading
    # deltas (e.g. a baseline that exhausted judge credits would look
    # worse than a complete new run on every axis).
    common = [q for q in common_all if _is_graded(base[q]) and _is_graded(new[q])]
    only_base_ungraded = [q for q in common_all if not _is_graded(base[q])]
    only_new_ungraded = [q for q in common_all if _is_graded(base[q]) and not _is_graded(new[q])]

    print("=== eval diff ===")
    print(f"  base: {base_path}  ({len(base)} rows)")
    print(f"  new:  {new_path}  ({len(new)} rows)")
    print(f"  shared: {len(common_all)} questions  "
          f"(base-only: {len(only_base)}, new-only: {len(only_new)})")
    print(f"  comparable (both-sides graded): {len(common)} questions")
    if only_base_ungraded or only_new_ungraded:
        print(f"  ungraded on one side: base={len(only_base_ungraded)}, "
              f"new={len(only_new_ungraded)} — skipped from rate deltas")

    if only_base:
        print(f"\n  only in base: {only_base}")
    if only_new:
        print(f"\n  only in new:  {only_new}")

    # ── Status flips (on shared ids) ────────────────────────────
    flips_to_pass: list[tuple[str, str, str]] = []  # (id, axis, "fail→pass")
    flips_to_fail: list[tuple[str, str, str]] = []
    cat_flips: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for qid in common:
        b_t, b_a, b_b = _passed(base[qid])
        n_t, n_a, n_b = _passed(new[qid])
        cat = new[qid].get("category", "?")
        if b_b != n_b:
            arrow = "fail→pass" if (not b_b and n_b) else "pass→fail"
            entry = (qid, cat, arrow)
            if not b_b and n_b:
                flips_to_pass.append(entry)
            else:
                flips_to_fail.append(entry)
            cat_flips[cat].append((qid, arrow))

    print()
    print(f"  status flips (both-axes): "
          f"fail→pass {len(flips_to_pass)}, pass→fail {len(flips_to_fail)}")
    if flips_to_pass:
        print("    fail → PASS:")
        for qid, cat, _ in flips_to_pass:
            print(f"      ✓ {qid}  [{cat}]  base judge rationale: "
                  f"{base[qid]['judge'].get('rationale','')[:120]}")
    if flips_to_fail:
        print("    pass → FAIL:")
        for qid, cat, _ in flips_to_fail:
            print(f"      ✗ {qid}  [{cat}]  new judge rationale:  "
                  f"{new[qid]['judge'].get('rationale','')[:120]}")

    # ── Per-category deltas ─────────────────────────────────────
    print()
    print("=== per-category pass-rate deltas (both axes) ===")
    print(f"  {'category':<14} {'base':<18} {'new':<18} {'delta'}")
    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"b_pass": 0, "n_pass": 0, "n": 0})
    for qid in common:
        cat = new[qid].get("category", "?")
        by_cat[cat]["n"] += 1
        if _passed(base[qid])[2]:
            by_cat[cat]["b_pass"] += 1
        if _passed(new[qid])[2]:
            by_cat[cat]["n_pass"] += 1
    for cat in sorted(by_cat):
        d = by_cat[cat]
        n = d["n"]
        print(f"  {cat:<14} {_rate(d['b_pass'], n):<18} {_rate(d['n_pass'], n):<18} {_delta(d['n_pass'], d['b_pass'], n)}")

    # ── Per-axis overall deltas ─────────────────────────────────
    n = len(common)
    b_tool = sum(1 for q in common if _passed(base[q])[0])
    n_tool = sum(1 for q in common if _passed(new[q])[0])
    b_ans = sum(1 for q in common if _passed(base[q])[1])
    n_ans = sum(1 for q in common if _passed(new[q])[1])
    b_both = sum(1 for q in common if _passed(base[q])[2])
    n_both = sum(1 for q in common if _passed(new[q])[2])

    print()
    print("=== overall ===")
    print("  axis        base               new                delta")
    print(f"  tool        {_rate(b_tool, n):<18} {_rate(n_tool, n):<18} {_delta(n_tool, b_tool, n)}")
    print(f"  answer      {_rate(b_ans, n):<18} {_rate(n_ans, n):<18} {_delta(n_ans, b_ans, n)}")
    print(f"  both        {_rate(b_both, n):<18} {_rate(n_both, n):<18} {_delta(n_both, b_both, n)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
