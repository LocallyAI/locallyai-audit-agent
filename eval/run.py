"""
eval/run.py — drive the 30-question eval suite end-to-end.

Sequence per question:
  1. Build fixtures (idempotent — re-uses on disk if already built).
  2. Set LOCALLYAI_AUDIT_LOG to the per-question fixture's active path.
  3. Run the agent loop on the question; capture: final answer, tools
     called (in order), trace file path, latency.
  4. Pass everything plus the dataset's ground-truth-facts/required/
     forbidden lists to the Claude judge.
  5. Append a JSONL line to eval/runs/{stamp}.jsonl per question.
  6. After all questions: emit eval/runs/{stamp}_summary.md with
     overall + per-category + per-difficulty pass rates and the
     failed-question list with judge rationales.

Runs sequentially (the local model can't multiplex on a MacBook).
Expected runtime: 20-40 min for 30 questions on a local Qwen 14B,
roughly 8-15 min on Qwen 2.5 Coder 7B via LM Studio.

CLI flags:
    --start-from <id>    resume mid-run by skipping every question
                         with id < <id>. Appends to the same stamped
                         JSONL when paired with --resume-into <path>.
    --resume-into <p>    write to an existing JSONL instead of a fresh
                         stamped one. Used with --start-from.
    --dataset <path>     override the dataset yaml.
    --limit <n>          only run the first n questions (debug).
    --no-judge           skip the Claude judge (offline dry-run; both
                         pass axes recorded as null + rationale="skipped").

Run:
    set -a; source /path/to/locallyai/.env; set +a    # LOCALLYAI_AUDIT_HMAC_KEY
    export BASE_URL=http://localhost:1234/v1          # LM Studio
    export MODEL=qwen2.5-coder-7b-instruct-mlx
    export ANTHROPIC_API_KEY=...                      # judge
    python -m eval.run
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
import traceback
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

# Local imports — adjust sys.path so `python -m eval.run` works whether
# invoked from the repo root or via the cli.py --eval flag.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agent import run_agent
from eval.fixtures import build as build_fixtures
from eval.fixtures import fixture_log_path
from eval.judge import JudgeNotConfigured
from eval.judge import grade as judge_grade

EVAL_DIR = Path(__file__).resolve().parent
RUNS_DIR = EVAL_DIR / "runs"


# ── Per-question agent runner with tool-call capture ────────────────────

def _run_one_with_capture(question: str) -> dict[str, Any]:
    """Run the agent on one question; return everything the runner +
    judge need, including the ordered list of tool names called."""
    tools_called: list[str] = []
    tool_call_details: list[dict[str, Any]] = []
    trace_path: str | None = None

    def _capture(kind: str, payload: dict[str, Any]) -> None:
        nonlocal trace_path
        if kind == "trace_started":
            trace_path = payload.get("path")
        elif kind == "tool_call":
            tools_called.append(payload["name"])
            tool_call_details.append({
                "name": payload["name"],
                "args_raw": payload.get("args_raw", ""),
            })

    t0 = time.perf_counter()
    try:
        answer = run_agent(question, on_event=_capture)
        agent_error: str | None = None
    except Exception as exc:
        answer = f"[agent raised {type(exc).__name__}: {exc}]"
        agent_error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
    latency_ms = int((time.perf_counter() - t0) * 1000)

    return {
        "answer":             answer,
        "tools_called":       tools_called,
        "tool_call_details":  tool_call_details,
        "trace_path":         trace_path,
        "agent_latency_ms":   latency_ms,
        "agent_error":        agent_error,
    }


# ── Summary generation ──────────────────────────────────────────────────

def _pct(numer: int, denom: int) -> str:
    if denom == 0:
        return "—"
    return f"{(numer / denom) * 100:.1f}%"


def _emit_summary(
    *,
    summary_path: Path,
    results: list[dict[str, Any]],
    started_at: datetime.datetime,
    duration_s: float,
    fixture_record: dict[str, Any],
    dataset_path: Path,
    model: str,
    base_url: str,
    judge_skipped: bool,
) -> None:
    total = len(results)
    judge_errors = sum(1 for r in results if r["judge"].get("judge_error"))
    judge_skipped_flag = sum(1 for r in results if r["judge"].get("rationale", "").startswith("skipped"))
    graded = [r for r in results
              if not r["judge"].get("judge_error")
              and not r["judge"].get("rationale", "").startswith("skipped")]
    graded_n = len(graded)
    tool_passes = sum(1 for r in graded if r["judge"]["tool_pass"])
    answer_passes = sum(1 for r in graded if r["judge"]["answer_pass"])
    both_passes = sum(1 for r in graded
                      if r["judge"]["tool_pass"] and r["judge"]["answer_pass"])

    # Per-category
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_diff: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in results:
        by_cat[r["category"]].append(r)
        by_diff[r["difficulty"]].append(r)

    # Tokens + estimated cost (Haiku rates as of ~2026-05; Anthropic
    # publishes updated rates on their pricing page).
    total_in = sum(r["judge"].get("input_tokens", 0) for r in results)
    total_out = sum(r["judge"].get("output_tokens", 0) for r in results)
    # Haiku 4.5 pricing (approx, public list price): $1/MTok input, $5/MTok output.
    cost_usd = (total_in / 1_000_000) * 1.0 + (total_out / 1_000_000) * 5.0

    failed = [r for r in graded
              if not (r["judge"]["tool_pass"] and r["judge"]["answer_pass"])]
    ungraded = [r for r in results
                if r["judge"].get("judge_error")
                or r["judge"].get("rationale", "").startswith("skipped")]

    lines: list[str] = []
    lines.append(f"# Eval run — {started_at.isoformat()}Z")
    lines.append("")
    lines.append(f"- **Dataset:** `{dataset_path.name}` ({total} questions)")
    lines.append(f"- **Agent base URL:** `{base_url}`")
    lines.append(f"- **Agent model:** `{model}`")
    if judge_skipped:
        lines.append("- **Judge:** SKIPPED (--no-judge)")
    else:
        lines.append(f"- **Judge:** `{results[0]['judge'].get('judge_model','?')}` (Claude, cloud, dev-only)")
    lines.append(f"- **Fixture tamper:** seq={fixture_record.get('tampered_seq')} field={fixture_record.get('tampered_field')}")
    lines.append(f"- **Total runtime:** {duration_s:.1f} s ({duration_s / 60:.1f} min)")
    if not judge_skipped:
        lines.append(f"- **Judge tokens:** {total_in} in / {total_out} out → est. ${cost_usd:.4f} USD")
    lines.append("")
    lines.append("## Pass rates")
    lines.append("")
    lines.append(f"- **Questions:** {total} total; **{graded_n} validly graded**; "
                 f"{judge_errors} judge-unavailable (e.g. API credit exhausted); "
                 f"{judge_skipped_flag} judge-skipped via --no-judge.")
    if graded_n == 0:
        lines.append("- **No valid grades — judge was unavailable for every question.**")
    else:
        lines.append(f"- **Tool selection:**   {tool_passes}/{graded_n}  ({_pct(tool_passes, graded_n)})  (graded only)")
        lines.append(f"- **Answer correctness:** {answer_passes}/{graded_n}  ({_pct(answer_passes, graded_n)})  (graded only)")
        lines.append(f"- **Both axes pass:**   {both_passes}/{graded_n}  ({_pct(both_passes, graded_n)})  (graded only)")
    lines.append("")
    lines.append("### By category")
    lines.append("")
    lines.append("| Category | Both pass | Tool pass | Answer pass |")
    lines.append("|---|---|---|---|")
    for cat in ("log_search", "time_range", "aggregation", "integrity", "multi_tool"):
        rs = [r for r in by_cat.get(cat, []) if not r["judge"].get("judge_error")
              and not r["judge"].get("rationale", "").startswith("skipped")]
        n = len(rs)
        if n == 0:
            lines.append(f"| `{cat}` | — | — | — | (no graded rows) |"
                         if False else f"| `{cat}` | — (no graded rows) | — | — |")
            continue
        b = sum(1 for r in rs if r["judge"]["tool_pass"] and r["judge"]["answer_pass"])
        t = sum(1 for r in rs if r["judge"]["tool_pass"])
        a = sum(1 for r in rs if r["judge"]["answer_pass"])
        lines.append(f"| `{cat}` | {b}/{n} ({_pct(b,n)}) | {t}/{n} ({_pct(t,n)}) | {a}/{n} ({_pct(a,n)}) |")
    lines.append("")
    lines.append("### By difficulty")
    lines.append("")
    lines.append("| Difficulty | Both pass | Tool pass | Answer pass |")
    lines.append("|---|---|---|---|")
    for diff in ("easy", "medium", "hard"):
        rs = [r for r in by_diff.get(diff, []) if not r["judge"].get("judge_error")
              and not r["judge"].get("rationale", "").startswith("skipped")]
        n = len(rs)
        if n == 0:
            lines.append(f"| {diff} | — (no graded rows) | — | — |")
            continue
        b = sum(1 for r in rs if r["judge"]["tool_pass"] and r["judge"]["answer_pass"])
        t = sum(1 for r in rs if r["judge"]["tool_pass"])
        a = sum(1 for r in rs if r["judge"]["answer_pass"])
        lines.append(f"| {diff} | {b}/{n} ({_pct(b,n)}) | {t}/{n} ({_pct(t,n)}) | {a}/{n} ({_pct(a,n)}) |")
    lines.append("")
    if ungraded:
        lines.append("## Ungraded questions (judge unavailable)")
        lines.append("")
        lines.append(f"{len(ungraded)} questions were run by the agent but could not be "
                     f"graded — the judge raised an error (typically API credit exhausted "
                     f"mid-run) or was skipped via `--no-judge`. The agent's answers are "
                     f"in the JSONL; re-run with `--start-from {ungraded[0]['id']} "
                     f"--resume-into eval/runs/<this>.jsonl` after fixing the judge.")
        lines.append("")
        for r in ungraded:
            lines.append(f"- `{r['id']}` ({r['category']}/{r['difficulty']}) — "
                         f"{r['judge'].get('rationale','')[:140]}")
        lines.append("")
    lines.append("## Failed questions (validly graded as failing)")
    lines.append("")
    if not failed:
        lines.append("None. All validly-graded questions passed on both axes.")
    else:
        for r in failed:
            axes = []
            if not r["judge"]["tool_pass"]:
                axes.append("tool")
            if not r["judge"]["answer_pass"]:
                axes.append("answer")
            lines.append(f"### {r['id']} — {r['category']}/{r['difficulty']}  (failed: {', '.join(axes)})")
            lines.append(f"- **Question:** {r['question']}")
            lines.append(f"- **Expected tools:** `{r['expected_tools']}`")
            lines.append(f"- **Tools called:** `{r['tools_called']}`")
            lines.append(f"- **Answer:** {r['answer'][:400]}{'…' if len(r['answer']) > 400 else ''}")
            lines.append(f"- **Judge rationale:** {r['judge'].get('rationale','')}")
            lines.append("")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── --grade-only mode ──────────────────────────────────────────────────
#
# Re-judge ungraded rows in an existing JSONL in place. The agent is NOT
# re-invoked — we trust the captured answer + tools_called from the
# original run. This is the right shape for "the judge ran out of credit
# mid-run; finish grading after a top-up" — re-running the agent against
# a different model would mix models in one baseline.
#
# Rows with judge.judge_error == True OR judge.tool_pass is None are
# considered "ungraded" and get re-judged. Rows that already have a
# valid grade are skipped (idempotent: safe to re-run after a partial
# regrade).

def _grade_only(path_str: str) -> int:
    from eval.judge import grade as judge_grade
    p = Path(path_str)
    if not p.exists():
        print(f"[grade-only] file not found: {p}", file=sys.stderr)
        return 1

    # Validate judge up-front so a credit issue surfaces before any work.
    try:
        from eval.judge import _load_client
        _load_client()
    except JudgeNotConfigured as e:
        print(f"\n[judge] {e}\n", file=sys.stderr)
        return 2

    with open(p, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    targets = [
        i for i, r in enumerate(rows)
        if (r.get("judge") or {}).get("judge_error")
        or (r.get("judge") or {}).get("tool_pass") is None
    ]
    if not targets:
        print(f"[grade-only] all {len(rows)} rows already have valid grades; nothing to do")
        return 0

    print(f"[grade-only] {p}")
    print(f"[grade-only] re-judging {len(targets)} of {len(rows)} rows (skipping already-graded)")

    t_start = time.perf_counter()
    for n, i in enumerate(targets, start=1):
        r = rows[i]
        print(f"\n[{n}/{len(targets)}] {r['id']}  ({r['category']}/{r['difficulty']})")
        try:
            judge_out = judge_grade(
                question=r["question"],
                expected_tools=r["expected_tools"],
                actual_tools=r.get("tools_called", []),
                ground_truth_facts=r["ground_truth_facts"],
                expected_answer_contains=r["expected_answer_contains"],
                expected_answer_excludes=r["expected_answer_excludes"],
                answer=r["answer"],
            )
            print(f"    judge: tool={judge_out['tool_pass']} answer={judge_out['answer_pass']}")
        except Exception as exc:
            judge_out = {
                "tool_pass":   None,
                "answer_pass": None,
                "rationale":   f"judge unavailable: {type(exc).__name__}: {str(exc)[:200]}",
                "judge_model": None,
                "judge_error": True,
            }
            print(f"    judge: ERROR — {type(exc).__name__}: {exc}")
        r["judge"] = judge_out

    # Atomic rewrite: tmp file → rename. Avoids half-written JSONL on crash.
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    tmp.replace(p)
    duration_s = time.perf_counter() - t_start

    # Regenerate the summary. Need fixture record for the header — load
    # from the existing tampered fixture's marker; build_fixtures()
    # returns it idempotently.
    fixture_record = build_fixtures()
    summary_path = p.with_name(p.stem + "_summary.md")
    started_at = datetime.datetime.now(datetime.timezone.utc)
    _emit_summary(
        summary_path=summary_path,
        results=rows,
        started_at=started_at,
        duration_s=duration_s,
        fixture_record=fixture_record,
        dataset_path=EVAL_DIR / "dataset.yaml",
        model=os.environ.get("MODEL", "(from original run)"),
        base_url=os.environ.get("BASE_URL", "(from original run)"),
        judge_skipped=False,
    )
    print(f"\n[grade-only] complete. {duration_s:.1f}s total.")
    print(f"[grade-only] JSONL:   {p}")
    print(f"[grade-only] summary: {summary_path}")
    return 0


# ── Main ────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dataset", default=str(EVAL_DIR / "dataset.yaml"))
    ap.add_argument("--start-from", default=None,
                    help="resume by skipping questions with id < this")
    ap.add_argument("--resume-into", default=None,
                    help="append to an existing JSONL instead of creating a stamped one")
    ap.add_argument("--limit", type=int, default=None,
                    help="run only the first N questions (debug)")
    ap.add_argument("--no-judge", action="store_true",
                    help="skip the Claude judge (dry-run)")
    ap.add_argument("--grade-only", default=None,
                    help=("re-judge existing rows in this JSONL in place, "
                          "without re-running the agent. Targets rows where "
                          "judge.judge_error is true or tool_pass is None. "
                          "Preserves the original agent answers + tool_calls. "
                          "Use after topping up the judge's API budget."))
    args = ap.parse_args(argv)

    # ── --grade-only branch — short-circuit before agent setup ──────────
    if args.grade_only:
        return _grade_only(args.grade_only)

    dataset_path = Path(args.dataset)
    with open(dataset_path, encoding="utf-8") as f:
        dataset = yaml.safe_load(f)
    if args.limit is not None:
        dataset = dataset[: args.limit]
    if args.start_from is not None:
        dataset = [q for q in dataset if q["id"] >= args.start_from]
    if not dataset:
        print("nothing to run", file=sys.stderr)
        return 1

    # Validate judge access up-front so we fail fast.
    if not args.no_judge:
        try:
            from eval.judge import _load_client
            _load_client()
        except JudgeNotConfigured as e:
            print(f"\n[judge] {e}\n", file=sys.stderr)
            print("Re-run with --no-judge for an offline dry-run that records "
                  "agent answers without grading.", file=sys.stderr)
            return 2

    fixture_record = build_fixtures()
    print(f"[fixtures] tamper @ seq={fixture_record['tampered_seq']} in {fixture_record['tampered_file']}")

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    started_at = datetime.datetime.now(datetime.UTC)
    stamp = started_at.strftime("%Y-%m-%dT%H%M%SZ")
    if args.resume_into:
        jsonl_path = Path(args.resume_into)
    else:
        jsonl_path = RUNS_DIR / f"{stamp}.jsonl"
    summary_path = jsonl_path.with_name(jsonl_path.stem + "_summary.md")

    print(f"[run] writing JSONL to {jsonl_path}")
    print(f"[run] {len(dataset)} questions; ANTHROPIC_API_KEY={'set' if os.environ.get('ANTHROPIC_API_KEY') else 'NOT SET'}")

    base_url = os.environ.get("BASE_URL", "(unset — agent default)")
    agent_model = os.environ.get("MODEL", "(unset — agent default)")
    t_run = time.perf_counter()
    results: list[dict[str, Any]] = []
    mode = "a" if args.resume_into else "w"

    with open(jsonl_path, mode, encoding="utf-8") as out:
        for idx, q in enumerate(dataset, start=1):
            qid = q["id"]
            print(f"\n[{idx}/{len(dataset)}] {qid}  ({q['category']}/{q['difficulty']}, "
                  f"fixture={q['log_fixture']}): {q['question'][:80]}{'…' if len(q['question']) > 80 else ''}")
            os.environ["LOCALLYAI_AUDIT_LOG"] = str(fixture_log_path(q["log_fixture"]))

            run_out = _run_one_with_capture(q["question"])
            print(f"    tools={run_out['tools_called']}  latency={run_out['agent_latency_ms']}ms")
            if run_out["agent_error"]:
                print(f"    [agent error] {run_out['agent_error']}")

            if args.no_judge:
                judge_out = {
                    "tool_pass":   None,
                    "answer_pass": None,
                    "rationale":   "skipped (--no-judge)",
                    "judge_model": None,
                }
            else:
                try:
                    judge_out = judge_grade(
                        question=q["question"],
                        expected_tools=q["expected_tools"],
                        actual_tools=run_out["tools_called"],
                        ground_truth_facts=q["ground_truth_facts"],
                        expected_answer_contains=q["expected_answer_contains"],
                        expected_answer_excludes=q["expected_answer_excludes"],
                        answer=run_out["answer"],
                    )
                except Exception as exc:
                    # Distinguish "judge couldn't grade" from "judge graded
                    # as fail": record pass-axes as None and surface via
                    # `judge_error` so the summary doesn't conflate a broken
                    # judge with a failed answer. Common cause: Anthropic
                    # credit exhaustion mid-run.
                    judge_out = {
                        "tool_pass":   None,
                        "answer_pass": None,
                        "rationale":   f"judge unavailable: {type(exc).__name__}: {str(exc)[:200]}",
                        "judge_model": None,
                        "judge_error": True,
                    }
                print(f"    judge: tool={judge_out['tool_pass']} answer={judge_out['answer_pass']}")

            record = {
                "id":                 qid,
                "category":           q["category"],
                "difficulty":         q["difficulty"],
                "log_fixture":        q["log_fixture"],
                "question":           q["question"],
                "expected_tools":     q["expected_tools"],
                "expected_answer_contains": q["expected_answer_contains"],
                "expected_answer_excludes": q["expected_answer_excludes"],
                "ground_truth_facts": q["ground_truth_facts"],
                "tools_called":       run_out["tools_called"],
                "tool_call_details":  run_out["tool_call_details"],
                "answer":             run_out["answer"],
                "agent_latency_ms":   run_out["agent_latency_ms"],
                "agent_error":        run_out["agent_error"],
                "trace_path":         run_out["trace_path"],
                "judge":              judge_out,
            }
            out.write(json.dumps(record) + "\n")
            out.flush()
            os.fsync(out.fileno())
            results.append(record)

    duration_s = time.perf_counter() - t_run
    _emit_summary(
        summary_path=summary_path,
        results=results,
        started_at=started_at,
        duration_s=duration_s,
        fixture_record=fixture_record,
        dataset_path=dataset_path,
        model=agent_model,
        base_url=base_url,
        judge_skipped=args.no_judge,
    )
    print(f"\n[run] complete. {duration_s:.1f}s total.")
    print(f"[run] JSONL:   {jsonl_path}")
    print(f"[run] summary: {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
