"""
eval/judge.py — Claude-as-judge for the agent eval.

DEV-ONLY TOOLING. The judge calls the real Anthropic API at
api.anthropic.com to grade agent answers. This is the ONE place
in the codebase where the air-gap rule is relaxed — judging is a
dev-side activity, not part of the agent's runtime deployment.

The judge never sees the audit log itself. It sees only:
  - the question
  - the expected tools + actually-called tools
  - the ground-truth facts the dataset declares about that question
  - the required + forbidden substrings
  - the agent's final answer

That separation is what makes the eval deterministic across runs:
the judge's input doesn't drift with log content, only with the
agent's behaviour.

Env vars:
  ANTHROPIC_API_KEY    required (the judge refuses to start without it)
  JUDGE_MODEL          optional; defaults to claude-haiku-4-5-20251001
                       (cheap + fast; the routing/answer grading is
                       a structured boolean classification, not an
                       open-ended generation, so Haiku is enough)
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

# Surface the missing-API-key error AT IMPORT-TIME-OF-USE, not at
# module load — so the eval runner can detect it cleanly and point
# at the README setup section instead of crashing mid-loop.


class JudgeNotConfigured(RuntimeError):
    """Raised when ANTHROPIC_API_KEY is missing. The runner converts
    this into a clear stderr message + non-zero exit."""


_DEFAULT_JUDGE_MODEL = "claude-haiku-4-5-20251001"


def _load_client():
    """Lazy + clear error if the SDK or key is missing."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise JudgeNotConfigured(
            "ANTHROPIC_API_KEY not set. The eval judge calls Claude "
            "(api.anthropic.com) and is dev-only tooling. Set the env "
            "var before running `python -m eval.run` — see README "
            "section 'Eval suite → Configuring the cloud judge'."
        )
    try:
        import anthropic
    except ImportError as e:
        raise JudgeNotConfigured(
            f"anthropic SDK not installed: {e}. Run "
            "`pip install anthropic` inside the agent's venv."
        ) from e
    return anthropic.Anthropic(api_key=api_key)


_PROMPT = """\
You are grading a forensic auditor agent's answer against a ground-truth
specification for a single eval question.

You DO NOT have access to the underlying audit log. You grade against the
ground-truth facts the dataset declares — that is what keeps the eval
deterministic across runs.

QUESTION:
{question}

EXPECTED TOOLS (the dataset says the agent should call at least these): {expected_tools}
TOOLS ACTUALLY CALLED (in order): {actual_tools}

GROUND-TRUTH FACTS (treat each as authoritative; the answer should reflect them):
{ground_truth_facts}

REQUIRED SUBSTRINGS (case-insensitive — every passing answer MUST contain each): {expected_answer_contains}
FORBIDDEN SUBSTRINGS (case-insensitive — passing answers MUST NOT contain any of these): {expected_answer_excludes}

AGENT'S FINAL ANSWER:
{answer}

Grade two axes independently:

1. tool_pass — true iff every tool name in EXPECTED TOOLS appears at least
   once in ACTUAL TOOLS, in any order. Extra tools the agent called beyond
   the expected set DO NOT fail tool_pass — they may be reasonable
   alternative routings. The check is "did the agent reach for the right
   tool(s)" not "did the agent call exactly these and only these".

2. answer_pass — true iff:
   - the answer reflects the ground-truth facts (not contradicting them),
   - every REQUIRED substring appears in the answer (case-insensitive), AND
   - no FORBIDDEN substring appears in the answer (case-insensitive).
   If the agent reports it could not find something that the ground truth
   says doesn't exist, that is PASSING — absence-of-evidence is a valid
   forensic answer. If the agent fabricates facts (e.g. invents user
   names that aren't pseudonymised in the log), that is FAILING.

Output ONLY a single JSON object (no markdown fences, no commentary):
{{"tool_pass": <bool>, "answer_pass": <bool>, "rationale": "<one sentence>"}}
"""


def grade(
    *,
    question: str,
    expected_tools: list[str],
    actual_tools: list[str],
    ground_truth_facts: list[str],
    expected_answer_contains: list[str],
    expected_answer_excludes: list[str],
    answer: str,
    model: str | None = None,
) -> dict[str, Any]:
    """Grade one (question, answer) pair. Returns:
        {
          "tool_pass":   bool,
          "answer_pass": bool,
          "rationale":   str,
          "judge_model": str,
          "input_tokens":  int,
          "output_tokens": int,
        }

    Never raises on malformed Claude output — falls back to a clearly-marked
    failure so a flaky judge doesn't kill the whole eval run.
    """
    client = _load_client()
    judge_model = model or os.environ.get("JUDGE_MODEL", _DEFAULT_JUDGE_MODEL)
    prompt = _PROMPT.format(
        question=question,
        expected_tools=expected_tools,
        actual_tools=actual_tools,
        ground_truth_facts="\n".join(f"  - {f}" for f in ground_truth_facts),
        expected_answer_contains=expected_answer_contains,
        expected_answer_excludes=expected_answer_excludes,
        answer=answer,
    )

    msg = client.messages.create(
        model=judge_model,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = "".join(getattr(b, "text", "") for b in msg.content).strip()
    parsed = _parse_judge_output(raw)
    return {
        "tool_pass":     bool(parsed.get("tool_pass", False)),
        "answer_pass":   bool(parsed.get("answer_pass", False)),
        "rationale":     str(parsed.get("rationale", "(no rationale)"))[:500],
        "judge_model":   judge_model,
        "input_tokens":  getattr(msg.usage, "input_tokens", 0),
        "output_tokens": getattr(msg.usage, "output_tokens", 0),
    }


def _parse_judge_output(raw: str) -> dict[str, Any]:
    """Pull the JSON object out of Claude's response. Tolerates a stray
    ```json fence even though the prompt forbids it; falls back to a
    failure marker if the response is genuinely unusable."""
    # Strip code fences if Claude added them despite the prompt.
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return {"tool_pass": False, "answer_pass": False,
                "rationale": f"judge output unparseable: {raw[:200]!r}"}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError as e:
        return {"tool_pass": False, "answer_pass": False,
                "rationale": f"judge JSON malformed: {e}; raw={raw[:200]!r}"}
