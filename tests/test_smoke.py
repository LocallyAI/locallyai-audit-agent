"""
Smoke test — proves every Python module in the project imports cleanly
without side effects.

CI runs this after `pip install -r requirements.txt`. Each module
listed here MUST be importable without:
  - touching the network
  - requiring LOCALLYAI_AUDIT_HMAC_KEY / ANTHROPIC_API_KEY
  - starting a model backend

This catches "the package doesn't even parse" regressions early.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize("module", [
    "tools",
    "agent",
    "cli",
    "tracing",
    "trace_viewer",
    "eval",
    "eval.fixtures",
    "eval.judge",
    "eval.run",
    "eval.compare",
])
def test_module_imports(module: str) -> None:
    """Every module imports cleanly."""
    m = importlib.import_module(module)
    assert m is not None


def test_all_four_tools_registered() -> None:
    """tools.AVAILABLE_TOOLS should expose exactly the four tools the
    agent loop expects. Regression guard: if a future refactor
    accidentally drops one, this fails."""
    import tools
    assert set(tools.AVAILABLE_TOOLS) == {
        "log_search", "hmac_verify", "time_range_query", "summary_stats"
    }


def test_tool_schemas_are_openai_shaped() -> None:
    """Each tool's schema must follow the OpenAI function-tool format:
    {type: 'function', function: {name, description, parameters}}."""
    import tools
    for schema in (tools.LOG_SEARCH_SCHEMA,
                   tools.HMAC_VERIFY_SCHEMA,
                   tools.TIME_RANGE_QUERY_SCHEMA,
                   tools.SUMMARY_STATS_SCHEMA):
        assert schema["type"] == "function"
        fn = schema["function"]
        assert "name" in fn
        assert "description" in fn
        assert "parameters" in fn
        assert fn["parameters"]["type"] == "object"


def test_log_search_handles_missing_log(monkeypatch, tmp_path) -> None:
    """log_search returns [] (does not raise) when the audit log path
    doesn't exist — a forensic tool shouldn't crash on a fresh install."""
    monkeypatch.setenv("LOCALLYAI_AUDIT_LOG", str(tmp_path / "audit.log"))
    from tools import log_search
    assert log_search("") == []


def test_summary_stats_rejects_bad_group_by(monkeypatch, tmp_path) -> None:
    """summary_stats returns a clear `invalid_group_by` error when the
    enum is violated, rather than silently coercing to a default.
    The model relies on this error message to self-correct."""
    monkeypatch.setenv("LOCALLYAI_AUDIT_LOG", str(tmp_path / "audit.log"))
    from tools import summary_stats
    r = summary_stats(group_by="not_a_real_dimension")
    assert r.get("error") == "invalid_group_by"
    assert "valid_group_by" in r
    assert set(r["valid_group_by"]) == {"user", "event_type", "hour_of_day", "day"}


def test_hmac_verify_errors_clearly_without_key(monkeypatch, tmp_path) -> None:
    """hmac_verify must raise HmacKeyMissing (clear message) when
    LOCALLYAI_AUDIT_HMAC_KEY is unset — never silently report
    `chain_intact=False` which would be a security footgun."""
    monkeypatch.setenv("LOCALLYAI_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.delenv("LOCALLYAI_AUDIT_HMAC_KEY", raising=False)
    from tools import HmacKeyMissing, hmac_verify
    with pytest.raises(HmacKeyMissing) as exc_info:
        hmac_verify()
    # The error message should explicitly name the env var so the
    # operator knows what to set.
    assert "LOCALLYAI_AUDIT_HMAC_KEY" in str(exc_info.value)
