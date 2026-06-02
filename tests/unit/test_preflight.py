"""QA-068 — tests for the top-of-scan PREFLIGHT phase narration.

The PREFLIGHT module wraps four readiness sub-stages around the existing
primitives (``check_model_exists`` + ``_endpoint_reachability_preflight``)
and surfaces ONE structured INFO line per stage on success / WARNING on
failure. These tests pin the log narration shape — what the operator sees
in the swarm-board scrollback.
"""

from __future__ import annotations

import logging

import pytest

from agent_guardian import preflight as pf


@pytest.fixture(autouse=True)
def _clear_validation_cache() -> None:
    """The validation primitive caches per-spec — drop it between tests so
    each test sees a fresh probe outcome."""
    from agent_guardian.llm.validation import clear_cache

    clear_cache()


# --------------------------------------------------------------------------- #
# model.invoke
# --------------------------------------------------------------------------- #


def test_preflight_model_invoke_stub_emits_skipped_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A ``stub`` spec must not probe the network."""
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = pf.preflight_model_invoke("stub")
    assert outcome.ok is True
    assert outcome.stage == "model.invoke"
    assert any(
        "preflight model.invoke" in r.message and "skipped" in r.message for r in caplog.records
    )


def test_preflight_model_invoke_auth_failure_emits_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Auth failure produces a WARNING with a remediation hint naming the env var."""
    # Force the openai probe path with no API key set so the validator
    # returns auth_failed without touching the network.
    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = pf.preflight_model_invoke("openai:gpt-4o")
    assert outcome.ok is False
    assert outcome.detail == "auth_failed"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected one WARNING line for auth_failed"
    assert "AGENT_GUARDIAN_OPENAI_API_KEY" in warnings[-1].message


# --------------------------------------------------------------------------- #
# target.ping
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_preflight_target_ping_skipped_when_no_endpoint(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_target_ping(None)
    assert outcome.ok is True
    assert outcome.detail == "skipped"
    assert any(
        "preflight target.ping" in r.message and "skipped" in r.message for r in caplog.records
    )


@pytest.mark.asyncio
async def test_preflight_target_ping_skipped_for_placeholder(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Documentation/scaffold hosts (``*.example.com``) never get probed."""
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_target_ping("https://api.example.com/chat")
    assert outcome.ok is True
    assert outcome.detail == "placeholder"


# --------------------------------------------------------------------------- #
# contract.schema_check
# --------------------------------------------------------------------------- #


def test_preflight_contract_schema_skipped_when_no_contract(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = pf.preflight_contract_schema(None)
    assert outcome.ok is True
    assert outcome.detail == "skipped"


def test_preflight_contract_schema_missing_path_warns(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    bogus = tmp_path / "does_not_exist.yaml"
    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = pf.preflight_contract_schema(bogus)
    assert outcome.ok is False
    assert outcome.detail == "missing"
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_preflight_contract_schema_ok_for_existing_file(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    contract_file = tmp_path / "contract.yaml"
    contract_file.write_text("version: 1\n", encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = pf.preflight_contract_schema(contract_file)
    assert outcome.ok is True
    assert any(
        "preflight contract.schema_check" in r.message and r.levelno == logging.INFO
        for r in caplog.records
    )


# --------------------------------------------------------------------------- #
# budget.parse
# --------------------------------------------------------------------------- #


def test_preflight_budget_parse_emits_info_line_with_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = pf.preflight_budget_parse(0.5, 300.0)
    assert outcome.ok is True
    matching = [r for r in caplog.records if "preflight budget.parse" in r.message]
    assert matching
    line = matching[-1].message
    assert "$0.5000" in line
    assert "300s" in line


def test_preflight_budget_parse_uncapped_renders_uncapped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = pf.preflight_budget_parse(None, None)
    assert outcome.ok is True
    matching = [r for r in caplog.records if "preflight budget.parse" in r.message]
    assert matching
    assert "uncapped" in matching[-1].message


def test_preflight_budget_parse_negative_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = pf.preflight_budget_parse(-1.0, None)
    assert outcome.ok is False
    assert any(r.levelno == logging.WARNING for r in caplog.records)


# --------------------------------------------------------------------------- #
# happy-path: all 4 stages narrate one INFO line each
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_scan_preflight_happy_path_emits_four_info_lines(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The happy-path narration is: 4 stages, 4 INFO ``preflight <stage>:`` lines."""
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcomes = await pf.run_scan_preflight(
            model_spec="stub",
            endpoint=None,
            contract_path=None,
            budget_usd=0.5,
            budget_seconds=300.0,
        )
    assert len(outcomes) == 4
    info_lines = [r for r in caplog.records if r.levelno == logging.INFO]
    stages_seen = {
        "preflight model.invoke",
        "preflight target.ping",
        "preflight contract.schema_check",
        "preflight budget.parse",
    }
    found = {stage for stage in stages_seen if any(stage in r.message for r in info_lines)}
    assert found == stages_seen, f"missing stages: {stages_seen - found}"
