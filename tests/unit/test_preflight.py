"""QA-068 — tests for the top-of-scan PREFLIGHT phase narration.

The PREFLIGHT module wraps four readiness sub-stages around the existing
primitives (``check_model_exists`` + ``_endpoint_reachability_preflight``)
and surfaces ONE structured INFO line per stage on success / WARNING on
failure. These tests pin the log narration shape — what the operator sees
in the swarm-board scrollback.
"""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from agent_guardian import preflight as pf

# A non-placeholder host (``*.example.com/org/net`` are skipped as scaffold
# hosts), so target.ping actually runs the probe.
_LIVE_ENDPOINT = "https://finbot.acme-test.dev/chat"


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


@respx.mock
@pytest.mark.asyncio
async def test_preflight_target_ping_healthy_200_validated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A 2xx is reported as a *validated* response, with the status + latency."""
    respx.post(_LIVE_ENDPOINT).mock(return_value=httpx.Response(200, json={"output": "pong"}))
    with caplog.at_level(logging.INFO, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_target_ping(_LIVE_ENDPOINT)
    assert outcome.ok is True
    assert "HTTP 200" in outcome.detail
    line = next(r.message for r in caplog.records if "preflight target.ping" in r.message)
    assert "validated" in line
    assert "HTTP 200" in line


@respx.mock
@pytest.mark.asyncio
async def test_preflight_target_ping_auth_failure_calls_out_authorization(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A 403 must be flagged as an authorization problem, NOT a dead box."""
    respx.post(_LIVE_ENDPOINT).mock(return_value=httpx.Response(403, text="forbidden"))
    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_target_ping(_LIVE_ENDPOINT)
    assert outcome.ok is False
    assert outcome.detail.startswith("auth_failed")
    assert "authorization" in outcome.remediation.lower()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings
    msg = warnings[-1].message
    assert "HTTP 403" in msg
    assert "authorization" in msg.lower()


@respx.mock
@pytest.mark.asyncio
async def test_preflight_target_ping_client_error_4xx(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A non-auth 4xx (404) is reachable-but-rejected, distinct from unreachable."""
    respx.post(_LIVE_ENDPOINT).mock(return_value=httpx.Response(404, text="nope"))
    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_target_ping(_LIVE_ENDPOINT)
    assert outcome.ok is False
    assert outcome.detail.startswith("client_error")
    assert "HTTP 404" in caplog.records[-1].message


@respx.mock
@pytest.mark.asyncio
async def test_preflight_target_ping_server_error_5xx(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A 5xx is reachable-but-erroring, distinct from a 2xx 'validated'."""
    respx.post(_LIVE_ENDPOINT).mock(return_value=httpx.Response(503, text="down"))
    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_target_ping(_LIVE_ENDPOINT)
    assert outcome.ok is False
    assert outcome.detail.startswith("server_error")
    assert "HTTP 503" in caplog.records[-1].message


@respx.mock
@pytest.mark.asyncio
async def test_preflight_target_ping_unreachable_transport(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A connect failure across all attempts is the only true 'unreachable'."""
    respx.post(_LIVE_ENDPOINT).mock(side_effect=httpx.ConnectError("refused"))
    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_target_ping(_LIVE_ENDPOINT)
    assert outcome.ok is False
    assert outcome.detail == "unreachable"


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
    # 4 narrated stages + the rc38 P0-#5 (#263) gemini quota stage (a silent
    # skip for the stub provider, but still appended to the outcome list).
    assert len(outcomes) == 5
    assert any(o.stage == "model.quota" and o.ok for o in outcomes)
    info_lines = [r for r in caplog.records if r.levelno == logging.INFO]
    stages_seen = {
        "preflight model.invoke",
        "preflight target.ping",
        "preflight contract.schema_check",
        "preflight budget.parse",
    }
    found = {stage for stage in stages_seen if any(stage in r.message for r in info_lines)}
    assert found == stages_seen, f"missing stages: {stages_seen - found}"


# --------------------------------------------------------------------------- #
# rc38 P0-#5 (#263) — gemini quota fail-fast pre-flight
# --------------------------------------------------------------------------- #


class _FakeGeminiClient:
    """Minimal stand-in for ``GeminiClient`` used by the quota pre-flight tests.

    ``preflight`` either raises the supplied exception or returns cleanly;
    ``aclose`` records that the client was closed so we can assert the probe
    never leaks an httpx client.
    """

    def __init__(self, raise_exc: Exception | None = None) -> None:
        self._raise_exc = raise_exc
        self.preflight_called = False
        self.closed = False

    async def preflight(self, model: str = "gemini-2.5-flash") -> None:
        self.preflight_called = True
        if self._raise_exc is not None:
            raise self._raise_exc

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_preflight_gemini_quota_skips_non_gemini(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-Gemini providers never build a client or run the quota probe."""
    built: list[str] = []

    def _fake_build_llm(spec: str, role: str) -> object:
        built.append(spec)
        return _FakeGeminiClient()

    monkeypatch.setattr("agent_guardian.llm.registry.build_llm", _fake_build_llm)

    outcome = await pf.preflight_gemini_quota("openai:gpt-4o")
    assert outcome.ok is True
    assert outcome.detail == "skipped"
    assert built == [], "non-gemini providers must not construct a client"


@pytest.mark.asyncio
async def test_preflight_gemini_quota_healthy_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A healthy Gemini pre-flight completion returns ok and closes the client."""
    client = _FakeGeminiClient(raise_exc=None)
    monkeypatch.setattr("agent_guardian.llm.registry.build_llm", lambda spec, role: client)

    outcome = await pf.preflight_gemini_quota("gemini:gemini-2.5-flash")
    assert outcome.ok is True
    assert client.preflight_called is True
    assert client.closed is True


@pytest.mark.asyncio
async def test_preflight_gemini_quota_429_fails_fast(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A 429 on the cheap completion marks the quota stage not-ok with a WARNING."""
    from agent_guardian.llm.errors import LLMRateLimitError

    client = _FakeGeminiClient(raise_exc=LLMRateLimitError("gemini: rate limited"))
    monkeypatch.setattr("agent_guardian.llm.registry.build_llm", lambda spec, role: client)

    with caplog.at_level(logging.WARNING, logger="agent_guardian.preflight"):
        outcome = await pf.preflight_gemini_quota("gemini:gemini-2.5-flash")
    assert outcome.ok is False
    assert "quota_exhausted" in outcome.detail
    assert client.closed is True, "client must be closed even on a 429"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("quota exhausted" in r.message for r in warnings)


@pytest.mark.asyncio
async def test_run_scan_preflight_raises_on_gemini_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A quota-exhausted Gemini key fails the whole pre-flight fast (no recon).

    ``run_scan_preflight`` must raise :class:`PreflightQuotaError` BEFORE the
    target.ping / contract / budget stages run, so the scan never starts.
    """
    from agent_guardian.llm.errors import LLMRateLimitError

    client = _FakeGeminiClient(raise_exc=LLMRateLimitError("gemini: rate limited"))
    monkeypatch.setattr("agent_guardian.llm.registry.build_llm", lambda spec, role: client)
    # Guard: the ping stage must NOT run once quota fails fast.
    ping_calls: list[str | None] = []

    async def _fake_ping(endpoint: str | None) -> pf.PreflightOutcome:
        ping_calls.append(endpoint)
        return pf.PreflightOutcome(stage="target.ping", ok=True)

    monkeypatch.setattr(pf, "preflight_target_ping", _fake_ping)

    with pytest.raises(pf.PreflightQuotaError) as excinfo:
        await pf.run_scan_preflight(
            model_spec="gemini:gemini-2.5-flash",
            endpoint="https://finbot.acme-test.dev/chat",
            contract_path=None,
            budget_usd=0.5,
            budget_seconds=300.0,
        )
    assert excinfo.value.spec == "gemini:gemini-2.5-flash"
    assert ping_calls == [], "recon-side stages must not run after a quota fail-fast"


@pytest.mark.asyncio
async def test_run_scan_preflight_healthy_gemini_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A healthy Gemini key runs all stages and returns the full outcome list."""
    client = _FakeGeminiClient(raise_exc=None)
    monkeypatch.setattr("agent_guardian.llm.registry.build_llm", lambda spec, role: client)
    from agent_guardian.llm.validation import clear_cache

    clear_cache()
    monkeypatch.setenv("AGENT_GUARDIAN_SKIP_MODEL_PROBE", "1")

    outcomes = await pf.run_scan_preflight(
        model_spec="gemini:gemini-2.5-flash",
        endpoint=None,
        contract_path=None,
        budget_usd=0.5,
        budget_seconds=300.0,
    )
    quota = [o for o in outcomes if o.stage == "model.quota"]
    assert quota and quota[0].ok is True
    assert client.preflight_called is True
