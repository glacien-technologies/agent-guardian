"""Tests for the telemetry HTTP client.

Locks the launch-readiness audit BLOCKER -- a clean install never
posts to the collector. The module-level :func:`emit` must short-
circuit before httpx is imported when (a) the user has not given
positive consent or (b) ``AGENT_GUARDIAN_TELEMETRY`` is set to an
opt-out value.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import respx
from httpx import Response

from agent_guardian.telemetry import client as client_module
from agent_guardian.telemetry.client import (
    DEFAULT_COLLECTOR_URL,
    TelemetryClient,
    emit,
)
from agent_guardian.telemetry.consent import ConsentState, set_consent
from agent_guardian.telemetry.events import (
    EventEnvelope,
    ForgetEvent,
    ScanCompletedEvent,
)
from agent_guardian.telemetry.local import LocalEventBuffer


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-test sandbox with scrubbed env vars."""
    monkeypatch.setenv("AGENT_GUARDIAN_HOME", str(tmp_path))
    monkeypatch.delenv("AGENT_GUARDIAN_TELEMETRY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_TELEMETRY_URL", raising=False)


def _scan_event() -> ScanCompletedEvent:
    now = datetime.now(UTC)
    return ScanCompletedEvent(
        install_id="11111111-2222-4333-8444-555555555555",
        scan_id="scan-test-0001",
        aivss=72,
        band="GOOD",
        tier="T2",
        mode="smart",
        duration_seconds=1.5,
        terminated_by="success",
        agents_count=2,
        attempts_count=10,
        successes_count=9,
        findings_total=1,
        findings_critical=0,
        findings_high=1,
        findings_medium=0,
        findings_low=0,
        agent_version="1.0.0",
        started_at=now,
        completed_at=now,
    )


def _envelope() -> EventEnvelope:
    return EventEnvelope(client_sent_at=datetime.now(UTC), event=_scan_event())


# ---------------------------------------------------------------------------
# BLOCKER: zero POSTs on a clean home
# ---------------------------------------------------------------------------


def test_emit_no_post_on_clean_home(tmp_path: Path) -> None:
    """A fresh install (NOT_PROMPTED) emits zero network requests.

    This is the headline BLOCKER assertion -- if this test ever flips,
    we've regressed back to default-on telemetry.
    """
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        emit(_scan_event())
        assert route.call_count == 0
        # Buffer must also be untouched -- the fast path returns before
        # any SQLite write.
        buffer = LocalEventBuffer()
        assert buffer.queue_depth() == 0


def test_emit_no_post_when_env_says_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AGENT_GUARDIAN_TELEMETRY=off short-circuits even if consent says on."""
    set_consent(ConsentState.ESSENTIAL)
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", "off")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        emit(_scan_event())
        assert route.call_count == 0
        assert LocalEventBuffer().queue_depth() == 0


@pytest.mark.parametrize("value", ["0", "false", "no", "OFF"])
def test_emit_honours_all_env_off_aliases(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every env opt-out alias yields the same zero-POST behaviour."""
    set_consent(ConsentState.ESSENTIAL)
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", value)
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        emit(_scan_event())
        assert route.call_count == 0


def test_emit_no_post_when_non_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-TTY run with no consent and no env-var still posts nothing.

    The defence in depth: even if a CI script accidentally calls
    emit() directly without running the consent prompt first, the
    is_opted_in check stops the network from being touched.
    """

    class NonTtyStdin:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(sys, "stdin", NonTtyStdin())
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        emit(_scan_event())
        assert route.call_count == 0


# ---------------------------------------------------------------------------
# Positive-consent path: POSTs DO go out
# ---------------------------------------------------------------------------


def test_emit_posts_after_positive_consent() -> None:
    """Once the user opts in, scan events DO reach the collector."""
    set_consent(ConsentState.ESSENTIAL)
    with respx.mock() as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        emit(_scan_event())
        assert route.call_count == 1


def test_emit_posts_for_each_event_type_on_extended() -> None:
    """ForgetEvent goes out too, as long as the user has consented."""
    set_consent(ConsentState.EXTENDED)
    with respx.mock() as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        emit(
            ForgetEvent(
                install_id="11111111-2222-4333-8444-555555555555",
                opted_out_at=datetime.now(UTC),
            )
        )
        assert route.call_count == 1


# ---------------------------------------------------------------------------
# TelemetryClient behaviour
# ---------------------------------------------------------------------------


def test_client_emit_skips_when_not_opted_in(tmp_path: Path) -> None:
    """TelemetryClient.emit is also a noop when consent is missing."""
    buffer = LocalEventBuffer(db_path=tmp_path / "tc.db")
    tc = TelemetryClient(buffer=buffer)
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        tc.emit(_envelope())
        assert route.call_count == 0
        assert buffer.queue_depth() == 0


def test_client_emit_skips_when_env_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The env opt-out is honoured by the class-based emit path too."""
    set_consent(ConsentState.ESSENTIAL)
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", "false")
    buffer = LocalEventBuffer(db_path=tmp_path / "tc.db")
    tc = TelemetryClient(buffer=buffer)
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(200))
        tc.emit(_envelope())
        assert route.call_count == 0
        assert buffer.queue_depth() == 0


def test_client_emit_buffers_on_network_failure(tmp_path: Path) -> None:
    """A 500 leaves the envelope in the buffer for retry."""
    set_consent(ConsentState.ESSENTIAL)
    buffer = LocalEventBuffer(db_path=tmp_path / "tc.db")
    tc = TelemetryClient(buffer=buffer)
    with respx.mock() as mock:
        mock.post(DEFAULT_COLLECTOR_URL).mock(return_value=Response(500))
        tc.emit(_envelope())
        # 5xx is transient -- the row stays.
        assert buffer.queue_depth() == 1


def test_emit_rejects_non_event_payload_when_consented() -> None:
    """Type validation still fires after the env / consent fast-path."""
    set_consent(ConsentState.ESSENTIAL)
    with pytest.raises(TypeError):
        emit("not an event")


# ---------------------------------------------------------------------------
# Internal contract -- fast-path lives in the module
# ---------------------------------------------------------------------------


def test_env_opt_out_helper_is_case_and_whitespace_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_env_opted_out trims and lowercases its input."""
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", "  False  ")
    assert client_module._env_opted_out() is True
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", "ON")
    assert client_module._env_opted_out() is False
    monkeypatch.delenv("AGENT_GUARDIAN_TELEMETRY")
    assert client_module._env_opted_out() is False
