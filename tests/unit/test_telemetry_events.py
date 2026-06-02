"""Tests for telemetry event allowlist + clock-skew filtering."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agent_guardian.server.analytics.store import _passes_clock_skew
from agent_guardian.telemetry.events import (
    EventEnvelope,
    ForgetEvent,
    InstallEvent,
    ScanCompletedEvent,
)

_NOW = datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC)
_VALID_INSTALL_ID = "00000000-0000-4000-8000-000000000001"


def _valid_scan_event(**overrides: object) -> ScanCompletedEvent:
    """Extended-tier event by default — all environment fields populated."""
    base: dict[str, object] = dict(
        install_id=_VALID_INSTALL_ID,
        scan_id="abcd1234efgh",
        aivss=84,
        band="GOOD",
        tier="T3",
        duration_seconds=82.5,
        terminated_by="success",
        agents_count=9,
        attempts_count=68,
        successes_count=63,
        findings_total=5,
        findings_critical=1,
        findings_high=2,
        findings_medium=1,
        findings_low=1,
        adapter="langgraph",
        target_mode="code",
        agent_version="1.0.0",
        python_version="3.11",
        os_family="Darwin",
        arch="arm64",
        started_at=_NOW,
        completed_at=_NOW,
    )
    base.update(overrides)
    return ScanCompletedEvent(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Allowlist enforcement — extra fields rejected at construction time
# ---------------------------------------------------------------------------


def test_extra_field_in_scan_event_rejected() -> None:
    """extra='forbid' must catch typos / unexpected fields at validation."""
    with pytest.raises(ValidationError) as exc:
        _valid_scan_event(user_email="oops@example.com")  # type: ignore[arg-type]
    assert "extra" in str(exc.value).lower() or "forbid" in str(exc.value).lower()


def test_aivss_out_of_range_rejected() -> None:
    """AIVSS is constrained to 0..100 — a 200 must reject."""
    with pytest.raises(ValidationError):
        _valid_scan_event(aivss=200)
    with pytest.raises(ValidationError):
        _valid_scan_event(aivss=-1)


def test_invalid_python_version_rejected() -> None:
    """python_version follows the pattern ``3.N`` — 2.7 must reject."""
    with pytest.raises(ValidationError):
        _valid_scan_event(python_version="2.7")
    with pytest.raises(ValidationError):
        _valid_scan_event(python_version="3.11.4")


def test_invalid_band_rejected() -> None:
    """band is a strict Literal — a typo must reject."""
    with pytest.raises(ValidationError):
        _valid_scan_event(band="GREAT")  # type: ignore[arg-type]


def test_invalid_tier_rejected() -> None:
    with pytest.raises(ValidationError):
        _valid_scan_event(tier="T5")  # type: ignore[arg-type]


def test_envelope_discriminator_routes_correctly() -> None:
    """EventEnvelope's discriminated union must route to the right model."""
    env = EventEnvelope(client_sent_at=_NOW, event=_valid_scan_event())
    assert isinstance(env.event, ScanCompletedEvent)
    assert env.event.event_type == "scan_completed"

    fe = ForgetEvent(install_id=_VALID_INSTALL_ID, opted_out_at=_NOW)
    env2 = EventEnvelope(client_sent_at=_NOW, event=fe)
    assert isinstance(env2.event, ForgetEvent)
    assert env2.event.event_type == "forget"


def test_install_event_constructs_with_minimum_fields() -> None:
    InstallEvent(
        install_id=_VALID_INSTALL_ID,
        agent_version="1.0.0",
        python_version="3.12",
        os_family="Linux",
        arch="x86_64",
        opted_in_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Clock-skew filter (server-side)
# ---------------------------------------------------------------------------


def test_clock_skew_accepts_recent_client_time() -> None:
    """Events from the recent past are accepted."""
    assert _passes_clock_skew(_NOW - timedelta(minutes=2), now=_NOW) is True


def test_clock_skew_rejects_far_past() -> None:
    """Events older than 30 days are rejected (PRD §4)."""
    assert _passes_clock_skew(_NOW - timedelta(days=31), now=_NOW) is False


def test_clock_skew_rejects_far_future() -> None:
    """Events with client_sent_at more than 5min in the future are rejected."""
    assert _passes_clock_skew(_NOW + timedelta(minutes=6), now=_NOW) is False


def test_clock_skew_accepts_small_future_drift() -> None:
    """Up to 5 minutes of future drift is tolerated (NTP slippage)."""
    assert _passes_clock_skew(_NOW + timedelta(minutes=4), now=_NOW) is True


# ---------------------------------------------------------------------------
# Essential vs extended field split (v1.0+ policy)
# ---------------------------------------------------------------------------


def test_essential_event_constructs_without_environment_fields() -> None:
    """An essential-only event omits adapter / python_version / os_family / arch.

    The model must accept these as None so the swarm can emit
    essential-tier events without populating environment fingerprint.
    """
    event = ScanCompletedEvent(
        install_id=_VALID_INSTALL_ID,
        scan_id="aaaa1111",
        aivss=84,
        band="GOOD",
        tier="T3",
        duration_seconds=82.5,
        terminated_by="success",
        agents_count=9,
        attempts_count=68,
        successes_count=68,
        findings_total=0,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        agent_version="1.0.0",
        started_at=_NOW,
        completed_at=_NOW,
        # Environment fields omitted — essential tier
    )
    assert event.adapter is None
    assert event.python_version is None
    assert event.os_family is None
    assert event.arch is None
    # But the operational counts are populated
    assert event.agents_count == 9
    assert event.attempts_count == 68
    assert event.successes_count == 68


def test_extended_event_carries_environment_fields() -> None:
    """An extended-tier event populates the environment fingerprint."""
    event = ScanCompletedEvent(
        install_id=_VALID_INSTALL_ID,
        scan_id="aaaa1111",
        aivss=84,
        band="GOOD",
        tier="T3",
        duration_seconds=82.5,
        terminated_by="success",
        agents_count=9,
        attempts_count=68,
        successes_count=68,
        findings_total=0,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        adapter="langgraph",
        target_mode="code",
        agent_version="1.0.0",
        python_version="3.11",
        os_family="Darwin",
        arch="arm64",
        started_at=_NOW,
        completed_at=_NOW,
    )
    assert event.adapter == "langgraph"
    assert event.python_version == "3.11"
    assert event.os_family == "Darwin"
    assert event.arch == "arm64"


def test_operational_counts_default_to_zero() -> None:
    """agents_count / attempts_count / successes_count default to 0
    when omitted so old clients don't break the schema."""
    event = ScanCompletedEvent(
        install_id=_VALID_INSTALL_ID,
        scan_id="aaaa1111",
        aivss=50,
        band="POOR",
        tier="T3",
        duration_seconds=1.0,
        terminated_by="success",
        findings_total=0,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        agent_version="1.0.0",
        started_at=_NOW,
        completed_at=_NOW,
    )
    assert event.agents_count == 0
    assert event.attempts_count == 0
    assert event.successes_count == 0
