"""Tests for the telemetry consent state machine + install_id stability."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.telemetry.consent import (
    ConsentState,
    consent_level,
    get_consent,
    has_been_notified,
    has_been_prompted,
    is_extended,
    is_opted_in,
    set_consent,
)
from agent_guardian.telemetry.install_id import get_install_id, reset_install_id


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test runs against a fresh ~/.agentguardian sandbox."""
    monkeypatch.setenv("AGENT_GUARDIAN_HOME", str(tmp_path))


# ---------------------------------------------------------------------------
# Consent state machine
# ---------------------------------------------------------------------------


def test_consent_default_is_essential_on() -> None:
    """v1.0+ policy: fresh install is essential-tier ON by default.

    NOT_PROMPTED is the underlying state but read paths treat it as
    essential — telemetry fires, the notice will print on first scan.
    """
    assert get_consent() is ConsentState.NOT_PROMPTED
    assert is_opted_in() is True  # default-ON
    assert is_extended() is False  # but essential-only
    assert consent_level() == "essential"
    assert has_been_notified() is False  # notice has not run yet


def test_consent_transitions_persist_across_reads() -> None:
    """set_consent → get_consent round-trips through disk for every state."""
    for state in (
        ConsentState.ESSENTIAL,
        ConsentState.EXTENDED,
        ConsentState.OPTED_OUT,
        ConsentState.DEFERRED,
        ConsentState.OPTED_IN,  # legacy
    ):
        set_consent(state)
        assert get_consent() is state


def test_opted_out_is_the_only_off_state() -> None:
    """is_opted_in must be False ONLY for OPTED_OUT — everything else
    is some flavour of telemetry-on per the new default policy."""
    for on_state in (
        ConsentState.NOT_PROMPTED,
        ConsentState.ESSENTIAL,
        ConsentState.EXTENDED,
        ConsentState.OPTED_IN,
        ConsentState.DEFERRED,
    ):
        set_consent(on_state)
        assert is_opted_in() is True, f"{on_state} should be on"
    set_consent(ConsentState.OPTED_OUT)
    assert is_opted_in() is False


def test_extended_only_true_for_extended_tier() -> None:
    """is_extended must be True only when the user explicitly upgraded."""
    for not_extended_state in (
        ConsentState.NOT_PROMPTED,
        ConsentState.ESSENTIAL,
        ConsentState.OPTED_OUT,
        ConsentState.DEFERRED,
    ):
        set_consent(not_extended_state)
        assert is_extended() is False, f"{not_extended_state} should not be extended"
    set_consent(ConsentState.EXTENDED)
    assert is_extended() is True
    # Legacy OPTED_IN from rc1 also maps to extended (back-compat).
    set_consent(ConsentState.OPTED_IN)
    assert is_extended() is True


def test_consent_level_returns_three_tiers() -> None:
    """consent_level returns one of: off / essential / extended."""
    set_consent(ConsentState.OPTED_OUT)
    assert consent_level() == "off"
    for essential_state in (
        ConsentState.NOT_PROMPTED,
        ConsentState.ESSENTIAL,
        ConsentState.DEFERRED,
    ):
        set_consent(essential_state)
        assert consent_level() == "essential"
    for extended_state in (ConsentState.EXTENDED, ConsentState.OPTED_IN):
        set_consent(extended_state)
        assert consent_level() == "extended"


def test_has_been_notified_excludes_not_prompted_only() -> None:
    """has_been_notified is False only in the initial state."""
    assert has_been_notified() is False
    for state in (
        ConsentState.ESSENTIAL,
        ConsentState.EXTENDED,
        ConsentState.OPTED_OUT,
        ConsentState.DEFERRED,
    ):
        set_consent(state)
        assert has_been_notified() is True
    # Legacy alias still works
    assert has_been_prompted is has_been_notified


def test_consent_file_corruption_falls_back_safely(tmp_path: Path) -> None:
    """Corrupt consent.json → treated as NOT_PROMPTED, not a crash."""
    consent_file = tmp_path / "consent.json"
    consent_file.write_text("{ this is not json", encoding="utf-8")
    assert get_consent() is ConsentState.NOT_PROMPTED


def test_consent_with_unknown_future_state_falls_back(tmp_path: Path) -> None:
    """A future schema version with a new state value reads as NOT_PROMPTED
    rather than crashing — forward-compat for the v2 schema."""
    import json

    (tmp_path / "consent.json").write_text(
        json.dumps({"state": "future_state_value", "version": 99}), encoding="utf-8"
    )
    assert get_consent() is ConsentState.NOT_PROMPTED


# ---------------------------------------------------------------------------
# Install ID
# ---------------------------------------------------------------------------


def test_install_id_is_stable_across_reads() -> None:
    """Two get_install_id calls return the SAME ID (it's persistent)."""
    id1 = get_install_id()
    id2 = get_install_id()
    assert id1 == id2


def test_install_id_is_uuid_format() -> None:
    """The ID is a UUID4 — 36 chars, lowercase hex with hyphens."""
    import uuid

    iid = get_install_id()
    # Must parse as a real UUID
    parsed = uuid.UUID(iid)
    assert parsed.version == 4
    assert len(iid) == 36


def test_install_id_reset_generates_fresh() -> None:
    """reset → next read → different ID."""
    first = get_install_id()
    reset_install_id()
    second = get_install_id()
    assert first != second


def test_install_id_corrupted_file_regenerates(tmp_path: Path) -> None:
    """A tampered install_id file (not a UUID) is replaced rather than honoured."""
    (tmp_path / "install_id").write_text("definitely-not-a-uuid\n", encoding="utf-8")
    iid = get_install_id()
    import uuid

    # Should be a fresh, valid UUID — not the tampered string.
    assert iid != "definitely-not-a-uuid"
    uuid.UUID(iid)
