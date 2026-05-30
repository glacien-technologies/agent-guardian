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
    # Don't let a developer-set env var bleed into the consent tests --
    # the prompt module reads AGENT_GUARDIAN_TELEMETRY too.
    monkeypatch.delenv("AGENT_GUARDIAN_TELEMETRY", raising=False)


# ---------------------------------------------------------------------------
# Consent state machine
# ---------------------------------------------------------------------------


def test_consent_default_is_off() -> None:
    """v1.0+ launch policy: fresh install is OFF until positive consent.

    NOT_PROMPTED is the underlying state and every read path treats it
    as off -- is_opted_in returns False, consent_level returns 'off',
    and the consent prompt will run on the next interactive scan.
    """
    assert get_consent() is ConsentState.NOT_PROMPTED
    assert is_opted_in() is False  # OFF by default -- positive consent required
    assert is_extended() is False
    assert consent_level() == "off"
    assert has_been_notified() is False  # prompt has not run yet


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


def test_is_opted_in_requires_positive_tier() -> None:
    """is_opted_in is True only for the three positive-consent tiers.

    Per the launch-readiness audit, NOT_PROMPTED, OPTED_OUT and legacy
    DEFERRED all return False -- the user has not positively consented.
    """
    for off_state in (
        ConsentState.NOT_PROMPTED,
        ConsentState.OPTED_OUT,
        ConsentState.DEFERRED,
    ):
        set_consent(off_state)
        assert is_opted_in() is False, f"{off_state} must be off"
    for on_state in (ConsentState.ESSENTIAL, ConsentState.EXTENDED, ConsentState.OPTED_IN):
        set_consent(on_state)
        assert is_opted_in() is True, f"{on_state} must be on"


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
    """consent_level returns one of: off / essential / extended.

    Per the launch-readiness audit NOT_PROMPTED maps to 'off' so a
    fresh install with no recorded decision never sends telemetry.
    """
    for off_state in (
        ConsentState.NOT_PROMPTED,
        ConsentState.OPTED_OUT,
        ConsentState.DEFERRED,
    ):
        set_consent(off_state)
        assert consent_level() == "off", f"{off_state} should map to off"
    set_consent(ConsentState.ESSENTIAL)
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
