"""Tests for the TargetAdapter ABC and TargetFingerprint model."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.models.tier import ObservedSurface


def test_target_adapter_is_abstract() -> None:
    with pytest.raises(TypeError):
        TargetAdapter()  # type: ignore[abstract]


def test_subclass_without_fingerprint_raises_on_fingerprint_call() -> None:
    class Bad(TargetAdapter):
        async def call(self, prompt: str, *, session: str | None = None) -> str:
            return prompt

    bad = Bad()
    with pytest.raises(RuntimeError, match="did not set _fingerprint"):
        bad.fingerprint()


def test_fingerprint_to_observed_surface_roundtrip() -> None:
    fp = TargetFingerprint(
        mode="code",
        ref="x:y",
        has_tools=True,
        has_memory=True,
        touches_pii=False,
        is_multi_agent=True,
    )
    obs = fp.to_observed_surface()
    assert isinstance(obs, ObservedSurface)
    assert obs.has_tools is True
    assert obs.has_memory is True
    assert obs.touches_pii is False
    assert obs.is_multi_agent is True


def test_fingerprint_is_frozen() -> None:
    fp = TargetFingerprint(mode="prompt", ref="r")
    with pytest.raises(ValidationError):
        fp.ref = "other"  # type: ignore[misc]


def test_fingerprint_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        TargetFingerprint(mode="prompt", ref="r", unknown="nope")  # type: ignore[call-arg]


def test_fingerprint_defaults() -> None:
    fp = TargetFingerprint(mode="http", ref="https://x")
    assert fp.has_tools is False
    assert fp.has_memory is False
    assert fp.declared_tools == []
    assert fp.declared_memory_keys == []
    assert fp.framework is None
    assert fp.notes == ""


async def test_default_aclose_is_noop() -> None:
    class Mini(TargetAdapter):
        def __init__(self) -> None:
            super().__init__()
            self._fingerprint = TargetFingerprint(mode="prompt", ref="r")

        async def call(self, prompt: str, *, session: str | None = None) -> str:
            return prompt

    m = Mini()
    # aclose() returns None and doesn't raise.
    assert await m.aclose() is None
