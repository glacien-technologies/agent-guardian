"""Phase C, C5 — recon-loop re-entry on tool-name diffs.

The :class:`ReconReentryHook` watches the per-agent reflection stream for
``declared_tools`` evidence that the original Phase 1 recon fingerprint did
not see. When the diff is non-empty it kicks off a single (idempotent)
non-blocking refresh that updates the swarm-shared fingerprint.

Tests cover:

* the happy path — a stub agent reports a new tool, reentry fires exactly
  once, the fingerprint's ``declared_tools`` set gains the new entry;
* a no-diff payload is a no-op (the hook does not fire and does not write);
* a second new-tool payload after the hook has already fired is suppressed
  (idempotency);
* an unbound hook is a silent no-op (defensive — reflection sinks can
  legally fire before :meth:`bind`).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.recon_reentry import (
    ReconReentryHook,
    extract_declared_tools,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _fp(tools: list[str] | None = None) -> TargetFingerprint:
    return TargetFingerprint(
        mode="http",
        ref="test-target",
        has_tools=bool(tools),
        declared_tools=tools or [],
    )


def _reflection(declared_tools: list[str], *, agent: str = "tool-abuse-agent") -> dict[str, Any]:
    return {
        "agent": agent,
        "asi_category": "ASI02",
        "turn": 1,
        "strategy": "stub",
        "prompt": "do something",
        "target_response": "ok",
        "verdict": "pass",
        "confidence": 0.7,
        "reasoning": "stub",
        "strategy_metadata": {"declared_tools": declared_tools},
        "seed_id": None,
    }


async def _make_memory(tmp_path: Path, baseline: list[str]) -> SharedMemory:
    mem = SharedMemory("scan-recon-reentry", root_dir=tmp_path)
    await mem.set_target_fingerprint(_fp(baseline))
    return mem


# ---------------------------------------------------------------------------
# extract_declared_tools
# ---------------------------------------------------------------------------


def test_extract_declared_tools_from_strategy_metadata() -> None:
    """Canonical path — strategy_metadata.declared_tools is the primary source."""
    payload = _reflection(["search_kb", "send_email"])
    assert extract_declared_tools(payload) == ["search_kb", "send_email"]


def test_extract_declared_tools_dedups_case_insensitive() -> None:
    payload = _reflection(["Search_KB", "search_kb", "SEND_EMAIL"])
    out = extract_declared_tools(payload)
    assert len(out) == 2
    assert out[0].lower() == "search_kb"
    assert out[1].lower() == "send_email"


def test_extract_declared_tools_falls_back_to_tool_calls_block() -> None:
    """Recon-shape reflection has ``tool_calls`` at root, no strategy_metadata."""
    payload = {
        "agent": "recon-agent",
        "tool_calls": [{"name": "lookup_order", "arguments": {}}],
    }
    assert extract_declared_tools(payload) == ["lookup_order"]


def test_extract_declared_tools_returns_empty_on_garbage() -> None:
    assert extract_declared_tools({}) == []
    assert extract_declared_tools({"strategy_metadata": "not a dict"}) == []
    assert extract_declared_tools({"strategy_metadata": {"declared_tools": "not a list"}}) == []


# ---------------------------------------------------------------------------
# ReconReentryHook lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reentry_fires_once_and_refreshes_fingerprint(tmp_path: Path) -> None:
    """Happy path: new tool surfaces -> refresh runs -> fingerprint updates."""
    memory = await _make_memory(tmp_path, baseline=["existing_tool"])

    refresh_calls: list[list[str]] = []

    async def refresh(new_tools: list[str]) -> TargetFingerprint:
        refresh_calls.append(list(new_tools))
        fp = memory.target_fingerprint() or _fp(["existing_tool"])
        merged = list(fp.declared_tools)
        for n in new_tools:
            if n.lower() not in {t.lower() for t in merged}:
                merged.append(n)
        return fp.model_copy(update={"declared_tools": merged, "has_tools": True})

    hook = ReconReentryHook(refresh_fn=refresh)
    hook.bind(memory, memory.target_fingerprint() or _fp(["existing_tool"]))

    assert hook.fired is False
    hook.on_reflection(_reflection(["newly_revealed_tool"]))
    assert hook.fired is True  # idempotency latch trips synchronously

    await hook.wait_for_pending_refresh()

    assert refresh_calls == [["newly_revealed_tool"]]
    refreshed = memory.target_fingerprint()
    assert refreshed is not None
    assert "newly_revealed_tool" in refreshed.declared_tools
    assert "existing_tool" in refreshed.declared_tools


@pytest.mark.asyncio
async def test_reentry_does_not_fire_when_no_diff(tmp_path: Path) -> None:
    """No tool in the diff -> hook stays unfired, no refresh, no memory write."""
    memory = await _make_memory(tmp_path, baseline=["search_kb"])

    refresh_calls: list[list[str]] = []

    async def refresh(new_tools: list[str]) -> TargetFingerprint | None:
        refresh_calls.append(list(new_tools))
        return None

    hook = ReconReentryHook(refresh_fn=refresh)
    hook.bind(memory, memory.target_fingerprint() or _fp(["search_kb"]))

    # Reflection names only tools the baseline already declares.
    hook.on_reflection(_reflection(["search_kb"]))
    await asyncio.sleep(0)  # let any (incorrectly) scheduled task settle

    assert hook.fired is False
    assert refresh_calls == []


@pytest.mark.asyncio
async def test_reentry_fires_exactly_once_across_multiple_diffs(tmp_path: Path) -> None:
    """A second new-tool payload after the first does NOT re-fire the hook."""
    memory = await _make_memory(tmp_path, baseline=["existing_tool"])

    refresh_calls: list[list[str]] = []

    async def refresh(new_tools: list[str]) -> TargetFingerprint:
        refresh_calls.append(list(new_tools))
        fp = memory.target_fingerprint() or _fp(["existing_tool"])
        merged = list(fp.declared_tools)
        for n in new_tools:
            if n.lower() not in {t.lower() for t in merged}:
                merged.append(n)
        return fp.model_copy(update={"declared_tools": merged, "has_tools": True})

    hook = ReconReentryHook(refresh_fn=refresh)
    hook.bind(memory, memory.target_fingerprint() or _fp(["existing_tool"]))

    hook.on_reflection(_reflection(["first_new"]))
    await hook.wait_for_pending_refresh()
    hook.on_reflection(_reflection(["second_new"]))
    await asyncio.sleep(0)

    assert len(refresh_calls) == 1
    assert refresh_calls[0] == ["first_new"]
    refreshed = memory.target_fingerprint()
    assert refreshed is not None
    assert "first_new" in refreshed.declared_tools
    assert "second_new" not in refreshed.declared_tools


def test_unbound_hook_silently_ignores_reflections() -> None:
    """A hook not yet bound must NOT raise, NOT fire, NOT call refresh."""
    refresh_calls: list[list[str]] = []

    async def refresh(new_tools: list[str]) -> TargetFingerprint | None:
        refresh_calls.append(list(new_tools))
        return None

    hook = ReconReentryHook(refresh_fn=refresh)
    # No bind() — this models recon's own reflection arriving before recon
    # has written its fingerprint.
    hook.on_reflection(_reflection(["any_tool"]))

    assert hook.fired is False
    assert refresh_calls == []


@pytest.mark.asyncio
async def test_reentry_swallows_refresh_failure_without_breaking_scan(
    tmp_path: Path,
) -> None:
    """A raising refresh_fn must NOT propagate — scan must keep running."""
    memory = await _make_memory(tmp_path, baseline=["existing_tool"])

    async def refresh(new_tools: list[str]) -> TargetFingerprint:
        raise RuntimeError("simulated refresh failure")

    hook = ReconReentryHook(refresh_fn=refresh)
    hook.bind(memory, memory.target_fingerprint() or _fp(["existing_tool"]))

    hook.on_reflection(_reflection(["explosive_tool"]))
    # wait_for_pending_refresh awaits the task; it MUST NOT raise.
    await hook.wait_for_pending_refresh()

    # Fingerprint unchanged because the refresh failed.
    fp = memory.target_fingerprint()
    assert fp is not None
    assert fp.declared_tools == ["existing_tool"]


@pytest.mark.asyncio
async def test_reentry_log_message_is_emitted(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The re-entry trigger log must fire at the decision site (per spec)."""
    import logging

    memory = await _make_memory(tmp_path, baseline=["existing_tool"])

    async def refresh(new_tools: list[str]) -> TargetFingerprint:
        fp = memory.target_fingerprint() or _fp(["existing_tool"])
        return fp.model_copy(
            update={
                "declared_tools": [*fp.declared_tools, *new_tools],
                "has_tools": True,
            }
        )

    hook = ReconReentryHook(refresh_fn=refresh)
    hook.bind(memory, memory.target_fingerprint() or _fp(["existing_tool"]))

    with caplog.at_level(logging.INFO, logger="agent_guardian.core.recon_reentry"):
        hook.on_reflection(_reflection(["never_seen_before"]))
        await hook.wait_for_pending_refresh()

    messages = [r.message for r in caplog.records]
    assert any("recon_reentry: trigger=" in m and "new_tools=" in m for m in messages), (
        f"re-entry trigger log missing; saw: {messages!r}"
    )
