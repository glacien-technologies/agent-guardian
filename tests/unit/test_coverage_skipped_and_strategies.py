"""Coverage roll-up: skipped-agent persistence and MAD-MAX attribution.

These tests pin the post-fix behaviour for IMPORTANT #5 and #6 in the
14-flaw inventory:

* Skipped agents (``record_type=agent_skipped``) surface in the coverage
  block under ``skipped_agents`` — operators can see "which agents did
  the swarm bypass and why?" without replaying live observer events.
* MAD-MAX's per-turn ``strategy_metadata.chosen_strategy`` field is
  attributed in a flattened ``strategies_flattened`` rollup so 12
  MAD-MAX turns that broke down internally into ~7 Crescendo + ~5 TAP
  picks are visible as such alongside the top-level breakdown.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_guardian.core.coverage import compute_coverage_from_memory
from agent_guardian.core.memory import MemoryRecord, SharedMemory
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier


def _stub_scan(scan_id: str) -> Scan:
    """Minimal Scan whose only purpose is to carry ``id`` for path lookup."""
    return Scan(
        id=scan_id,
        package_version="0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="0.0",
        target_mode="prompt",
        target_ref="x",
        tier=Tier.T3_STANDARD,
        aivss=100,
        band=SeverityBand.EXCELLENT,
        sub_scores={},
        findings=[],
        asi_scores={},
        duration_seconds=0.0,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 27, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# IMPORTANT #5 — skipped agent persistence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_coverage_surfaces_persisted_skipped_agents(tmp_path: Path) -> None:
    """``write_agent_skipped`` must round-trip through coverage."""
    mem = SharedMemory("cov-skip", root_dir=tmp_path)
    await mem.write_agent_skipped(
        agent="a2a-agent",
        asi=AsiCategory.ASI07,
        reason="not applicable for fingerprint",
    )
    await mem.write_agent_skipped(
        agent="tool-abuse-agent",
        asi=AsiCategory.ASI02,
        reason="not applicable for fingerprint",
    )
    scan = _stub_scan("cov-skip")
    cov = compute_coverage_from_memory(scan, root_dir=tmp_path)
    skipped = cov["skipped_agents"]
    names = {entry["agent"] for entry in skipped}
    assert names == {"a2a-agent", "tool-abuse-agent"}
    for entry in skipped:
        assert entry["reason"] == "not applicable for fingerprint"
        assert entry["asi"] in {"ASI02", "ASI07"}


def test_coverage_empty_skipped_when_no_records(tmp_path: Path) -> None:
    """The coverage shape must include the empty list when nothing was skipped."""
    SharedMemory("cov-no-skip", root_dir=tmp_path)
    scan = _stub_scan("cov-no-skip")
    cov = compute_coverage_from_memory(scan, root_dir=tmp_path)
    assert cov["skipped_agents"] == []


def test_coverage_skipped_records_dedupe_by_agent_name(tmp_path: Path) -> None:
    """If two skip records share an agent name we surface a single entry."""
    scan_dir = tmp_path / "cov-dedupe"
    scan_dir.mkdir(parents=True)
    jsonl = scan_dir / "memory.jsonl"
    rec1 = MemoryRecord(
        record_type="agent_skipped",
        scan_id="cov-dedupe",
        timestamp=datetime.now(tz=timezone.utc),
        payload={"agent": "a2a-agent", "asi": "ASI07", "reason": "first"},
    )
    rec2 = MemoryRecord(
        record_type="agent_skipped",
        scan_id="cov-dedupe",
        timestamp=datetime.now(tz=timezone.utc),
        payload={"agent": "a2a-agent", "asi": "ASI07", "reason": "second"},
    )
    jsonl.write_text(
        rec1.model_dump_json() + "\n" + rec2.model_dump_json() + "\n",
        encoding="utf-8",
    )
    scan = _stub_scan("cov-dedupe")
    cov = compute_coverage_from_memory(scan, root_dir=tmp_path)
    assert len(cov["skipped_agents"]) == 1


@pytest.mark.asyncio
async def test_shared_memory_replays_skipped_records(tmp_path: Path) -> None:
    """Records written before a restart must replay into the in-memory index."""
    first = SharedMemory("cov-replay", root_dir=tmp_path)
    await first.write_agent_skipped(
        agent="memory-poison-agent",
        asi=AsiCategory.ASI06,
        reason="no memory affordance",
    )
    # Rehydrate from disk and verify the read API returns the same record.
    second = SharedMemory("cov-replay", root_dir=tmp_path)
    rows = second.skipped_agents()
    assert len(rows) == 1
    assert rows[0]["agent"] == "memory-poison-agent"
    assert rows[0]["asi"] == "ASI06"


# ---------------------------------------------------------------------------
# IMPORTANT #6 — MAD-MAX child attribution (lands with Commit D)
# ---------------------------------------------------------------------------
# The MAD-MAX attribution tests live in a separate file so the two
# concerns commit independently. See test_coverage_strategies_used.py.
