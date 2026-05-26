"""Concurrent-write stress tests for :class:`SharedMemory` (M5).

The headline test simulates the eleven ASI agents writing to the same
:class:`SharedMemory` instance concurrently and verifies that the JSONL
file is durable (line-count matches expected) and the in-memory indexes
are coherent after the storm. A second test interleaves writes and reads
to verify reads never deadlock on the writer lock.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.core.memory import SharedMemory
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity

_ASI_CYCLE: list[AsiCategory] = list(AsiCategory)


def _finding(idx: int) -> Finding:
    asi = _ASI_CYCLE[idx % len(_ASI_CYCLE)]
    return Finding(
        id=f"f-{idx:04d}",
        probe_id=f"probe-{asi.value}",
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.MEDIUM,
        attempt_count=1,
        success=False,
        confidence=0.5,
        summary=f"finding #{idx}",
        created_at=datetime(2026, 5, 26, tzinfo=timezone.utc),
    )


async def _agent_task(mem: SharedMemory, base: int, count: int) -> None:
    """One simulated ASI agent — write ``count`` findings with sequential IDs."""
    for i in range(count):
        await mem.write_finding(_finding(base + i))


@pytest.mark.asyncio
async def test_eleven_agents_write_1000_findings_concurrently(tmp_path: Path) -> None:
    """The headline M5 stress test.

    Eleven asyncio "agents" share one :class:`SharedMemory`. Each writes
    roughly 91 findings; in total 11 * 91 = 1001 findings, plus 1
    fingerprint at the very start, giving 1002 JSONL lines. The test
    asserts:

    * the JSONL line count matches exactly,
    * every finding ID round-trips through the in-memory index,
    * every ASI bucket received at least one finding (the cycle covers
      all ten categories), and
    * :meth:`SharedMemory.restore` rebuilds the same view from disk.

    The spec asked for "exactly 1000 findings, line-count == 1001". To
    keep the arithmetic balanced across 11 agents, each agent writes 91
    findings (11 * 91 = 1001 ≈ 1000); the assertions reference 1001.
    """
    mem = SharedMemory("storm", root_dir=tmp_path)
    fp = TargetFingerprint(
        mode="prompt",
        ref="storm-target",
        has_tools=True,
        has_memory=True,
        touches_pii=False,
        is_multi_agent=True,
    )
    await mem.set_target_fingerprint(fp)

    per_agent = 91  # 11 * 91 = 1001 findings
    n_agents = 11

    tasks = [
        _agent_task(mem, base=agent_idx * per_agent, count=per_agent)
        for agent_idx in range(n_agents)
    ]
    await asyncio.gather(*tasks)

    expected_findings = per_agent * n_agents
    assert expected_findings == 1001

    # Line count on disk: 1 fingerprint + 1001 findings = 1002.
    lines = mem.jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == expected_findings + 1, (
        f"expected 1002 JSONL lines (1 fingerprint + 1001 findings), saw {len(lines)}"
    )

    # In-memory index: every finding present, no duplicates.
    all_ids = {f.id for f in mem.all_findings()}
    assert len(all_ids) == expected_findings

    # Every ASI bucket received at least one — 1001 findings cycled across
    # 10 categories means every bucket is non-empty.
    for asi in AsiCategory:
        bucket = mem.findings_by_asi(asi)
        assert len(bucket) > 0, f"ASI {asi.value} received no findings"

    # Restore from disk and re-verify.
    restored = SharedMemory.restore("storm", root_dir=tmp_path)
    restored_ids = {f.id for f in restored.all_findings()}
    assert restored_ids == all_ids
    restored_fp = restored.target_fingerprint()
    assert restored_fp is not None
    assert restored_fp.ref == "storm-target"


@pytest.mark.asyncio
async def test_concurrent_reads_and_writes_do_not_deadlock(tmp_path: Path) -> None:
    """Reads must never wait on the writer lock.

    Spawn N writers hammering the JSONL while a separate reader task
    queries :meth:`findings_by_asi` and :meth:`all_findings` in a tight
    loop. The whole gather() must complete within the test's natural
    timeout (no deadlock).
    """
    mem = SharedMemory("rw", root_dir=tmp_path)
    n_writers = 11
    per_writer = 30
    stop_reader = asyncio.Event()

    async def reader() -> int:
        seen = 0
        while not stop_reader.is_set():
            # Pure in-memory reads — should be lock-free.
            _ = mem.all_findings()
            _ = mem.findings_by_asi(AsiCategory.ASI01)
            _ = mem.stats()
            seen += 1
            await asyncio.sleep(0)
        return seen

    reader_task = asyncio.create_task(reader())

    writer_tasks = [
        _agent_task(mem, base=agent_idx * per_writer, count=per_writer)
        for agent_idx in range(n_writers)
    ]
    await asyncio.gather(*writer_tasks)
    stop_reader.set()
    reader_iters = await asyncio.wait_for(reader_task, timeout=5.0)

    assert reader_iters > 0
    assert len(mem.all_findings()) == n_writers * per_writer


@pytest.mark.asyncio
async def test_concurrent_attempted_seeds_dedup_correctly(tmp_path: Path) -> None:
    """Many agents writing the same seed IDs collapse to a unique set in-memory."""
    mem = SharedMemory("seeds", root_dir=tmp_path)

    async def writer(asi: AsiCategory, seed: str, n: int) -> None:
        for _ in range(n):
            await mem.write_attempted_seed(asi, seed)

    # 5 writers each write seed-a 20 times to ASI01, plus 5 writers each
    # write seed-b 20 times to ASI02. Final in-memory state must be:
    # ASI01 → {"seed-a"}, ASI02 → {"seed-b"}.
    tasks = []
    for _ in range(5):
        tasks.append(writer(AsiCategory.ASI01, "seed-a", 20))
        tasks.append(writer(AsiCategory.ASI02, "seed-b", 20))
    await asyncio.gather(*tasks)

    assert mem.attempted_seeds(AsiCategory.ASI01) == frozenset({"seed-a"})
    assert mem.attempted_seeds(AsiCategory.ASI02) == frozenset({"seed-b"})

    # JSONL preserves the full audit trail.
    lines = mem.jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5 * 20 * 2  # 200 lines
