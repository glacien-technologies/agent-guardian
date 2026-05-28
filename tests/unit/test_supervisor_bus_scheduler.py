"""Tests for the M2 Pattern 9 building blocks: supervisor, bus, scheduler."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agent_guardian.core.bus import BundleBus, BusEvent
from agent_guardian.core.scheduler import EpochScheduler, ScheduledItem
from agent_guardian.core.supervisor import ScanCancelled, Supervisor, SupervisorState

# ---------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------


def test_supervisor_starts_running() -> None:
    s = Supervisor()
    assert s.state is SupervisorState.RUNNING
    s.raise_if_cancelled()  # no-op


def test_supervisor_cancel_raises() -> None:
    s = Supervisor()
    s.cancel("operator stopped it")
    assert s.is_cancelled
    assert s.cancel_reason == "operator stopped it"
    with pytest.raises(ScanCancelled) as exc:
        s.raise_if_cancelled()
    assert exc.value.reason == "operator stopped it"


def test_supervisor_resume_after_cancel_is_noop() -> None:
    s = Supervisor()
    s.cancel()
    s.resume()
    assert s.is_cancelled  # cancel is terminal


@pytest.mark.asyncio
async def test_supervisor_pause_blocks_until_resume() -> None:
    s = Supervisor()
    s.pause()
    assert s.is_paused
    released = asyncio.Event()

    async def worker() -> None:
        await s.wait_if_paused()
        released.set()

    task = asyncio.create_task(worker())
    await asyncio.sleep(0.02)
    assert not released.is_set()  # still blocked while paused
    s.resume()
    await asyncio.wait_for(task, timeout=1.0)
    assert released.is_set()


@pytest.mark.asyncio
async def test_supervisor_cancel_releases_paused_waiter() -> None:
    s = Supervisor()
    s.pause()

    async def worker() -> None:
        await s.wait_if_paused()

    task = asyncio.create_task(worker())
    await asyncio.sleep(0.02)
    s.cancel("abort")
    await asyncio.wait_for(task, timeout=1.0)  # cancel unblocks the waiter


# ---------------------------------------------------------------------------
# BundleBus
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bus_publish_get_and_replay() -> None:
    bus = BundleBus()
    await bus.publish(BusEvent(kind="finding", payload={"id": "f1"}))
    await bus.publish(BusEvent(kind="scan_done"))
    e1 = await bus.get()
    assert e1.kind == "finding"
    assert [e.kind for e in bus.replay()] == ["finding", "scan_done"]


@pytest.mark.asyncio
async def test_bus_jsonl_replay_log(tmp_path: Path) -> None:
    p = tmp_path / "bus.jsonl"
    bus = BundleBus(jsonl_path=p)
    await bus.publish(BusEvent(kind="finding", payload={"id": "f1"}))
    rows = [json.loads(line) for line in p.read_text().splitlines()]
    assert rows[0]["kind"] == "finding"
    assert rows[0]["payload"] == {"id": "f1"}


# ---------------------------------------------------------------------------
# EpochScheduler
# ---------------------------------------------------------------------------


def test_scheduler_orders_by_value_density() -> None:
    sched = EpochScheduler()
    # high score / low cost first
    sched.add(ScheduledItem("cheap_good", score=0.9, est_cost_usd=0.01))  # density 90
    sched.add(ScheduledItem("pricey_good", score=0.9, est_cost_usd=0.50))  # density 1.8
    sched.add(ScheduledItem("cheap_meh", score=0.2, est_cost_usd=0.01))  # density 20
    order = [it.item_id for it in sched.prioritized()]
    assert order == ["cheap_good", "cheap_meh", "pricey_good"]
    assert sched.next_item().item_id == "cheap_good"


def test_scheduler_demotes_repeated_failures() -> None:
    sched = EpochScheduler(failure_demotion=2)
    sched.add(ScheduledItem("a", score=0.9, est_cost_usd=0.01))  # highest density
    sched.add(ScheduledItem("b", score=0.3, est_cost_usd=0.01))
    sched.record_failure("a")
    sched.record_failure("a")  # now at threshold -> demoted
    order = [it.item_id for it in sched.prioritized()]
    assert order == ["b", "a"]


def test_scheduler_excludes_done_items() -> None:
    sched = EpochScheduler()
    sched.add(ScheduledItem("a"))
    sched.add(ScheduledItem("b"))
    sched.record_success("a")
    order = [it.item_id for it in sched.prioritized()]
    assert order == ["b"]


def test_scheduler_advance_epoch() -> None:
    sched = EpochScheduler(epoch_seconds=600.0)
    assert sched.epoch == 0
    assert sched.advance_epoch() == 1
    assert sched.epoch == 1
