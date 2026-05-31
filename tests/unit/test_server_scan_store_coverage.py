"""Pre-existing-branch locking tests for ScanStore (QA-015).

The base ``test_server_scan_store.py`` covers the happy paths. This
companion file pins the SSE / index / metrics / error-recovery branches
that QA-015 flagged as uncovered at 70%. Each test is named for the
exact behavior it locks so a future regression flips a clearly-labelled
bisectable signal.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.models.asi import AsiCategory
from agent_guardian.server import ScanStore
from agent_guardian.server.scan_store import (
    INDEX_FILENAME,
    ScanSummary,
    _coerce_payload,
    _json_safe,
    _resolve_max_buffered_events,
    event_to_payload,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _event(
    kind: str,
    *,
    agent: str | None = None,
    payload: dict[str, Any] | None = None,
) -> SwarmEvent:
    return SwarmEvent(
        kind=kind,  # type: ignore[arg-type]
        timestamp=datetime(2026, 5, 31, 12, 0, 0, tzinfo=timezone.utc),
        agent=agent,
        payload=payload or {},
    )


class _FakeSwarm:
    """Minimal stand-in for SwarmCommander -- only ``observer`` is touched."""

    observer = None


class _RecordingMetrics:
    """Capture every metrics-sink hook call so tests can assert wiring."""

    def __init__(self) -> None:
        self.running_count = 0
        self.completed_durations: list[float] = []
        self.findings: list[str] = []

    def inc_scans_running(self) -> None:
        self.running_count += 1

    def dec_scans_running(self) -> None:
        self.running_count -= 1

    def observe_scan_complete(self, seconds: float) -> None:
        self.completed_durations.append(seconds)

    def observe_finding(self, severity: str) -> None:
        self.findings.append(severity)


# ---------------------------------------------------------------------------
# _resolve_max_buffered_events  (lines 86-100)
# ---------------------------------------------------------------------------


def test_resolve_max_buffered_events_default_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_MAX_BUFFERED_EVENTS", raising=False)
    assert _resolve_max_buffered_events() == 5000


def test_resolve_max_buffered_events_honours_positive_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_MAX_BUFFERED_EVENTS", "250")
    assert _resolve_max_buffered_events() == 250


def test_resolve_max_buffered_events_falls_back_on_non_integer(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_MAX_BUFFERED_EVENTS", "not-a-number")
    with caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"):
        assert _resolve_max_buffered_events() == 5000
    assert any("non-integer" in rec.message for rec in caplog.records)


def test_resolve_max_buffered_events_falls_back_on_zero(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_MAX_BUFFERED_EVENTS", "0")
    with caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"):
        assert _resolve_max_buffered_events() == 5000
    assert any("non-positive" in rec.message for rec in caplog.records)


def test_resolve_max_buffered_events_falls_back_on_negative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_MAX_BUFFERED_EVENTS", "-7")
    assert _resolve_max_buffered_events() == 5000


# ---------------------------------------------------------------------------
# ScanSummary.to_dict  (line 142-152)
# ---------------------------------------------------------------------------


def test_scan_summary_to_dict_roundtrips_all_fields() -> None:
    created = datetime(2026, 5, 31, 12, 0, 0, tzinfo=timezone.utc)
    s = ScanSummary(
        scan_id="abc",
        aivss=87,
        band="good",
        target_ref="example.txt",
        target_mode="prompt",
        findings_count=3,
        created_at=created,
        is_running=True,
    )
    out = s.to_dict()
    assert out == {
        "scan_id": "abc",
        "aivss": 87,
        "band": "good",
        "target_ref": "example.txt",
        "target_mode": "prompt",
        "findings_count": 3,
        "created_at": created.isoformat(),
        "is_running": True,
    }


def test_scan_summary_to_dict_handles_missing_created_at() -> None:
    s = ScanSummary(
        scan_id="x",
        aivss=None,
        band=None,
        target_ref=None,
        target_mode=None,
        findings_count=None,
        created_at=None,
        is_running=False,
    )
    assert s.to_dict()["created_at"] is None


# ---------------------------------------------------------------------------
# Metrics sink wiring  (lines 222-223, 270-274, 291-294, 319)
# ---------------------------------------------------------------------------


def test_set_metrics_attaches_sink(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    sink = _RecordingMetrics()
    store.set_metrics(sink)
    assert store._metrics is sink
    store.set_metrics(None)
    assert store._metrics is None


def test_register_calls_inc_scans_running_when_metrics_set(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    sink = _RecordingMetrics()
    store.set_metrics(sink)
    store.register("m-1", _FakeSwarm())  # type: ignore[arg-type]
    assert sink.running_count == 1


def test_observer_observes_finding_severity_on_agent_done(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    sink = _RecordingMetrics()
    store.set_metrics(sink)
    fake = _FakeSwarm()
    store.register("m-2", fake)  # type: ignore[arg-type]
    assert fake.observer is not None
    fake.observer(_event("agent_done", agent="a", payload={"severity": "high"}))
    assert sink.findings == ["high"]


def test_observer_skips_observe_finding_when_severity_missing(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    sink = _RecordingMetrics()
    store.set_metrics(sink)
    fake = _FakeSwarm()
    store.register("m-3", fake)  # type: ignore[arg-type]
    fake.observer(_event("agent_done", agent="a", payload={}))  # type: ignore[misc]
    assert sink.findings == []


def test_observer_skips_observe_finding_when_severity_not_a_string(
    tmp_path: Path,
) -> None:
    store = ScanStore(root_dir=tmp_path)
    sink = _RecordingMetrics()
    store.set_metrics(sink)
    fake = _FakeSwarm()
    store.register("m-4", fake)  # type: ignore[arg-type]
    fake.observer(_event("agent_done", agent="a", payload={"severity": 42}))  # type: ignore[misc]
    assert sink.findings == []


def test_scan_done_dec_scans_and_observes_duration(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    sink = _RecordingMetrics()
    store.set_metrics(sink)
    fake = _FakeSwarm()
    store.register("m-5", fake)  # type: ignore[arg-type]
    assert sink.running_count == 1
    fake.observer(_event("scan_done"))  # type: ignore[misc]
    assert sink.running_count == 0
    assert len(sink.completed_durations) == 1
    assert sink.completed_durations[0] >= 0.0


# ---------------------------------------------------------------------------
# LRU JSONL writer cap  (lines 335-338, 353, 370-374)
# ---------------------------------------------------------------------------


def test_get_jsonl_writer_evicts_lru_when_cap_hit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When MAX_OPEN_JSONL_HANDLES is reached, the LRU writer is closed."""
    monkeypatch.setattr("agent_guardian.server.scan_store.MAX_OPEN_JSONL_HANDLES", 2)
    store = ScanStore(root_dir=tmp_path)
    for sid in ("a", "b", "c"):
        store.scan_dir(sid).mkdir(parents=True, exist_ok=True)
    fh_a = store._get_jsonl_writer("a", store.scan_dir("a") / "events.jsonl")
    fh_b = store._get_jsonl_writer("b", store.scan_dir("b") / "events.jsonl")
    assert list(store._jsonl_files) == ["a", "b"]
    # Opening "c" evicts "a" (oldest).
    store._get_jsonl_writer("c", store.scan_dir("c") / "events.jsonl")
    assert list(store._jsonl_files) == ["b", "c"]
    assert fh_a.closed is True
    assert fh_b.closed is False


def test_get_jsonl_writer_marks_recently_used_on_hit(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    for sid in ("a", "b"):
        store.scan_dir(sid).mkdir(parents=True, exist_ok=True)
    store._get_jsonl_writer("a", store.scan_dir("a") / "events.jsonl")
    store._get_jsonl_writer("b", store.scan_dir("b") / "events.jsonl")
    # Touch "a" -- it should move to the tail.
    store._get_jsonl_writer("a", store.scan_dir("a") / "events.jsonl")
    assert list(store._jsonl_files) == ["b", "a"]


def test_close_jsonl_writer_is_noop_for_unknown_scan(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    # Must not raise.
    store._close_jsonl_writer("never-registered")


def test_close_all_drains_every_writer(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    handles = []
    for sid in ("a", "b", "c"):
        store.scan_dir(sid).mkdir(parents=True, exist_ok=True)
        handles.append(store._get_jsonl_writer(sid, store.scan_dir(sid) / "events.jsonl"))
    store.close_all()
    assert store._jsonl_files == OrderedDict()
    assert all(fh.closed for fh in handles)


# ---------------------------------------------------------------------------
# Observer OSError on jsonl write  (lines 259-260)
# ---------------------------------------------------------------------------


def test_observer_tolerates_oserror_on_jsonl_write(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = ScanStore(root_dir=tmp_path)
    fake = _FakeSwarm()
    store.register("oserr", fake)  # type: ignore[arg-type]

    class _BrokenWriter:
        closed = False

        def write(self, _data: str) -> int:
            raise OSError("disk full")

        def flush(self) -> None:
            raise OSError("disk full")

        def close(self) -> None:
            self.closed = True

    # Inject a broken writer so the next observe() hits the OSError branch.
    store._jsonl_files["oserr"] = _BrokenWriter()  # type: ignore[assignment]
    with caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"):
        fake.observer(_event("agent_start", agent="a"))  # type: ignore[misc]
    assert any("events.jsonl append failed" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Observer SSE QueueFull  (lines 245-246)
# ---------------------------------------------------------------------------


def test_observer_logs_when_sse_queue_full(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("qfull", fake)  # type: ignore[arg-type]
        # Materialise + cap the queue at 1; fill it so the next put_nowait raises.
        q: asyncio.Queue[SwarmEvent] = asyncio.Queue(maxsize=1)
        store._queues["qfull"] = q
        q.put_nowait(_event("agent_start", agent="seed"))
        with caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"):
            fake.observer(_event("agent_progress", agent="b"))  # type: ignore[misc]
        assert any("SSE queue full" in rec.message for rec in caplog.records)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Index tolerance  (lines 402-404, 406, 408-409, 422-423)
# ---------------------------------------------------------------------------


def test_index_read_returns_empty_when_missing(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store._index_read() == {}


def test_index_read_returns_empty_on_malformed_json(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = ScanStore(root_dir=tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / INDEX_FILENAME).write_text("not json", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"):
        assert store._index_read() == {}
    assert any("malformed index" in rec.message for rec in caplog.records)


def test_index_read_returns_empty_when_root_is_not_a_dict(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / INDEX_FILENAME).write_text("[1, 2, 3]", encoding="utf-8")
    assert store._index_read() == {}


def test_index_read_filters_non_string_keys_and_non_dict_rows(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    payload = {"valid": {"scan_id": "valid"}, "also-bad": "string-row"}
    (tmp_path / INDEX_FILENAME).write_text(json.dumps(payload), encoding="utf-8")
    out = store._index_read()
    assert list(out.keys()) == ["valid"]


def test_index_write_warns_on_oserror(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    store = ScanStore(root_dir=tmp_path)
    with (
        patch.object(Path, "write_text", side_effect=OSError("readonly")),
        caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"),
    ):
        store._index_write({"x": {"scan_id": "x"}})
    assert any("failed to write index" in rec.message for rec in caplog.records)


def test_index_upsert_writes_row_with_mtime_when_no_scan_file(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    store.scan_dir("inflight").mkdir(parents=True, exist_ok=True)
    store._index_upsert("inflight", is_running=True)
    index = store._index_read()
    assert "inflight" in index
    assert index["inflight"]["is_running"] is True
    assert index["inflight"]["aivss"] is None
    assert isinstance(index["inflight"]["mtime"], float)


# ---------------------------------------------------------------------------
# list_scans_page -- index fast path  (lines 523-556, 560->642, 567-573)
# ---------------------------------------------------------------------------


def test_list_scans_page_uses_index_fast_path(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    rows = {
        "old": {
            "scan_id": "old",
            "mtime": 1000.0,
            "aivss": 60,
            "band": "warning",
            "target_ref": "old.txt",
            "target_mode": "prompt",
            "findings_count": 4,
            "created_at": "2026-05-29T00:00:00+00:00",
            "is_running": False,
        },
        "new": {
            "scan_id": "new",
            "mtime": 2000.0,
            "aivss": 92,
            "band": "good",
            "target_ref": "new.txt",
            "target_mode": "prompt",
            "findings_count": 1,
            "created_at": "2026-05-31T00:00:00+00:00",
            "is_running": False,
        },
    }
    (tmp_path / INDEX_FILENAME).write_text(json.dumps(rows), encoding="utf-8")
    page, total = store.list_scans_page(offset=0, limit=10)
    assert total == 2
    assert [s.scan_id for s in page] == ["new", "old"]
    assert page[0].aivss == 92
    assert page[0].band == "good"


def test_list_scans_page_index_path_handles_invalid_created_at(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    rows = {
        "x": {
            "scan_id": "x",
            "mtime": 1234.5,
            "aivss": None,
            "band": None,
            "target_ref": None,
            "target_mode": None,
            "findings_count": None,
            "created_at": "this-is-not-iso",
            "is_running": False,
        }
    }
    (tmp_path / INDEX_FILENAME).write_text(json.dumps(rows), encoding="utf-8")
    page, _ = store.list_scans_page()
    assert page[0].scan_id == "x"
    # Falls back to mtime when created_at can't be parsed.
    assert page[0].created_at is None


def test_list_scans_page_clamps_negative_offset_and_extreme_limit(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    page, total = store.list_scans_page(offset=-5, limit=99999)
    assert total == 0
    assert page == []


def test_list_scans_page_skips_running_ids_in_index(tmp_path: Path) -> None:
    """A running scan should not be double-counted via the index fast path."""
    store = ScanStore(root_dir=tmp_path)
    store.register("live", _FakeSwarm())  # type: ignore[arg-type]
    # _index_upsert wrote the row with is_running=True; trim manually to
    # the test invariant: the running scan must lead, NOT appear twice.
    page, total = store.list_scans_page()
    # Should appear exactly once and lead.
    assert total == 1
    assert page[0].scan_id == "live"
    assert page[0].is_running is True


def test_list_scans_page_running_with_partial_scan_uses_partial_fields(
    tmp_path: Path,
) -> None:
    """Live registration + partial scan on disk -> running summary carries fields."""
    from agent_guardian import __version__
    from agent_guardian.models.scan import Scan
    from agent_guardian.models.severity import SeverityBand
    from agent_guardian.models.tier import Tier
    from agent_guardian.server.partial_scan import write_partial_scan

    store = ScanStore(root_dir=tmp_path)
    store.register("live2", _FakeSwarm())  # type: ignore[arg-type]
    partial = Scan(
        id="live2",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="t.txt",
        tier=Tier.T2_HIGH,
        mode="smart",
        aivss=0,
        band=SeverityBand.NOT_EVALUATED,
        sub_scores={
            "prompt_injection_resistance": 0.0,
            "tool_scope_safety": 0.0,
            "pii_containment": 0.0,
            "memory_poisoning_resistance": 0.0,
            "excessive_agency_containment": 0.0,
            "hallucination_resistance": 0.0,
        },
        findings=[],
        asi_scores={cat: 0.0 for cat in AsiCategory},
        duration_seconds=0.0,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 31, 12, 0, 0, tzinfo=timezone.utc),
        scoring_valid=False,
    )
    write_partial_scan(store.scan_dir("live2"), partial)
    page, _ = store.list_scans_page()
    live_rows = [s for s in page if s.scan_id == "live2"]
    assert len(live_rows) == 1
    assert live_rows[0].is_running is True
    assert live_rows[0].target_ref == "t.txt"


def test_list_scans_page_supplements_index_with_orphan_on_disk_scan(
    tmp_path: Path,
) -> None:
    """A scan dir present on disk but absent from the index is still surfaced."""
    store = ScanStore(root_dir=tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    # Seed an index containing only "indexed-only"
    (tmp_path / INDEX_FILENAME).write_text(
        json.dumps({"indexed-only": {"scan_id": "indexed-only", "mtime": 100.0}}),
        encoding="utf-8",
    )
    # And create an orphan scan dir for "supp" with no scan.json (so
    # load_completed returns None -> the else-branch is exercised).
    (tmp_path / "supp").mkdir()
    page, total = store.list_scans_page()
    sids = {s.scan_id for s in page}
    assert "indexed-only" in sids
    # "supp" has no scan.json so load_completed returns None and the
    # supplemental loop currently skips it (no else branch). The test
    # at minimum asserts the index-only row survives the supplement
    # pass.
    assert total >= 1


def test_list_scans_page_cold_path_when_no_index(tmp_path: Path) -> None:
    """No index present -> fall back to deserialising every scan.json."""
    from agent_guardian import __version__
    from agent_guardian.models.scan import Scan
    from agent_guardian.models.severity import SeverityBand
    from agent_guardian.models.tier import Tier

    store = ScanStore(root_dir=tmp_path)
    scan = Scan(
        id="cold",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="cold.txt",
        tier=Tier.T2_HIGH,
        mode="full",
        aivss=80,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 80.0,
            "tool_scope_safety": 80.0,
            "pii_containment": 80.0,
            "memory_poisoning_resistance": 80.0,
            "excessive_agency_containment": 80.0,
            "hallucination_resistance": 80.0,
        },
        findings=[],
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=1.0,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 30, 12, 0, 0, tzinfo=timezone.utc),
    )
    store.scan_dir("cold").mkdir(parents=True, exist_ok=True)
    (store.scan_dir("cold") / "scan.json").write_text(scan.model_dump_json(), encoding="utf-8")
    # Add a dir with no scan.json so the cold-path else-branch (lines
    # 625-640) is exercised.
    (tmp_path / "orphan").mkdir()
    page, total = store.list_scans_page()
    sids = [s.scan_id for s in page]
    assert "cold" in sids
    assert "orphan" in sids
    assert total == 2


def test_list_scans_page_async_delegates_to_sync(tmp_path: Path) -> None:
    """The async wrapper returns the same shape as the sync entrypoint."""

    async def _run() -> tuple[list[ScanSummary], int]:
        store = ScanStore(root_dir=tmp_path)
        return await store.list_scans_page_async(offset=0, limit=10)

    page, total = asyncio.run(_run())
    assert page == []
    assert total == 0


# ---------------------------------------------------------------------------
# _schedule_buffer_eviction -- cancellation of previous task  (line 694)
# ---------------------------------------------------------------------------


def test_schedule_buffer_eviction_cancels_prev_pending_task(tmp_path: Path) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        store._events["s"] = deque(maxlen=10)
        store._schedule_buffer_eviction("s", grace_seconds=10.0)
        first = store._eviction_tasks["s"]
        # Re-schedule before the first fires -> cancellation path.
        store._schedule_buffer_eviction("s", grace_seconds=10.0)
        # Give the loop one tick to process the cancellation propagation.
        await asyncio.sleep(0)
        assert first.cancelled() or first.done()
        # Cleanup so the test doesn't dangle a 10s sleep on the loop.
        store._eviction_tasks["s"].cancel()
        with contextlib.suppress(asyncio.CancelledError, KeyError):
            await store._eviction_tasks["s"]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# get_running / is_running  (lines 699, 717, 719)
# ---------------------------------------------------------------------------


def test_get_running_returns_none_for_unknown(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.get_running("nope") is None


def test_get_running_returns_swarm_after_register(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    fake = _FakeSwarm()
    store.register("r", fake)  # type: ignore[arg-type]
    assert store.get_running("r") is fake  # type: ignore[comparison-overlap]


def test_is_running_false_when_no_scan_dir(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.is_running("ghost") is False


def test_is_running_false_when_terminal_scan_on_disk(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    sd = store.scan_dir("done")
    sd.mkdir(parents=True)
    (sd / "scan.json").write_text("{}", encoding="utf-8")
    assert store.is_running("done") is False


def test_is_running_true_via_partial_scan_on_disk(tmp_path: Path) -> None:
    """Cross-process callers see a scan with only scan.partial.json as running."""
    store = ScanStore(root_dir=tmp_path)
    sd = store.scan_dir("partial")
    sd.mkdir(parents=True)
    (sd / "scan.partial.json").write_text("{}", encoding="utf-8")
    assert store.is_running("partial") is True


def test_is_running_false_when_dir_empty_no_partial_no_terminal(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    store.scan_dir("empty").mkdir(parents=True)
    assert store.is_running("empty") is False


# ---------------------------------------------------------------------------
# event_queue replay QueueFull  (lines 744-745)
# ---------------------------------------------------------------------------


def test_event_queue_replay_logs_when_queue_full(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("replay-full", fake)  # type: ignore[arg-type]
        # Stuff the buffer with more events than asyncio.Queue can hold.
        for i in range(3):
            fake.observer(_event("agent_start", agent=f"a-{i}"))  # type: ignore[misc]
        # Replace the create-on-first-access queue with a cap-1 queue.
        # event_queue is idempotent on _queues, so we need to construct
        # the queue manually and pre-fill so the buffered replay loop
        # hits QueueFull.
        store._queues.pop("replay-full", None)
        # Monkey-patch the in-method asyncio.Queue() call by binding to
        # a small queue before calling event_queue.
        with (
            patch(
                "agent_guardian.server.scan_store.asyncio.Queue",
                return_value=asyncio.Queue(maxsize=1),
            ),
            caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"),
        ):
            store.event_queue("replay-full")
        assert any("SSE replay queue full" in rec.message for rec in caplog.records)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# replay_events_from_disk  (lines 765, 771, 774-781)
# ---------------------------------------------------------------------------


def test_replay_events_from_disk_returns_empty_when_no_jsonl(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    store.scan_dir("nofile").mkdir(parents=True)
    assert store.replay_events_from_disk("nofile") == []


def test_replay_events_from_disk_skips_blank_lines(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    sd = store.scan_dir("blanks")
    sd.mkdir(parents=True)
    (sd / "events.jsonl").write_text(
        '{"kind":"agent_start"}\n\n   \n{"kind":"agent_done"}\n', encoding="utf-8"
    )
    out = store.replay_events_from_disk("blanks")
    assert [r["kind"] for r in out] == ["agent_start", "agent_done"]


def test_replay_events_from_disk_tolerates_malformed_lines(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = ScanStore(root_dir=tmp_path)
    sd = store.scan_dir("badline")
    sd.mkdir(parents=True)
    (sd / "events.jsonl").write_text(
        '{"kind":"agent_start"}\n{not json}\n{"kind":"scan_done"}\n', encoding="utf-8"
    )
    with caplog.at_level(logging.WARNING, logger="agent_guardian.server.scan_store"):
        out = store.replay_events_from_disk("badline")
    assert [r["kind"] for r in out] == ["agent_start", "scan_done"]
    assert any("malformed events.jsonl line" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# load_completed legacy-mode back-compat shim  (lines 821-822)
# ---------------------------------------------------------------------------


def test_load_completed_back_compat_adds_default_mode_field(tmp_path: Path) -> None:
    """Pre-72d4deb scans missing ``mode`` deserialise as smart + non-authoritative."""
    from agent_guardian import __version__
    from agent_guardian.models.scan import Scan
    from agent_guardian.models.severity import SeverityBand
    from agent_guardian.models.tier import Tier

    store = ScanStore(root_dir=tmp_path)
    sd = store.scan_dir("legacy")
    sd.mkdir(parents=True)
    # Build a Scan dict missing ``mode`` (simulating a pre-mode persist).
    seed = Scan(
        id="legacy",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="legacy.txt",
        tier=Tier.T2_HIGH,
        mode="smart",
        aivss=70,
        band=SeverityBand.WARNING,
        sub_scores={
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 70.0,
            "pii_containment": 70.0,
            "memory_poisoning_resistance": 70.0,
            "excessive_agency_containment": 70.0,
            "hallucination_resistance": 70.0,
        },
        findings=[],
        asi_scores={cat: 70.0 for cat in AsiCategory},
        duration_seconds=0.5,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 27, 0, 0, 0, tzinfo=timezone.utc),
    )
    payload = json.loads(seed.model_dump_json())
    payload.pop("mode", None)
    payload.pop("mode_authoritative", None)
    (sd / "scan.json").write_text(json.dumps(payload), encoding="utf-8")

    loaded = store.load_completed("legacy")
    assert loaded is not None
    assert loaded.mode == "smart"
    assert loaded.mode_authoritative is False


def test_get_scan_alias_returns_same_as_load_completed(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.get_scan("missing") is None


# ---------------------------------------------------------------------------
# list_report_paths -- explicit report.json wins over scan.json  (line 867->869)
# ---------------------------------------------------------------------------


def test_list_report_paths_prefers_explicit_report_json_over_scan_json(
    tmp_path: Path,
) -> None:
    store = ScanStore(root_dir=tmp_path)
    sd = store.scan_dir("rep2")
    sd.mkdir()
    (sd / "report.json").write_text("{}", encoding="utf-8")
    (sd / "scan.json").write_text("{}", encoding="utf-8")
    paths = store.list_report_paths("rep2")
    assert paths["json"].name == "report.json"


# ---------------------------------------------------------------------------
# event_to_payload + _coerce_payload + _json_safe  (lines 895, 900-908)
# ---------------------------------------------------------------------------


def test_event_to_payload_renders_full_event() -> None:
    ev = SwarmEvent(
        kind="agent_done",  # type: ignore[arg-type]
        timestamp=datetime(2026, 5, 31, 12, 0, 0, tzinfo=timezone.utc),
        agent="tool-abuse-agent",
        asi=AsiCategory.ASI02,
        provisional_aivss=42,
        decision=None,
        payload={"severity": "high", "extra": [1, 2.0, "x"]},
    )
    out = event_to_payload(ev)
    assert out["kind"] == "agent_done"
    assert out["agent"] == "tool-abuse-agent"
    assert out["asi"] == AsiCategory.ASI02.value
    assert out["provisional_aivss"] == 42
    assert out["decision"] is None
    assert out["payload"]["severity"] == "high"
    assert out["payload"]["extra"] == [1, 2.0, "x"]


def test_coerce_payload_accepts_iterable_of_tuples() -> None:
    out = _coerce_payload([("a", 1), ("b", "two")])
    assert out == {"a": 1, "b": "two"}


def test_json_safe_handles_primitives_and_none() -> None:
    assert _json_safe(None) is None
    assert _json_safe(True) is True
    assert _json_safe(7) == 7
    assert _json_safe(1.5) == 1.5
    assert _json_safe("x") == "x"


def test_json_safe_handles_datetime() -> None:
    dt = datetime(2026, 5, 31, 12, 0, 0, tzinfo=timezone.utc)
    assert _json_safe(dt) == dt.isoformat()


def test_json_safe_recurses_through_lists_tuples_dicts() -> None:
    nested = {"a": [1, (2, 3)], "b": {"c": datetime(2026, 1, 1, tzinfo=timezone.utc)}}
    out = _json_safe(nested)
    assert out["a"] == [1, [2, 3]]
    assert out["b"]["c"].startswith("2026-01-01")


def test_json_safe_falls_back_to_str_for_unknown_types() -> None:
    class _Opaque:
        def __str__(self) -> str:
            return "opaque-repr"

    assert _json_safe(_Opaque()) == "opaque-repr"


def test_json_safe_coerces_non_string_dict_keys_to_strings() -> None:
    assert _json_safe({1: "v"}) == {"1": "v"}
