"""Unit tests for the M12 :class:`ScanStore`."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from agent_guardian import __version__
from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.server import ScanStore


def _make_scan(scan_id: str) -> Scan:
    findings = [
        Finding(
            id=f"{scan_id}-f-1",
            probe_id="probe-1",
            asi=AsiCategory.ASI01,
            mitre_atlas=["AML.T0054"],
            csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
            severity=Severity.HIGH,
            attempt_count=1,
            success=False,
            confidence=0.5,
            summary="finding 1",
            created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
        )
    ]
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=85,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 90.0,
            "tool_scope_safety": 90.0,
            "pii_containment": 80.0,
            "memory_poisoning_resistance": 85.0,
            "excessive_agency_containment": 80.0,
            "hallucination_resistance": 85.0,
        },
        findings=findings,
        asi_scores={cat: 90.0 for cat in AsiCategory},
        duration_seconds=4.2,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=timezone.utc),
    )


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Construction / paths
# ---------------------------------------------------------------------------


def test_root_defaults_under_home_when_unset() -> None:
    store = ScanStore()
    assert store.root == Path.home() / ".agentguardian" / "scans"


def test_custom_root_honoured(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.root == tmp_path
    assert store.scan_dir("abc") == tmp_path / "abc"


# ---------------------------------------------------------------------------
# Completed scan loading
# ---------------------------------------------------------------------------


def test_load_completed_returns_none_for_unknown(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.load_completed("missing") is None


def test_load_completed_roundtrips(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan = _make_scan("scan-1")
    _persist(store, scan)
    loaded = store.load_completed("scan-1")
    assert loaded is not None
    assert loaded.id == "scan-1"
    assert loaded.aivss == 85
    assert len(loaded.findings) == 1


def test_load_completed_handles_malformed_json(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("broken")
    scan_dir.mkdir(parents=True)
    (scan_dir / "scan.json").write_text("not json", encoding="utf-8")
    assert store.load_completed("broken") is None


# ---------------------------------------------------------------------------
# list_scans
# ---------------------------------------------------------------------------


def test_list_scans_empty(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.list_scans() == []


def test_list_scans_orders_completed_by_recency(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    older = _make_scan("older")
    newer = _make_scan("newer")
    object.__setattr__(
        newer,
        "__pydantic_fields_set__",
        newer.__pydantic_fields_set__,
    )
    # Re-make with explicit created_at differences.
    older = older.model_copy(
        update={"created_at": datetime(2026, 5, 26, 0, 0, 0, tzinfo=timezone.utc)}
    )
    newer = newer.model_copy(
        update={"created_at": datetime(2026, 5, 27, 0, 0, 0, tzinfo=timezone.utc)}
    )
    _persist(store, older)
    _persist(store, newer)
    summaries = store.list_scans()
    assert [s.scan_id for s in summaries] == ["newer", "older"]
    assert all(not s.is_running for s in summaries)


# ---------------------------------------------------------------------------
# Event queue / observer / replay
# ---------------------------------------------------------------------------


def _event(kind: str, agent: str | None = None) -> SwarmEvent:
    return SwarmEvent(
        kind=kind,  # type: ignore[arg-type]
        timestamp=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
        agent=agent,
    )


def test_event_queue_isolated_per_scan(tmp_path: Path) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        q1 = store.event_queue("a")
        q2 = store.event_queue("b")
        assert q1 is not q2
        # event_queue is idempotent.
        assert store.event_queue("a") is q1

    asyncio.run(_run())


def test_register_wires_observer_and_buffers_events(tmp_path: Path) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)

        # Minimal stand-in for SwarmCommander — only `observer` is touched.
        class FakeSwarm:
            observer = None

        fake = FakeSwarm()
        store.register("scan-x", fake)  # type: ignore[arg-type]
        assert fake.observer is not None
        # Emit one event before the SSE queue exists.
        fake.observer(_event("agent_start", "tool-abuse-agent"))
        # Now the consumer asks for the queue — buffered event should be there.
        q = store.event_queue("scan-x")
        ev = q.get_nowait()
        assert ev.kind == "agent_start"
        assert ev.agent == "tool-abuse-agent"
        # On-disk JSONL written too.
        jsonl = store.scan_dir("scan-x") / "events.jsonl"
        assert jsonl.is_file()
        line = json.loads(jsonl.read_text(encoding="utf-8").splitlines()[0])
        assert line["kind"] == "agent_start"
        assert line["agent"] == "tool-abuse-agent"
        # `scan_done` should drop the running registration.
        assert store.is_running("scan-x")
        fake.observer(_event("scan_done"))
        assert not store.is_running("scan-x")

    asyncio.run(_run())


def test_register_makes_scan_appear_in_list(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    store.register("live-scan", FakeSwarm())  # type: ignore[arg-type]
    summaries = store.list_scans()
    assert any(s.scan_id == "live-scan" and s.is_running for s in summaries)


def test_replay_events_from_disk(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("replay")
    scan_dir.mkdir(parents=True)
    payloads = [
        {"kind": "agent_start", "agent": "recon-agent"},
        {"kind": "agent_done", "agent": "recon-agent"},
        {"kind": "scan_done"},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")
    replayed = store.replay_events_from_disk("replay")
    assert [p["kind"] for p in replayed] == [
        "agent_start",
        "agent_done",
        "scan_done",
    ]


def test_list_report_paths_picks_up_known_formats(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("rep")
    scan_dir.mkdir()
    (scan_dir / "report.sarif").write_text("{}", encoding="utf-8")
    (scan_dir / "report.md").write_text("# hi", encoding="utf-8")
    (scan_dir / "scan.json").write_text("{}", encoding="utf-8")
    paths = store.list_report_paths("rep")
    assert "sarif" in paths
    assert "md" in paths
    # scan.json provides the json fallback.
    assert "json" in paths
