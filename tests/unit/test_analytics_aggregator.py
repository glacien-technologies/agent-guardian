"""Tests for the analytics aggregator's k-anonymity protection + hero math."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_guardian.server.analytics import Aggregator, EventStore
from agent_guardian.telemetry.events import EventEnvelope, ScanCompletedEvent

# Anchor to real "now" (minus a day) rather than a hardcoded calendar date.
# The analytics store rejects any envelope whose ``client_sent_at`` is >30 days
# in the past (clock-skew guard, store.py ``_passes_clock_skew``). A fixed date
# silently ages out of that window as wall-clock advances, which made every test
# in this module fail once 30 days had elapsed. A day in the past is safely
# inside both the 30-day-past and 5-minute-future bounds.
_NOW = datetime.now(UTC) - timedelta(days=1)


def _make_event(install_id_suffix: int, aivss: int, **overrides: object) -> EventEnvelope:
    """Build an extended-tier event by default (so per-adapter tests still
    work). Pass ``adapter=None`` etc. for essential-only events."""
    base: dict[str, object] = dict(
        install_id=f"00000000-0000-4000-8000-{install_id_suffix:012x}",
        scan_id=f"{install_id_suffix:08x}aaaaaaaa",
        aivss=aivss,
        band=(
            "EXCELLENT"
            if aivss >= 90
            else "GOOD"
            if aivss >= 80
            else "WARNING"
            if aivss >= 60
            else "POOR"
            if aivss >= 40
            else "CRITICAL"
        ),
        tier="T3",
        duration_seconds=10.0,
        terminated_by="success",
        agents_count=10,
        attempts_count=70,
        successes_count=70,
        findings_total=0,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        adapter="langgraph",
        target_mode="code",
        agent_version="1.0.0",
        python_version="3.11",
        os_family="Linux",
        arch="x86_64",
        started_at=_NOW,
        completed_at=_NOW,
    )
    base.update(overrides)
    return EventEnvelope(client_sent_at=_NOW, event=ScanCompletedEvent(**base))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# k-anonymity gate
# ---------------------------------------------------------------------------


def test_below_k_threshold_suppresses_median_and_distribution(tmp_path: Path) -> None:
    """With <50 distinct installs, median + histogram both return None / []."""
    store = EventStore(tmp_path / "db.sqlite")
    # 10 scans, 10 distinct installs — well below k=50.
    for i in range(10):
        store.ingest(_make_event(i, aivss=70))
    agg = Aggregator(store.connection())
    h = agg.hero_numbers(window_days=0)
    assert h.total_scans == 10  # raw count is published
    assert h.median_aivss is None  # but median is suppressed
    assert h.crash_free_rate_pct is None
    assert h.monthly_active_installs == 0  # MAU only published when threshold cleared
    assert agg.aivss_distribution(window_days=0) == []
    assert agg.asi_breakdown(window_days=0) == []


def test_exactly_k_threshold_passes(tmp_path: Path) -> None:
    """50 distinct installs = the threshold, so cells must publish."""
    store = EventStore(tmp_path / "db.sqlite")
    for i in range(50):
        store.ingest(_make_event(i, aivss=70))
    agg = Aggregator(store.connection())
    h = agg.hero_numbers(window_days=0)
    assert h.median_aivss == 70
    assert h.crash_free_rate_pct == 100.0
    assert h.monthly_active_installs == 50


def test_per_adapter_suppression_independent_of_overall(tmp_path: Path) -> None:
    """The per-adapter table can suppress an adapter row even when the
    overall k threshold has cleared."""
    store = EventStore(tmp_path / "db.sqlite")
    # 50 installs on langgraph (clears threshold)
    for i in range(50):
        store.ingest(_make_event(i, aivss=70, adapter="langgraph"))
    # Only 5 installs on crewai — suppressed.
    for i in range(50, 55):
        store.ingest(_make_event(i, aivss=70, adapter="crewai"))
    agg = Aggregator(store.connection())
    rows = agg.adapter_mix(window_days=0)
    adapters = [r.adapter for r in rows]
    assert "langgraph" in adapters
    assert "crewai" not in adapters  # suppressed


# ---------------------------------------------------------------------------
# Hero math
# ---------------------------------------------------------------------------


def test_median_aivss_is_actually_the_median(tmp_path: Path) -> None:
    """Sanity: feed a known sorted set and check the median."""
    store = EventStore(tmp_path / "db.sqlite")
    # 51 distinct installs with AIVSS = 1, 2, ..., 51 → median = 26.
    for i in range(51):
        store.ingest(_make_event(i, aivss=i + 1))
    agg = Aggregator(store.connection())
    assert agg.hero_numbers(window_days=0).median_aivss == 26


def test_crash_free_rate_decrements_only_for_crash(tmp_path: Path) -> None:
    """terminated_by='success' and 'error' don't affect crash-free; only 'crash' does."""
    store = EventStore(tmp_path / "db.sqlite")
    # 47 successes + 1 error + 2 crashes = 50 distinct installs, 96% crash-free.
    for i in range(47):
        store.ingest(_make_event(i, aivss=70, terminated_by="success"))
    store.ingest(_make_event(47, aivss=70, terminated_by="error"))
    store.ingest(_make_event(48, aivss=70, terminated_by="crash"))
    store.ingest(_make_event(49, aivss=70, terminated_by="crash"))
    agg = Aggregator(store.connection())
    cf = agg.hero_numbers(window_days=0).crash_free_rate_pct
    assert cf is not None
    assert cf == 96.0


def test_histogram_buckets_sum_to_100_percent(tmp_path: Path) -> None:
    """All 10 histogram buckets together must sum to (close to) 100%."""
    store = EventStore(tmp_path / "db.sqlite")
    # Spread 60 installs across the whole AIVSS range.
    for i in range(60):
        store.ingest(_make_event(i, aivss=i + 20))  # 20..79
    agg = Aggregator(store.connection())
    hist = agg.aivss_distribution(window_days=0)
    total = sum(b.percent for b in hist)
    assert 99.0 <= total <= 101.0  # rounding tolerance
    # Cells outside 20..79 should be empty
    assert hist[0].count == 0  # 0-10
    assert hist[1].count == 0  # 10-20
    assert hist[8].count == 0  # 80-90
    assert hist[9].count == 0  # 90-100


def test_ticker_returns_most_recent_first(tmp_path: Path) -> None:
    """recent_scans returns the latest N in reverse-time order."""
    store = EventStore(tmp_path / "db.sqlite")
    for i in range(5):
        store.ingest(_make_event(i, aivss=50 + i))
    agg = Aggregator(store.connection())
    recent = agg.recent_scans(limit=3)
    assert len(recent) == 3
    # Most recent ingest was install_id=4 with aivss=54.
    assert recent[0]["aivss"] == 54
    # All 4 fields safe for public display
    assert set(recent[0].keys()) == {"aivss", "band", "adapter", "completed_at"}


# ---------------------------------------------------------------------------
# Ingest path
# ---------------------------------------------------------------------------


def test_ingest_returns_false_for_skewed_client_time(tmp_path: Path) -> None:
    """Far-past client_sent_at envelopes are rejected at ingest time."""
    from datetime import timedelta

    store = EventStore(tmp_path / "db.sqlite")
    old = _NOW - timedelta(days=60)
    envelope = EventEnvelope(
        client_sent_at=old,
        event=ScanCompletedEvent(
            install_id=f"00000000-0000-4000-8000-{0:012x}",
            scan_id="aaaa1111",
            aivss=50,
            band="POOR",
            tier="T3",
            duration_seconds=10,
            terminated_by="success",
            findings_total=0,
            findings_critical=0,
            findings_high=0,
            findings_medium=0,
            findings_low=0,
            adapter="langgraph",
            target_mode="code",
            agent_version="1.0.0",
            python_version="3.11",
            os_family="Linux",
            arch="x86_64",
            started_at=old,
            completed_at=old,
        ),
    )
    assert store.ingest(envelope) is False
    assert store.row_count() == 0
