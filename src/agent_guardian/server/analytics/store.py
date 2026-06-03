"""Reference SQLite event store for the collector.

The production deployment runs ClickHouse per the analytics PRD §4
(2-3x faster batch inserts than TimescaleDB). The schema here is
written to be portable -- same DDL works on SQLite and ClickHouse with
trivial syntactic changes -- so anyone can self-host the collector
for testing or audit.

Schema (one row per event):

    scan_events  install_id, scan_id, aivss, band, tier, adapter,
                 target_mode, duration_seconds, terminated_by,
                 findings_total, findings_critical, findings_high,
                 findings_medium, findings_low, agent_version,
                 python_version, os_family, arch, started_at,
                 completed_at, client_sent_at, server_received_at

The store ignores ``probe_fire`` and ``install`` events in v1.0 --
the day-1 aggregator only needs ``scan_completed``. Adding them is
a v1.1 schema migration.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from agent_guardian.logging_setup import sanitize_for_log
from agent_guardian.telemetry.events import EventEnvelope, ScanCompletedEvent

__all__ = ["EventStore", "init_schema"]

_LOG = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    install_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    aivss INTEGER NOT NULL,
    band TEXT NOT NULL,
    tier TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    terminated_by TEXT NOT NULL,
    -- Essential operational counts (always present)
    agents_count INTEGER NOT NULL DEFAULT 0,
    attempts_count INTEGER NOT NULL DEFAULT 0,
    successes_count INTEGER NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL,
    findings_critical INTEGER NOT NULL,
    findings_high INTEGER NOT NULL,
    findings_medium INTEGER NOT NULL,
    findings_low INTEGER NOT NULL,
    agent_version TEXT NOT NULL,
    -- Extended environment fingerprint (NULL when user is on essential-only tier)
    adapter TEXT,
    target_mode TEXT,
    python_version TEXT,
    os_family TEXT,
    arch TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    client_sent_at TEXT NOT NULL,
    server_received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_events_server_received_at
    ON scan_events(server_received_at);
CREATE INDEX IF NOT EXISTS idx_scan_events_install_id
    ON scan_events(install_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_adapter
    ON scan_events(adapter);
"""


def init_schema(conn: sqlite3.Connection) -> None:
    """Create tables + indexes if missing. Idempotent."""
    conn.executescript(_SCHEMA)


class EventStore:
    """SQLite-backed write-side of the collector.

    Connections are short-lived per call so tests with multiple
    EventStore instances on the same file don't deadlock on WAL.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            init_schema(c)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            yield conn
        finally:
            conn.close()

    def ingest(self, envelope: EventEnvelope) -> bool:
        """Insert one envelope into the store. Returns False if it was
        rejected by the clock-skew filter."""
        event = envelope.event
        if not isinstance(event, ScanCompletedEvent):
            _LOG.debug(  # noqa: py/log-injection  -- event_type sanitized via sanitize_for_log
                "analytics store: ignoring event_type=%s (v1.0 only persists scan_completed)",
                sanitize_for_log(event.event_type),
            )
            return False
        if not _passes_clock_skew(envelope.client_sent_at):
            _LOG.warning(
                "analytics store: rejecting envelope with skewed client_sent_at=%s",
                envelope.client_sent_at.isoformat(),
            )
            return False
        with self._conn() as c:
            c.execute(
                """
                INSERT INTO scan_events (
                    install_id, scan_id, aivss, band, tier,
                    duration_seconds, terminated_by,
                    agents_count, attempts_count, successes_count,
                    findings_total, findings_critical, findings_high,
                    findings_medium, findings_low,
                    agent_version,
                    adapter, target_mode, python_version, os_family, arch,
                    started_at, completed_at,
                    client_sent_at, server_received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.install_id,
                    event.scan_id,
                    event.aivss,
                    event.band,
                    event.tier,
                    event.duration_seconds,
                    event.terminated_by,
                    event.agents_count,
                    event.attempts_count,
                    event.successes_count,
                    event.findings_total,
                    event.findings_critical,
                    event.findings_high,
                    event.findings_medium,
                    event.findings_low,
                    event.agent_version,
                    event.adapter,  # may be NULL (essential-only tier)
                    event.target_mode,  # may be NULL
                    event.python_version,  # may be NULL
                    event.os_family,  # may be NULL
                    event.arch,  # may be NULL
                    event.started_at.isoformat(),
                    event.completed_at.isoformat(),
                    envelope.client_sent_at.isoformat(),
                    datetime.now(UTC).isoformat(),
                ),
            )
        return True

    def row_count(self) -> int:
        with self._conn() as c:
            row = c.execute("SELECT COUNT(*) FROM scan_events").fetchone()
        return int(row[0]) if row else 0

    def connection(self) -> sqlite3.Connection:
        """Open a read connection for the aggregator. Caller closes it."""
        conn = sqlite3.connect(self._db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Test fixtures -- synthetic event generators
    # ------------------------------------------------------------------

    def seed_synthetic(self, n_scans: int = 100, *, seed: int = 0) -> None:
        """Insert N synthetic scan events with realistic-looking distributions.

        Used by tests + the local dev harness. Not called in production.
        The casts below satisfy mypy strict mode where ``random.choice``
        on a ``list[str]`` widens past the Pydantic Literal constraint.
        """
        import random
        from typing import Any, cast

        rng = random.Random(seed)
        adapters = ["langgraph", "adk", "crewai", "openai-agents", "autogen", "strands", "custom"]
        target_modes = ["prompt", "code", "http", "framework"]
        oses = ["Linux", "Darwin", "Windows"]
        archs = ["x86_64", "arm64"]
        pythons = ["3.10", "3.11", "3.12", "3.13"]

        # We need at least 50 distinct install_ids for k-anonymity to clear.
        install_ids = [f"00000000-0000-4000-8000-{i:012x}" for i in range(max(50, n_scans // 2))]

        for i in range(n_scans):
            # AIVSS sampled from a vaguely realistic distribution
            # (median ~67, p10 ~41, p90 ~87 per the PRD's mockup).
            aivss = max(0, min(100, int(rng.gauss(67, 15))))
            band = (
                "EXCELLENT"
                if aivss >= 90
                else "GOOD"
                if aivss >= 80
                else "WARNING"
                if aivss >= 60
                else "POOR"
                if aivss >= 40
                else "CRITICAL"
            )
            tier = rng.choice(["T1", "T2", "T3", "T4"])
            adapter = rng.choice(adapters)
            # Crash-free rate ~99.7% -- 3 in 1000 crash.
            terminated_by = "crash" if rng.random() < 0.003 else "success"
            findings_total = max(0, int(rng.gauss(4.5, 3)))
            findings_critical = 1 if rng.random() < 0.04 else 0
            findings_high = min(findings_total, max(0, int(rng.gauss(0.7, 1))))
            findings_medium = min(
                max(0, findings_total - findings_critical - findings_high),
                max(0, int(rng.gauss(2, 1.5))),
            )
            findings_low = max(
                0,
                findings_total - findings_critical - findings_high - findings_medium,
            )
            now = datetime.now(UTC)
            # Realistic-ish operational counts: 9-11 agents per scan,
            # ~7 turns/agent on average → ~70 attempts, plus the per-
            # attempt success/failure split derived from findings_total.
            agents_count = rng.randint(9, 11)
            attempts_count = agents_count * rng.randint(5, 9)
            successes_count = max(0, attempts_count - findings_total)
            envelope = EventEnvelope(
                client_sent_at=now,
                # ``cast(Any, ...)`` on the Pydantic side widens the
                # str literals from rng.choice past mypy strict mode.
                # Pydantic still validates each field against its Literal
                # constraint at runtime -- this only relaxes the type
                # check, not the actual runtime allowlist.
                event=ScanCompletedEvent(
                    install_id=rng.choice(install_ids),
                    scan_id=f"{i:08x}{rng.randint(0, 0xFFFFFFFF):08x}",
                    aivss=aivss,
                    band=cast(Any, band),
                    tier=cast(Any, tier),
                    duration_seconds=max(5.0, rng.gauss(120, 60)),
                    terminated_by=cast(Any, terminated_by),
                    agents_count=agents_count,
                    attempts_count=attempts_count,
                    successes_count=successes_count,
                    findings_total=findings_total,
                    findings_critical=findings_critical,
                    findings_high=findings_high,
                    findings_medium=findings_medium,
                    findings_low=findings_low,
                    agent_version="1.0.0",
                    # Half the synthetic installs are on extended tier
                    # (env fingerprint populated); half are essential-only.
                    adapter=cast(Any, adapter) if rng.random() < 0.5 else None,
                    target_mode=cast(Any, rng.choice(target_modes)) if rng.random() < 0.5 else None,
                    python_version=rng.choice(pythons) if rng.random() < 0.5 else None,
                    os_family=cast(Any, rng.choice(oses)) if rng.random() < 0.5 else None,
                    arch=cast(Any, rng.choice(archs)) if rng.random() < 0.5 else None,
                    started_at=now,
                    completed_at=now,
                ),
            )
            self.ingest(envelope)


def _passes_clock_skew(client_sent_at: datetime, *, now: datetime | None = None) -> bool:
    """Return False if the client timestamp is >30d past or >5min future.

    Per analytics PRD §4 -- drops obviously-wrong events at the boundary
    rather than letting them poison the rollups.
    """
    reference = now if now is not None else datetime.now(UTC)
    delta = (reference - client_sent_at).total_seconds()
    # Past -- must be within 30 days
    if delta > 30 * 86400:
        return False
    # Future -- must be within 5 minutes (NTP slippage tolerance)
    return delta >= -300


# Sentinel for the analytics route -- exposed for clarity.
_ = json  # quiet linter; json is used implicitly via Pydantic JSON paths
