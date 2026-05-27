"""Local SQLite buffer for telemetry events.

When the collector endpoint is unreachable, events queue here. On the
next successful flush they go out in FIFO order. The store at
``~/.agentguardian/local.db`` is the user-side store the analytics
PRD calls for (§4 storage rules).

Schema is intentionally one wide table -- events are deleted after
successful send, so the table never holds more than a few hundred
rows even on heavy usage.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from agent_guardian.telemetry.consent import default_consent_dir
from agent_guardian.telemetry.events import EventEnvelope

__all__ = ["LocalEventBuffer", "local_db_path"]

_LOG = logging.getLogger(__name__)


def local_db_path(consent_dir: Path | None = None) -> Path:
    base = consent_dir if consent_dir is not None else default_consent_dir()
    return base / "local.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    queued_at TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_pending_events_queued_at
    ON pending_events(queued_at);
"""


class LocalEventBuffer:
    """SQLite-backed FIFO queue for telemetry envelopes.

    Connections are short-lived (opened per operation) so cross-process
    invocations (multiple CLI runs) don't fight over a long-held
    handle.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path if db_path is not None else local_db_path()
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def enqueue(self, envelope: EventEnvelope) -> int:
        """Append an envelope to the queue. Returns the row id."""
        payload = envelope.model_dump_json()
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO pending_events(queued_at, envelope_json) VALUES (datetime('now'), ?)",
                (payload,),
            )
            row_id = cur.lastrowid
        _LOG.debug(
            "telemetry buffer: enqueued envelope id=%d event_type=%s",
            row_id,
            envelope.event.event_type,
        )
        return row_id or 0

    def pending(self, limit: int = 100) -> list[tuple[int, EventEnvelope]]:
        """Read up to ``limit`` pending envelopes in FIFO order."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT id, envelope_json FROM pending_events ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        out: list[tuple[int, EventEnvelope]] = []
        for row_id, payload in rows:
            try:
                env = EventEnvelope.model_validate_json(payload)
            except Exception as exc:  # pragma: no cover -- defensive
                _LOG.warning(
                    "telemetry buffer: dropping malformed row %d (%s: %s)",
                    row_id,
                    type(exc).__name__,
                    exc,
                )
                self._drop_row(row_id)
                continue
            out.append((row_id, env))
        return out

    def mark_sent(self, row_id: int) -> None:
        """Delete a row after the collector accepted it."""
        with self._conn() as c:
            c.execute("DELETE FROM pending_events WHERE id = ?", (row_id,))

    def mark_attempt_failed(self, row_id: int, error: str) -> None:
        """Increment attempt counter; keep the row for the next flush."""
        with self._conn() as c:
            c.execute(
                "UPDATE pending_events "
                "SET attempt_count = attempt_count + 1, "
                "    last_attempt_at = datetime('now'), "
                "    last_error = ? "
                "WHERE id = ?",
                (error[:500], row_id),
            )

    def _drop_row(self, row_id: int) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM pending_events WHERE id = ?", (row_id,))

    def queue_depth(self) -> int:
        with self._conn() as c:
            row = c.execute("SELECT COUNT(*) FROM pending_events").fetchone()
        return int(row[0]) if row else 0

    def purge_all(self) -> int:
        """Delete every queued envelope. Called from ``telemetry reset``.

        Returns the number of rows that were deleted (for the operator
        log line).
        """
        with self._conn() as c:
            before = c.execute("SELECT COUNT(*) FROM pending_events").fetchone()[0]
            c.execute("DELETE FROM pending_events")
        _LOG.info("telemetry buffer: purged %d pending envelopes", before)
        return int(before)
