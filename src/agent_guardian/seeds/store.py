"""WinningSeedStore — production-grade SQLite persistence (Phase B.B6).

Stores attack seeds that produced a ``verdict='fail'`` outcome so a future
scan against the same target fingerprint can warm-start from known-winning
seeds. PII is scrubbed before persistence via :class:`PiiScrubber`.

Retention policy
----------------
Default retention is **180 days from insertion**. Records older than the
retention window are purged by :meth:`expire_old`, which is invoked
automatically on every 1000th :meth:`insert` (a counter modulo). Operators
can disable retention entirely with ``enabled=False`` (the ``--no-winning-seeds``
CLI flag is a Phase C wiring) or reduce it via ``retention_days``.

The database lives at ``~/.agentguardian/winning_seeds.db`` by default —
the same directory as the user's ``config.yaml``. The parent directory is
created on ``__init__`` with ``parents=True, exist_ok=True``.

Thread + process safety
-----------------------
A ``threading.Lock`` serialises calls within a process. ``PRAGMA
journal_mode=WAL`` is set on connection open so concurrent writes from
multiple processes (multiple agents in a single scan, all writing winning
seeds simultaneously) do not corrupt the file.

Logs
----
Every insert and expiration is logged at DEBUG/INFO with the ``PhaseB.B6``
tag so the audit replay can verify the store actually persisted what the
agent loop intended.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.seeds.scrubber import PiiScrubber

__all__ = ["WinningSeedRecord", "WinningSeedStore"]

_LOG = logging.getLogger("agent_guardian.seeds.store")


# Auto-expire counter modulus: expire_old() runs every Nth insert.
_EXPIRE_EVERY_N_INSERTS = 1000


class WinningSeedRecord(BaseModel):
    """One winning-seed row.

    Composite key (``target_fingerprint_hash``, ``asi``, ``mutant``) is a
    natural dedup key but is NOT enforced as a UNIQUE constraint in
    Phase B — dedup is Phase C.
    """

    target_fingerprint_hash: str = Field(min_length=1)
    asi: str = Field(min_length=1)
    mutant: str = ""
    seed_text: str = Field(min_length=1)
    verdict: str = Field(min_length=1)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: datetime
    expires_at: datetime

    model_config = ConfigDict(frozen=True)


_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS winning_seeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_fingerprint_hash TEXT NOT NULL,
    asi TEXT NOT NULL,
    mutant TEXT NOT NULL,
    seed_text TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL,
    created_at TEXT,
    expires_at TEXT
)
""".strip()

_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_target_asi
    ON winning_seeds (target_fingerprint_hash, asi)
""".strip()


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class WinningSeedStore:
    """SQLite-backed persistence for winning attack seeds.

    Args:
        db_path: Database file location. ``None`` defaults to
            ``~/.agentguardian/winning_seeds.db``.
        retention_days: Number of days a record is kept before
            :meth:`expire_old` removes it. Default 180.
        enabled: When ``False``, every write is a no-op — the user has
            opted out via ``--no-winning-seeds``. Reads still work
            against an existing database file.
    """

    def __init__(
        self,
        db_path: Path | None = None,
        retention_days: int = 180,
        enabled: bool = True,
    ) -> None:
        if retention_days < 1:
            raise ValueError("retention_days must be >= 1")
        self._db_path = (
            db_path if db_path is not None else Path.home() / ".agentguardian" / "winning_seeds.db"
        )
        self._retention_days = retention_days
        self._enabled = enabled
        self._lock = threading.Lock()
        self._scrubber = PiiScrubber()
        self._insert_counter = 0

        # Ensure parent dir.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        # Initialise schema.
        with self._connect() as conn:
            conn.execute(_CREATE_SQL)
            conn.execute(_INDEX_SQL)
            conn.commit()

        _LOG.debug(
            "PhaseB.B6 store_init: db_path=%s enabled=%s retention_days=%d",
            self._db_path,
            self._enabled,
            self._retention_days,
        )

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def retention_days(self) -> int:
        return self._retention_days

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Open a new sqlite3 connection with WAL journaling.

        WAL mode is needed for safe concurrent writes from multiple
        processes (multiple agents in a single scan all writing winning
        seeds simultaneously). The threading lock serialises within
        process, WAL handles cross-process.
        """
        conn = sqlite3.connect(str(self._db_path), isolation_level=None, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError as exc:
            # PRAGMA failures are non-fatal — fall back to whatever default.
            _LOG.debug(
                "PhaseB.B6 store.pragma_fallback: pragma_set_failed err=%s — "
                "using sqlite default journal/sync modes",
                exc,
            )
        return conn

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def insert(self, record: WinningSeedRecord) -> bool:
        """Persist a winning seed, scrubbing PII first.

        Returns ``True`` if the row was written, ``False`` when the store
        is disabled. Auto-expiration runs every 1000th insert.
        """
        if not self._enabled:
            _LOG.debug(
                "PhaseB.B6 insert.noop: store_enabled=False target_hash=%s asi=%s",
                record.target_fingerprint_hash,
                record.asi,
            )
            return False

        pre_len = len(record.seed_text)
        _LOG.debug(
            "PhaseB.B6 insert: target_hash=%s asi=%s mutant=%s seed_len_pre_scrub=%d",
            record.target_fingerprint_hash,
            record.asi,
            record.mutant,
            pre_len,
        )
        scrubbed_text = self._scrubber.scrub(record.seed_text)
        n_redactions = self._scrubber.last_redaction_count
        post_len = len(scrubbed_text)
        _LOG.debug(
            "PhaseB.B6 insert_post_scrub: seed_len_post_scrub=%d n_redactions=%d expires_at=%s",
            post_len,
            n_redactions,
            record.expires_at.isoformat(),
        )

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO winning_seeds (target_fingerprint_hash, asi, mutant, "
                    "seed_text, verdict, confidence, created_at, expires_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        record.target_fingerprint_hash,
                        record.asi,
                        record.mutant,
                        scrubbed_text,
                        record.verdict,
                        float(record.confidence),
                        record.created_at.isoformat(),
                        record.expires_at.isoformat(),
                    ),
                )
                conn.commit()
            self._insert_counter += 1
            should_expire = self._insert_counter % _EXPIRE_EVERY_N_INSERTS == 0

        if should_expire:
            self.expire_old()
        return True

    def insert_seed(
        self,
        *,
        target_fingerprint_hash: str,
        asi: str,
        seed_text: str,
        verdict: str,
        confidence: float,
        mutant: str = "",
    ) -> bool:
        """Convenience constructor — builds the :class:`WinningSeedRecord` for the caller."""
        now = _utcnow()
        record = WinningSeedRecord(
            target_fingerprint_hash=target_fingerprint_hash,
            asi=asi,
            mutant=mutant,
            seed_text=seed_text,
            verdict=verdict,
            confidence=confidence,
            created_at=now,
            expires_at=now + timedelta(days=self._retention_days),
        )
        return self.insert(record)

    def expire_old(self) -> int:
        """Delete rows whose ``expires_at`` is in the past. Returns the count."""
        cutoff = _utcnow().isoformat()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM winning_seeds WHERE expires_at < ?",
                (cutoff,),
            )
            deleted = cur.rowcount or 0
            conn.commit()
        _LOG.info(
            "PhaseB.B6 expire_old: rows_deleted=%d retention_days=%d",
            deleted,
            self._retention_days,
        )
        return deleted

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def query(
        self,
        target_fingerprint_hash: str,
        asi: str | None = None,
    ) -> list[WinningSeedRecord]:
        """Return every record for a target (and optionally an ASI)."""
        with self._lock, self._connect() as conn:
            if asi is None:
                cur = conn.execute(
                    "SELECT target_fingerprint_hash, asi, mutant, seed_text, "
                    "verdict, confidence, created_at, expires_at "
                    "FROM winning_seeds WHERE target_fingerprint_hash = ? "
                    "ORDER BY id",
                    (target_fingerprint_hash,),
                )
            else:
                cur = conn.execute(
                    "SELECT target_fingerprint_hash, asi, mutant, seed_text, "
                    "verdict, confidence, created_at, expires_at "
                    "FROM winning_seeds WHERE target_fingerprint_hash = ? AND asi = ? "
                    "ORDER BY id",
                    (target_fingerprint_hash, asi),
                )
            rows = cur.fetchall()
        out: list[WinningSeedRecord] = []
        for row in rows:
            (
                tfh,
                row_asi,
                mutant,
                seed_text,
                verdict,
                confidence,
                created_at,
                expires_at,
            ) = row
            out.append(
                WinningSeedRecord(
                    target_fingerprint_hash=tfh,
                    asi=row_asi,
                    mutant=mutant or "",
                    seed_text=seed_text,
                    verdict=verdict,
                    confidence=float(confidence or 0.0),
                    created_at=datetime.fromisoformat(created_at),
                    expires_at=datetime.fromisoformat(expires_at),
                )
            )
        _LOG.debug(
            "PhaseB.B6 query: target_fingerprint_hash=%s asi=%s hits=%d miss=%s",
            target_fingerprint_hash,
            asi,
            len(out),
            len(out) == 0,
        )
        return out

    def all_records(self) -> Iterable[WinningSeedRecord]:
        """Iterate every row (intended for tests + debugging)."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "SELECT target_fingerprint_hash, asi, mutant, seed_text, "
                "verdict, confidence, created_at, expires_at "
                "FROM winning_seeds ORDER BY id"
            )
            rows = cur.fetchall()
        for row in rows:
            (
                tfh,
                row_asi,
                mutant,
                seed_text,
                verdict,
                confidence,
                created_at,
                expires_at,
            ) = row
            yield WinningSeedRecord(
                target_fingerprint_hash=tfh,
                asi=row_asi,
                mutant=mutant or "",
                seed_text=seed_text,
                verdict=verdict,
                confidence=float(confidence or 0.0),
                created_at=datetime.fromisoformat(created_at),
                expires_at=datetime.fromisoformat(expires_at),
            )

    def __len__(self) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM winning_seeds")
            (count,) = cur.fetchone()
        return int(count)
