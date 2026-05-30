"""Live-scan registry + on-disk replay for the M12 web dashboard.

The :class:`ScanStore` is the bridge between the running
:class:`~agent_guardian.core.swarm.SwarmCommander` and the FastAPI
dashboard. It serves three jobs:

1. **Register running scans.** When the CLI or library starts a swarm
   that should be visible on the dashboard, it calls
   :meth:`register` with the ``scan_id`` and the
   :class:`SwarmCommander`. The store wires an observer onto the
   commander that enqueues every :class:`SwarmEvent` to a per-scan
   ``asyncio.Queue`` and writes it to ``events.jsonl`` for replay.
2. **Replay finished scans.** When the dashboard loads a scan that
   already finished, the store reads ``scan.json`` from
   ``~/.agentguardian/scans/{id}/`` so the user can browse history.
3. **Stream SSE events.** :meth:`event_queue` returns the per-scan
   queue the SSE endpoint consumes. The queue is drained until a
   ``scan_done`` event arrives, at which point the SSE generator
   closes the response.

The store is single-process; multiple uvicorn workers will not share
state. M12 ships only the single-worker dashboard (``--reload`` or
default uvicorn run), so this is sufficient. A future milestone can
swap the in-memory queue for Redis if multi-worker is needed.

The on-disk layout is::

    ~/.agentguardian/scans/{scan_id}/
        scan.json          # final Scan model_dump_json
        events.jsonl       # one SwarmEvent per line (timestamp ASC)
        report.json        # last-rendered report (per format)
        report.sarif       # …
        report.junit       # …
        report.md          # …

A sibling ``_index.json`` lives at the root of the scans directory and
caches per-scan metadata (id, mtime, aivss, band, findings_count) so
the paginated ``/home`` cold path doesn't deserialise every
``scan.json`` to render a single page.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from agent_guardian.core.swarm import SwarmCommander, SwarmEvent
from agent_guardian.models.scan import Scan

__all__ = [
    "INDEX_FILENAME",
    "MAX_BUFFERED_EVENTS_PER_SCAN",
    "MAX_OPEN_JSONL_HANDLES",
    "ScanStore",
    "ScanSummary",
]

_LOG = logging.getLogger(__name__)


def _resolve_max_buffered_events() -> int:
    """Resolve the per-scan in-memory event buffer cap.

    The default (``5000``) keeps memory bounded for a long-running uvicorn
    process whose dashboard is open to several hundred concurrently active
    scans. Operators who run very long swarms can raise the cap with the
    ``AGENT_GUARDIAN_MAX_BUFFERED_EVENTS`` env var; invalid values fall back
    to the default so a typo can't silently disable bounding.
    """
    raw = os.environ.get("AGENT_GUARDIAN_MAX_BUFFERED_EVENTS")
    if raw is None:
        return 5000
    try:
        value = int(raw)
    except ValueError:
        _LOG.warning(
            "scan_store: ignoring non-integer AGENT_GUARDIAN_MAX_BUFFERED_EVENTS=%r",
            raw,
        )
        return 5000
    if value <= 0:
        _LOG.warning(
            "scan_store: ignoring non-positive AGENT_GUARDIAN_MAX_BUFFERED_EVENTS=%d",
            value,
        )
        return 5000
    return value


# Per-scan cap on the in-memory ring buffer of :class:`SwarmEvent` records.
# events.jsonl on disk remains the authoritative replay source for any
# subscriber that connects after older events have been evicted.
MAX_BUFFERED_EVENTS_PER_SCAN: int = _resolve_max_buffered_events()


# Grace window after ``scan_done`` before the in-memory event buffer is
# dropped. Late SSE subscribers within this window get an in-memory replay;
# subscribers beyond it must read from disk (events.jsonl).
SCAN_DONE_BUFFER_GRACE_SECONDS: float = 300.0


# Cap on the number of simultaneously-open ``events.jsonl`` file handles.
# The store holds one writer per running scan so the observer does not pay
# an open()+close() per event (each open is a syscall round-trip, ~10us on
# Linux). Beyond the cap, the LRU-evicted writer is flushed + closed and
# reopens lazily the next time its scan emits.
MAX_OPEN_JSONL_HANDLES: int = 256


# On-disk index of scan metadata, maintained on register/finalize. The
# /home pagination cold path uses it to render a list of (id, mtime,
# aivss, band) rows without deserialising every scan.json.
INDEX_FILENAME: str = "_index.json"


@dataclass(frozen=True)
class ScanSummary:
    """One row in the dashboard's scan-history list."""

    scan_id: str
    aivss: int | None
    band: str | None
    target_ref: str | None
    target_mode: str | None
    findings_count: int | None
    created_at: datetime | None
    is_running: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "aivss": self.aivss,
            "band": self.band,
            "target_ref": self.target_ref,
            "target_mode": self.target_mode,
            "findings_count": self.findings_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_running": self.is_running,
        }


def _default_root_dir() -> Path:
    return Path.home() / ".agentguardian" / "scans"


class ScanStore:
    """In-memory registry of running scans plus on-disk history reader.

    The store is safe to construct without a running event loop; each
    :class:`asyncio.Queue` is created lazily inside
    :meth:`event_queue` so the lifetime of the loop matches the lifetime
    of the queue.
    """

    def __init__(self, root_dir: Path | None = None) -> None:
        self._root = root_dir or _default_root_dir()
        self._running: dict[str, SwarmCommander] = {}
        self._queues: dict[str, asyncio.Queue[SwarmEvent]] = {}
        # ``_events`` buffers the most recent events per scan so a late SSE
        # subscriber can replay what it missed without re-reading the JSONL
        # file. The buffer is a ring (``deque(maxlen=...)``) so a long-running
        # scan can't push memory unboundedly — old events fall off the front
        # and the on-disk events.jsonl remains the authoritative replay
        # source for any subscriber that needs the full history.
        self._events: dict[str, deque[SwarmEvent]] = {}
        # Tracks the post-``scan_done`` eviction timers so cancellation /
        # re-scheduling works deterministically.
        self._eviction_tasks: dict[str, asyncio.Task[None]] = {}
        # LRU of open events.jsonl writers, capped at MAX_OPEN_JSONL_HANDLES.
        # OrderedDict gives O(1) move-to-end (mark recently used) + O(1)
        # popitem(last=False) (evict LRU). Handles are append-mode text
        # writers; we ``flush()`` after every event so an SSE subscriber
        # racing with a writer always sees committed bytes.
        self._jsonl_files: OrderedDict[str, IO[str]] = OrderedDict()
        # Per-scan wall-clock start so the metrics histogram can record a
        # real duration on scan_done even when the SwarmCommander doesn't
        # surface one (e.g. unit-stub tests).
        self._scan_started_at: dict[str, float] = {}
        # Optional metrics sink (set by the app factory). Decoupled so the
        # store stays usable in library / test mode without /metrics wired.
        self._metrics: Any | None = None

    # ------------------------------------------------------------------
    # Roots / paths
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    def scan_dir(self, scan_id: str) -> Path:
        return self._root / scan_id

    # ------------------------------------------------------------------
    # Registration of live scans
    # ------------------------------------------------------------------

    def register(self, scan_id: str, swarm: SwarmCommander) -> None:
        """Wire a :class:`SwarmCommander` so its events flow to the store.

        Replaces any existing :attr:`SwarmCommander.observer`. Idempotent
        — calling twice with the same ``scan_id`` rewires the observer
        but doesn't reset the existing queue.
        """
        self._running[scan_id] = swarm
        self._events.setdefault(scan_id, deque(maxlen=MAX_BUFFERED_EVENTS_PER_SCAN))
        self._scan_started_at.setdefault(scan_id, time.monotonic())
        if self._metrics is not None:
            try:
                self._metrics.inc_scans_running()
            except Exception:  # pragma: no cover — metrics sink must never raise
                _LOG.exception("scan_store: metrics inc_scans_running failed")
        scan_dir = self.scan_dir(scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        jsonl_path = scan_dir / "events.jsonl"
        # Touch the on-disk index now — the row will be filled in on
        # finalize() with aivss/band/findings_count.
        self._index_upsert(scan_id, is_running=True)

        def _observer(event: SwarmEvent) -> None:
            # Buffer the event in memory. The deque auto-evicts the oldest
            # entry once the buffer hits MAX_BUFFERED_EVENTS_PER_SCAN so a
            # long-running scan can't push the in-memory state unboundedly.
            buffer = self._events.setdefault(scan_id, deque(maxlen=MAX_BUFFERED_EVENTS_PER_SCAN))
            buffer.append(event)
            # Best-effort enqueue to the asyncio queue if it has been
            # materialised (i.e. someone is listening over SSE).
            queue = self._queues.get(scan_id)
            if queue is not None:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    _LOG.warning(
                        "scan_store: SSE queue full for %s — dropping %s event",
                        scan_id,
                        event.kind,
                    )
            # Best-effort append to the on-disk JSONL via a per-scan persistent
            # handle. The handle is opened lazily and cached in the LRU; the
            # legacy open()+close()-per-event path was a measurable bottleneck
            # for chatty scans (~3-5x throughput floor at 1k events/sec).
            try:
                fh = self._get_jsonl_writer(scan_id, jsonl_path)
                fh.write(json.dumps(event_to_payload(event)) + "\n")
                fh.flush()
            except OSError as exc:
                _LOG.warning(
                    "scan_store: events.jsonl append failed for %s (%s)",
                    scan_id,
                    exc,
                )
            # Findings counter — observed on ``agent_done`` (the canonical
            # place a probe surfaces its outcome). Payload contract is
            # best-effort; missing keys are silently ignored so an observer
            # regression elsewhere can't break the metrics path.
            if self._metrics is not None and event.kind == "agent_done":
                payload = event.payload if isinstance(event.payload, dict) else dict(event.payload)
                severity_raw = payload.get("severity")
                if isinstance(severity_raw, str):
                    try:
                        self._metrics.observe_finding(severity_raw)
                    except Exception:  # pragma: no cover
                        _LOG.exception("scan_store: metrics observe_finding failed")
            # On scan_done, drop the running registration so subsequent
            # /scan/{id} reads fall through to the on-disk replay. Schedule
            # the in-memory buffer for eviction after a short grace window so
            # late SSE subscribers have a chance to replay the final events
            # in-memory; once the timer fires, the on-disk events.jsonl is
            # the only replay source (which is the documented contract).
            if event.kind == "scan_done":
                self._running.pop(scan_id, None)
                # Close the per-scan jsonl writer so we don't hold a fd
                # forever after the scan ends.
                self._close_jsonl_writer(scan_id)
                # Wall-clock duration → metrics histogram.
                started = self._scan_started_at.pop(scan_id, None)
                if self._metrics is not None:
                    try:
                        self._metrics.dec_scans_running()
                        if started is not None:
                            self._metrics.observe_scan_complete(time.monotonic() - started)
                    except Exception:  # pragma: no cover
                        _LOG.exception("scan_store: metrics scan_done hooks failed")
                self._schedule_buffer_eviction(scan_id)
                # Refresh the on-disk index so /home pagination sees the
                # finalised row without having to read scan.json.
                self._index_upsert(scan_id, is_running=False)

        # Replace any previously attached observer.
        swarm.observer = _observer

    # ------------------------------------------------------------------
    # Metrics sink wiring
    # ------------------------------------------------------------------

    def set_metrics(self, metrics: Any | None) -> None:
        """Attach (or detach) a metrics sink.

        The sink must expose ``inc_scans_running``, ``dec_scans_running``,
        ``observe_scan_complete(seconds)``, and ``observe_finding(severity)``.
        We deliberately accept a duck-typed ``Any`` so the store does not
        import :mod:`agent_guardian.server.routes.health` (the health route
        already depends on the scan store, and we want to keep the
        dependency one-way).
        """
        self._metrics = metrics

    # ------------------------------------------------------------------
    # Persistent events.jsonl writer cache (LRU-bounded)
    # ------------------------------------------------------------------

    def _get_jsonl_writer(self, scan_id: str, jsonl_path: Path) -> IO[str]:
        """Return the (cached) writer for ``scan_id``, opening lazily."""
        existing = self._jsonl_files.get(scan_id)
        if existing is not None:
            # Mark recently used.
            self._jsonl_files.move_to_end(scan_id)
            return existing
        # Cap-evict the least recently used writer first to keep fd pressure
        # bounded under many concurrent scans.
        while len(self._jsonl_files) >= MAX_OPEN_JSONL_HANDLES:
            evicted_id, evicted_fh = self._jsonl_files.popitem(last=False)
            try:
                evicted_fh.flush()
                evicted_fh.close()
            except OSError as exc:  # pragma: no cover — best-effort close
                _LOG.warning(
                    "scan_store: failed to close events.jsonl handle for %s (%s)",
                    evicted_id,
                    exc,
                )
        fh = jsonl_path.open("a", encoding="utf-8")
        self._jsonl_files[scan_id] = fh
        return fh

    def _close_jsonl_writer(self, scan_id: str) -> None:
        """Flush + close the cached writer for ``scan_id`` (if any)."""
        fh = self._jsonl_files.pop(scan_id, None)
        if fh is None:
            return
        try:
            fh.flush()
            fh.close()
        except OSError as exc:  # pragma: no cover
            _LOG.warning(
                "scan_store: failed to close events.jsonl handle for %s (%s)",
                scan_id,
                exc,
            )

    def close_all(self) -> None:
        """Flush + close every cached writer.

        Called from the app lifespan shutdown hook so we never leave a
        dangling fd behind on a clean uvicorn shutdown.
        """
        while self._jsonl_files:
            scan_id, fh = self._jsonl_files.popitem(last=False)
            try:
                fh.flush()
                fh.close()
            except OSError as exc:  # pragma: no cover
                _LOG.warning(
                    "scan_store: close_all failed to close handle for %s (%s)",
                    scan_id,
                    exc,
                )

    # ------------------------------------------------------------------
    # On-disk index (cheap pagination cold path)
    # ------------------------------------------------------------------

    def _index_path(self) -> Path:
        return self._root / INDEX_FILENAME

    def _index_read(self) -> dict[str, dict[str, Any]]:
        """Read the on-disk index. Missing / malformed → empty dict.

        Returns a mapping ``scan_id -> row`` where each row has keys
        ``scan_id``, ``mtime`` (float, posix seconds), ``aivss``, ``band``,
        ``target_ref``, ``target_mode``, ``findings_count``, ``created_at``
        (ISO string or ``None``).
        """
        path = self._index_path()
        if not path.is_file():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _LOG.warning("scan_store: ignoring malformed index at %s (%s)", path, exc)
            return {}
        if not isinstance(raw, dict):
            return {}
        out: dict[str, dict[str, Any]] = {}
        for sid, row in raw.items():
            if isinstance(sid, str) and isinstance(row, dict):
                out[sid] = row
        return out

    def _index_write(self, index: dict[str, dict[str, Any]]) -> None:
        path = self._index_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic-ish write: tmp + replace so a crash never leaves a
        # truncated index that the next read would silently treat as empty.
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.write_text(json.dumps(index, sort_keys=True), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            _LOG.warning("scan_store: failed to write index at %s (%s)", path, exc)

    def _index_upsert(self, scan_id: str, *, is_running: bool) -> None:
        """Upsert a row in the on-disk index from the freshest source.

        Reads ``scan.json`` (canonical, signed/redacted) or
        ``scan.raw.json`` (model-roundtrippable) when present so the row
        carries the proper aivss/band/findings_count. Falls back to the
        directory mtime when no scan record exists yet (in-flight scans).
        """
        index = self._index_read()
        scan_dir = self.scan_dir(scan_id)
        row: dict[str, Any] = {
            "scan_id": scan_id,
            "mtime": (scan_dir.stat().st_mtime if scan_dir.is_dir() else time.time()),
            "aivss": None,
            "band": None,
            "target_ref": None,
            "target_mode": None,
            "findings_count": None,
            "created_at": None,
            "is_running": is_running,
        }
        scan = self.load_completed(scan_id)
        if scan is not None:
            row.update(
                {
                    "aivss": scan.aivss,
                    "band": scan.band.value,
                    "target_ref": scan.target_ref,
                    "target_mode": scan.target_mode,
                    "findings_count": len(scan.findings),
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                }
            )
        index[scan_id] = row
        self._index_write(index)

    # ------------------------------------------------------------------
    # Paginated listing (cheap cold path)
    # ------------------------------------------------------------------

    def list_scans_page(self, *, offset: int = 0, limit: int = 50) -> tuple[list[ScanSummary], int]:
        """Return ``(page, total_count)`` newest-first.

        The fast path uses :meth:`_index_read` (one file read, no per-scan
        deserialise). When the index is missing we fall back to deserialising
        every ``scan.json`` so we can sort by the canonical ``created_at``
        field. Running scans always lead the page regardless of mtime so the
        user sees in-flight work first.

        Args:
            offset: Zero-based offset into the merged (running + completed)
                list. Negative values are clamped to ``0``.
            limit: Number of rows to return. Values ``< 1`` are clamped to
                ``1``; values above ``500`` are clamped to ``500`` so a
                pathological query can't OOM the renderer.
        """
        offset = max(0, offset)
        limit = max(1, min(limit, 500))

        # Build the running set first — these always lead.
        running_summaries: list[ScanSummary] = []
        for sid in self._running:
            scan = self.load_completed(sid)
            if scan is not None:
                running_summaries.append(
                    ScanSummary(
                        scan_id=sid,
                        aivss=scan.aivss,
                        band=scan.band.value,
                        target_ref=scan.target_ref,
                        target_mode=scan.target_mode,
                        findings_count=len(scan.findings),
                        created_at=scan.created_at,
                        is_running=True,
                    )
                )
            else:
                running_summaries.append(
                    ScanSummary(
                        scan_id=sid,
                        aivss=None,
                        band=None,
                        target_ref=None,
                        target_mode=None,
                        findings_count=None,
                        created_at=None,
                        is_running=True,
                    )
                )

        # Completed-scan rows — prefer the index if present.
        index = self._index_read()
        completed_rows: list[tuple[float, ScanSummary]] = []
        seen_completed: set[str] = set()
        if index:
            for sid, row in index.items():
                if sid in self._running:
                    continue
                created_at_raw = row.get("created_at")
                created_at: datetime | None = None
                if isinstance(created_at_raw, str):
                    try:
                        created_at = datetime.fromisoformat(created_at_raw)
                    except ValueError:
                        created_at = None
                sort_key = (
                    created_at.timestamp()
                    if created_at is not None
                    else float(row.get("mtime") or 0.0)
                )
                completed_rows.append(
                    (
                        sort_key,
                        ScanSummary(
                            scan_id=sid,
                            aivss=row.get("aivss") if isinstance(row.get("aivss"), int) else None,
                            band=row.get("band") if isinstance(row.get("band"), str) else None,
                            target_ref=row.get("target_ref")
                            if isinstance(row.get("target_ref"), str)
                            else None,
                            target_mode=row.get("target_mode")
                            if isinstance(row.get("target_mode"), str)
                            else None,
                            findings_count=row.get("findings_count")
                            if isinstance(row.get("findings_count"), int)
                            else None,
                            created_at=created_at,
                            is_running=False,
                        ),
                    )
                )
                seen_completed.add(sid)
            # Supplement: any on-disk scan that the index doesn't know about
            # (e.g. created before the index existed, or imported from
            # another machine). We still want it visible on /home.
            if self._root.is_dir():
                for child in self._root.iterdir():
                    if not child.is_dir():
                        continue
                    sid = child.name
                    if sid in self._running or sid in seen_completed:
                        continue
                    try:
                        mtime = child.stat().st_mtime
                    except OSError:
                        continue
                    scan = self.load_completed(sid)
                    if scan is not None:
                        completed_rows.append(
                            (
                                scan.created_at.timestamp()
                                if scan.created_at is not None
                                else mtime,
                                ScanSummary(
                                    scan_id=sid,
                                    aivss=scan.aivss,
                                    band=scan.band.value,
                                    target_ref=scan.target_ref,
                                    target_mode=scan.target_mode,
                                    findings_count=len(scan.findings),
                                    created_at=scan.created_at,
                                    is_running=False,
                                ),
                            )
                        )
        elif self._root.is_dir():
            # Cold path (no index): deserialise every scan.json so we can
            # sort by the canonical ``created_at`` field. This is the legacy
            # ``list_scans`` behaviour; the on-disk index path (built by
            # register() and the scan_done observer) avoids it once a single
            # scan has been registered through this process. Deployments
            # large enough to feel this cost should be running with the
            # index — the cold path stays for first-run / DR only.
            for child in self._root.iterdir():
                if not child.is_dir():
                    continue
                if child.name in self._running:
                    continue
                try:
                    mtime = child.stat().st_mtime
                except OSError:
                    continue
                sid = child.name
                scan = self.load_completed(sid)
                if scan is not None:
                    completed_rows.append(
                        (
                            scan.created_at.timestamp() if scan.created_at is not None else mtime,
                            ScanSummary(
                                scan_id=sid,
                                aivss=scan.aivss,
                                band=scan.band.value,
                                target_ref=scan.target_ref,
                                target_mode=scan.target_mode,
                                findings_count=len(scan.findings),
                                created_at=scan.created_at,
                                is_running=False,
                            ),
                        )
                    )
                else:
                    completed_rows.append(
                        (
                            mtime,
                            ScanSummary(
                                scan_id=sid,
                                aivss=None,
                                band=None,
                                target_ref=None,
                                target_mode=None,
                                findings_count=None,
                                created_at=None,
                                is_running=False,
                            ),
                        )
                    )

        completed_rows.sort(key=lambda r: -r[0])
        completed_summaries = [s for (_k, s) in completed_rows]

        all_rows = running_summaries + completed_summaries
        total = len(all_rows)
        page = all_rows[offset : offset + limit]
        return page, total

    async def list_scans_page_async(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[ScanSummary], int]:
        """Async wrapper around :meth:`list_scans_page`.

        Pushes the (potentially fs-heavy) cold-path read into a worker
        thread so the event loop doesn't block on a slow disk during a
        ``/`` render with thousands of scans on record.
        """
        return await asyncio.to_thread(self.list_scans_page, offset=offset, limit=limit)

    def _schedule_buffer_eviction(
        self,
        scan_id: str,
        *,
        grace_seconds: float = SCAN_DONE_BUFFER_GRACE_SECONDS,
    ) -> None:
        """Schedule eviction of ``self._events[scan_id]`` after a grace window.

        If no event loop is running (e.g. tests calling the observer
        synchronously from sync code), evict immediately — the on-disk
        events.jsonl is the source of truth for any late subscriber.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No loop — evict now; preserves the bounded-memory invariant
            # even in synchronous test contexts.
            self._events.pop(scan_id, None)
            return

        async def _evict() -> None:
            try:
                await asyncio.sleep(grace_seconds)
            except asyncio.CancelledError:  # pragma: no cover — shutdown path
                raise
            finally:
                self._events.pop(scan_id, None)
                self._eviction_tasks.pop(scan_id, None)

        # Cancel any previously scheduled eviction so a second scan_done
        # event (shouldn't happen, but defend) doesn't leak a stray task.
        prev = self._eviction_tasks.pop(scan_id, None)
        if prev is not None and not prev.done():
            prev.cancel()
        task = loop.create_task(_evict())
        self._eviction_tasks[scan_id] = task

    def get_running(self, scan_id: str) -> SwarmCommander | None:
        return self._running.get(scan_id)

    def is_running(self, scan_id: str) -> bool:
        return scan_id in self._running

    # ------------------------------------------------------------------
    # SSE plumbing
    # ------------------------------------------------------------------

    def event_queue(self, scan_id: str) -> asyncio.Queue[SwarmEvent]:
        """Return (or create) the per-scan SSE queue.

        Buffered events (those observed before the queue was created)
        are immediately enqueued so a late subscriber sees the full
        history.
        """
        queue = self._queues.get(scan_id)
        if queue is not None:
            return queue
        queue = asyncio.Queue()
        self._queues[scan_id] = queue
        # Replay buffered events.
        for event in list(self._events.get(scan_id, [])):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                _LOG.warning(
                    "scan_store: SSE replay queue full for %s — dropping %s event",
                    scan_id,
                    event.kind,
                )
        return queue

    def replay_events(self, scan_id: str) -> list[SwarmEvent]:
        """Return the buffered events for a scan (in-memory only)."""
        return list(self._events.get(scan_id, []))

    def replay_events_from_disk(self, scan_id: str) -> list[dict[str, Any]]:
        """Replay events from the on-disk ``events.jsonl``.

        Returns the raw payload dicts (as written by the observer). The
        caller is responsible for any deserialisation it needs — for SSE
        we just re-emit the JSON.
        """
        jsonl = self.scan_dir(scan_id) / "events.jsonl"
        if not jsonl.is_file():
            return []
        out: list[dict[str, Any]] = []
        with jsonl.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    _LOG.warning(
                        "scan_store: malformed events.jsonl line %d for scan %s (%s)",
                        line_no,
                        scan_id,
                        exc,
                    )
                    continue
        return out

    # ------------------------------------------------------------------
    # Disk history reads
    # ------------------------------------------------------------------

    def load_completed(self, scan_id: str) -> Scan | None:
        """Read the on-disk scan record. Returns ``None`` if missing.

        Since the hardening work, ``scan.json`` is the canonical *signed +
        redacted* report (a different schema than the ``Scan`` model), and the
        raw, model-roundtrippable dump is persisted alongside as
        ``scan.raw.json``. We load the raw dump first and fall back to the
        legacy single-file layout (where ``scan.json`` *was* the raw model
        dump) so pre-existing on-disk scans still deserialise.
        """
        scan_dir = self.scan_dir(scan_id)
        for name in ("scan.raw.json", "scan.json"):
            path = scan_dir / name
            if not path.is_file():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                # Back-compat shim for pre-72d4deb scans persisted before the
                # ``mode`` field was required. Treat them as ``smart`` with
                # ``mode_authoritative=False`` so the dashboard renders them
                # as legacy results rather than silently claiming they were
                # FULL-mode authoritative scans. We deliberately do NOT add a
                # default on the Scan model itself -- that re-creates the
                # silent-misreporting bug 72d4deb intentionally fixed.
                if isinstance(payload, dict) and "mode" not in payload:
                    payload["mode"] = "smart"
                    payload.setdefault("mode_authoritative", False)
                return Scan.model_validate(payload)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                _LOG.warning(
                    "failed to load scan %s from %s: %s: %s",
                    scan_id,
                    name,
                    type(exc).__name__,
                    exc,
                )
                continue
        return None

    def get_scan(self, scan_id: str) -> Scan | None:
        """Resolve a scan by id — running or completed."""
        return self.load_completed(scan_id)

    def list_scans(self) -> list[ScanSummary]:
        """Return all known scans (running + on-disk), newest first.

        Retained for backwards compatibility; ``list_scans_page`` is the
        preferred entry point. Returns the full page (offset=0, limit=500).
        """
        summaries, _ = self.list_scans_page(offset=0, limit=500)
        return summaries

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def list_report_paths(self, scan_id: str) -> dict[str, Path]:
        """Map known report formats to their on-disk path (if present)."""
        scan_dir = self.scan_dir(scan_id)
        formats = ("json", "sarif", "junit", "md")
        out: dict[str, Path] = {}
        for fmt in formats:
            candidate = scan_dir / f"report.{fmt}"
            if candidate.is_file():
                out[fmt] = candidate
        # The canonical signed/redacted scan.json always counts as a JSON
        # report fall-back when no explicit report.json was written.
        scan_json = scan_dir / "scan.json"
        if "json" not in out and scan_json.is_file():
            out["json"] = scan_json
        return out


def event_to_payload(event: SwarmEvent) -> dict[str, Any]:
    """Serialise a :class:`SwarmEvent` to a JSON-safe dict.

    Used by both the on-disk JSONL writer and the SSE wire format so
    the dashboard sees identical shapes whether it's replaying from
    disk or streaming live.
    """
    return {
        "kind": event.kind,
        "agent": event.agent,
        "asi": event.asi.value if event.asi is not None else None,
        "provisional_aivss": event.provisional_aivss,
        "decision": event.decision.value if event.decision is not None else None,
        "timestamp": event.timestamp.isoformat(),
        "payload": _coerce_payload(event.payload),
    }


def _coerce_payload(payload: Iterable[tuple[str, Any]] | dict[str, Any]) -> dict[str, Any]:
    """Coerce payload values to JSON-safe primitives."""
    items: Iterable[tuple[str, Any]] = payload.items() if isinstance(payload, dict) else payload
    out: dict[str, Any] = {}
    for key, value in items:
        out[key] = _json_safe(value)
    return out


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list | tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return str(value)
