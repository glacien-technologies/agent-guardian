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
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_guardian.core.swarm import SwarmCommander, SwarmEvent
from agent_guardian.models.scan import Scan

__all__ = ["ScanStore", "ScanSummary"]

_LOG = logging.getLogger(__name__)


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
        # ``_events`` buffers every event so a late SSE subscriber can
        # replay what it missed without re-reading the JSONL file. M12
        # keeps this trivial; an LRU bound is a future refinement.
        self._events: dict[str, list[SwarmEvent]] = {}

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
        self._events.setdefault(scan_id, [])
        scan_dir = self.scan_dir(scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        jsonl_path = scan_dir / "events.jsonl"

        def _observer(event: SwarmEvent) -> None:
            # Buffer the event in memory.
            self._events.setdefault(scan_id, []).append(event)
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
            # Best-effort append to the on-disk JSONL.
            try:
                with jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event_to_payload(event)) + "\n")
            except OSError as exc:
                _LOG.warning(
                    "scan_store: events.jsonl append failed for %s (%s)",
                    scan_id,
                    exc,
                )
            # On scan_done, drop the running registration so subsequent
            # /scan/{id} reads fall through to the on-disk replay.
            if event.kind == "scan_done":
                self._running.pop(scan_id, None)

        # Replace any previously attached observer.
        swarm.observer = _observer

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

        Running scans are listed first; completed scans are sorted by
        ``created_at`` descending.
        """
        summaries: dict[str, ScanSummary] = {}
        # First: completed scans on disk.
        if self._root.is_dir():
            for child in self._root.iterdir():
                if not child.is_dir():
                    continue
                scan_id = child.name
                scan = self.load_completed(scan_id)
                if scan is not None:
                    summaries[scan_id] = ScanSummary(
                        scan_id=scan_id,
                        aivss=scan.aivss,
                        band=scan.band.value,
                        target_ref=scan.target_ref,
                        target_mode=scan.target_mode,
                        findings_count=len(scan.findings),
                        created_at=scan.created_at,
                        is_running=False,
                    )
                else:
                    # No scan.json yet — could be an in-flight scan whose
                    # finalisation hasn't run. Surface a minimal row.
                    summaries[scan_id] = ScanSummary(
                        scan_id=scan_id,
                        aivss=None,
                        band=None,
                        target_ref=None,
                        target_mode=None,
                        findings_count=None,
                        created_at=None,
                        is_running=False,
                    )
        # Overlay: running scans (override completed flag).
        for scan_id in self._running:
            existing = summaries.get(scan_id)
            if existing is not None:
                summaries[scan_id] = ScanSummary(
                    scan_id=existing.scan_id,
                    aivss=existing.aivss,
                    band=existing.band,
                    target_ref=existing.target_ref,
                    target_mode=existing.target_mode,
                    findings_count=existing.findings_count,
                    created_at=existing.created_at,
                    is_running=True,
                )
            else:
                summaries[scan_id] = ScanSummary(
                    scan_id=scan_id,
                    aivss=None,
                    band=None,
                    target_ref=None,
                    target_mode=None,
                    findings_count=None,
                    created_at=None,
                    is_running=True,
                )

        ordered = sorted(
            summaries.values(),
            key=lambda s: (
                0 if s.is_running else 1,
                # Newer first; missing timestamp sorts last.
                -(s.created_at.timestamp() if s.created_at else 0.0),
            ),
        )
        return ordered

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
