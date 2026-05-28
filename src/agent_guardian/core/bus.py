"""In-process bundle bus (M2 Pattern 9).

A single ``asyncio.Queue`` the Commander publishes scan events / finding bundles
onto, plus an append-only JSONL replay log so a crashed or paused scan can be
reconstructed. Consumers (dashboards, the bundle writer) read from the queue;
the replay log is the durable record.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["BundleBus", "BusEvent"]

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class BusEvent:
    """One event on the bundle bus."""

    kind: str
    timestamp: float = field(default_factory=time.monotonic)
    payload: dict[str, Any] = field(default_factory=dict)


class BundleBus:
    """asyncio.Queue + append-only JSONL replay log."""

    def __init__(self, *, jsonl_path: Path | None = None, maxsize: int = 0) -> None:
        self._queue: asyncio.Queue[BusEvent] = asyncio.Queue(maxsize=maxsize)
        self._replay: list[BusEvent] = []
        self._jsonl_path = jsonl_path

    async def publish(self, event: BusEvent) -> None:
        self._replay.append(event)
        self._write_jsonl(event)
        await self._queue.put(event)

    def publish_nowait(self, event: BusEvent) -> None:
        """Non-blocking publish (drops onto the replay log even if the queue is full)."""
        self._replay.append(event)
        self._write_jsonl(event)
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:  # pragma: no cover — only when a bounded queue saturates
            _LOG.warning("bundle bus: queue full, event %s kept in replay only", event.kind)

    async def get(self) -> BusEvent:
        return await self._queue.get()

    def replay(self) -> list[BusEvent]:
        return list(self._replay)

    def empty(self) -> bool:
        return self._queue.empty()

    def _write_jsonl(self, event: BusEvent) -> None:
        if self._jsonl_path is None:
            return
        try:
            self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with self._jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {"ts": event.timestamp, "kind": event.kind, "payload": event.payload}
                    )
                    + "\n"
                )
        except OSError as exc:  # pragma: no cover — defensive; the bus must not crash a scan
            _LOG.warning("bundle bus: failed to append to %s (%s)", self._jsonl_path, exc)
