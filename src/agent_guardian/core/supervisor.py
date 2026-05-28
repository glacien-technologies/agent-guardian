"""Human-in-the-loop supervisor (M2 Pattern 9).

The Swarm Commander owns scheduling and budget; the :class:`Supervisor` is the
single place a human can pause / resume / cancel a running scan. Workers call
:meth:`wait_if_paused` at safe boundaries (turn / checkpoint) and
:meth:`raise_if_cancelled` to bail out cleanly.

Backed by ``asyncio.Event`` so a paused scan blocks waiters without busy-loops,
and a cancel both flips state and releases any paused waiter.
"""

from __future__ import annotations

import asyncio
import logging
from enum import Enum

__all__ = ["ScanCancelled", "Supervisor", "SupervisorState"]

_LOG = logging.getLogger(__name__)


class ScanCancelled(Exception):
    """Raised by :meth:`Supervisor.raise_if_cancelled` after a cancel."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SupervisorState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class Supervisor:
    """Pause / resume / cancel control surface for a running scan."""

    def __init__(self) -> None:
        self._state = SupervisorState.RUNNING
        self._reason: str | None = None
        # "resume" is set while running; cleared while paused so waiters block.
        self._resume = asyncio.Event()
        self._resume.set()
        self._cancelled = asyncio.Event()

    @property
    def state(self) -> SupervisorState:
        return self._state

    @property
    def is_paused(self) -> bool:
        return self._state is SupervisorState.PAUSED

    @property
    def is_cancelled(self) -> bool:
        return self._state is SupervisorState.CANCELLED

    @property
    def cancel_reason(self) -> str | None:
        return self._reason

    def pause(self) -> None:
        if self._state is SupervisorState.CANCELLED:
            return
        if self._state is not SupervisorState.PAUSED:
            self._state = SupervisorState.PAUSED
            # Replace the set event with a fresh cleared one so waiters block.
            self._resume = asyncio.Event()
            _LOG.info("supervisor: scan PAUSED")

    def resume(self) -> None:
        if self._state is SupervisorState.CANCELLED:
            return
        if self._state is SupervisorState.PAUSED:
            self._state = SupervisorState.RUNNING
            self._resume.set()
            _LOG.info("supervisor: scan RESUMED")

    def cancel(self, reason: str = "operator cancelled") -> None:
        self._state = SupervisorState.CANCELLED
        self._reason = reason
        self._cancelled.set()
        # Release any paused waiter so it can observe the cancel and exit.
        self._resume.set()
        _LOG.info("supervisor: scan CANCELLED (%s)", reason)

    async def wait_if_paused(self) -> None:
        """Block while paused; return immediately when running or cancelled."""
        if self._state is SupervisorState.PAUSED:
            await self._resume.wait()

    def raise_if_cancelled(self) -> None:
        """Raise :class:`ScanCancelled` if a cancel has been requested."""
        if self._state is SupervisorState.CANCELLED:
            raise ScanCancelled(self._reason or "cancelled")
