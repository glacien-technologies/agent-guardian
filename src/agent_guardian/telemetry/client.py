"""Collector HTTP client.

Posts telemetry envelopes to ``telemetry.agentguardian.ai/v1/events``
(configurable via ``AGENT_GUARDIAN_TELEMETRY_URL``). Failures are
swallowed and the envelope is left in the local buffer for retry.

The client never blocks the user's scan. Every call is fire-and-forget
async with a short timeout -- if the collector is unreachable, the
event is buffered and we move on. The user's CLI exit code is never
affected by collector state.

Per the v1.0+ launch-audit policy, telemetry is **off by default**.
The module-level :func:`emit` short-circuits on three conditions
*before* importing :mod:`httpx` or touching the local buffer:

* the user has set ``AGENT_GUARDIAN_TELEMETRY`` to an opt-out value
  (``off`` / ``0`` / ``false`` / ``no``);
* the consent state on disk is anything but a positive tier
  (``ESSENTIAL`` / ``EXTENDED`` / legacy ``OPTED_IN``);
* the supplied object is not a known telemetry event model.

A user who has not consented therefore pays zero cost (no httpx
import, no SQLite write, no DNS lookup, no network call) -- which is
also what the audit asserts in test_no_post_on_clean_home.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from agent_guardian.telemetry.consent import is_opted_in
from agent_guardian.telemetry.events import EventEnvelope
from agent_guardian.telemetry.local import LocalEventBuffer

if TYPE_CHECKING:
    import httpx

__all__ = ["DEFAULT_COLLECTOR_URL", "TelemetryClient", "emit"]

_LOG = logging.getLogger(__name__)

DEFAULT_COLLECTOR_URL = "https://telemetry.agentguardian.ai/v1/events"

# Env-var opt-out values. Kept in sync with prompt._ENV_OFF -- duplicated
# here so the emit() fast-path does not need to import the prompt
# module (which would pull in typer just to read a string set).
_ENV_VAR = "AGENT_GUARDIAN_TELEMETRY"
_ENV_OFF_VALUES: frozenset[str] = frozenset({"off", "0", "false", "no"})


def _env_opted_out() -> bool:
    """True iff ``AGENT_GUARDIAN_TELEMETRY`` is set to an opt-out value."""
    raw = os.environ.get(_ENV_VAR)
    if raw is None:
        return False
    return raw.strip().lower() in _ENV_OFF_VALUES


def _resolve_collector_url() -> str:
    return os.environ.get("AGENT_GUARDIAN_TELEMETRY_URL", DEFAULT_COLLECTOR_URL)


class TelemetryClient:
    """Synchronous HTTP poster + local buffer.

    The client is sync because telemetry emission happens at the very
    end of a CLI invocation -- there's no event loop to schedule onto
    and adding one for a single fire-and-forget POST adds latency.
    """

    def __init__(
        self,
        *,
        collector_url: str | None = None,
        timeout_seconds: float = 2.0,
        buffer: LocalEventBuffer | None = None,
        consent_dir: Path | None = None,
    ) -> None:
        self._url = collector_url if collector_url is not None else _resolve_collector_url()
        self._timeout = timeout_seconds
        self._buffer = buffer if buffer is not None else LocalEventBuffer()
        self._consent_dir = consent_dir

    def emit(self, envelope: EventEnvelope) -> None:
        """Best-effort post. If the network fails, the event is buffered.

        No exception escapes this method -- telemetry must never break
        the user's CLI exit code.
        """
        if _env_opted_out() or not is_opted_in(self._consent_dir):
            _LOG.debug(
                "telemetry: skipping emit, user not opted in (event_type=%s)",
                envelope.event.event_type,
            )
            return
        try:
            row_id = self._buffer.enqueue(envelope)
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.warning(
                "telemetry: failed to enqueue (%s: %s) -- dropping event silently",
                type(exc).__name__,
                exc,
            )
            return
        # Try to flush this envelope (and any prior pending ones) now.
        self._try_flush(max_envelopes=10, primary_row_id=row_id)

    def flush(self, *, max_envelopes: int = 100) -> int:
        """Drain pending envelopes. Returns the number successfully sent."""
        return self._try_flush(max_envelopes=max_envelopes)

    def _try_flush(self, *, max_envelopes: int, primary_row_id: int | None = None) -> int:
        pending = self._buffer.pending(limit=max_envelopes)
        if not pending:
            return 0
        # Local import keeps httpx out of the cold-path of a user who
        # has never opted in -- emit() short-circuits long before this.
        import httpx

        sent = 0
        try:
            with httpx.Client(timeout=self._timeout) as client:
                for row_id, env in pending:
                    if self._post_one(client, row_id, env):
                        sent += 1
                    else:
                        # Don't fight further on the first failure of this batch --
                        # network is probably down, retry on next emit.
                        break
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.debug(
                "telemetry: flush aborted (%s: %s) -- events remain buffered",
                type(exc).__name__,
                exc,
            )
        _LOG.debug(
            "telemetry: flushed %d/%d envelopes (primary_row=%s)",
            sent,
            len(pending),
            primary_row_id,
        )
        return sent

    def _post_one(self, client: httpx.Client, row_id: int, env: EventEnvelope) -> bool:
        import httpx

        payload = env.model_dump(mode="json")
        try:
            resp = client.post(self._url, json=payload)
        except httpx.RequestError as exc:
            self._buffer.mark_attempt_failed(row_id, f"{type(exc).__name__}: {exc}")
            return False
        if resp.status_code >= 400:
            self._buffer.mark_attempt_failed(row_id, f"HTTP {resp.status_code}: {resp.text[:120]}")
            # 4xx is permanent (schema mismatch or rejection) -- drop after 3 attempts.
            if 400 <= resp.status_code < 500:
                self._buffer._drop_row(row_id)
                _LOG.warning(
                    "telemetry: dropping envelope row=%d after permanent 4xx (status=%d)",
                    row_id,
                    resp.status_code,
                )
            return False
        self._buffer.mark_sent(row_id)
        return True


def emit(event: object) -> None:
    """Module-level convenience: wrap an event in an envelope and emit.

    Accepts any of the concrete event classes. No-op if the user has
    not positively consented, and a strict no-op if the env-var
    opt-out is set -- in that case we return *before* importing
    :mod:`httpx`, touching the local SQLite buffer, or doing any
    other side-effecting work.
    """
    # Fast path: env-var opt-out takes precedence over everything --
    # not even the type-check below runs, so a user who exports
    # ``AGENT_GUARDIAN_TELEMETRY=off`` pays zero cost.
    if _env_opted_out():
        _LOG.debug("telemetry: emit skipped (%s opt-out)", _ENV_VAR)
        return
    if not is_opted_in():
        _LOG.debug("telemetry: emit skipped (no positive consent on file)")
        return

    from agent_guardian.telemetry.events import (
        ForgetEvent,
        InstallEvent,
        ProbeFireEvent,
        ScanCompletedEvent,
    )

    if not isinstance(event, (ScanCompletedEvent, InstallEvent, ProbeFireEvent, ForgetEvent)):
        raise TypeError(
            f"telemetry.emit: expected a telemetry event model, got {type(event).__name__}"
        )
    envelope = EventEnvelope(client_sent_at=datetime.now(timezone.utc), event=event)
    TelemetryClient().emit(envelope)
