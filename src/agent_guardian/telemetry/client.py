"""Telemetry HTTP client (PostHog Cloud capture).

Posts each anonymous event to PostHog's ``/capture/`` endpoint
(default EU host ``https://eu.i.posthog.com``). The typed event models
are translated to PostHog's capture shape at POST time: ``install_id``
becomes the ``distinct_id``, ``event_type`` becomes the event name, and
the remaining anonymous fields become ``properties``. Failures are
swallowed and the envelope is left in the local buffer for retry.

The client never blocks the user's scan -- every call is fire-and-forget
with a short timeout; if PostHog is unreachable the event is buffered
and we move on. The CLI exit code is never affected.

Telemetry is **on by default** (opt-out). The module-level :func:`emit`
short-circuits *before* importing :mod:`httpx` or touching the buffer
when:

* ``AGENT_GUARDIAN_TELEMETRY`` is set to an opt-out value
  (``off`` / ``0`` / ``false`` / ``no``);
* the consent state on disk is ``OPTED_OUT`` (or legacy ``DEFERRED``);
* no PostHog project key is configured (the client is a graceful no-op
  until a key is baked in / provided via ``AGENT_GUARDIAN_TELEMETRY_KEY``);
* the supplied object is not a known telemetry event model.

A user who has opted out pays zero cost -- no httpx import, no SQLite
write, no DNS lookup, no network call.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from agent_guardian.telemetry.consent import is_opted_in
from agent_guardian.telemetry.events import EventEnvelope
from agent_guardian.telemetry.local import LocalEventBuffer

if TYPE_CHECKING:
    import httpx

__all__ = ["DEFAULT_COLLECTOR_URL", "DEFAULT_POSTHOG_HOST", "TelemetryClient", "emit"]

_LOG = logging.getLogger(__name__)

# PostHog Cloud, EU region (data stays in the EU). Overridable for
# self-host / testing via AGENT_GUARDIAN_TELEMETRY_HOST or a full-URL
# AGENT_GUARDIAN_TELEMETRY_URL override.
DEFAULT_POSTHOG_HOST = "https://eu.i.posthog.com"
DEFAULT_COLLECTOR_URL = f"{DEFAULT_POSTHOG_HOST}/capture/"

# The PostHog *project API key* (``phc_...``) is a PUBLIC, write-only
# ingest key -- safe to ship in the package; that is how PostHog client
# keys are designed. Baked in at release; overridable via
# ``AGENT_GUARDIAN_TELEMETRY_KEY`` for testing / self-host. While empty the
# client is a graceful no-op (nothing is sent), so the package can ship
# before the key is provisioned.
_DEFAULT_POSTHOG_KEY = ""  # TODO(release): set the real PostHog EU project key

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
    override = os.environ.get("AGENT_GUARDIAN_TELEMETRY_URL")
    if override:
        return override
    host = os.environ.get("AGENT_GUARDIAN_TELEMETRY_HOST", DEFAULT_POSTHOG_HOST).rstrip("/")
    return f"{host}/capture/"


def _resolve_project_key() -> str:
    """PostHog project API key from env override, else the baked default."""
    return os.environ.get("AGENT_GUARDIAN_TELEMETRY_KEY", _DEFAULT_POSTHOG_KEY).strip()


def _to_posthog_payload(env: EventEnvelope, project_key: str) -> dict[str, object]:
    """Translate a typed :class:`EventEnvelope` into PostHog's capture shape.

    ``install_id`` -> ``distinct_id`` (the stable anonymous identity),
    ``event_type`` -> the PostHog event name, everything else -> properties.
    No PII is introduced -- the event models are already anonymous and the
    ``model`` field is qualifier-stripped upstream.
    """
    props = env.event.model_dump(mode="json", exclude_none=True)
    distinct_id = props.pop("install_id", "anonymous")
    event_name = props.pop("event_type", "scan_completed")
    return {
        "api_key": project_key,
        "event": event_name,
        "distinct_id": distinct_id,
        "properties": props,
        "timestamp": env.client_sent_at.isoformat(),
    }


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
        self._project_key = _resolve_project_key()

    def emit(self, envelope: EventEnvelope) -> None:
        """Best-effort post. If the network fails, the event is buffered.

        No exception escapes this method -- telemetry must never break
        the user's CLI exit code.
        """
        if _env_opted_out() or not is_opted_in(self._consent_dir):
            _LOG.debug(
                "telemetry: skipping emit, user opted out (event_type=%s)",
                envelope.event.event_type,
            )
            return
        if not self._project_key:
            # No PostHog key configured -- graceful no-op (don't even buffer,
            # there's nowhere to flush to). Activates once a key is provided.
            _LOG.debug("telemetry: skipping emit, no project key configured")
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

        payload = _to_posthog_payload(env, self._project_key)
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

    Accepts any of the concrete event classes. Telemetry is on by default;
    this is a strict no-op -- returning *before* importing :mod:`httpx`,
    touching the local SQLite buffer, or any other side-effecting work --
    when the env-var opt-out is set, the user has opted out, or no PostHog
    project key is configured.
    """
    # Fast path: env-var opt-out takes precedence over everything --
    # not even the type-check below runs, so a user who exports
    # ``AGENT_GUARDIAN_TELEMETRY=off`` pays zero cost.
    if _env_opted_out():
        _LOG.debug("telemetry: emit skipped (%s opt-out)", _ENV_VAR)
        return
    if not is_opted_in():
        _LOG.debug("telemetry: emit skipped (user opted out)")
        return
    if not _resolve_project_key():
        _LOG.debug("telemetry: emit skipped (no project key configured)")
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
    envelope = EventEnvelope(client_sent_at=datetime.now(UTC), event=event)
    TelemetryClient().emit(envelope)
