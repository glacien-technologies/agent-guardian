"""Telemetry consent state machine.

State is persisted at ``~/.agentguardian/consent.json`` as a small
JSON document:

    {
      "state": "opted_in" | "opted_out" | "deferred" | "not_prompted",
      "decided_at": "2026-05-27T15:04:23Z" | null,
      "version": 1
    }

The default state when the file does not exist is ``NOT_PROMPTED``.
The first-run prompt (see :mod:`agent_guardian.telemetry.prompt`) is
what transitions ``NOT_PROMPTED`` → one of the three decided states.

Once decided, the state is sticky -- the prompt never re-fires unless
the user explicitly runs ``agent-guardian telemetry reset``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

__all__ = [
    "ConsentState",
    "consent_level",
    "consent_path",
    "default_consent_dir",
    "get_consent",
    "has_been_notified",
    "has_been_prompted",  # legacy alias of has_been_notified
    "is_extended",
    "is_opted_in",
    "set_consent",
]

_LOG = logging.getLogger(__name__)
_SCHEMA_VERSION = 1


class ConsentState(str, Enum):
    """Five states covering the essential/extended/off tiering.

    Default policy (v1.0+): we ship with **essential operational
    telemetry on by default** -- only aggregate counts (number of
    agents, attempts, findings, AIVSS) that cannot identify the
    user, their machine, or their code. The first scan emits a
    one-line notice; from then on the user can downgrade
    (``telemetry disable``) or upgrade (``telemetry extended``).

    States:

    * ``NOT_PROMPTED`` -- fresh install, no notice shown yet. Treated
      as ESSENTIAL by all read paths (telemetry fires) but the
      first-scan notice will print and transition to ESSENTIAL.
    * ``ESSENTIAL`` -- basic counts only. The default after first scan.
    * ``EXTENDED`` -- counts + environment fingerprint (adapter,
      Python version, OS, arch). Explicit upgrade.
    * ``OPTED_OUT`` -- nothing sent ever. Explicit opt-out.
    * ``DEFERRED`` -- legacy state from the v1.0rc1 opt-in flow;
      kept for backwards-compat reading of old consent.json files.
      Treated as ESSENTIAL by read paths.

    The semantic check for "should we send any telemetry?" is
    :func:`is_opted_in`. For the fine-grained "may we include
    environment fields?" check use :func:`is_extended`.
    """

    NOT_PROMPTED = "not_prompted"  # initial state
    ESSENTIAL = "essential"  # default-on operational metrics
    EXTENDED = "extended"  # essential + environment fingerprint
    OPTED_OUT = "opted_out"  # nothing collected
    DEFERRED = "deferred"  # legacy -- treat as ESSENTIAL

    # Backwards-compat: the v1.0rc1 OPTED_IN state maps to EXTENDED
    # under the new policy (rc1 users explicitly accepted environment
    # fields when they said yes to the opt-in prompt).
    OPTED_IN = "opted_in"


def default_consent_dir() -> Path:
    """Resolve the consent directory. Honours ``AGENT_GUARDIAN_HOME`` for tests."""
    import os

    override = os.environ.get("AGENT_GUARDIAN_HOME")
    if override:
        return Path(override)
    return Path.home() / ".agentguardian"


def consent_path(consent_dir: Path | None = None) -> Path:
    base = consent_dir if consent_dir is not None else default_consent_dir()
    return base / "consent.json"


def get_consent(consent_dir: Path | None = None) -> ConsentState:
    """Read the current consent state. Defaults to ``NOT_PROMPTED`` if missing or corrupt."""
    path = consent_path(consent_dir)
    if not path.is_file():
        return ConsentState.NOT_PROMPTED
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning(
            "telemetry consent: failed to read %s (%s: %s) -- treating as NOT_PROMPTED",
            path,
            type(exc).__name__,
            exc,
        )
        return ConsentState.NOT_PROMPTED
    raw_state = payload.get("state")
    if not isinstance(raw_state, str):
        _LOG.warning("telemetry consent: bad state field %r -- treating as NOT_PROMPTED", raw_state)
        return ConsentState.NOT_PROMPTED
    try:
        return ConsentState(raw_state)
    except ValueError:
        _LOG.warning(
            "telemetry consent: unknown state %r -- treating as NOT_PROMPTED (was a future schema?)",
            raw_state,
        )
        return ConsentState.NOT_PROMPTED


def set_consent(state: ConsentState, *, consent_dir: Path | None = None) -> None:
    """Persist a new consent state. Atomic: write to .tmp then rename."""
    base = consent_dir if consent_dir is not None else default_consent_dir()
    base.mkdir(parents=True, exist_ok=True)
    path = consent_path(base)
    tmp = path.with_suffix(".json.tmp")

    payload: dict[str, Any] = {
        "state": state.value,
        "decided_at": (
            datetime.now(tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            if state is not ConsentState.NOT_PROMPTED
            else None
        ),
        "version": _SCHEMA_VERSION,
    }
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    _LOG.info("telemetry consent: state set to %s (persisted at %s)", state.value, path)


def is_opted_in(consent_dir: Path | None = None) -> bool:
    """True iff ANY telemetry tier is active (ESSENTIAL or EXTENDED).

    Note the v1.0+ default: a fresh install with NO consent decision
    yet (``NOT_PROMPTED``) is treated as ESSENTIAL -- telemetry fires.
    The user opts OUT, not in. ``OPTED_OUT`` is the only state that
    returns False.
    """
    state = get_consent(consent_dir)
    return state is not ConsentState.OPTED_OUT


def is_extended(consent_dir: Path | None = None) -> bool:
    """True iff the EXTENDED tier is active -- environment fingerprint
    (adapter, Python version, OS, arch) may be included in events."""
    state = get_consent(consent_dir)
    return state in (ConsentState.EXTENDED, ConsentState.OPTED_IN)


def consent_level(consent_dir: Path | None = None) -> str:
    """Return ``"off"`` / ``"essential"`` / ``"extended"`` -- the
    three semantic tiers the telemetry client cares about."""
    state = get_consent(consent_dir)
    if state is ConsentState.OPTED_OUT:
        return "off"
    if state in (ConsentState.EXTENDED, ConsentState.OPTED_IN):
        return "extended"
    # NOT_PROMPTED / ESSENTIAL / DEFERRED all map to essential.
    return "essential"


def has_been_notified(consent_dir: Path | None = None) -> bool:
    """True iff the user has seen the first-scan notice.

    Replaces the old ``has_been_prompted``. The notice runs once per
    NOT_PROMPTED state; after it shows, state transitions to
    ESSENTIAL (or the user's existing choice) and the notice never
    re-fires.
    """
    state = get_consent(consent_dir)
    return state is not ConsentState.NOT_PROMPTED


# Legacy alias -- old code may still call has_been_prompted().
has_been_prompted = has_been_notified
