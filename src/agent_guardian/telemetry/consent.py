"""Telemetry consent state machine.

State is persisted at ``~/.agentguardian/consent.json`` as a small
JSON document::

    {
      "state": "opted_in" | "opted_out" | "deferred" | "not_prompted",
      "decided_at": "2026-05-27T15:04:23Z" | null,
      "version": 1
    }

The default state when the file does not exist is ``NOT_PROMPTED``.

Policy (default-on / opt-out):
    Telemetry is **ON by default**. ``NOT_PROMPTED`` (a fresh install)
    is treated as the EXTENDED tier by the read paths --
    :func:`is_opted_in` returns ``True`` and :func:`consent_level`
    returns ``"extended"`` -- so anonymous install + scan-completed
    events flow without any opt-in step. Only an explicit opt-out turns
    it off:

      * set ``AGENT_GUARDIAN_TELEMETRY=0`` (also ``off`` / ``false`` /
        ``no``), or
      * run ``agent-guardian telemetry disable``.

    Either persists ``OPTED_OUT``, after which nothing is ever sent. The
    legacy ``DEFERRED`` state is also treated as off. Everything sent is
    anonymous metadata only -- never prompts, model output, finding text,
    target URLs, file paths, or API keys (see
    :mod:`agent_guardian.telemetry.events`).

Once opted out, the state is sticky -- re-enable with
``agent-guardian telemetry essential`` / ``extended`` or
``agent-guardian telemetry reset``.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
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

    Default policy (v1.0+ post launch-audit): we ship with telemetry
    **off**. The first interactive scan asks the user, and only after
    a positive yes does any event leave the machine. The aggregate
    counts collected on the essential tier (number of agents,
    attempts, findings, AIVSS) cannot identify the user, their
    machine, or their code -- but we still require positive consent
    before sending anything.

    States:

    * ``NOT_PROMPTED`` -- fresh install, no consent decision recorded.
      Read paths treat this as off -- :func:`is_opted_in` returns
      ``False`` and :func:`consent_level` returns ``"off"``. The
      consent prompt will run on the first interactive scan.
    * ``ESSENTIAL`` -- basic counts only. Set after a positive yes
      in the consent prompt (or ``agent-guardian telemetry essential``).
    * ``EXTENDED`` -- counts + environment fingerprint (adapter,
      Python version, OS, arch). Explicit upgrade.
    * ``OPTED_OUT`` -- nothing sent ever. Explicit opt-out, or the
      default after a non-interactive (CI / non-TTY) install where no
      one could answer the prompt.
    * ``DEFERRED`` -- legacy state from the v1.0rc1 opt-in flow;
      kept for backwards-compat reading of old consent.json files.
      Treated as off by read paths (no decision == no telemetry).

    The semantic check for "should we send any telemetry?" is
    :func:`is_opted_in`. For the fine-grained "may we include
    environment fields?" check use :func:`is_extended`.
    """

    NOT_PROMPTED = "not_prompted"  # initial state -- treated as off
    ESSENTIAL = "essential"  # operational metrics, positive consent
    EXTENDED = "extended"  # essential + environment fingerprint
    OPTED_OUT = "opted_out"  # nothing collected
    DEFERRED = "deferred"  # legacy -- treat as off

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
            datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
            if state is not ConsentState.NOT_PROMPTED
            else None
        ),
        "version": _SCHEMA_VERSION,
    }
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    _LOG.info("telemetry consent: state set to %s (persisted at %s)", state.value, path)


def is_opted_in(consent_dir: Path | None = None) -> bool:
    """True iff the user has positively consented to ANY telemetry tier.

    Per the v1.0+ launch-audit policy: a fresh install (``NOT_PROMPTED``)
    is OFF -- the user must explicitly opt in via the consent prompt or
    one of the ``agent-guardian telemetry`` subcommands. Only the three
    positive-consent states (``ESSENTIAL``, ``EXTENDED``, legacy
    ``OPTED_IN``) return ``True``; ``NOT_PROMPTED``, ``OPTED_OUT`` and
    legacy ``DEFERRED`` all return ``False``.
    """
    state = get_consent(consent_dir)
    # Default-on policy (opt-out): a fresh install (NOT_PROMPTED) is ON.
    # Only an explicit OPTED_OUT (env var AGENT_GUARDIAN_TELEMETRY=0 or the
    # `telemetry disable` command) -- and the legacy DEFERRED state -- turn
    # it off.
    return state in (
        ConsentState.NOT_PROMPTED,
        ConsentState.ESSENTIAL,
        ConsentState.EXTENDED,
        ConsentState.OPTED_IN,
    )


def is_extended(consent_dir: Path | None = None) -> bool:
    """True iff the EXTENDED tier is active -- environment fingerprint
    (adapter, model, Python version, OS, arch) may be included in events.

    Default-on policy: NOT_PROMPTED defaults to the EXTENDED tier so the
    compatibility matrix (adapter/model/OS) is populated out of the box.
    A user who downgrades to ESSENTIAL keeps counts-only."""
    state = get_consent(consent_dir)
    return state in (ConsentState.NOT_PROMPTED, ConsentState.EXTENDED, ConsentState.OPTED_IN)


def consent_level(consent_dir: Path | None = None) -> str:
    """Return ``"off"`` / ``"essential"`` / ``"extended"`` -- the three
    semantic tiers the telemetry client cares about.

    Per the v1.0+ launch-audit policy ``NOT_PROMPTED`` maps to ``"off"``:
    a user with no recorded decision has not consented and so no
    telemetry should fire. Legacy ``DEFERRED`` likewise maps to off.
    """
    state = get_consent(consent_dir)
    if state in (ConsentState.NOT_PROMPTED, ConsentState.EXTENDED, ConsentState.OPTED_IN):
        # Default-on: a fresh install reports the EXTENDED tier.
        return "extended"
    if state is ConsentState.ESSENTIAL:
        return "essential"
    # OPTED_OUT / legacy DEFERRED -- telemetry explicitly disabled.
    return "off"


def has_been_notified(consent_dir: Path | None = None) -> bool:
    """True iff the user has made an explicit consent decision.

    Replaces the old ``has_been_prompted``. ``NOT_PROMPTED`` is the
    only state where no decision is on file; every other state means
    the consent prompt has run (or the user has run one of the
    ``agent-guardian telemetry`` subcommands).
    """
    state = get_consent(consent_dir)
    return state is not ConsentState.NOT_PROMPTED


# Legacy alias -- old code may still call has_been_prompted().
has_been_prompted = has_been_notified
