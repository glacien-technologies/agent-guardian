"""First-scan telemetry consent prompt + tier-upgrade flow.

Policy (v1.0+, post launch-readiness audit): telemetry is **off by
default**. The first interactive scan on a fresh install asks the user
whether to share anonymous operational counts. Until they answer yes,
no event leaves the machine. The legacy "on by default + one-line
notice" flow has been retired -- positive consent is now required.

Resolution order in :func:`maybe_prompt_consent`:

1. State is already decided (anything other than ``NOT_PROMPTED``):
   noop.
2. The environment variable ``AGENT_GUARDIAN_TELEMETRY`` is set: its
   value is treated as the user's answer (``off`` / ``0`` / ``false`` /
   ``no`` -> ``OPTED_OUT``; ``essential`` / ``on`` / ``1`` / ``true`` /
   ``yes`` -> ``ESSENTIAL``; ``extended`` -> ``EXTENDED``). A short
   one-line note prints to stderr so the user can see what was applied.
3. The run is non-interactive (no TTY on stdin, or one of the standard
   CI environment variables is set): persist ``OPTED_OUT`` (the safe
   default in CI -- nobody can answer a prompt) and print a one-line
   stderr notice explaining how to enable it later.
4. Otherwise: ask via :func:`typer.confirm` with ``default=False``.
   ``yes`` -> ``ESSENTIAL`` plus a one-time :class:`InstallEvent`; any
   other answer -> ``OPTED_OUT``.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
from datetime import datetime, timezone
from typing import Literal, cast

import typer

from agent_guardian._version import __version__
from agent_guardian.telemetry.consent import (
    ConsentState,
    get_consent,
    set_consent,
)
from agent_guardian.telemetry.events import InstallEvent
from agent_guardian.telemetry.install_id import get_install_id

__all__ = [
    "CONSENT_PROMPT_QUESTION",
    "FIRST_SCAN_NOTICE",
    "PROMPT_TEXT",
    "maybe_prompt_consent",
    "maybe_prompt_first_run",
    "maybe_show_first_scan_notice",
]

_LOG = logging.getLogger(__name__)


# Environment-variable answer set. Lowercased for case-insensitive match.
_ENV_VAR = "AGENT_GUARDIAN_TELEMETRY"
_ENV_OFF: frozenset[str] = frozenset({"off", "0", "false", "no"})
_ENV_ESSENTIAL: frozenset[str] = frozenset({"essential", "on", "1", "true", "yes"})
_ENV_EXTENDED: frozenset[str] = frozenset({"extended"})

# Standard CI markers -- enough of a signal that the run is unattended
# that we should not block on a confirm prompt. Keep this list small
# and well-known; anything obscure can still set AGENT_GUARDIAN_TELEMETRY
# explicitly.
_CI_ENV_VARS: tuple[str, ...] = (
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "JENKINS_HOME",
    "TF_BUILD",  # Azure DevOps
)


CONSENT_PROMPT_QUESTION = "Share anonymous operational counts?"
"""The exact question shown by :func:`typer.confirm`. Kept as a
module-level constant so tests can assert the wording (it's part of
the user-facing UX contract)."""


FIRST_SCAN_NOTICE = """
  AgentGuardian -- telemetry is OFF.
  To share anonymous operational counts (agents, attempts, findings,
  AIVSS) run:  agent-guardian telemetry essential
"""
"""Legacy export kept so external callers that imported the symbol
still resolve. The new flow does not print this banner on every scan;
:func:`maybe_prompt_consent` prints a short one-line stderr message
instead. The string is retained for ``agent-guardian telemetry show``
back-compat."""


PROMPT_TEXT = """
AgentGuardian -- what telemetry collects
═══════════════════════════════════════════════
Default state: OFF. Telemetry only fires after positive consent
(via the first-scan prompt or `agent-guardian telemetry essential`).

What gets sent on the ESSENTIAL tier (after positive consent):

  • install_id      anonymous UUID4 generated locally
  • scan_id         anonymous random per-scan ID
  • aivss, band, tier        the security score + its bucket
  • duration_seconds         how long the scan took
  • terminated_by   success / error / crash (drives crash-free rate)
  • agents_count    number of swarm agents that ran
  • attempts_count  total per-turn judged events across all agents
  • successes_count attempts where the target defended (target_pass)
  • findings_total + severity counts (the "threats captured" numbers)
  • agent_version   to attribute crashes to a specific release

What gets sent ONLY on the EXTENDED tier (opt-in via
`agent-guardian telemetry extended`):

  • adapter         which agent framework (langgraph / adk / crewai / …)
  • target_mode     prompt / code / http / framework
  • python_version  e.g. "3.11"
  • os_family       Linux / Darwin / Windows
  • arch            x86_64 / arm64

What we NEVER send:
  prompts · model output · finding text · file paths · hostnames ·
  IP addresses · env vars · API keys · usernames · GitHub handles.

Schema source:
  https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/telemetry/events.py
Aggregates published at:
  https://agentguardian.ai/analytics  (k>=50 enforced on every cell)
"""


def _is_non_interactive() -> bool:
    """Return ``True`` if no human is available to answer a prompt.

    We treat a missing or non-tty stdin as non-interactive, plus any of
    the well-known CI environment markers. The check is conservative --
    if in doubt we treat as non-interactive and default to ``OPTED_OUT``
    rather than block a scan waiting for input nobody can give.
    """
    for var in _CI_ENV_VARS:
        if os.environ.get(var):
            return True
    stdin = sys.stdin
    if stdin is None:
        return True
    try:
        return not stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return True


def _env_decision() -> ConsentState | None:
    """Read ``AGENT_GUARDIAN_TELEMETRY`` and map to a consent state.

    Returns ``None`` when the env var is unset or holds an unknown
    value (so the caller falls through to the interactive prompt).
    """
    raw = os.environ.get(_ENV_VAR)
    if raw is None:
        return None
    value = raw.strip().lower()
    if not value:
        return None
    if value in _ENV_OFF:
        return ConsentState.OPTED_OUT
    if value in _ENV_ESSENTIAL:
        return ConsentState.ESSENTIAL
    if value in _ENV_EXTENDED:
        return ConsentState.EXTENDED
    _LOG.warning(
        "telemetry: ignoring unknown %s=%r value; falling back to interactive prompt",
        _ENV_VAR,
        raw,
    )
    return None


def maybe_prompt_consent(*, force: bool = False) -> ConsentState:
    """Ask the user once whether to enable telemetry, then persist.

    Telemetry is off by default. This function is the single entry
    point that can transition ``NOT_PROMPTED`` to a decided state. It
    is safe to call multiple times -- once a decision is on file the
    function is a noop and returns the existing state.

    Args:
        force: if ``True``, re-run even when the state is already
            decided. Used by ``agent-guardian telemetry reset`` after
            it wipes consent back to ``NOT_PROMPTED``.

    Returns the resolved :class:`ConsentState`. An :class:`InstallEvent`
    is emitted only when the user (or env var) selects a positive
    consent tier; ``OPTED_OUT`` never causes a network call.
    """
    current = get_consent()
    if current is not ConsentState.NOT_PROMPTED and not force:
        return current

    env_state = _env_decision()
    if env_state is not None:
        set_consent(env_state)
        if env_state is ConsentState.OPTED_OUT:
            print(
                f"AgentGuardian telemetry: disabled via {_ENV_VAR}. "
                "Enable later with `agent-guardian telemetry essential`.",
                file=sys.stderr,
            )
        else:
            print(
                f"AgentGuardian telemetry: {env_state.value} via {_ENV_VAR}. "
                "Disable with `agent-guardian telemetry disable`.",
                file=sys.stderr,
            )
            _emit_install_event()
        return env_state

    if _is_non_interactive():
        set_consent(ConsentState.OPTED_OUT)
        print(
            "AgentGuardian telemetry: off (no interactive terminal). "
            "Enable later with `agent-guardian telemetry essential`.",
            file=sys.stderr,
        )
        return ConsentState.OPTED_OUT

    try:
        accepted = typer.confirm(CONSENT_PROMPT_QUESTION, default=False)
    except (typer.Abort, EOFError, KeyboardInterrupt):
        accepted = False
    if accepted:
        set_consent(ConsentState.ESSENTIAL)
        _emit_install_event()
        return ConsentState.ESSENTIAL
    set_consent(ConsentState.OPTED_OUT)
    return ConsentState.OPTED_OUT


def _emit_install_event() -> None:
    """Fire the one-time install event after the user opts in.

    Even on the essential tier we send the :class:`InstallEvent` so the
    collector can derive MAU correctly. The :class:`InstallEvent`
    deliberately omits environment fields when consent_level is
    essential -- handled by the same :func:`is_extended` check in the
    swarm emission path.
    """
    from agent_guardian.telemetry.client import emit
    from agent_guardian.telemetry.consent import is_extended

    try:
        ext = is_extended()
        evt = InstallEvent(
            install_id=get_install_id(),
            agent_version=__version__,
            # On the essential tier, Python/OS/arch are not collected on
            # scan events -- but the InstallEvent's fields are required
            # by the v1 schema, so we send placeholders that the
            # aggregator will ignore when consent_level == essential.
            # Future schema bump can make these Optional too.
            python_version=(f"{sys.version_info.major}.{sys.version_info.minor}" if ext else "3.0"),
            os_family=_os_family() if ext else "Linux",
            arch=_arch() if ext else "x86_64",
            opted_in_at=datetime.now(timezone.utc),
        )
        emit(evt)
    except Exception as exc:  # pragma: no cover -- defensive
        _LOG.warning(
            "telemetry: failed to emit InstallEvent (%s: %s) -- install_id will be "
            "inferred from first scan instead",
            type(exc).__name__,
            exc,
        )


def _os_family() -> Literal["Linux", "Darwin", "Windows"]:
    sysname = platform.system()
    if sysname in ("Linux", "Darwin", "Windows"):
        return cast(Literal["Linux", "Darwin", "Windows"], sysname)
    return "Linux"


def _arch() -> Literal["x86_64", "arm64", "aarch64", "i686"]:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine == "arm64":
        return "arm64"
    if machine == "aarch64":
        return "aarch64"
    if machine in ("i686", "i386"):
        return "i686"
    return "x86_64"


# Legacy exports -- older callers still reference these names. They
# now route to maybe_prompt_consent so the new policy is uniformly
# enforced regardless of which entry point fires.
maybe_show_first_scan_notice = maybe_prompt_consent
maybe_prompt_first_run = maybe_prompt_consent
