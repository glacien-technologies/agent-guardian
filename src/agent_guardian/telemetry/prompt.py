"""First-scan telemetry notice + tier-upgrade flow.

Policy change for v1.0+: telemetry is no longer opt-in. Essential
operational counts (agents fired, attempts, successes, threats) are
collected ON by default -- the user opts OUT with
``agent-guardian telemetry disable``, or upgrades to the extended
tier with ``agent-guardian telemetry extended``.

The first scan a fresh install completes prints a one-line notice
explaining what's collected and how to disable it. From then on the
notice never re-fires (state transitions from NOT_PROMPTED to
ESSENTIAL, which silences the notice).

The notice is NON-blocking. It does not wait for input. It prints,
the scan continues, and the user reads it at their own pace.
"""

from __future__ import annotations

import logging
import platform
import sys
from datetime import datetime, timezone
from typing import Literal, cast

from agent_guardian._version import __version__
from agent_guardian.telemetry.consent import (
    ConsentState,
    get_consent,
    has_been_notified,
    set_consent,
)
from agent_guardian.telemetry.events import InstallEvent
from agent_guardian.telemetry.install_id import get_install_id

__all__ = ["FIRST_SCAN_NOTICE", "PROMPT_TEXT", "maybe_show_first_scan_notice"]

_LOG = logging.getLogger(__name__)


FIRST_SCAN_NOTICE = """
  ────────────────────────────────────────────────────────────────────────
  AgentGuardian Open -- essential telemetry is on by default.
  Each scan sends ONLY anonymous operational counts:
      agents fired · attempts · successes · threats captured · AIVSS score
  No prompts, model output, file paths, hostnames, or environment data.

  Disable:    agent-guardian telemetry disable
  Share more: agent-guardian telemetry extended    (adds adapter + Python + OS)
  Audit:      agent-guardian telemetry show
  ────────────────────────────────────────────────────────────────────────
"""


# Legacy export -- the old opt-in prompt text is now an audit display
# string used by ``agent-guardian telemetry show``. Keeps backwards
# compatibility with any external code that imports PROMPT_TEXT.
PROMPT_TEXT = """
AgentGuardian Open -- what telemetry collects
═══════════════════════════════════════════════
Default state: ESSENTIAL (on). Disable with `agent-guardian telemetry disable`.

What ALWAYS gets sent (essential tier, default-on):

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


def maybe_show_first_scan_notice(*, force: bool = False) -> ConsentState:
    """Print the one-line first-scan notice if the user has never seen it.

    Non-blocking. No input collected. The notice prints to stderr so
    it shows up under the CLI's existing scan-status output without
    confusing programs that pipe stdout.

    Args:
        force: re-print the notice even if the user has already seen
            it. Used by ``telemetry reset``.

    Returns the new ConsentState (always ESSENTIAL after this call
    completes, unless the user is already on EXTENDED / OPTED_OUT).
    """
    current = get_consent()
    # Never overwrite an explicit choice.
    if current in (ConsentState.EXTENDED, ConsentState.OPTED_OUT, ConsentState.OPTED_IN):
        return current
    if has_been_notified() and not force:
        return current
    # Print to stderr so it shows up next to the scan-status line
    # without colliding with stdout consumers (CI scripts, pipes).
    print(FIRST_SCAN_NOTICE, file=sys.stderr)
    set_consent(ConsentState.ESSENTIAL)
    _emit_install_event()
    return ConsentState.ESSENTIAL


def _emit_install_event() -> None:
    """Fire the one-time install event after the first-scan notice prints.

    Even on the essential tier we send the InstallEvent so the
    collector can derive MAU correctly. The InstallEvent itself
    deliberately omits environment fields when consent_level is
    essential -- handled by the same is_extended check in the swarm
    emission path.
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


# Legacy export -- older callers may still reference maybe_prompt_first_run.
maybe_prompt_first_run = maybe_show_first_scan_notice
