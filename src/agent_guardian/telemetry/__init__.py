"""Telemetry -- opt-in only, allowlist-only, auditable.

AgentGuardian Open ships **off-by-default** telemetry. The user must
explicitly opt in via the first-run prompt or ``agent-guardian telemetry
enable``. Until they do, no event is collected, no event is buffered to
disk, and no network request leaves the machine.

Once opted in, a strict allowlist of fields is collected per event:

* ``scan_completed`` -- aivss, band, tier, adapter, target_mode,
  duration_seconds, crash_status, agent_version, python_version,
  os_family, arch, anonymous install_id, timestamp.
* ``install`` -- install_id, agent_version, python_version,
  os_family, arch, timestamp.
* ``probe_fire`` -- scan_id (anonymous random per-scan UUID),
  probe_id, asi_category, severity, timestamp.

The module is deliberately small, no third-party deps beyond what the
core package already pulls in (httpx, pydantic). The collector source
code lives at :mod:`agent_guardian.server.analytics` so anyone can
audit what would be received on the other end.

Privacy invariants:
  * No prompt text, no LLM response text, no probe seed text leaves the
    machine.
  * No file paths, no hostnames, no IP addresses.
  * No environment variables.
  * The install_id is a single random UUID generated locally and
    stored at ``~/.agentguardian/install_id``; it has no link to the
    user's identity.
  * If the user opts out after opting in, the local buffer is wiped
    and the collector is sent a single ``forget`` event so the
    server-side install_id row can be deleted.
"""

from __future__ import annotations

from agent_guardian.telemetry.consent import (
    ConsentState,
    consent_level,
    get_consent,
    has_been_notified,
    has_been_prompted,
    is_extended,
    is_opted_in,
    set_consent,
)
from agent_guardian.telemetry.install_id import get_install_id, reset_install_id

__all__ = [
    "ConsentState",
    "consent_level",
    "get_consent",
    "get_install_id",
    "has_been_notified",
    "has_been_prompted",
    "is_extended",
    "is_opted_in",
    "reset_install_id",
    "set_consent",
]
