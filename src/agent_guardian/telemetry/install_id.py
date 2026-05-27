"""Anonymous install identifier.

A single UUID4 generated once per install and persisted at
``~/.agentguardian/install_id``. The ID has no link to the user's
GitHub handle, email, hostname, or any other identifier -- it exists
solely so the aggregator can count distinct installs without counting
the same install twice.

Resetting the file (or running ``agent-guardian telemetry reset``)
generates a fresh ID. The previous ID is **not** retained anywhere
on the client; if the user reset their consent + ID, the server-side
ID is dropped via a ``forget`` event.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from agent_guardian.telemetry.consent import default_consent_dir

__all__ = ["get_install_id", "install_id_path", "reset_install_id"]

_LOG = logging.getLogger(__name__)


def install_id_path(consent_dir: Path | None = None) -> Path:
    base = consent_dir if consent_dir is not None else default_consent_dir()
    return base / "install_id"


def get_install_id(consent_dir: Path | None = None) -> str:
    """Read or generate the install_id. UUID4, lowercase hex with hyphens."""
    path = install_id_path(consent_dir)
    if path.is_file():
        try:
            existing = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            _LOG.warning(
                "telemetry install_id: failed to read %s (%s: %s) -- generating fresh",
                path,
                type(exc).__name__,
                exc,
            )
            existing = ""
        if existing:
            try:
                # Validate it's a real UUID -- don't accept arbitrary strings
                # from a tampered file (mild defence against accidental seeding).
                uuid.UUID(existing)
                return existing
            except ValueError:
                _LOG.warning(
                    "telemetry install_id: existing file %s is not a UUID -- generating fresh",
                    path,
                )
    new_id = str(uuid.uuid4())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_id + "\n", encoding="utf-8")
    _LOG.info("telemetry install_id: generated new install_id (persisted at %s)", path)
    return new_id


def reset_install_id(consent_dir: Path | None = None) -> None:
    """Delete the install_id so the next ``get_install_id`` call generates a fresh one.

    Called from ``agent-guardian telemetry reset``. The companion
    ``forget`` event sent to the collector tells the server to delete
    the previous install_id's row.
    """
    path = install_id_path(consent_dir)
    try:
        path.unlink()
        _LOG.info("telemetry install_id: deleted %s -- next call will generate a fresh ID", path)
    except FileNotFoundError:
        _LOG.debug("telemetry install_id: no install_id file at %s to delete", path)
