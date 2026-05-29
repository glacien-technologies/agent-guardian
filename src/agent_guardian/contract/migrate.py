"""Contract migration (Stage 1A skeleton).

When a contract declares an older schema ``version`` the loader raises
:class:`~agent_guardian.contract.errors.MigrationNeeded`. The eventual fix is
to run the document through a chain of version-to-version migrations until it
reaches :data:`~agent_guardian.contract.schema.CURRENT_CONTRACT_VERSION`.

Stage 1A ships only the skeleton: the registry is empty and
:func:`migrate_contract` raises :class:`MigrationNeeded` for any document that
isn't already current. The function is intentionally callable so callers (and
tests) can depend on the surface today.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_guardian.contract.errors import MigrationNeeded, UnsupportedContractVersion
from agent_guardian.contract.schema import (
    CURRENT_CONTRACT_VERSION,
    MAX_KNOWN_CONTRACT_VERSION,
)

__all__ = ["MIGRATIONS", "migrate_contract"]

# Maps a *source* version to a callable that upgrades a raw contract mapping to
# the next recognised version. Empty in Stage 1A — populated as schema versions
# land.
MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {}


def migrate_contract(data: dict[str, Any]) -> dict[str, Any]:
    """Migrate a raw contract mapping toward the current schema version.

    Stage 1A behaviour (skeleton — no migrations registered yet):

    * already-current document → returned unchanged;
    * non-int version → :class:`UnsupportedContractVersion`;
    * version beyond :data:`MAX_KNOWN_CONTRACT_VERSION` →
      :class:`UnsupportedContractVersion`;
    * any other known, non-current version with no registered migration →
      :class:`MigrationNeeded`.
    """
    version = data.get("version", CURRENT_CONTRACT_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        raise UnsupportedContractVersion(
            f"contract 'version' must be an integer (got {version!r})",
            supported=CURRENT_CONTRACT_VERSION,
        )
    if version == CURRENT_CONTRACT_VERSION:
        return dict(data)
    if version < 1 or version > MAX_KNOWN_CONTRACT_VERSION:
        raise UnsupportedContractVersion(
            f"contract version {version} is not a recognised, migratable version "
            f"(known range 1..{MAX_KNOWN_CONTRACT_VERSION})",
            found=version,
            supported=CURRENT_CONTRACT_VERSION,
        )

    result = dict(data)
    current = version
    while current != CURRENT_CONTRACT_VERSION:
        step = MIGRATIONS.get(current)
        if step is None:
            raise MigrationNeeded(
                f"no migration registered from contract version {current} "
                f"toward {CURRENT_CONTRACT_VERSION}",
                found=version,
                target=CURRENT_CONTRACT_VERSION,
            )
        result = step(result)
        current = int(result.get("version", current))
    return result
