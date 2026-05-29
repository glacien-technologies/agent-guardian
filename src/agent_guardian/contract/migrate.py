"""Contract migration (Stage 4).

When a contract declares an older schema ``version`` it must be run through a
chain of version-to-version migrations until it reaches the requested target
version. Each registered migrator upgrades a document from version ``n`` to
version ``n + 1``; :func:`migrate` chains them so a v1 → v3 jump just runs the
1→2 then 2→3 steps in order.

Two public entry points:

* :func:`migrate` — the general engine. Migrates a raw mapping *up* to a
  ``target`` version (default :data:`~agent_guardian.contract.schema.CURRENT_CONTRACT_VERSION`)
  by chaining :data:`MIGRATIONS`. Idempotent: a document already at (or above)
  the target is returned unchanged (a copy).
* :func:`migrate_contract` — the loader-facing wrapper. Migrates toward the
  *current* build version and preserves the historical
  :class:`MigrationNeeded` / :class:`UnsupportedContractVersion` semantics the
  loader and CLI depend on.

Each migrator is a pure ``dict -> dict`` transform that **must** bump the
``version`` field to its output version. Migrators never mutate their input
(they return a fresh mapping), so the chain is safe to re-run.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_guardian.contract.errors import MigrationNeeded, UnsupportedContractVersion
from agent_guardian.contract.schema import (
    CURRENT_CONTRACT_VERSION,
    MAX_KNOWN_CONTRACT_VERSION,
)

__all__ = ["MIGRATIONS", "fix_file", "migrate", "migrate_contract"]


def _migrate_1_to_2(data: dict[str, Any]) -> dict[str, Any]:
    """Upgrade a version-1 contract mapping to version 2.

    The v1 → v2 bump is additive: v2 introduces no required fields that a v1
    document lacks, so the migration is structurally a version stamp. We still
    route it through the mechanism (rather than special-casing) so the chain is
    uniform and a future v2 → v3 step composes for free. The transform is pure
    (returns a fresh mapping) and idempotent under the chaining engine.
    """
    out = dict(data)
    out["version"] = 2
    return out


# Maps a *source* version to a callable that upgrades a raw contract mapping to
# the next version (source + 1). The chaining engine in :func:`migrate` walks
# this registry one version at a time.
MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {
    1: _migrate_1_to_2,
}


def _version_of(data: dict[str, Any]) -> int:
    """Read + validate the ``version`` field, defaulting to the current version."""
    version = data.get("version", CURRENT_CONTRACT_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        raise UnsupportedContractVersion(
            f"contract 'version' must be an integer (got {version!r})",
            supported=CURRENT_CONTRACT_VERSION,
        )
    return version


def migrate(data: dict[str, Any], *, target: int = CURRENT_CONTRACT_VERSION) -> dict[str, Any]:
    """Migrate a raw contract mapping *up* to ``target`` by chaining migrators.

    Behaviour:

    * non-int ``version`` → :class:`UnsupportedContractVersion`;
    * ``version`` already at or above ``target`` → returned unchanged (a copy),
      so calling ``migrate`` twice is a no-op the second time (idempotent);
    * ``version`` below 1 or ``target`` beyond :data:`MAX_KNOWN_CONTRACT_VERSION`
      → :class:`UnsupportedContractVersion`;
    * a gap in the chain (no migrator registered for an intermediate version) →
      :class:`MigrationNeeded`.

    Each registered migrator must bump ``version`` by exactly one step; the
    engine asserts forward progress so a buggy migrator can never spin.
    """
    version = _version_of(data)
    if target > MAX_KNOWN_CONTRACT_VERSION:
        raise UnsupportedContractVersion(
            f"migration target {target} is beyond the maximum version this build "
            f"recognises ({MAX_KNOWN_CONTRACT_VERSION}); upgrade AgentGuardian",
            found=version,
            supported=CURRENT_CONTRACT_VERSION,
        )
    if version < 1:
        raise UnsupportedContractVersion(
            f"contract version {version} is not a valid version",
            found=version,
            supported=CURRENT_CONTRACT_VERSION,
        )
    if version >= target:
        # Already current-or-newer for this target: nothing to do. Return a copy
        # so callers never alias the input.
        return dict(data)

    result = dict(data)
    current = version
    while current < target:
        step = MIGRATIONS.get(current)
        if step is None:
            raise MigrationNeeded(
                f"no migration registered from contract version {current} toward {target}",
                found=version,
                target=target,
            )
        result = step(result)
        nxt = _version_of(result)
        if nxt <= current:
            # A migrator that fails to advance the version would loop forever.
            raise MigrationNeeded(
                f"migration from version {current} did not advance the version "
                f"(got {nxt}); migrator is broken",
                found=version,
                target=target,
            )
        current = nxt
    return result


def migrate_contract(data: dict[str, Any]) -> dict[str, Any]:
    """Migrate a raw contract mapping toward the *current* build version.

    Loader-facing wrapper around :func:`migrate` that preserves the historical
    error semantics the loader + CLI branch on:

    * already-current document → returned unchanged (a copy);
    * non-int version → :class:`UnsupportedContractVersion`;
    * version outside ``[1, MAX_KNOWN]`` → :class:`UnsupportedContractVersion`;
    * a *known* version newer than the build (e.g. a v2 doc on a v1 build, which
      cannot be down-migrated) → :class:`MigrationNeeded`;
    * a known older version with no registered migration → :class:`MigrationNeeded`.
    """
    version = _version_of(data)
    if version == CURRENT_CONTRACT_VERSION:
        return dict(data)
    if version < 1 or version > MAX_KNOWN_CONTRACT_VERSION:
        raise UnsupportedContractVersion(
            f"contract version {version} is not a recognised, migratable version "
            f"(known range 1..{MAX_KNOWN_CONTRACT_VERSION})",
            found=version,
            supported=CURRENT_CONTRACT_VERSION,
        )
    if version > CURRENT_CONTRACT_VERSION:
        # The document is newer than this build understands natively and there is
        # no down-migration path — the operator must upgrade AgentGuardian.
        raise MigrationNeeded(
            f"contract version {version} requires migration to the current version "
            f"{CURRENT_CONTRACT_VERSION}",
            found=version,
            target=CURRENT_CONTRACT_VERSION,
        )
    # Older-than-current document: chain forward to CURRENT. Unreachable while
    # CURRENT == 1 (no valid version < 1), but the right behaviour once CURRENT
    # advances and an older-version doc can be up-migrated.
    return migrate(data, target=CURRENT_CONTRACT_VERSION)  # pragma: no cover


def fix_file(
    path: Path, *, target: int = MAX_KNOWN_CONTRACT_VERSION, write: bool = False
) -> dict[str, Any]:
    """Load a contract YAML, migrate it to ``target``, and optionally write it back.

    Reads ``path`` as a YAML mapping, runs it through :func:`migrate`, and
    returns the migrated mapping. When ``write`` is true the migrated document
    is rendered back to ``path`` (after copying the original to ``path.bak`` so
    an operator can recover the pre-migration document). When ``write`` is false
    the file is left untouched and only the migrated mapping is returned.

    ``target`` defaults to :data:`MAX_KNOWN_CONTRACT_VERSION` because ``fix_file``
    is the explicit "bring this document up to the newest schema" tool, distinct
    from the loader's conservative migrate-to-current behaviour.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ValueError: the file is not a YAML mapping.
        MigrationNeeded / UnsupportedContractVersion: the version chain cannot
            reach ``target``.
    """
    import yaml

    if not path.is_file():
        raise FileNotFoundError(f"contract file not found: {path}")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ValueError(f"contract file {path} must contain a YAML mapping at the top level")

    migrated = migrate(loaded, target=target)

    if write:
        backup = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup)
        rendered = yaml.safe_dump(migrated, sort_keys=False, default_flow_style=False)
        path.write_text(rendered, encoding="utf-8")
    return migrated
