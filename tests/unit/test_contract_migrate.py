"""Unit tests for the contract migration engine (Stage 4)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent_guardian.contract.errors import MigrationNeeded, UnsupportedContractVersion
from agent_guardian.contract.migrate import (
    MIGRATIONS,
    fix_file,
    migrate,
    migrate_contract,
)
from agent_guardian.contract.schema import (
    CURRENT_CONTRACT_VERSION,
    MAX_KNOWN_CONTRACT_VERSION,
)


def _data(version: object) -> dict[str, object]:
    return {
        "version": version,
        "name": "demo",
        "target": {"kind": "http", "base_url": "https://x.example"},
    }


# ---------------------------------------------------------------------------
# Registry + the real v1 -> v2 migrator
# ---------------------------------------------------------------------------


def test_migrations_registry_has_v1_to_v2() -> None:
    # The chaining engine keys each migrator on its *source* version.
    assert 1 in MIGRATIONS
    out = MIGRATIONS[1](_data(1))
    assert out["version"] == 2


def test_v1_to_v2_migrator_does_not_mutate_input() -> None:
    src = _data(1)
    MIGRATIONS[1](src)
    assert src["version"] == 1  # original untouched


# ---------------------------------------------------------------------------
# migrate() — the general engine
# ---------------------------------------------------------------------------


def test_migrate_v1_to_v2() -> None:
    out = migrate(_data(1), target=2)
    assert out["version"] == 2
    # Non-version fields ride along unchanged.
    assert out["name"] == "demo"
    assert out["target"] == {"kind": "http", "base_url": "https://x.example"}


def test_migrate_is_idempotent() -> None:
    once = migrate(_data(1), target=2)
    twice = migrate(once, target=2)
    assert once == twice
    # Re-running the migration at-or-above target is a no-op (returns a copy).
    assert twice is not once


def test_migrate_at_target_is_noop_copy() -> None:
    src = _data(2)
    out = migrate(src, target=2)
    assert out == src
    assert out is not src


def test_migrate_above_target_is_noop() -> None:
    # A doc newer than the requested target is returned unchanged (no down-migrate).
    out = migrate(_data(2), target=1)
    assert out["version"] == 2


def test_migrate_default_target_is_current() -> None:
    # Default target is CURRENT; a current doc is a no-op.
    out = migrate(_data(CURRENT_CONTRACT_VERSION))
    assert out["version"] == CURRENT_CONTRACT_VERSION


def test_migrate_chains_through_intermediate_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Register a fake 2 -> 3 step and lift MAX_KNOWN so a v1 -> v3 jump chains
    # 1->2 then 2->3 in order, proving multi-step chaining works.
    def _bump_2_to_3(data: dict[str, object]) -> dict[str, object]:
        out = dict(data)
        out["version"] = 3
        out["touched_by_v3"] = True
        return out

    monkeypatch.setitem(MIGRATIONS, 2, _bump_2_to_3)
    monkeypatch.setattr("agent_guardian.contract.migrate.MAX_KNOWN_CONTRACT_VERSION", 3)
    out = migrate(_data(1), target=3)
    assert out["version"] == 3
    assert out["touched_by_v3"] is True


def test_migrate_gap_in_chain_raises_migration_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Lift MAX_KNOWN to 3 but register no 2->3 step: the chain stalls at 2.
    monkeypatch.setattr("agent_guardian.contract.migrate.MAX_KNOWN_CONTRACT_VERSION", 3)
    with pytest.raises(MigrationNeeded) as exc:
        migrate(_data(1), target=3)
    assert exc.value.found == 1
    assert exc.value.target == 3


def test_migrate_target_beyond_max_known_is_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion, match="beyond the maximum"):
        migrate(_data(1), target=MAX_KNOWN_CONTRACT_VERSION + 5)


def test_migrate_non_int_version_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate(_data("two"))


def test_migrate_bool_version_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate(_data(True))


def test_migrate_version_below_one_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion, match="not a valid version"):
        migrate(_data(0), target=2)


def test_migrate_broken_migrator_raises_migration_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A migrator that fails to advance the version must trip the guard rather
    # than spin forever.
    def _no_advance(data: dict[str, object]) -> dict[str, object]:
        return dict(data)  # leaves version == 1

    monkeypatch.setitem(MIGRATIONS, 1, _no_advance)
    with pytest.raises(MigrationNeeded, match="did not advance"):
        migrate(_data(1), target=2)


# ---------------------------------------------------------------------------
# migrate_contract() — loader-facing wrapper (migrate toward CURRENT)
# ---------------------------------------------------------------------------


def test_migrate_contract_current_version_is_noop() -> None:
    data = _data(CURRENT_CONTRACT_VERSION)
    out = migrate_contract(data)
    assert out == data
    assert out is not data


def test_migrate_contract_v2_needs_migration() -> None:
    # CURRENT is 1; a v2 document cannot be down-migrated on this build.
    with pytest.raises(MigrationNeeded) as exc:
        migrate_contract(_data(2))
    assert exc.value.found == 2
    assert exc.value.target == CURRENT_CONTRACT_VERSION


def test_migrate_contract_v99_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate_contract(_data(99))


def test_migrate_contract_non_int_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate_contract(_data("two"))


def test_migrate_contract_bool_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate_contract(_data(True))


# ---------------------------------------------------------------------------
# fix_file() — YAML round-trip with backup
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, data: dict[str, object]) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_fix_file_read_only_does_not_write(tmp_path: Path) -> None:
    f = tmp_path / "contract.yaml"
    _write_yaml(f, _data(1))
    before = f.read_text(encoding="utf-8")

    migrated = fix_file(f, target=2, write=False)
    assert migrated["version"] == 2
    # File untouched, no backup created.
    assert f.read_text(encoding="utf-8") == before
    assert not (tmp_path / "contract.yaml.bak").exists()


def test_fix_file_write_round_trips_and_backs_up(tmp_path: Path) -> None:
    f = tmp_path / "contract.yaml"
    _write_yaml(f, _data(1))

    migrated = fix_file(f, target=2, write=True)
    assert migrated["version"] == 2

    # The on-disk file now parses to the migrated document.
    on_disk = yaml.safe_load(f.read_text(encoding="utf-8"))
    assert on_disk["version"] == 2
    assert on_disk["name"] == "demo"

    # A backup of the pre-migration document is left alongside.
    backup = tmp_path / "contract.yaml.bak"
    assert backup.exists()
    assert yaml.safe_load(backup.read_text(encoding="utf-8"))["version"] == 1


def test_fix_file_idempotent_when_already_at_target(tmp_path: Path) -> None:
    f = tmp_path / "contract.yaml"
    _write_yaml(f, _data(2))
    migrated = fix_file(f, target=2, write=True)
    assert migrated["version"] == 2
    assert yaml.safe_load(f.read_text(encoding="utf-8"))["version"] == 2


def test_fix_file_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        fix_file(tmp_path / "nope.yaml", target=2)


def test_fix_file_non_mapping_raises(tmp_path: Path) -> None:
    f = tmp_path / "contract.yaml"
    f.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError, match="YAML mapping"):
        fix_file(f, target=2)


def test_fix_file_empty_file_is_versioned(tmp_path: Path) -> None:
    # An empty document defaults to the current version, then migrates up.
    f = tmp_path / "contract.yaml"
    f.write_text("", encoding="utf-8")
    migrated = fix_file(f, target=2, write=False)
    assert migrated["version"] == 2
