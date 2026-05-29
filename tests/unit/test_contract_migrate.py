"""Unit tests for the contract migration skeleton (Stage 1A)."""

from __future__ import annotations

import pytest

from agent_guardian.contract.errors import MigrationNeeded, UnsupportedContractVersion
from agent_guardian.contract.migrate import MIGRATIONS, migrate_contract
from agent_guardian.contract.schema import CURRENT_CONTRACT_VERSION


def _data(version: object) -> dict[str, object]:
    return {
        "version": version,
        "name": "demo",
        "target": {"kind": "http", "base_url": "https://x.example"},
    }


def test_migrations_registry_empty_in_stage_1a() -> None:
    assert MIGRATIONS == {}


def test_migrate_current_version_is_noop() -> None:
    data = _data(CURRENT_CONTRACT_VERSION)
    out = migrate_contract(data)
    assert out == data
    # Returns a copy, not the same object.
    assert out is not data


def test_migrate_v2_needs_migration() -> None:
    with pytest.raises(MigrationNeeded) as exc:
        migrate_contract(_data(2))
    assert exc.value.found == 2
    assert exc.value.target == CURRENT_CONTRACT_VERSION


def test_migrate_v99_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate_contract(_data(99))


def test_migrate_non_int_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate_contract(_data("two"))


def test_migrate_bool_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        migrate_contract(_data(True))


def test_migrate_applies_registered_step(monkeypatch: pytest.MonkeyPatch) -> None:
    # Register a fake v2 -> current migration to prove the loop wiring works.
    def _bump(data: dict[str, object]) -> dict[str, object]:
        out = dict(data)
        out["version"] = CURRENT_CONTRACT_VERSION
        out["migrated"] = True
        return out

    monkeypatch.setitem(MIGRATIONS, 2, _bump)
    out = migrate_contract(_data(2))
    assert out["version"] == CURRENT_CONTRACT_VERSION
    assert out["migrated"] is True
