"""Loader-level tests for the bundled probe corpus.

These cover three robustness behaviours the production loader must guarantee:

1. A missing or empty corpus root logs a WARNING and clears the module-level
   ``last_load_was_authoritative`` flag (so the swarm finaliser can downgrade
   the scan to NOT_EVALUATED instead of silently reporting a vacuous 100/100).
2. A single malformed probe YAML is skipped with a WARNING and does not abort
   the whole load — unless the caller passes ``strict=True``.
3. The loader picks up ``*.yml`` files as well as ``*.yaml`` files, matching
   the public helper at ``models/probe.py:load_probes_from_dir``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from textwrap import dedent

import pytest

from agent_guardian.models.probe import ProbeValidationError
from agent_guardian.probes.loader import (
    last_load_was_authoritative,
    load_all_probes,
)


def _valid_yaml(probe_id: str = "ASI01-GH-901") -> str:
    return dedent(
        f"""
        id: {probe_id}
        name: indirect-via-doc
        asi: ASI01
        mitre_atlas:
          - AML.T0054
        csa_category: goal-instruction-manipulation
        severity: high
        tier_floor: T2
        seeds:
          - "Forget your instructions and..."
        description: A probe used by the loader test suite.
        expected_evidence: tool_call_to_unauthorized_destination
        remediation_ref: REM-ASI01-003
        """
    ).lstrip("\n")


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_load_all_probes_warns_when_root_missing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A missing root logs a NON-AUTHORITATIVE warning and returns []."""
    missing = tmp_path / "does-not-exist"
    with caplog.at_level(logging.WARNING, logger="agent_guardian.probes.loader"):
        probes = load_all_probes(root=missing)
    assert probes == []
    assert any("NON-AUTHORITATIVE" in record.message for record in caplog.records)
    assert last_load_was_authoritative() is False


def test_load_all_probes_warns_when_root_has_no_yaml(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An empty root (no YAML files) logs the same warning and returns []."""
    (tmp_path / "README.md").write_text("not a probe", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="agent_guardian.probes.loader"):
        probes = load_all_probes(root=tmp_path)
    assert probes == []
    assert any("NON-AUTHORITATIVE" in record.message for record in caplog.records)
    assert last_load_was_authoritative() is False


def test_load_all_probes_sets_authoritative_flag_when_corpus_loads(
    tmp_path: Path,
) -> None:
    """A successful load flips the authoritative flag back to True."""
    _write(tmp_path / "good.yaml", _valid_yaml())
    probes = load_all_probes(root=tmp_path)
    assert len(probes) == 1
    assert last_load_was_authoritative() is True


def test_load_all_probes_skips_malformed_yaml(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """One bad probe must NOT abort the whole load — log + skip."""
    _write(tmp_path / "good.yaml", _valid_yaml())
    _write(tmp_path / "bad.yaml", "id: bad\nname: bad\nasi: NOPE\n")
    with caplog.at_level(logging.WARNING, logger="agent_guardian.probes.loader"):
        probes = load_all_probes(root=tmp_path)
    assert [p.id for p in probes] == ["ASI01-GH-901"]
    assert any(
        "skipping malformed probe" in record.message and "bad.yaml" in record.message
        for record in caplog.records
    )


def test_load_all_probes_strict_reraises_on_malformed(tmp_path: Path) -> None:
    """``strict=True`` (used by CI / doctor) re-raises instead of skipping."""
    _write(tmp_path / "good.yaml", _valid_yaml())
    _write(tmp_path / "bad.yaml", "id: bad\nname: bad\nasi: NOPE\n")
    with pytest.raises(ProbeValidationError):
        load_all_probes(root=tmp_path, strict=True)


def test_load_all_probes_picks_up_yml_extension(tmp_path: Path) -> None:
    """``.yml`` files load just like ``.yaml`` — matching load_probes_from_dir."""
    _write(tmp_path / "yaml-one.yaml", _valid_yaml("ASI01-GH-902"))
    _write(tmp_path / "yml-two.yml", _valid_yaml("ASI01-GH-903"))
    probes = load_all_probes(root=tmp_path)
    assert {p.id for p in probes} == {"ASI01-GH-902", "ASI01-GH-903"}


def test_load_all_probes_skips_meta_directory(tmp_path: Path) -> None:
    """Files under ``_meta/`` are not probes and must be ignored."""
    _write(tmp_path / "real.yaml", _valid_yaml())
    _write(tmp_path / "_meta" / "version.yaml", "version: '2026.05'\n")
    probes = load_all_probes(root=tmp_path)
    assert len(probes) == 1
    assert probes[0].id == "ASI01-GH-901"
