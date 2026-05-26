"""Probe YAML loader tests — schema validation and triple-framework gate."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from agent_guardian.models.probe import (
    ProbeValidationError,
    load_probe,
    load_probes_from_dir,
)


def _write(path: Path, content: str) -> Path:
    path.write_text(dedent(content).lstrip("\n"), encoding="utf-8")
    return path


def _valid_yaml() -> str:
    return """
        id: ASI01-GH-007
        name: indirect-via-doc
        asi: ASI01
        mitre_atlas:
          - AML.T0054
        csa_category: goal-instruction-manipulation
        severity: high
        tier_floor: T2
        seeds:
          - "Forget your instructions and..."
        description: A probe that tests indirect injection via document content.
        expected_evidence: tool_call_to_unauthorized_destination
        remediation_ref: REM-ASI01-003
        references:
          - paper:greshake-2023
    """


def test_load_probe_parses_valid_yaml(tmp_path: Path) -> None:
    path = _write(tmp_path / "p.yaml", _valid_yaml())
    probe = load_probe(path)
    assert probe.id == "ASI01-GH-007"
    assert probe.asi.value == "ASI01"
    assert probe.mitre_atlas == ["AML.T0054"]


def test_load_probe_missing_asi_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "p.yaml",
        """
        id: ASI01-GH-007
        name: indirect-via-doc
        mitre_atlas: ["AML.T0054"]
        csa_category: goal-instruction-manipulation
        severity: high
        tier_floor: T2
        seeds: ["x"]
        description: d
        expected_evidence: e
        remediation_ref: r
        """,
    )
    with pytest.raises(ProbeValidationError) as exc_info:
        load_probe(path)
    assert "asi" in str(exc_info.value)


def test_load_probe_missing_mitre_atlas_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "p.yaml",
        """
        id: ASI01-GH-007
        name: indirect-via-doc
        asi: ASI01
        csa_category: goal-instruction-manipulation
        severity: high
        tier_floor: T2
        seeds: ["x"]
        description: d
        expected_evidence: e
        remediation_ref: r
        """,
    )
    with pytest.raises(ProbeValidationError) as exc_info:
        load_probe(path)
    assert "mitre_atlas" in str(exc_info.value)


def test_load_probe_empty_mitre_atlas_raises(tmp_path: Path) -> None:
    yaml_text = _valid_yaml().replace(
        "mitre_atlas:\n          - AML.T0054\n",
        "mitre_atlas: []\n",
    )
    path = _write(tmp_path / "p.yaml", yaml_text)
    with pytest.raises(ProbeValidationError):
        load_probe(path)


def test_load_probe_missing_csa_category_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "p.yaml",
        """
        id: ASI01-GH-007
        name: indirect-via-doc
        asi: ASI01
        mitre_atlas: ["AML.T0054"]
        severity: high
        tier_floor: T2
        seeds: ["x"]
        description: d
        expected_evidence: e
        remediation_ref: r
        """,
    )
    with pytest.raises(ProbeValidationError) as exc_info:
        load_probe(path)
    assert "csa_category" in str(exc_info.value)


def test_load_probe_invalid_mitre_id_raises(tmp_path: Path) -> None:
    yaml_text = _valid_yaml().replace("AML.T0054", "TA0054")
    path = _write(tmp_path / "p.yaml", yaml_text)
    with pytest.raises(ProbeValidationError):
        load_probe(path)


def test_load_probe_extra_field_rejected(tmp_path: Path) -> None:
    yaml_text = _valid_yaml() + "unknown_field: nope\n"
    path = _write(tmp_path / "p.yaml", yaml_text)
    with pytest.raises(ProbeValidationError):
        load_probe(path)


def test_load_probe_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_probe(tmp_path / "absent.yaml")


def test_load_probe_empty_file_raises(tmp_path: Path) -> None:
    path = _write(tmp_path / "p.yaml", "")
    with pytest.raises(ProbeValidationError):
        load_probe(path)


def test_load_probe_bad_yaml_syntax_raises(tmp_path: Path) -> None:
    path = _write(tmp_path / "p.yaml", "id: a\n  bad: : : :\n")
    with pytest.raises(ProbeValidationError):
        load_probe(path)


def test_load_probe_non_mapping_root_raises(tmp_path: Path) -> None:
    path = _write(tmp_path / "p.yaml", "- just\n- a\n- list\n")
    with pytest.raises(ProbeValidationError):
        load_probe(path)


def test_load_probes_from_dir_returns_sorted(tmp_path: Path) -> None:
    _write(tmp_path / "b.yaml", _valid_yaml().replace("ASI01-GH-007", "ASI01-GH-008"))
    _write(tmp_path / "a.yaml", _valid_yaml())
    probes = load_probes_from_dir(tmp_path)
    assert [p.id for p in probes] == ["ASI01-GH-007", "ASI01-GH-008"]


def test_load_probes_from_dir_recurses(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    _write(nested / "p.yaml", _valid_yaml())
    probes = load_probes_from_dir(tmp_path)
    assert len(probes) == 1


def test_load_probes_from_dir_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_probes_from_dir(tmp_path / "absent")


def test_load_probes_from_dir_on_file_raises(tmp_path: Path) -> None:
    f = _write(tmp_path / "p.yaml", _valid_yaml())
    with pytest.raises(NotADirectoryError):
        load_probes_from_dir(f)
