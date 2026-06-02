"""Phase A.A4 bug-fix coverage — judge-injection corpus reaches per-ASI dispatch.

Before the fix, ``load_probes_for_asi`` scoped its scan to ``probes/asiNN/``
only, so the peer ``probes/judges/`` directory (carrying JDG-* judge-injection
probes) was unreachable from every agent's seed load. These tests guard the
union: each JDG probe must surface under its declared ``asi:`` category.
"""

from __future__ import annotations

import logging
from pathlib import Path
from textwrap import dedent

import pytest

import agent_guardian.probes.loader as loader_mod
from agent_guardian.models.asi import AsiCategory
from agent_guardian.probes.loader import load_probes_for_asi


def _judge_yaml(probe_id: str, asi: str = "ASI01") -> str:
    return dedent(
        f"""
        id: {probe_id}
        name: judge-stub
        asi: {asi}
        mitre_atlas:
          - AML.T0064
        csa_category: goal-instruction-manipulation
        severity: low
        tier_floor: T3
        seeds:
          - "judge probe seed"
        description: A judge probe used by the union test suite.
        expected_evidence: judge_emits_pass_when_target_should_have_been_labelled_fail
        remediation_ref: REM-JDG-TEST-001
        """
    ).lstrip("\n")


def test_load_probes_for_asi01_includes_bundled_jdg_probes() -> None:
    """Bundled JDG-* probes declaring asi=ASI01 must surface in the ASI01 dispatch."""
    probes = load_probes_for_asi(AsiCategory.ASI01)
    ids = {p.id for p in probes}
    # ASI01-declared judge probes per the corpus.
    assert "JDG-CAL-001" in ids
    assert "JDG-INJ-001" in ids
    assert "JDG-INJ-002" in ids


def test_load_probes_for_asi09_includes_cross_family_judge_probe() -> None:
    """The cross-family self-preference probe declares asi=ASI09 and must surface there."""
    probes = load_probes_for_asi(AsiCategory.ASI09)
    ids = {p.id for p in probes}
    assert "JDG-INJ-003" in ids


def test_load_probes_for_asi02_excludes_asi01_declared_judge_probes() -> None:
    """A judge probe declaring asi=ASI01 must NOT leak into other ASI dispatches."""
    probes = load_probes_for_asi(AsiCategory.ASI02)
    ids = {p.id for p in probes}
    assert "JDG-CAL-001" not in ids
    assert "JDG-INJ-001" not in ids
    assert "JDG-INJ-002" not in ids
    assert "JDG-INJ-003" not in ids


def test_load_probes_for_asi_is_idempotent() -> None:
    """Repeated calls return identical id sets (no per-call mutation)."""
    first = {p.id for p in load_probes_for_asi(AsiCategory.ASI01)}
    second = {p.id for p in load_probes_for_asi(AsiCategory.ASI01)}
    assert first == second


def test_load_probes_for_asi_handles_missing_judges_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Missing judges/ dir must NOT crash — returns asi probes only, with a warning."""
    # Build a fake corpus root with an asi01/ subdir but NO judges/ peer.
    asi01_dir = tmp_path / "asi01"
    asi01_dir.mkdir(parents=True)
    (asi01_dir / "p.yaml").write_text(
        dedent(
            """
            id: ASI01-GH-997
            name: stub
            asi: ASI01
            mitre_atlas:
              - AML.T0054
            csa_category: goal-instruction-manipulation
            severity: low
            tier_floor: T3
            seeds:
              - "stub seed"
            description: stub for the missing-judges-dir test
            expected_evidence: tool_call_to_unauthorized_destination
            remediation_ref: REM-ASI01-997
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )
    monkeypatch.setattr(loader_mod, "find_corpus_root", lambda: tmp_path)
    with caplog.at_level(logging.WARNING, logger="agent_guardian.probes.loader"):
        probes = load_probes_for_asi(AsiCategory.ASI01)
    assert [p.id for p in probes] == ["ASI01-GH-997"]


def test_load_probes_for_asi_handles_empty_judges_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty judges/ dir (no YAML files) is tolerated — no probes added, no crash."""
    asi01_dir = tmp_path / "asi01"
    asi01_dir.mkdir(parents=True)
    (asi01_dir / "p.yaml").write_text(
        dedent(
            """
            id: ASI01-GH-996
            name: stub
            asi: ASI01
            mitre_atlas:
              - AML.T0054
            csa_category: goal-instruction-manipulation
            severity: low
            tier_floor: T3
            seeds:
              - "stub seed"
            description: stub for the empty-judges-dir test
            expected_evidence: tool_call_to_unauthorized_destination
            remediation_ref: REM-ASI01-996
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )
    (tmp_path / "judges").mkdir()  # exists but empty
    monkeypatch.setattr(loader_mod, "find_corpus_root", lambda: tmp_path)
    probes = load_probes_for_asi(AsiCategory.ASI01)
    assert [p.id for p in probes] == ["ASI01-GH-996"]


def test_load_probes_for_asi_unions_synthetic_judges_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A synthetic judges/ peer with a JDG probe is unioned into the matching ASI."""
    asi01_dir = tmp_path / "asi01"
    asi01_dir.mkdir(parents=True)
    (asi01_dir / "p.yaml").write_text(
        dedent(
            """
            id: ASI01-GH-995
            name: stub
            asi: ASI01
            mitre_atlas:
              - AML.T0054
            csa_category: goal-instruction-manipulation
            severity: low
            tier_floor: T3
            seeds:
              - "stub seed"
            description: stub for the synthetic-judges-dir test
            expected_evidence: tool_call_to_unauthorized_destination
            remediation_ref: REM-ASI01-995
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )
    judges_dir = tmp_path / "judges"
    judges_dir.mkdir()
    (judges_dir / "j1.yaml").write_text(_judge_yaml("JDG-TEST-001", asi="ASI01"), encoding="utf-8")
    (judges_dir / "j2.yaml").write_text(_judge_yaml("JDG-TEST-002", asi="ASI09"), encoding="utf-8")
    monkeypatch.setattr(loader_mod, "find_corpus_root", lambda: tmp_path)
    asi01_probes = {p.id for p in load_probes_for_asi(AsiCategory.ASI01)}
    asi09_probes = {p.id for p in load_probes_for_asi(AsiCategory.ASI09)}
    assert asi01_probes == {"ASI01-GH-995", "JDG-TEST-001"}
    # JDG-TEST-002 declares ASI09 — it must appear only under ASI09.
    assert "JDG-TEST-002" in asi09_probes
    assert "JDG-TEST-001" not in asi09_probes
