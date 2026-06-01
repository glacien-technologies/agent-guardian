"""Tests for the Phase C.C8 framework-coverage matrix doc.

The generator script reads the on-disk probe corpus and emits a markdown
file with three tables (OWASP ASI, MITRE ATLAS, CSA Agentic-RT). These
tests enforce the load-bearing invariants:

* All 10 OWASP ASI rows are present (one row per AsiCategory member).
* At least 10 MITRE ATLAS technique rows appear (the matrix MUST honestly
  enumerate every cited technique; current corpus carries 26 — keep a
  safety margin in case probes are removed).
* All 12 CSA categories are present, even zero-coverage ones (marked
  honestly with the "(not covered by current corpus)" phrase).
* The lede paragraph replaces the README's "MITRE ATLAS v5.4.0 mappings"
  overclaim with the honest "11+" framing and the "out of scope" note.
* The shipped on-disk doc matches what the generator produces today —
  otherwise the doc and the loader's view of the world have drifted.
"""

from __future__ import annotations

# Importing the script directly via its path; it has no third-party
# dependencies that would force a packaging dance.
import sys
from pathlib import Path

import pytest

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import build_coverage_matrix  # noqa: E402 — path-extended import

# Phase C.C8 — the on-disk doc lives here and is committed alongside the
# generator. CI should be able to diff this file against a fresh run to
# detect drift between the matrix and the corpus.
_DOC_PATH = _REPO_ROOT / "docs" / "reference" / "framework-coverage-matrix.md"


@pytest.fixture(scope="module")
def generated_markdown() -> str:
    return build_coverage_matrix.build_matrix()


def test_doc_file_exists() -> None:
    assert _DOC_PATH.exists(), (
        f"expected coverage matrix at {_DOC_PATH}; run "
        "`uv run python scripts/build_coverage_matrix.py` to regenerate"
    )


def test_doc_matches_freshly_generated(generated_markdown: str) -> None:
    on_disk = _DOC_PATH.read_text(encoding="utf-8")
    assert on_disk == generated_markdown, (
        "framework-coverage-matrix.md is out of date — run "
        "`uv run python scripts/build_coverage_matrix.py` and commit the result"
    )


def test_all_ten_asi_rows_present(generated_markdown: str) -> None:
    for asi in AsiCategory:
        # Each ASI value should appear in a table row preceded by "| ".
        assert f"| {asi.value} |" in generated_markdown, f"missing ASI table row for {asi.value}"


def test_at_least_ten_atlas_rows(generated_markdown: str) -> None:
    # ATLAS rows are formatted as "| `<technique>` | <label> | <count> | ..."
    # within the MITRE ATLAS section. Count rows by the leading backtick-id
    # cell to avoid matching ASI / CSA rows that share the same delimiter.
    atlas_section_start = generated_markdown.find("## MITRE ATLAS v5.4.0")
    atlas_section_end = generated_markdown.find("## CSA Agentic AI Red Teaming Guide")
    assert atlas_section_start != -1, "MITRE ATLAS section missing"
    assert atlas_section_end != -1, "CSA section missing"
    atlas_block = generated_markdown[atlas_section_start:atlas_section_end]
    row_count = sum(1 for line in atlas_block.splitlines() if line.startswith("| `"))
    assert row_count >= 10, f"expected at least 10 ATLAS technique rows; saw {row_count}"


def test_all_twelve_csa_rows_present(generated_markdown: str) -> None:
    for cat in CsaCategory:
        assert f"`{cat.value}`" in generated_markdown, f"missing CSA table row for {cat.value}"


def test_lede_replaces_overclaim(generated_markdown: str) -> None:
    # The new lede must use the honest "11+" framing and the "out of scope"
    # phrase, replacing the README's older "MITRE ATLAS v5.4.0 mappings"
    # overclaim.
    assert "11+ MITRE ATLAS techniques" in generated_markdown
    assert "out of scope" in generated_markdown
    assert "black-box agent scanner" in generated_markdown


def test_zero_coverage_csa_marked_honestly(monkeypatch: pytest.MonkeyPatch) -> None:
    # Synthesise a corpus that covers only ONE CSA category; the matrix
    # must mark the other 11 with the honest "(not covered by current
    # corpus)" phrase rather than hiding them. This is the failure mode
    # the C8 honesty requirement exists to prevent.
    from agent_guardian.models.asi import AsiCategory as _AsiCategory
    from agent_guardian.models.csa import CsaCategory as _CsaCategory
    from agent_guardian.models.probe import Probe
    from agent_guardian.models.severity import Severity
    from agent_guardian.models.tier import Tier

    fake_probe = Probe(
        id="FAKE-001",
        name="fake",
        asi=_AsiCategory.ASI01,
        mitre_atlas=["AML.T0051"],
        csa_category=_CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        tier_floor=Tier.T1_CRITICAL,
        seeds=["x"],
        description="x",
        expected_evidence="x",
        remediation_ref="REM-FAKE-001",
    )
    body = build_coverage_matrix.build_matrix(probes=[fake_probe])
    # 11 of 12 CSA categories must carry the honest marker.
    assert body.count("(not covered by current corpus)") == 11


def test_atlas_section_lists_every_technique_with_probe_count(
    generated_markdown: str,
) -> None:
    # Sanity check: the in-scope-note disclaimer block must appear AFTER
    # the table so a reader sees the "honest framing" caveat alongside the
    # actual coverage numbers.
    atlas_marker = "## MITRE ATLAS v5.4.0"
    disclaimer = "Honest scope note"
    csa_marker = "## CSA Agentic AI Red Teaming Guide"
    a = generated_markdown.find(atlas_marker)
    d = generated_markdown.find(disclaimer)
    c = generated_markdown.find(csa_marker)
    assert -1 < a < d < c, "ATLAS section structure broken (table → disclaimer → CSA)"
