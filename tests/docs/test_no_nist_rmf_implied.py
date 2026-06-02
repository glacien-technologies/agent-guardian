"""Phase A.A5 — docs-only audit that AgentGuardian does NOT imply NIST RMF alignment.

DECISIONS directive: stay silent on NIST SP 800-218A until ratified. The
README must not imply AgentGuardian carries NIST RMF alignment; the
roadmap and threat-model must qualify any forward-looking NIST RMF
mention as pending / deferred.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_readme_does_not_imply_nist_rmf_alignment_for_agent_guardian() -> None:
    """README — AgentGuardian row must NOT carry NIST RMF, PyRIT row must read PyRIT risk taxonomy."""
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # Locate the comparison table block.
    lines = readme.splitlines()
    table_lines = [ln for ln in lines if ln.startswith("|")]
    assert table_lines, "comparison table not found in README"
    # The AgentGuardian row contains the literal '**AgentGuardian**' cell.
    ag_rows = [ln for ln in table_lines if "AgentGuardian" in ln]
    assert ag_rows, "AgentGuardian row missing from comparison table"
    for row in ag_rows:
        assert "NIST" not in row, (
            f"AgentGuardian comparison row must not imply NIST alignment; row was: {row}"
        )
    # The PyRIT row must now describe its own risk taxonomy, not NIST RMF.
    pyrit_rows = [ln for ln in table_lines if "PyRIT" in ln]
    assert pyrit_rows, "PyRIT row missing from comparison table"
    for row in pyrit_rows:
        assert "PyRIT risk taxonomy" in row, (
            f"PyRIT row must read 'PyRIT risk taxonomy'; row was: {row}"
        )
        assert "NIST AI RMF (partial)" not in row, (
            f"PyRIT row must no longer claim 'NIST AI RMF (partial)'; row was: {row}"
        )


@pytest.mark.parametrize(
    "rel_path",
    [
        "docs.legacy/reference/roadmap.md",
        "docs.legacy/security/threat-model.md",
    ],
)
def test_docs_nist_sp800_218a_not_advertised(rel_path: str) -> None:
    """Roadmap + threat-model — any NIST AI RMF mention must carry a deferral qualifier."""
    text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
    # Walk every paragraph that mentions NIST AI RMF and confirm it carries
    # one of the deferral qualifiers.
    for paragraph in text.split("\n"):
        if "NIST AI RMF" not in paragraph:
            continue
        assert "pending ratification" in paragraph or "deferred" in paragraph, (
            f"file {rel_path} mentions NIST AI RMF without deferral qualifier: {paragraph!r}"
        )
