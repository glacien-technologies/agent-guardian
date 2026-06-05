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


def test_comparison_page_does_not_imply_nist_rmf_alignment_for_agent_guardian() -> None:
    """Comparison page — the AgentGuardian row must NOT carry NIST RMF.

    The competitor comparison table moved out of the README into its own docs
    page (``docs/concepts/agent-guardian-vs.mdx``); this NIST-positioning guard
    follows it. The core invariant is unchanged: AgentGuardian itself must not
    imply NIST RMF alignment. How OTHER tools are described — e.g. whether the
    PyRIT row reads "NIST AI RMF (partial)" — is the page's editorial call and is
    not asserted here.
    """
    page = (_REPO_ROOT / "docs" / "concepts" / "agent-guardian-vs.mdx").read_text(encoding="utf-8")
    table_lines = [ln for ln in page.splitlines() if ln.startswith("|")]
    assert table_lines, "comparison table not found on the comparison page"
    # The AgentGuardian row contains the literal '**AgentGuardian**' cell.
    ag_rows = [ln for ln in table_lines if "**AgentGuardian**" in ln]
    assert ag_rows, "AgentGuardian row missing from comparison table"
    for row in ag_rows:
        assert "NIST" not in row, (
            f"AgentGuardian comparison row must not imply NIST alignment; row was: {row}"
        )


@pytest.mark.parametrize(
    "rel_path",
    [
        "docs/reference/roadmap.md",
    ],
)
def test_docs_nist_sp800_218a_not_advertised(rel_path: str) -> None:
    """Roadmap — any NIST AI RMF mention must carry a deferral qualifier.

    The legacy mkdocs tree (`docs.legacy/`) was removed once the Mintlify
    migration landed; the invariant now lives against the canonical
    Mintlify roadmap. The companion `threat-model.md` no longer exists in
    the canonical tree — when it returns under `docs/security/`, add it
    back to the parametrize list.
    """
    text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
    # Walk every paragraph that mentions NIST AI RMF and confirm it carries
    # one of the deferral qualifiers.
    for paragraph in text.split("\n"):
        if "NIST AI RMF" not in paragraph:
            continue
        assert "pending ratification" in paragraph or "deferred" in paragraph, (
            f"file {rel_path} mentions NIST AI RMF without deferral qualifier: {paragraph!r}"
        )
