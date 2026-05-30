"""Guard the documented probe count against drift.

``docs/concepts/glossary.md`` and ``docs/research/preprint.md`` (renamed in the
Diátaxis restructure from ``docs/glossary.md`` and ``docs/arxiv-preprint.md``)
quote the size of the bundled probe corpus. The previous launch-review caught
both pages quoting ``50`` while the wheel had grown to ``90`` (corpus
``2026.05``). This test counts the real YAML probes shipped under
``src/agent_guardian/probes/`` and asserts both pages agree.

The glossary entry now anchors via the corpus *version* (``2026.05``) and a
source-of-truth link to ``PROBE_CORPUS_VERSION`` rather than re-stating the
raw count, because the count drifts more often than the corpus version. The
preprint still quotes both. We keep guards on both representations.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROBES_DIR = REPO_ROOT / "src" / "agent_guardian" / "probes"
GLOSSARY = REPO_ROOT / "docs" / "concepts" / "glossary.md"
ARXIV = REPO_ROOT / "docs" / "research" / "preprint.md"


def _count_probes() -> int:
    """Count YAML probes under any ``asi*`` sub-directory (the manifest lives in ``_meta``)."""

    count = 0
    for asi_dir in PROBES_DIR.glob("asi*"):
        if not asi_dir.is_dir():
            continue
        count += sum(1 for _ in asi_dir.glob("*.yaml"))
        count += sum(1 for _ in asi_dir.glob("*.yml"))
    return count


def test_real_corpus_has_at_least_92_probes() -> None:
    assert _count_probes() >= 92, (
        f"probe corpus has {_count_probes()} files — expected at least 92. "
        f"Update docs/glossary.md, docs/arxiv-preprint.md and this floor in lock-step."
    )


def test_glossary_quotes_real_probe_count() -> None:
    # The glossary now anchors the corpus by *version* (``2026.05``) plus a
    # source-of-truth link to ``PROBE_CORPUS_VERSION`` instead of restating
    # the count, but it must still pin the corpus version and never reintroduce
    # the historical "ships 50" wording.
    body = GLOSSARY.read_text(encoding="utf-8")
    assert "2026.05" in body, (
        "docs/concepts/glossary.md must reference the corpus version (2026.05)"
    )
    # Catch a regression to the historical "50" count.
    assert "ships 50" not in body, (
        "docs/concepts/glossary.md still says 'ships 50' — corpus has grown past that floor"
    )


def test_arxiv_quotes_real_probe_count() -> None:
    body = ARXIV.read_text(encoding="utf-8")
    real_count = _count_probes()
    assert str(real_count) in body, (
        f"docs/research/preprint.md does not mention the real probe count {real_count}"
    )
    assert "ships 50" not in body, (
        "docs/research/preprint.md still says 'ships 50' — corpus has grown past that floor"
    )


def test_corpus_version_token_in_arxiv() -> None:
    """The arxiv page should anchor the corpus version when quoting the count."""

    body = ARXIV.read_text(encoding="utf-8")
    assert "2026.05" in body, (
        "docs/research/preprint.md must reference the corpus version (2026.05) "
        "when quoting the count"
    )
