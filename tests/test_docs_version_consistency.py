"""GA-status / version-consistency guard.

Production/Stable in ``pyproject.toml`` means the public-facing surface
(README + docs/roadmap.md) must not still describe the project as
``pre-1.0`` or as a release candidate. The classifier is the single
source of truth for whether the project is GA; if it says
Production/Stable then any "pre-1.0" / "1.0.0rc1" wording outside the
**changelog history** is a contradiction users will reasonably hold
against us at launch.

The check has two layers:

1. If pyproject declares ``Development Status :: 5 - Production/Stable``,
   then ``README.md`` and ``docs/roadmap.md`` MUST NOT contain the
   strings ``pre-1.0`` or ``1.0.0rc1``. The changelog is allowed to
   reference the historical RC tag (that is what changelogs are for).
2. The package ``__version__`` and the ``CITATION.cff`` ``version`` field
   must agree — releasing 1.0.0 wheels with a 1.1.0 citation file would
   confuse the academic users we are explicitly targeting.

If you intentionally roll the project back to pre-GA, flip the
classifier first and these guards relax automatically.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_PRE_GA_NEEDLES = ("pre-1.0", "1.0.0rc1")
_GA_CLASSIFIER = "Development Status :: 5 - Production/Stable"
# Files that promise the GA story to users; the changelog is explicitly
# excluded — historical RC notes belong there. The roadmap moved from
# ``docs/roadmap.md`` to ``docs/reference/roadmap.md`` in the Diátaxis
# restructure. The README was removed from this list when README-content
# assertions were dropped project-wide: the README is treated as iterable
# marketing copy, not a tested artifact.
_GA_NARRATIVE_FILES = ("docs/reference/roadmap.md",)


def _pyproject_text() -> str:
    return (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _is_ga() -> bool:
    return _GA_CLASSIFIER in _pyproject_text()


@pytest.mark.parametrize("relpath", _GA_NARRATIVE_FILES)
def test_ga_narrative_has_no_prelaunch_wording(relpath: str) -> None:
    if not _is_ga():
        pytest.skip("project classifier is not Production/Stable; pre-GA wording is acceptable")
    body = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    offenders = [needle for needle in _PRE_GA_NEEDLES if needle in body]
    assert not offenders, (
        f"{relpath} still contains pre-GA wording {offenders} while pyproject "
        f"declares Production/Stable. Either update {relpath} to GA wording or "
        f"flip the classifier back to Beta."
    )


def test_changelog_keeps_historical_rc_tag_reference() -> None:
    """The 1.0.0rc1 tag is part of git history; the changelog must still link it."""

    body = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "[1.0.0rc1]" in body, "CHANGELOG must keep the historical 1.0.0rc1 anchor"
    assert "## [1.0.0]" in body, "CHANGELOG must contain a [1.0.0] GA section"


def test_version_matches_citation_cff() -> None:
    pkg_version_src = (REPO_ROOT / "src" / "agent_guardian" / "_version.py").read_text(
        encoding="utf-8"
    )
    match = re.search(r'__version__\s*=\s*"([^"]+)"', pkg_version_src)
    assert match, "_version.py is missing a __version__ assignment"
    pkg_version = match.group(1)

    cff = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    cff_match = re.search(r'^version:\s*"?([^"\n]+)"?\s*$', cff, re.MULTILINE)
    assert cff_match, "CITATION.cff is missing a version field"
    cff_version = cff_match.group(1).strip()

    assert pkg_version == cff_version, (
        f"CITATION.cff version {cff_version!r} disagrees with package __version__ "
        f"{pkg_version!r}; bump them together."
    )
