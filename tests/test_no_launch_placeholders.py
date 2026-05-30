"""Launch-placeholder guard.

This test fails CI if any of the canonical governance / security files
still contain the placeholder phrases that were used during pre-launch
drafting. The package metadata declares Production/Stable; users
landing on PyPI clicking through to MAINTAINERS / SECURITY /
governance must NOT find a ``_to be published_`` or
``_to be filled at launch_`` row staring back at them.

Why is this a CI test instead of a one-shot edit? Because the file
shapes (Markdown tables, prose paragraphs, future on-call rows) will
be edited dozens of times over the life of the project — it is
embarrassingly easy to re-introduce a placeholder while drafting next
quarter's on-call rotation and ship it to PyPI before someone notices.
A single deterministic substring scan in CI catches that class of
regression for ~0 ms.

The needles are written exactly as the placeholders appeared in the
pre-launch drafts. We deliberately do NOT lower-case-fold or apply
regex normalization — false positives on legitimate prose ("this
field is pending review") would be more annoying than the regressions
this guard protects against.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_GOVERNANCE_FILES = (
    "MAINTAINERS.md",
    "SECURITY.md",
    "governance.md",
)

# Exact placeholder phrases the pre-launch drafts used. Each must be
# unique enough that legitimate prose does not collide — we keep them
# as full Markdown-emphasised strings (with underscores) for that reason.
_PLACEHOLDER_NEEDLES = (
    "_to be published_",
    "_pending_",
    "_to be filled at launch_",
    "pre-launch",
)


@pytest.mark.parametrize("relpath", _GOVERNANCE_FILES)
def test_governance_file_has_no_launch_placeholders(relpath: str) -> None:
    path = REPO_ROOT / relpath
    assert path.is_file(), f"governance file is missing: {relpath}"
    body = path.read_text(encoding="utf-8")
    offenders = [needle for needle in _PLACEHOLDER_NEEDLES if needle in body]
    assert not offenders, (
        f"{relpath} still contains pre-launch placeholders {offenders}. Fill in "
        f"the real values before tagging a release — see the file's own "
        f"'Onboarding note' for the procedure."
    )
