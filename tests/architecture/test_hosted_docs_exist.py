"""Architecture-doc presence tests (QA-003).

The hosted-dashboard architecture is captured in docs/, not implemented in
code. These tests guard against silent doc loss — if someone deletes the
file or rewrites it past recognition, the build fails loudly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_HOSTED_DOC = _REPO_ROOT / "docs" / "architecture" / "hosted-dashboard.md"
_MKDOCS = _REPO_ROOT / "mkdocs.yml"


def test_hosted_dashboard_doc_exists() -> None:
    assert _HOSTED_DOC.is_file(), f"missing architecture doc: {_HOSTED_DOC}"


@pytest.mark.parametrize(
    "section",
    [
        "Trust anchor",
        "Tenant model",
        "Auth flow",
        "Migration from local",
    ],
)
def test_hosted_dashboard_doc_has_required_sections(section: str) -> None:
    body = _HOSTED_DOC.read_text(encoding="utf-8")
    assert f"## {section}" in body, f"missing section: ## {section}"


def test_hosted_dashboard_doc_mentions_env_var() -> None:
    """The doc must reference the single env-var swap-point so operators
    know how to flip from local to hosted.
    """
    body = _HOSTED_DOC.read_text(encoding="utf-8")
    assert "AGENT_GUARDIAN_DASHBOARD_URL" in body


def test_hosted_dashboard_referenced_in_mkdocs_nav() -> None:
    nav = _MKDOCS.read_text(encoding="utf-8")
    assert "architecture/hosted-dashboard.md" in nav, (
        "hosted-dashboard.md must appear in mkdocs.yml nav (Concepts) so the "
        "doc is reachable from the published site"
    )


def test_hosted_doc_carries_status_marker() -> None:
    """Operators should be able to see at a glance that this is forward-
    looking documentation, not a shipping feature.
    """
    body = _HOSTED_DOC.read_text(encoding="utf-8")
    assert "Status" in body
    assert "Not yet deployed" in body or "not yet deployed" in body
