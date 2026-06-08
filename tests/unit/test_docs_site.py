"""Docs-site, Docker, and README infrastructure tests.

These tests verify the static deliverables — they do not run mkdocs,
mintlify, docker, or any external process. The goal is to catch
broken-nav and missing-file mistakes at PR time without adding a heavy
CI dependency.

History (2026-05-31): the docs site migrated from MkDocs (Material
theme) to Mintlify under QA-025. The MkDocs-specific assertions in this
module were removed; the surviving tests cover the Mintlify ``docs.json``
sanity, the README marketing/comparison sections, the Dockerfile, and
``docker-compose.yml``. The strict Mintlify build check runs out-of-band
via ``npx mintlify dev --validate`` before each docs push (see
``docs/site-deployment.md``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------- mintlify


def test_mintlify_docs_json_exists() -> None:
    assert (REPO_ROOT / "docs" / "docs.json").is_file()


def test_mintlify_docs_json_is_valid() -> None:
    data = json.loads((REPO_ROOT / "docs" / "docs.json").read_text(encoding="utf-8"))
    assert data["theme"] == "mint"
    # Product name rule (CLAUDE.md): exactly "AgentGuardian", never
    # "AgentGuardian Open".
    assert data["name"] == "AgentGuardian"
    assert "navigation" in data
    groups = data["navigation"]["groups"]
    assert len(groups) >= 5, "expected at least 5 navigation groups"


def test_mintlify_nav_pages_resolve_on_disk() -> None:
    """Every page slug listed in ``docs.json`` navigation must exist as an
    ``.mdx`` file under ``docs/``. Catches the slug/disk drift class of bug
    that broke the QA-025 first deploy (``try/scan-docker`` vs
    ``try/scan-with-docker``)."""
    data = json.loads((REPO_ROOT / "docs" / "docs.json").read_text(encoding="utf-8"))

    def _collect(groups: list[dict]) -> list[str]:
        pages: list[str] = []
        for g in groups:
            for p in g.get("pages", []):
                if isinstance(p, str):
                    pages.append(p)
                elif isinstance(p, dict):
                    pages.extend(_collect([p]))
        return pages

    slugs = _collect(data["navigation"]["groups"])
    docs_dir = REPO_ROOT / "docs"
    missing = [s for s in slugs if not (docs_dir / f"{s}.mdx").is_file()]
    assert not missing, f"nav slugs point at non-existent MDX files: {missing}"


# --------------------------------------------------------------------- readme


def test_readme_has_marketing_sections() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for needle in (
        "AgentGuardian",
        "Quickstart",
        "License",
    ):
        assert needle in readme, f"README missing section: {needle}"


def test_comparison_page_lists_competitors() -> None:
    # The competitor comparison moved out of the README into its own docs page
    # (docs/concepts/agent-guardian-vs.mdx). The positioning guard follows it:
    # the page must still name every competitor we compare against.
    page = (REPO_ROOT / "docs" / "concepts" / "agent-guardian-vs.mdx").read_text(encoding="utf-8")
    for vendor in ("PyRIT", "garak", "Promptfoo", "Inspect", "DeepTeam"):
        assert vendor in page, f"comparison page missing {vendor}"


def test_readme_documents_coverage_standards() -> None:
    # The README's "What AgentGuardian catches" section maps to the published
    # standards in plain language; the per-ASI taxonomy + swarm diagram moved to
    # docs (framework-coverage-matrix.md). Guard that the README still names the
    # standards and links the coverage matrix so coverage stays discoverable.
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for needle in ("OWASP", "MITRE ATLAS", "CSA", "framework-coverage-matrix"):
        assert needle in readme, f"README coverage section missing {needle}"


def test_readme_product_name_lint() -> None:
    """CLAUDE.md product-name rule applied to the published README: the
    project is exactly ``AgentGuardian`` (one word), never the discontinued
    ``AgentGuardian Open`` variant."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "AgentGuardian Open" not in readme


# --------------------------------------------------------------------- docker


def test_dockerfile_exists_and_has_correct_base_image() -> None:
    dockerfile = REPO_ROOT / "Dockerfile"
    assert dockerfile.is_file()
    body = dockerfile.read_text(encoding="utf-8")
    # Strip comment lines so we only inspect the active FROM instruction.
    active = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
    # Accept either the legacy `python:3.11-slim` tag or a SHA-256 digest pin with a
    # trailing `# 3.11-slim` comment (OpenSSF Scorecard §2.4 pinned-dependencies form).
    assert re.search(
        r"^FROM\s+python(?::3\.11-slim|@sha256:[0-9a-f]{64}\s+#\s*3\.11-slim)",
        active,
        re.MULTILINE,
    )
    assert "libpango-1.0-0" in body
    assert "ENTRYPOINT" in body
    assert "agent-guardian" in body
    assert "EXPOSE 7474" in body


def test_dockerignore_lists_key_paths() -> None:
    path = REPO_ROOT / ".dockerignore"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    for needle in (".git", ".venv", "__pycache__", "dist", ".pytest_cache"):
        assert needle in body, f".dockerignore missing {needle}"


def test_docker_compose_serves_dashboard() -> None:
    path = REPO_ROOT / "docker-compose.yml"
    assert path.is_file()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    svc = data["services"]["agentguardian"]
    assert "7474:7474" in svc["ports"]
    assert svc["command"][0] == "serve"
