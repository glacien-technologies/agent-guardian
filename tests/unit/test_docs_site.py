"""M14 docs-site and Docker infrastructure tests.

These tests verify the static deliverables of M14 — they do not run
mkdocs, docker, or any external process. The goal is to catch
broken-nav and missing-file mistakes at PR time without adding a heavy
CI dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------- helpers


def _collect_nav_paths(nav: list[object]) -> list[str]:
    """Recursively collect every Markdown file referenced in an mkdocs nav."""

    paths: list[str] = []
    for entry in nav:
        if isinstance(entry, dict):
            for value in entry.values():
                if isinstance(value, str):
                    paths.append(value)
                elif isinstance(value, list):
                    paths.extend(_collect_nav_paths(value))
        elif isinstance(entry, str):
            paths.append(entry)
    return paths


# --------------------------------------------------------------------- mkdocs


def test_mkdocs_yml_exists() -> None:
    assert (REPO_ROOT / "mkdocs.yml").is_file()


def test_mkdocs_yml_is_valid_yaml() -> None:
    raw = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    # mkdocs uses custom tags (!!python/name, etc.) but we only need
    # structural keys, so SafeLoader is sufficient for this corpus.
    data = yaml.safe_load(raw)
    assert isinstance(data, dict)
    assert data.get("site_name") == "AgentGuardian"
    assert "nav" in data
    assert "theme" in data
    assert data["theme"]["name"] == "material"


def test_mkdocs_nav_targets_all_exist() -> None:
    data = yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
    nav_paths = _collect_nav_paths(data["nav"])
    assert nav_paths, "expected at least one nav entry"
    docs_dir = REPO_ROOT / "docs"
    missing = [p for p in nav_paths if not (docs_dir / p).is_file()]
    assert not missing, f"nav entries point at non-existent docs: {missing}"


def test_mkdocs_nav_covers_required_pages() -> None:
    data = yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
    nav_paths = set(_collect_nav_paths(data["nav"]))
    # The docs were reorganised into Diátaxis-style buckets (concepts /
    # tutorials / how-to / reference / integrations / operations /
    # security / contributing). Old flat-namespace paths still resolve via
    # the mkdocs-redirects plugin (see ``mkdocs.yml`` plugins section), but
    # this nav-coverage guard tracks the *new* canonical locations.
    required = {
        "index.md",
        "concepts/why.md",
        "tutorials/quickstart.md",
        "concepts/architecture.md",
        "concepts/aivss.md",
        "integrations/adapters/index.md",
        "how-to/scan-a-system-prompt.md",
        "how-to/scan-python-source.md",
        "how-to/scan-an-http-endpoint.md",
        "integrations/adapters/framework.md",
        "reference/api/index.md",
        "security/ethics.md",
        "reference/roadmap.md",
    }
    assert required.issubset(nav_paths)


# --------------------------------------------------------------------- docs


@pytest.mark.parametrize(
    "relpath",
    [
        "index.md",
        "concepts/why.md",
        "tutorials/quickstart.md",
        "concepts/architecture.md",
        "concepts/aivss.md",
        "integrations/adapters/index.md",
        "how-to/scan-a-system-prompt.md",
        "how-to/scan-python-source.md",
        "how-to/scan-an-http-endpoint.md",
        "integrations/adapters/framework.md",
        "reference/api/index.md",
        "security/ethics.md",
        "reference/roadmap.md",
    ],
)
def test_docs_pages_are_nonempty(relpath: str) -> None:
    path = REPO_ROOT / "docs" / relpath
    assert path.is_file(), f"missing docs page: {relpath}"
    body = path.read_text(encoding="utf-8")
    # Every page should at least have a top-level H1 and a paragraph.
    assert re.search(r"^#\s+\S", body, re.MULTILINE), f"{relpath} lacks an H1"
    assert len(body.strip()) > 120, f"{relpath} is suspiciously short"


def test_ethics_page_contains_authorised_use_clause() -> None:
    """The PRD §15.6 ethical-use clause is load-bearing — pin its wording.

    Ethics doc moved from ``docs/ethics.md`` to ``docs/security/ethics.md``
    in the Diátaxis restructure. The clause itself is unchanged.
    """

    body = (REPO_ROOT / "docs" / "security" / "ethics.md").read_text(encoding="utf-8")
    assert "for testing systems you own or are explicitly" in body
    assert "unlawful in most jurisdictions" in body


def test_aivss_formula_page_has_worked_example() -> None:
    # AIVSS formula doc moved from ``docs/aivss-formula.md`` to
    # ``docs/concepts/aivss.md``. The worked example pins the fixture's
    # expected_aivss (89) from tests/golden/aivss_regression/good_t1.json.
    # See tests/unit/test_docs_aivss_example.py for the live-recompute guard.
    body = (REPO_ROOT / "docs" / "concepts" / "aivss.md").read_text(encoding="utf-8")
    assert "good_t1.json" in body
    assert "89" in body


def test_glossary_exists_and_lists_aivss_term() -> None:
    # Glossary moved from ``docs/glossary.md`` to ``docs/concepts/glossary.md``.
    glossary = (REPO_ROOT / "docs" / "concepts" / "glossary.md").read_text(encoding="utf-8")
    assert "AIVSS" in glossary
    assert "ASI" in glossary
    assert "PAIR" in glossary
    assert "MITRE ATLAS" in glossary


# --------------------------------------------------------------------- readme


def test_readme_has_marketing_sections() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for needle in (
        "AgentGuardian",
        "Why",
        "Quickstart",
        "Architecture",
        "Roadmap",
        "License",
        "Trademark",
    ):
        assert needle in readme, f"README missing section: {needle}"


def test_readme_has_comparison_table() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # Quick markers — the comparison row must mention PyRIT, garak, etc.
    for vendor in ("PyRIT", "garak", "Promptfoo", "Inspect", "DeepTeam"):
        assert vendor in readme, f"README comparison table missing {vendor}"


def test_readme_embeds_swarm_diagram() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # All ten ASI categories should appear in the embedded diagram.
    for asi in (f"ASI{n:02d}" for n in range(1, 11)):
        assert asi in readme, f"README architecture diagram missing {asi}"


# --------------------------------------------------------------------- docker


def test_dockerfile_exists_and_has_correct_base_image() -> None:
    dockerfile = REPO_ROOT / "Dockerfile"
    assert dockerfile.is_file()
    body = dockerfile.read_text(encoding="utf-8")
    # Strip comment lines so we only inspect the active FROM instruction.
    active = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
    assert re.search(r"^FROM\s+python:3\.11-slim", active, re.MULTILINE)
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


# --------------------------------------------------------------------- ci


def test_docs_workflow_exists_and_targets_main() -> None:
    workflow = REPO_ROOT / ".github" / "workflows" / "docs.yml"
    assert workflow.is_file()
    data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    # PyYAML parses bare `on:` as Python True on Python <3.12 without
    # custom loaders. Accept either key form to stay compatible.
    triggers = data.get("on") or data.get(True)
    assert triggers is not None, "workflow has no triggers"
    assert "main" in triggers["push"]["branches"]
    jobs = data["jobs"]
    assert "docs" in jobs
    steps_yaml = yaml.safe_dump(jobs["docs"]["steps"])
    assert "mkdocs-material" in steps_yaml
    assert "gh-deploy" in steps_yaml


# --------------------------------------------------------------------- pyproject


def test_pyproject_has_docs_extra() -> None:
    pyproject = REPO_ROOT / "pyproject.toml"
    body = pyproject.read_text(encoding="utf-8")
    assert "docs = [" in body
    assert "mkdocs-material" in body
    assert "mkdocs>=1.6" in body
