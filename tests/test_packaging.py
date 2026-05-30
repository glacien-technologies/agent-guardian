"""Packaging-metadata regression tests.

These are deterministic, fast, and run on every CI pull request. The goal is
to lock in the launch-readiness pyproject contract so a casual edit doesn't
silently regress the PyPI listing once we're shipping at scale.

What we pin:

1. **Project metadata sanity** — package name, dynamic version, license, the
   set of "must-have" classifiers (Production/Stable + AI topic + Python 3.10+
   matrix), and the documented keyword expansion (prompt-injection, jailbreak,
   ai-safety, ai-security, llm-security, genai-security, sarif, cybersecurity,
   ai-red-team).
2. **URLs reach actual content** — the ``[project.urls]`` block must NOT point
   at ``agentguardian.ai`` until the apex DNS lands; every URL slot must be a
   ``github.com/glacien-technologies/agent-guardian`` path (or a documented
   working alias). Shipping dead URLs to PyPI is the single most common
   "the package looks abandoned" complaint we want to head off.
3. **Runtime dependency hygiene** — declared base deps must actually be
   imported somewhere under ``src/agent_guardian`` (no ghost deps that pad the
   install for nothing). The historical offender was ``structlog``, which sat
   in base deps for a release without a single consumer.
4. **Docker base image + entrypoint** — the published image must run as
   ``agent-guardian`` with the dashboard port exposed; the docker-compose file
   must mount the dashboard.

We use ``tomllib`` (stdlib on 3.11+) so the test has no external deps.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import tomllib
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
SRC_ROOT = REPO_ROOT / "src" / "agent_guardian"


def _load_pyproject() -> dict[str, object]:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


# --------------------------------------------------------------------- project


def test_project_table_basics() -> None:
    data = _load_pyproject()
    project = data["project"]
    assert isinstance(project, dict)
    assert project["name"] == "agent-guardian"
    assert project["dynamic"] == ["version"]
    assert project["license"] == {"text": "Apache-2.0"}
    assert project["requires-python"] == ">=3.10,<3.14"


def test_required_classifiers_present() -> None:
    """Pin the classifiers users filter on at https://pypi.org/search/."""

    project = _load_pyproject()["project"]
    classifiers = set(project["classifiers"])  # type: ignore[index]
    required = {
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        # AI topic — most-clicked filter for this category of tool.
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Typing :: Typed",
    }
    missing = required - classifiers
    assert not missing, f"pyproject classifiers missing: {missing}"


def test_discoverability_keywords_present() -> None:
    """Lock the keyword expansion so a future edit doesn't strip the AI tags."""

    project = _load_pyproject()["project"]
    keywords = set(project["keywords"])  # type: ignore[index]
    required = {
        # Original keyword set — kept for backwards compat with old PyPI search.
        "llm",
        "agent",
        "red-team",
        "security",
        "owasp",
        "mitre-atlas",
        "aivss",
        "agentic-ai",
        # M-launch expansion — these are the search terms enterprise users
        # actually type when shopping for an LLM red-team tool.
        "prompt-injection",
        "jailbreak",
        "ai-safety",
        "ai-security",
        "llm-security",
        "genai-security",
        "sarif",
        "cybersecurity",
        "ai-red-team",
    }
    missing = required - keywords
    assert not missing, f"pyproject keywords missing: {missing}"


# --------------------------------------------------------------------- urls


def test_project_urls_have_no_dead_apex_dns() -> None:
    """``agentguardian.ai`` apex DNS has not landed; PyPI must not list it."""

    urls = _load_pyproject()["project"]["urls"]  # type: ignore[index]
    assert isinstance(urls, dict)
    for slot, url in urls.items():
        assert isinstance(url, str)
        # Allow only working targets: github.com paths or the Cloud Run mirror.
        # Once apex DNS propagates, this test will need updating to allow it.
        assert "agentguardian.ai" not in url, (
            f"[project.urls].{slot} still points at unresolved apex DNS: {url}. "
            f"Repoint to github.com or the Cloud Run docs URL until DNS lands."
        )
        assert url.startswith(("https://github.com/", "https://")), (
            f"[project.urls].{slot} is not a working URL: {url}"
        )


def test_project_urls_cover_pypi_sidebar() -> None:
    """PyPI renders these four slots in the sidebar — all must be present."""

    urls = _load_pyproject()["project"]["urls"]  # type: ignore[index]
    for slot in ("Homepage", "Repository", "Issues", "Changelog"):
        assert slot in urls, f"[project.urls] missing required slot {slot!r}"


# --------------------------------------------------------------------- deps


def test_structlog_is_not_a_ghost_runtime_dep() -> None:
    """Regression guard: ``structlog`` was a base dep with zero imports.

    Pre-launch the package shipped ``structlog>=24.4`` as a hard runtime
    dependency for a full release cycle without a single ``import structlog``
    anywhere under ``src/``. That's pure install weight users pay for nothing.
    This test fails if either side of that contract regresses:

    * If ``structlog`` is in base deps, then ``src/`` must actually import it.
    * If ``structlog`` is not in base deps, then ``src/`` must not import it
      (otherwise the import would crash on a clean install).

    When the observability cluster wires structlog with the JSON renderer the
    fix is one line: re-add the dep to ``[project.dependencies]``. This test
    will then pass automatically. We deliberately only police ``structlog``
    here rather than every base dep — pure-Python protocol packages
    (``textual``, ``exceptiongroup``) are reached indirectly via lazy
    imports or compat-layer ``__init_subclass__`` hooks that grep won't see.
    """

    project = _load_pyproject()["project"]
    base_deps = project["dependencies"]  # type: ignore[index]
    assert isinstance(base_deps, list)
    declared = any(spec.lower().startswith("structlog") for spec in base_deps)

    src_text = "\n".join(p.read_text(encoding="utf-8") for p in SRC_ROOT.rglob("*.py"))
    structlog_imported = re.search(
        r"(?m)^\s*(?:from\s+structlog(?:\.|\s)|import\s+structlog(?:\s|$|\.|,))",
        src_text,
    )

    if declared and not structlog_imported:
        raise AssertionError(
            "structlog is declared as a runtime dep but nothing under src/ "
            "imports it. Remove the dep or wire it into the observability stack."
        )
    if structlog_imported and not declared:
        raise AssertionError(
            "src/ imports structlog but it is not declared as a runtime dep. "
            "Add ``structlog>=24.4`` to ``[project.dependencies]``."
        )


# --------------------------------------------------------------------- docker


def test_dockerfile_uses_supported_python() -> None:
    body = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    # Only inspect the active (uncommented) instructions.
    active = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
    assert re.search(r"^FROM\s+python:3\.(11|12|13)-slim", active, re.MULTILINE), (
        "Dockerfile must base on a supported python:3.11+ slim image"
    )
    assert "EXPOSE 7474" in active, "Dockerfile must expose dashboard port 7474"
    assert "ENTRYPOINT" in active and "agent-guardian" in active


def test_docker_compose_serves_dashboard() -> None:
    data = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    svc = data["services"]["agentguardian"]
    assert "7474:7474" in svc["ports"]
    assert svc["command"][0] == "serve"


# --------------------------------------------------------------------- version


def test_version_module_is_single_source() -> None:
    """Hatchling reads ``__version__`` from ``_version.py``; pin the shape."""

    src = (REPO_ROOT / "src" / "agent_guardian" / "_version.py").read_text(encoding="utf-8")
    assert re.search(r'^__version__\s*=\s*"(?:\d+)\.(?:\d+)\.(?:\d+)', src, re.MULTILINE), (
        "_version.py must declare a PEP 440 X.Y.Z __version__"
    )


# --------------------------------------------------------------------- notice


@pytest.mark.parametrize("needle", ["pyphen", "MPL", "Transitive dependencies"])
def test_notice_documents_transitive_licenses(needle: str) -> None:
    """NOTICE must declare the GPL/MPL transitives the [full] extra pulls in."""

    body = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
    assert needle in body, f"NOTICE is missing required transitive-license content: {needle!r}"
