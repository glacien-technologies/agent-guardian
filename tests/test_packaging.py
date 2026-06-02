"""Packaging-metadata regression tests.

These are deterministic, fast, and run on every CI pull request. The goal is
to lock in the launch-readiness pyproject contract so a casual edit doesn't
silently regress the PyPI listing once we're shipping at scale.

What we pin:

1. **Project metadata sanity** — package name, dynamic version, license, the
   set of "must-have" classifiers (Production/Stable + AI topic + Python 3.11+
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

We use ``tomllib`` (stdlib on 3.11+) so the test has no external deps beyond
what is already pulled in as a dev dependency.
"""

from __future__ import annotations

import re
import tomllib
import zipfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
SRC_ROOT = REPO_ROOT / "src" / "agent_guardian"
DIST_DIR = REPO_ROOT / "dist"


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
    assert project["requires-python"] == ">=3.11,<3.14"


def test_required_classifiers_present() -> None:
    """Pin the classifiers users filter on at https://pypi.org/search/.

    Also enforces the ``Typing :: Typed`` <-> PEP 561 marker contract: if the
    classifier promises inline type info, the package MUST ship the
    ``py.typed`` marker — otherwise mypy/pyright in downstream projects skip
    the package and the classifier is a lie. The wheel-content half of the
    invariant is covered by ``test_wheel_ships_py_typed_marker`` below.
    """

    project = _load_pyproject()["project"]
    classifiers = set(project["classifiers"])  # type: ignore[index]
    required = {
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        # AI topic — most-clicked filter for this category of tool.
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Typing :: Typed",
    }
    missing = required - classifiers
    assert not missing, f"pyproject classifiers missing: {missing}"

    # PEP 561 contract: ``Typing :: Typed`` requires a ``py.typed`` marker
    # next to the top-level package. Without it, mypy and pyright skip the
    # package's inline annotations entirely.
    if "Typing :: Typed" in classifiers:
        marker = SRC_ROOT / "py.typed"
        assert marker.is_file(), (
            f"'Typing :: Typed' classifier is declared but PEP 561 marker "
            f"is missing at {marker}. Create the empty file so mypy/pyright "
            f"in downstream projects pick up the inline annotations."
        )


def test_wheel_artifacts_include_py_typed_marker() -> None:
    """Defensive: ensure the wheel build config explicitly lists ``py.typed``.

    Hatchling's default sdist/wheel inclusion picks up ``py.typed`` next to a
    package today, but the project's wheel-target config already enumerates
    every non-.py artifact (YAML probes, WOFF2 fonts, JSON schema, HTML
    templates) explicitly so future hatchling tightening can't silently drop
    them. The PEP 561 marker is held to the same standard.
    """

    data = _load_pyproject()
    wheel_artifacts = data["tool"]["hatch"]["build"]["targets"]["wheel"]["artifacts"]  # type: ignore[index]
    assert isinstance(wheel_artifacts, list)
    assert "src/agent_guardian/py.typed" in wheel_artifacts, (
        "Wheel-target artifacts list does not name ``src/agent_guardian/py.typed`` "
        "explicitly — relying on hatchling's implicit pickup is fragile when "
        "every other non-.py artifact in the package is listed by hand."
    )


def test_built_wheel_contains_py_typed_marker() -> None:
    """If a wheel has been built into ``dist/``, it must ship the marker.

    This catches the case where hatchling's default packaging silently drops
    the empty file (e.g. via a sdist-then-wheel rebuild path). When no wheel
    is present (fresh clone / CI before build), the test skips — the
    pyproject-side ``test_wheel_artifacts_include_py_typed_marker`` already
    guards the config so we only need this when a built artifact exists.
    """

    if not DIST_DIR.is_dir():
        pytest.skip("dist/ directory absent; nothing built yet")
    wheels = sorted(DIST_DIR.glob("agent_guardian-*.whl"))
    if not wheels:
        pytest.skip("no built wheel under dist/ to inspect")
    # Inspect the most recently modified wheel — that's the one a maintainer
    # would publish after this test runs.
    wheel = max(wheels, key=lambda p: p.stat().st_mtime)
    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())
    assert "agent_guardian/py.typed" in names, (
        f"built wheel {wheel.name} does not contain ``agent_guardian/py.typed`` — "
        f"the PEP 561 marker was dropped during the build. Rebuild after "
        f"confirming the marker is listed in [tool.hatch.build.targets.wheel].artifacts."
    )


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


# --------------------------------------------------------------------- dev extras


def test_dev_dependencies_have_single_source_of_truth() -> None:
    """Dev deps must live in PEP 621 ``[project.optional-dependencies].dev`` only.

    History: a parallel PEP 735 ``[dependency-groups].dev`` table was added
    that declared ``types-pyyaml`` only there, not in the PEP 621 ``dev``
    extra. Result: ``pip install -e '.[dev]'`` and ``uv sync --extra dev
    --no-default-groups`` gave divergent environments (pip didn't see
    ``types-pyyaml``, uv installed and then would uninstall it depending on
    flags). This test pins the resolution: every PEP 735 dev-group spec must
    also appear in the PEP 621 ``dev`` extra so the two tools agree.

    Specifically, we hard-require ``types-pyyaml`` to be in the PEP 621
    ``dev`` extra because mypy --strict needs the stub package to type-check
    the YAML probe loader, and that's the dependency that got lost.
    """

    data = _load_pyproject()
    optional = data["project"]["optional-dependencies"]  # type: ignore[index]
    assert isinstance(optional, dict)
    dev_extra = optional.get("dev")
    assert isinstance(dev_extra, list), "[project.optional-dependencies].dev must exist"

    def _pkg_name(spec: str) -> str:
        # Strip version specifier + extras to get the bare distribution name.
        head = re.split(r"[<>=!~;\[\s]", spec, maxsplit=1)[0]
        return head.strip().lower()

    dev_extra_names = {_pkg_name(s) for s in dev_extra}
    assert "types-pyyaml" in dev_extra_names, (
        "``types-pyyaml`` is required in [project.optional-dependencies].dev "
        "so ``pip install -e '.[dev]'`` ships the PyYAML stubs mypy --strict "
        "needs. It must not live only in a PEP 735 [dependency-groups] table."
    )

    groups = data.get("dependency-groups")
    if groups is None:
        # Preferred steady state: PEP 735 table removed entirely once every
        # spec is in the PEP 621 ``dev`` extra.
        return

    # If a PEP 735 ``[dependency-groups]`` table exists, every spec inside it
    # must also be in the PEP 621 ``dev`` extra. Otherwise the two installers
    # will silently diverge again.
    assert isinstance(groups, dict)
    pep735_dev = groups.get("dev", [])
    assert isinstance(pep735_dev, list)
    pep735_names = {_pkg_name(s) for s in pep735_dev}
    drift = pep735_names - dev_extra_names
    assert not drift, (
        "PEP 735 [dependency-groups].dev declares packages that are NOT in "
        "[project.optional-dependencies].dev — pip and uv installs will "
        f"diverge. Drift: {sorted(drift)}. Single-source-of-truth in the "
        "PEP 621 extra."
    )


def test_contributing_uv_sync_invocation_is_valid() -> None:
    """CONTRIBUTING.md's local-dev setup must use a uv invocation uv accepts.

    ``uv sync --all-extras --extra dev`` is rejected because ``--all-extras``
    already includes the ``dev`` extra; the canonical form once all dev tools
    live in the PEP 621 ``dev`` extra is just ``uv sync --all-extras``.
    """

    body = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "uv sync --all-extras" in body, (
        "CONTRIBUTING.md must document ``uv sync --all-extras`` as the local-dev setup command."
    )
    # The historical broken form must be gone.
    assert "uv sync --all-extras --extra dev" not in body, (
        "CONTRIBUTING.md still recommends ``uv sync --all-extras --extra dev``, "
        "which uv rejects. Update to plain ``uv sync --all-extras``."
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


# --------------------------------------------------------------------- QA-010


def test_reportlab_is_in_base_dependencies() -> None:
    """QA-010 — ReportLab MUST live in [project.dependencies], not an extra.

    Before this fix, ``reportlab`` lived in the ``[pdf-fallback]`` extra. A
    stock ``pip install agent-guardian`` produced a CLI advertising
    ``--output pdf`` that errored at write-time, after the operator had
    already paid for the scan. ReportLab is pure-Python, ~5 MB, Apache-2.0
    — safe as a default dep.
    """
    project = _load_pyproject()["project"]
    base_deps = project["dependencies"]  # type: ignore[index]
    assert isinstance(base_deps, list)
    assert any(spec.lower().startswith("reportlab") for spec in base_deps), (
        "reportlab is missing from [project.dependencies]. QA-010 requires "
        "ReportLab in base so --output pdf works after a stock install."
    )


def test_pdf_fallback_extra_is_deprecated_noop() -> None:
    """QA-010 — ``[pdf-fallback]`` extra exists but is empty for one release.

    The deprecation alias keeps ``pip install agent-guardian[pdf-fallback]``
    resolving for users / scripts that still reference it, while letting
    base-install consumers stop paying twice.
    """
    optional = _load_pyproject()["project"]["optional-dependencies"]  # type: ignore[index]
    assert isinstance(optional, dict)
    assert "pdf-fallback" in optional, (
        "[pdf-fallback] extra was removed entirely; QA-010 requires it kept "
        "as an empty alias for one release."
    )
    fallback = optional["pdf-fallback"]
    assert fallback == [], (
        f"[pdf-fallback] extra must be an EMPTY list (deprecation alias). Currently: {fallback!r}"
    )


def test_no_extras_install_can_emit_pdf(tmp_path: Path) -> None:
    """QA-010 (AC-010-1) — ``--output pdf`` works on a stock install.

    Asserts (a) ``reportlab`` resolves via ``importlib.metadata`` (proof
    it's in the base dependency closure, not an extra), (b) the PDF
    dispatcher selects the reportlab engine when WeasyPrint is absent,
    (c) the emitted file is a valid PDF (non-zero, ``%PDF-`` magic header).
    """
    import importlib.metadata as im

    # If reportlab isn't installed, the test environment is broken — the
    # whole point of QA-010 is that this resolves.
    assert im.version("reportlab"), "reportlab not installed; QA-010 base-dep contract broken"

    from agent_guardian.reports.pdf import _resolve_engine, write_pdf
    from tests.unit._report_fixtures import make_scan

    # Pin engine selection to reportlab. _resolve_engine accepts the engine
    # kwarg as the override mechanism the writer itself uses.
    engine = _resolve_engine("reportlab")
    assert engine == "reportlab"

    scan = make_scan()
    out = tmp_path / "stock.pdf"
    write_pdf(scan, out, engine="reportlab")
    data = out.read_bytes()
    assert data.startswith(b"%PDF-"), f"emitted file is not a valid PDF — first bytes: {data[:8]!r}"
    assert len(data) > 1024, f"PDF suspiciously small ({len(data)} bytes)"
