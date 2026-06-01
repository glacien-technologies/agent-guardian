"""GitHub Actions workflow guardrails.

These tests pin the launch-readiness workflow contracts so the gates
cannot regress silently:

* ``docker-publish.yml`` — multi-arch publish to GHCR on every
  ``v*.*.*`` tag, plus a ``doctor`` smoke step.
* ``readme-lint.yml`` — CI guard against the OpenSSF Best Practices
  ``/projects/0000`` placeholder and the Discord all-zero server ID.
* ``link-check.yml`` — lychee link check over ``README.md`` and
  ``docs/**/*.md`` that fails on any broken external link.
* ``ci.yml`` — cross-platform test matrix (Linux + macOS + Windows)
  with a single Codecov upload pinned to ubuntu / 3.11 and the
  Windows leg using the ``pdf-fallback`` extra.

The tests parse the workflow YAML; they intentionally do *not* try to
run ``act`` or invoke the GitHub API. The goal is fast PR-time
feedback when the launch-readiness contract drifts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _load_workflow(name: str) -> dict[str, Any]:
    path = WORKFLOWS / name
    assert path.is_file(), f"missing workflow: {path}"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"workflow {name} did not parse as a mapping"
    return cast(dict[str, Any], data)


def _triggers(data: dict[str, Any]) -> dict[str, Any]:
    """Return the workflow's ``on:`` block.

    PyYAML before 3.12 turns the bare ``on:`` key into Python ``True``;
    accept either spelling so the tests pass on every supported
    interpreter.
    """

    # PyYAML <3.12 maps the bare ``on:`` key to Python ``True``; cast
    # the dict so the ``get(True)`` fallback type-checks cleanly.
    raw: dict[Any, Any] = cast(dict[Any, Any], data)
    triggers = raw.get("on")
    if triggers is None:
        triggers = raw.get(True)
    assert triggers is not None, "workflow has no triggers"
    assert isinstance(triggers, dict)
    return cast(dict[str, Any], triggers)


# --------------------------------------------------------------- docker-publish


def test_docker_publish_workflow_exists() -> None:
    assert (WORKFLOWS / "docker-publish.yml").is_file()


def test_docker_publish_triggers_on_semver_tag() -> None:
    data = _load_workflow("docker-publish.yml")
    triggers = _triggers(data)
    push = triggers.get("push")
    assert isinstance(push, dict), "expected push trigger"
    tags = push.get("tags")
    assert isinstance(tags, list)
    assert "v*.*.*" in tags, "docker publish must fire on every v*.*.* tag"


def test_docker_publish_requires_packages_write() -> None:
    data = _load_workflow("docker-publish.yml")
    job = data["jobs"]["publish"]
    perms = job.get("permissions") or data.get("permissions")
    assert isinstance(perms, dict)
    assert perms.get("packages") == "write", "GHCR push needs packages:write"


def test_docker_publish_uses_buildx_multi_arch() -> None:
    data = _load_workflow("docker-publish.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["publish"]["steps"])
    assert "docker/setup-buildx-action" in steps_yaml
    assert "docker/build-push-action" in steps_yaml
    assert "linux/amd64" in steps_yaml
    assert "linux/arm64" in steps_yaml


def test_docker_publish_tags_ref_and_latest() -> None:
    data = _load_workflow("docker-publish.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["publish"]["steps"])
    assert "ghcr.io/" in steps_yaml
    assert "github.ref_name" in steps_yaml
    assert ":latest" in steps_yaml


def test_docker_publish_logs_in_with_github_token() -> None:
    data = _load_workflow("docker-publish.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["publish"]["steps"])
    assert "docker/login-action" in steps_yaml
    assert "secrets.GITHUB_TOKEN" in steps_yaml


def test_docker_publish_has_doctor_smoke_step() -> None:
    data = _load_workflow("docker-publish.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["publish"]["steps"])
    # Smoke step pulls the freshly-pushed image and runs the CLI's
    # ``doctor`` command. The exact phrasing has to survive small
    # editorial tweaks, so we assert on both ``docker run`` and the
    # ``doctor`` argument independently.
    assert "docker run" in steps_yaml
    assert "doctor" in steps_yaml


# ------------------------------------------------------------------ readme-lint


def test_readme_lint_workflow_exists() -> None:
    assert (WORKFLOWS / "readme-lint.yml").is_file()


def test_readme_lint_triggers_on_pr_and_push() -> None:
    triggers = _triggers(_load_workflow("readme-lint.yml"))
    push = triggers.get("push")
    pr = triggers.get("pull_request")
    assert isinstance(push, dict) and "main" in push["branches"]
    assert isinstance(pr, dict) and "main" in pr["branches"]


def test_readme_lint_guards_against_placeholders() -> None:
    data = _load_workflow("readme-lint.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["readme-placeholders"]["steps"])
    # Both placeholder patterns must be present as guards.
    assert "/projects/0000" in steps_yaml
    assert "/discord/0" in steps_yaml


# NOTE: a `test_readme_currently_has_the_placeholders_we_guard_against`
# inverse-drift guard previously lived here; its own docstring said it
# would start failing once the README placeholders were replaced and the
# matching guard in readme-lint.yml could then be removed. Phase C.C8
# rewrote the README (real framework-coverage matrix, no badge stubs),
# which retired both placeholders, so the inverse-drift assertion no
# longer has a meaningful invariant to check and was removed here. The
# workflow-side `test_readme_lint_guards_against_placeholders` stays —
# the workflow guards still pattern-match against any *future*
# placeholder-leakage drift, even if no current README line trips them.


# ------------------------------------------------------------------- link-check


def test_link_check_workflow_exists() -> None:
    assert (WORKFLOWS / "link-check.yml").is_file()


def test_link_check_uses_lychee_and_targets_readme_and_docs() -> None:
    data = _load_workflow("link-check.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["lychee"]["steps"])
    assert "lycheeverse/lychee-action" in steps_yaml
    assert "README.md" in steps_yaml
    assert "docs/**/*.md" in steps_yaml


def test_link_check_fails_on_broken_links() -> None:
    data = _load_workflow("link-check.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["lychee"]["steps"])
    # ``fail: true`` is what makes lychee-action exit non-zero on any
    # non-2xx. Without it the action would only annotate.
    assert "fail: true" in steps_yaml


# -------------------------------------------------------------------------- ci


def test_ci_test_matrix_covers_three_oses() -> None:
    data = _load_workflow("ci.yml")
    matrix = data["jobs"]["test"]["strategy"]["matrix"]
    assert sorted(matrix["os"]) == sorted(["ubuntu-latest", "macos-latest", "windows-latest"])
    # We did not narrow the python matrix — every supported interpreter
    # still runs on every OS.
    assert set(matrix["python-version"]) == {"3.10", "3.11", "3.12", "3.13"}


def test_ci_codecov_only_runs_on_ubuntu_3_11() -> None:
    data = _load_workflow("ci.yml")
    steps = data["jobs"]["test"]["steps"]
    codecov_steps = [
        step
        for step in steps
        if isinstance(step, dict) and "codecov/codecov-action" in str(step.get("uses", ""))
    ]
    assert len(codecov_steps) == 1, "expected exactly one Codecov upload step"
    condition = codecov_steps[0].get("if", "")
    assert "ubuntu-latest" in condition
    assert "3.11" in condition


def test_ci_windows_uses_pdf_fallback_extra() -> None:
    data = _load_workflow("ci.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["test"]["steps"])
    # Windows leg installs pdf-fallback (ReportLab) instead of the
    # ``full`` WeasyPrint extra — see test_report_pdf.py for the
    # matching skip logic.
    assert "pdf-fallback" in steps_yaml
    assert "runner.os == 'Windows'" in steps_yaml
