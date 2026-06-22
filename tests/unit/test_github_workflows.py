"""GitHub Actions workflow guardrails.

These tests pin the launch-readiness workflow contracts so the gates
cannot regress silently:

* ``docker-publish.yml`` — multi-arch publish to GHCR on every
  ``v*.*.*`` tag, plus a ``doctor`` smoke step.
* ``readme-lint.yml`` — CI guard against the OpenSSF Best Practices
  ``/projects/0000`` placeholder and the Discord all-zero server ID.
* ``link-check.yml`` — lychee link check over ``README.md`` and
  ``docs/**/*.md`` that fails on any broken external link.
* ``ci.yml`` — supported-platform test matrix (Linux + macOS, Python
  3.11/3.12/3.13) with a single Codecov upload pinned to ubuntu / 3.11.
  Windows + Python 3.10 are tracked as v1.1 portability work in the
  Guardian backlog (QA-038).

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


def test_docker_publish_attests_image_provenance() -> None:
    data = _load_workflow("docker-publish.yml")
    job = data["jobs"]["publish"]
    perms = job.get("permissions") or data.get("permissions")
    assert isinstance(perms, dict)
    assert perms.get("id-token") == "write", "image provenance needs OIDC"
    assert perms.get("attestations") == "write", "image provenance needs attestations:write"
    steps_yaml = yaml.safe_dump(job["steps"])
    assert "docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf" in steps_yaml
    assert "id: build" in steps_yaml
    assert "actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32" in steps_yaml
    assert "subject-digest: ${{ steps.build.outputs.digest }}" in steps_yaml
    assert "push-to-registry: true" in steps_yaml


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
    # `steps_yaml` is a YAML text dump of GitHub-Actions step definitions, not
    # a URL — these assertions are deliberate substring/fragment matches against
    # workflow content, not host-sanitisation checks.
    assert "ghcr.io/" in steps_yaml  # noqa: py/incomplete-url-substring-sanitization  -- substring assertion on YAML text, not URL host check
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


def test_ci_per_pr_test_matrix_is_ubuntu_only() -> None:
    """Per-PR ``test`` job must NOT include macOS in its matrix.

    macOS runners always bill against the org-level Actions allowance,
    even on public repos (they are classified as "larger runners" per
    GitHub's billing model). Running the macOS matrix on every PR
    drains the same minute pool the org's private repos share. The
    cross-platform contract is exercised by the separate ``test-macos``
    job which runs only on release tag pushes.

    Windows is also excluded (Guardian backlog QA-038 — v1.1
    portability milestone). Python 3.10 is excluded — it has a known
    asyncio subprocess teardown bug fixed in 3.11.
    ``pyproject.toml`` declares ``requires-python>=3.11`` to match.
    """
    data = _load_workflow("ci.yml")
    matrix = data["jobs"]["test"]["strategy"]["matrix"]
    # No ``os`` axis on the per-PR test matrix — the job's runs-on is
    # the fixed string ``ubuntu-latest``.
    assert "os" not in matrix, (
        "the per-PR ``test`` job must NOT have an ``os`` matrix axis; "
        "macOS testing belongs in the gated ``test-macos`` job"
    )
    assert data["jobs"]["test"]["runs-on"] == "ubuntu-latest"
    assert set(matrix["python-version"]) == {"3.11", "3.12", "3.13"}


def test_ci_macos_job_only_runs_on_release_tags() -> None:
    """``test-macos`` exists, mirrors the Python matrix, and only fires
    on release tag pushes (``refs/tags/v*.*.*``).

    This is the cost guard: macOS minutes get spent at most once per
    PyPI release (~1/week historically), not three times per PR.
    """
    data = _load_workflow("ci.yml")
    job = data["jobs"].get("test-macos")
    assert job is not None, "test-macos job is missing from ci.yml"
    assert job["runs-on"] == "macos-latest"
    condition = job.get("if", "")
    assert "startsWith(github.ref, 'refs/tags/v')" in condition, (
        f"test-macos must be gated to release tag pushes, got: {condition!r}"
    )
    assert set(job["strategy"]["matrix"]["python-version"]) == {"3.11", "3.12", "3.13"}


def test_ci_codecov_uploads_once_on_python_3_11() -> None:
    """Codecov gating must keep exactly one upload step on the 3.11 leg.

    With the matrix collapsed to ubuntu-only, the gate no longer needs
    ``matrix.os ==``; ``matrix.python-version == '3.11'`` is sufficient
    to single out one of the three runs. Double-uploads would race the
    Codecov token + double-count coverage (Standard §11.1).
    """
    data = _load_workflow("ci.yml")
    steps = data["jobs"]["test"]["steps"]
    codecov_steps = [
        step
        for step in steps
        if isinstance(step, dict) and "codecov/codecov-action" in str(step.get("uses", ""))
    ]
    assert len(codecov_steps) == 1, "expected exactly one Codecov upload step"
    condition = codecov_steps[0].get("if", "")
    assert "3.11" in condition
    # The collapsed matrix has no ``os`` axis, so the prior
    # ``matrix.os == 'ubuntu-latest'`` clause would always be true
    # and is intentionally absent.
    assert "matrix.os" not in condition


def test_ci_every_job_has_a_timeout() -> None:
    """Every job MUST declare ``timeout-minutes`` so a stuck run cannot
    burn the account-level 6-hour cap (PR #151 ran for 6 hours on
    macOS before being killed by GitHub's own ceiling). The 30-minute
    test ceiling caps the worst case at ~1/12 of that."""
    data = _load_workflow("ci.yml")
    missing = [name for name, job in data["jobs"].items() if "timeout-minutes" not in job]
    assert missing == [], (
        f"these CI jobs have no timeout-minutes set: {missing}. "
        "Every job must declare one or a deadlock burns the org's "
        "Actions allowance until GitHub's 6-hour cap kills it."
    )


def test_ci_install_step_uses_dev_aws_otel_extras() -> None:
    data = _load_workflow("ci.yml")
    steps_yaml = yaml.safe_dump(data["jobs"]["test"]["steps"])
    # Single install step now that Windows is dropped (Guardian backlog QA-038).
    # ``--extra aws`` lights up the Bedrock provider tests; ``--extra otel``
    # lights up the OTEL active-path observer tests under tests/unit/test_obs_otel.py.
    assert "uv sync --extra dev --extra aws --extra otel" in steps_yaml
    # No Windows-conditional branch should remain on the test job.
    assert "runner.os == 'Windows'" not in steps_yaml
    assert "pdf-fallback" not in steps_yaml


# --------------------------------------------------------------------- publish


def test_publish_workflow_attests_release_artifacts() -> None:
    data = _load_workflow("publish.yml")
    job = data["jobs"]["sign"]
    perms = job.get("permissions") or data.get("permissions")
    assert isinstance(perms, dict)
    assert perms.get("id-token") == "write", "release artifact attestation needs OIDC"
    assert perms.get("attestations") == "write", "release artifact attestation needs attestations"
    steps_yaml = yaml.safe_dump(job["steps"])
    assert "sigstore/gh-action-sigstore-python" in steps_yaml
    assert "actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32" in steps_yaml
    assert "subject-path" in steps_yaml
    assert "dist/*.whl" in steps_yaml
    assert "dist/*.tar.gz" in steps_yaml
    assert "dist/*.cdx.json" in steps_yaml


# ------------------------------------------------------------- ClusterFuzzLite


def test_clusterfuzzlite_workflow_uses_pinned_actions() -> None:
    data = _load_workflow("clusterfuzzlite.yml")
    triggers = _triggers(data)
    assert "pull_request" in triggers
    assert "schedule" in triggers
    steps_yaml = yaml.safe_dump(data["jobs"]["fuzz"]["steps"])
    assert (
        "google/clusterfuzzlite/actions/build_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1"
        in steps_yaml
    )
    assert (
        "google/clusterfuzzlite/actions/run_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1"
        in steps_yaml
    )
    assert "github-token: ${{ secrets.GITHUB_TOKEN }}" in steps_yaml
    assert (
        "mode: ${{ github.event_name == 'pull_request' && 'code-change' || 'batch' }}" in steps_yaml
    )
    assert "fuzz-seconds: ${{ github.event_name == 'pull_request' && '60' || '600' }}" in steps_yaml
    assert "sanitizer: ${{ matrix.sanitizer }}" in steps_yaml


def test_clusterfuzzlite_project_files_exist() -> None:
    assert (REPO_ROOT / ".clusterfuzzlite" / "project.yaml").is_file()
    assert (REPO_ROOT / ".clusterfuzzlite" / "Dockerfile").is_file()
    build_sh = REPO_ROOT / ".clusterfuzzlite" / "build.sh"
    assert build_sh.is_file()
    build_script = build_sh.read_text(encoding="utf-8")
    assert "python3 -m pip install ." in build_script
    assert 'fuzzer_package="${target}.pkg"' in build_script
    assert (
        'pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" "$fuzzer"' in build_script
    )
    assert 'exec "\\$this_dir/${fuzzer_package}" "\\$@"' in build_script
    dockerfile = (REPO_ROOT / ".clusterfuzzlite" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY .clusterfuzzlite/build.sh $SRC/build.sh" in dockerfile


def test_clusterfuzzlite_fuzzer_targets_cover_security_parsers() -> None:
    fuzzer_dir = REPO_ROOT / "fuzzers"
    targets = {path.name for path in fuzzer_dir.glob("*_fuzzer.py")}
    assert {
        "probe_yaml_fuzzer.py",
        "contract_parser_fuzzer.py",
        "report_emitters_fuzzer.py",
        "redaction_fuzzer.py",
        "http_response_parser_fuzzer.py",
    }.issubset(targets)
