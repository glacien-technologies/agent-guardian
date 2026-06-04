"""Tests for the ``agent-guardian comment`` command + the GitHub poster.

Covers:

* ``comment --dry-run`` prints the rendered body (with the marker) to stdout
  and never touches the network.
* :class:`GithubPoster.upsert` both CREATES (POST) a new comment when none with
  the marker exists, and UPDATES (PATCH) the existing one when it does — with a
  fully mocked ``httpx.Client`` so no network call is made.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agent_guardian.ci.comment import MARKER
from agent_guardian.ci.posters.github import GithubPoster
from agent_guardian.cli import app
from tests.unit._report_fixtures import make_scan


def _write_scan(tmp_path: Path) -> Path:
    scan = make_scan()
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan_file


def test_comment_dry_run_prints_body_with_marker(tmp_path: Path) -> None:
    scan_file = _write_scan(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["comment", "--scan", str(scan_file), "--dry-run", "--fail-under", "80"],
    )
    assert result.exit_code == 0, result.output
    assert MARKER in result.output
    # Marker is the first non-blank stdout line of the body.
    first_non_blank = next(line for line in result.output.splitlines() if line.strip())
    assert first_non_blank == MARKER
    assert "Gate:" in result.output


class _FakeResponse:
    def __init__(self, json_data: Any) -> None:
        self._json = json_data

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    """A minimal stand-in for ``httpx.Client`` recording the calls made."""

    def __init__(self, list_payload: list[dict[str, Any]]) -> None:
        self._list_payload = list_payload
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, **_kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url))
        return _FakeResponse(self._list_payload)

    def post(self, url: str, **_kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url))
        return _FakeResponse({"id": 999})

    def patch(self, url: str, **_kwargs: Any) -> _FakeResponse:
        self.calls.append(("PATCH", url))
        return _FakeResponse({"id": 42})


def _poster(client: _FakeClient) -> GithubPoster:
    return GithubPoster(
        token="t0ken",
        repository="acme/widget",
        pr_number=7,
        client=client,  # type: ignore[arg-type]
    )


def test_github_poster_creates_when_no_marker() -> None:
    """No existing marker comment -> POST a new one."""
    client = _FakeClient(list_payload=[{"id": 1, "body": "unrelated comment"}])
    _poster(client).upsert("hello world")
    methods = [m for m, _ in client.calls]
    assert "GET" in methods
    assert "POST" in methods
    assert "PATCH" not in methods


def test_github_poster_patches_existing_marker() -> None:
    """An existing marker comment -> PATCH it (update in place)."""
    client = _FakeClient(
        list_payload=[
            {"id": 1, "body": "unrelated comment"},
            {"id": 42, "body": f"{MARKER}\nold body"},
        ]
    )
    _poster(client).upsert("new body")
    methods = [m for m, _ in client.calls]
    assert "PATCH" in methods
    assert "POST" not in methods
    # The PATCH targets the existing comment id.
    patch_url = next(url for m, url in client.calls if m == "PATCH")
    assert patch_url.endswith("/issues/comments/42")


def test_resolve_pr_number_from_event_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """get_poster reads the PR number from GITHUB_EVENT_PATH -> pull_request.number."""
    event = tmp_path / "event.json"
    event.write_text('{"pull_request": {"number": 123}}', encoding="utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widget")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.delenv("GITHUB_REF", raising=False)

    from agent_guardian.ci.posters.github import get_poster

    poster = get_poster()
    assert poster._pr_number == 123


def test_resolve_pr_number_from_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    """Falls back to parsing GITHUB_REF 'refs/pull/<n>/merge'."""
    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widget")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/55/merge")

    from agent_guardian.ci.posters.github import get_poster

    poster = get_poster()
    assert poster._pr_number == 55
