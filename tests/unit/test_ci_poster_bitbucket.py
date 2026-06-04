"""Tests for the Bitbucket Cloud poster (``ci.posters.bitbucket``).

Exercises:

* ``upsert`` creates a comment when no marker-bearing comment exists (POST),
* ``upsert`` updates the existing marker-bearing comment in place (PUT),
* ``post_code_insights`` PUTs a fixed-key report then upserts a valid
  annotation payload per finding.

All HTTP is served by an in-process :class:`httpx.MockTransport` so no network
is touched and the request bodies/methods/urls can be asserted directly.
"""

from __future__ import annotations

import json

import httpx
import pytest

from agent_guardian.ci.comment import MARKER
from agent_guardian.ci.posters.base import PosterError
from agent_guardian.ci.posters.bitbucket import (
    _REPORT_KEY,
    BitbucketPoster,
    get_poster,
)
from tests.unit._report_fixtures import make_scan

_WS = "acme"
_REPO = "agent"
_PR = 42
_COMMIT = "abc123def456"


def _poster(handler: httpx.MockTransport, **overrides: object) -> BitbucketPoster:
    client = httpx.Client(transport=handler)
    kwargs: dict[str, object] = {
        "workspace": _WS,
        "repo_slug": _REPO,
        "pr_id": _PR,
        "commit": _COMMIT,
        "token": "tok",
        "client": client,
    }
    kwargs.update(overrides)
    return BitbucketPoster(**kwargs)  # type: ignore[arg-type]


# -- upsert: create -----------------------------------------------------------


def test_upsert_creates_when_no_existing_comment() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            # No existing AgentGuardian comment.
            return httpx.Response(200, json={"values": []})
        # POST a new comment.
        assert request.method == "POST"
        return httpx.Response(201, json={"id": 1})

    poster = _poster(httpx.MockTransport(handler))
    poster.upsert(f"{MARKER}\nhello")

    methods = [c.method for c in calls]
    assert methods == ["GET", "POST"]
    post = calls[-1]
    assert post.url.path.endswith(f"/pullrequests/{_PR}/comments")
    body = json.loads(post.content)
    assert body["content"]["raw"].startswith(MARKER)
    # Bearer auth carried in the header (no basic auth).
    assert post.headers["Authorization"] == "Bearer tok"


# -- upsert: update by marker -------------------------------------------------


def test_upsert_updates_existing_marker_comment() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "values": [
                        {"id": 7, "content": {"raw": "unrelated chatter"}},
                        {"id": 9, "content": {"raw": f"{MARKER}\nold body"}},
                    ]
                },
            )
        assert request.method == "PUT"
        return httpx.Response(200, json={"id": 9})

    poster = _poster(httpx.MockTransport(handler))
    poster.upsert(f"{MARKER}\nnew body")

    methods = [c.method for c in calls]
    assert methods == ["GET", "PUT"]
    put = calls[-1]
    # Updated the marker-bearing comment (id 9), not the unrelated one.
    assert put.url.path.endswith(f"/pullrequests/{_PR}/comments/9")
    body = json.loads(put.content)
    assert body["content"]["raw"] == f"{MARKER}\nnew body"


def test_upsert_follows_pagination_next_link() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET" and "page=2" not in str(request.url):
            return httpx.Response(
                200,
                json={
                    "values": [{"id": 1, "content": {"raw": "nope"}}],
                    "next": (
                        f"https://api.bitbucket.org/2.0/repositories/{_WS}/{_REPO}"
                        f"/pullrequests/{_PR}/comments?page=2"
                    ),
                },
            )
        if request.method == "GET":
            return httpx.Response(
                200,
                json={"values": [{"id": 5, "content": {"raw": f"{MARKER}\nx"}}]},
            )
        return httpx.Response(200, json={"id": 5})

    poster = _poster(httpx.MockTransport(handler))
    poster.upsert(f"{MARKER}\nbody")

    assert [c.method for c in calls] == ["GET", "GET", "PUT"]
    assert calls[-1].url.path.endswith("/comments/5")


def test_upsert_raises_without_pr_id() -> None:
    poster = _poster(httpx.MockTransport(lambda r: httpx.Response(200)), pr_id=None)
    with pytest.raises(PosterError, match="BITBUCKET_PR_ID"):
        poster.upsert("body")


# -- code insights ------------------------------------------------------------


def test_post_code_insights_puts_report_and_annotations() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    scan = make_scan(aivss=55)  # has 4 findings (critical/high/medium/low)
    poster = _poster(httpx.MockTransport(handler))
    poster.post_code_insights(scan)

    # First call is the report PUT against the FIXED report key.
    report_call = calls[0]
    assert report_call.method == "PUT"
    assert report_call.url.path.endswith(f"/commit/{_COMMIT}/reports/{_REPORT_KEY}")
    report = json.loads(report_call.content)
    assert report["result"] in {"PASSED", "FAILED"}
    assert report["report_type"] == "SECURITY"
    titles = {item["title"] for item in report["data"]}
    assert {"AIVSS", "Findings", "Critical", "High"}.issubset(titles)

    # Then one annotation PUT per finding.
    annotation_calls = calls[1:]
    assert len(annotation_calls) == len(scan.findings)
    first = json.loads(annotation_calls[0].content)
    assert first["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert first["path"].startswith("agentguardian/")
    assert first["path"].endswith(".md")
    assert first["line"] == 1
    assert first["annotation_type"] == "VULNERABILITY"
    # Highest severity sorted first -> CRITICAL annotation leads.
    assert first["severity"] == "CRITICAL"
    # Annotation upserted under its stable external id.
    assert annotation_calls[0].url.path.endswith(f"/annotations/{first['external_id']}")


def test_code_insights_passing_scan_reports_passed() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    scan = make_scan(aivss=98, findings=[])
    poster = _poster(httpx.MockTransport(handler))
    poster.post_code_insights(scan)

    report = json.loads(calls[0].content)
    assert report["result"] == "PASSED"
    # No findings -> no annotation calls.
    assert len(calls) == 1


def test_code_insights_dry_run_sends_nothing() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    poster = _poster(httpx.MockTransport(handler))
    poster.post_code_insights(make_scan(), dry_run=True)
    assert calls == []


def test_code_insights_swallows_non_2xx() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    poster = _poster(httpx.MockTransport(handler))
    # Best-effort: a 500 must not raise.
    poster.post_code_insights(make_scan(aivss=55))


# -- auth + construction ------------------------------------------------------


def test_basic_auth_used_when_no_token() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"values": []})
        return httpx.Response(201, json={"id": 1})

    poster = _poster(
        httpx.MockTransport(handler),
        token=None,
        username="bot",
        app_password="secret",
    )
    poster.upsert("body")
    # Basic auth header set by httpx from BasicAuth(username, app_password).
    assert captured[-1].headers["Authorization"].startswith("Basic ")


def test_constructor_requires_credentials() -> None:
    with pytest.raises(PosterError, match="credentials"):
        BitbucketPoster(workspace=_WS, repo_slug=_REPO)


def test_constructor_requires_workspace_and_repo() -> None:
    with pytest.raises(PosterError, match="BITBUCKET_WORKSPACE"):
        BitbucketPoster(workspace="", repo_slug=_REPO, token="t")
    with pytest.raises(PosterError, match="BITBUCKET_REPO_SLUG"):
        BitbucketPoster(workspace=_WS, repo_slug="", token="t")


def test_get_poster_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BITBUCKET_WORKSPACE", _WS)
    monkeypatch.setenv("BITBUCKET_REPO_SLUG", _REPO)
    monkeypatch.setenv("BITBUCKET_PR_ID", str(_PR))
    monkeypatch.setenv("BITBUCKET_COMMIT", _COMMIT)
    monkeypatch.setenv("BITBUCKET_TOKEN", "tok")
    poster = get_poster()
    assert isinstance(poster, BitbucketPoster)
    assert poster._pr_id == _PR
    assert poster._commit == _COMMIT
