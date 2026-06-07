"""Tests for VertexClient.complete() — ADC OAuth2 auth (M9), mocked.

google.auth.default is monkeypatched so no real GCP credentials are needed; the
Vertex URL is intercepted with respx and the Bearer header asserted. The
concurrency test covers reviewer correction #4: two concurrent complete() calls
must trigger ``creds.refresh`` exactly once.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

pytest.importorskip("google.auth", reason="Vertex auth tests require the [gcp] extra (google-auth)")

import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.vertex import VertexClient


class _FakeCreds:
    """Stands in for google.auth credentials.

    ``valid`` is False when ``expired`` is True or no token has been minted —
    matching the real google-auth gate VertexClient checks.
    """

    def __init__(self, *, expired: bool = False, refresh_delay: float = 0.0) -> None:
        self.token: str | None = None if expired else "fake-token"
        self._expired = expired
        self._refresh_delay = refresh_delay
        self.refresh_calls = 0
        self._lock = threading.Lock()

    @property
    def expired(self) -> bool:
        return self._expired

    @property
    def valid(self) -> bool:
        return self.token is not None and not self._expired

    def refresh(self, request: object) -> None:
        if self._refresh_delay:
            import time

            time.sleep(self._refresh_delay)
        with self._lock:
            self.refresh_calls += 1
        self.token = "refreshed-token"
        self._expired = False


def _req(model: str = "gemini-2.5-flash") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content="hi")], model=model)


def _ok_response() -> Response:
    return Response(
        200,
        json={
            "candidates": [
                {
                    "content": {"role": "model", "parts": [{"text": "ack"}]},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 3,
                "candidatesTokenCount": 1,
                "totalTokenCount": 4,
            },
        },
    )


def _vertex_url(project: str, location: str, model: str) -> str:
    host = (
        "aiplatform.googleapis.com"
        if location == "global"
        else f"{location}-aiplatform.googleapis.com"
    )
    return (
        f"https://{host}/v1/projects/{project}/locations/{location}"
        f"/publishers/google/models/{model}:generateContent"
    )


@respx.mock
async def test_vertex_complete_happy_path_bearer_and_url(monkeypatch: pytest.MonkeyPatch) -> None:
    creds = _FakeCreds(expired=False)
    monkeypatch.setattr("google.auth.default", lambda scopes=None: (creds, "detected-proj"))

    url = _vertex_url("my-proj", "us-central1", "gemini-2.5-flash")
    route = respx.post(url).mock(return_value=_ok_response())
    client = VertexClient(project="my-proj", location="us-central1")
    try:
        resp = await client.complete(_req())
        assert resp.text == "ack"
        assert resp.provider == "vertex"
        assert resp.usage.total_tokens == 4
        sent = route.calls.last.request
        assert str(sent.url) == url
        assert sent.headers["authorization"] == "Bearer fake-token"
        # Token was already valid → no refresh needed.
        assert creds.refresh_calls == 0
    finally:
        await client.aclose()


@respx.mock
async def test_vertex_complete_refreshes_when_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    creds = _FakeCreds(expired=True)
    monkeypatch.setattr("google.auth.default", lambda scopes=None: (creds, "p"))

    url = _vertex_url("my-proj", "us-central1", "gemini-2.5-flash")
    route = respx.post(url).mock(return_value=_ok_response())
    client = VertexClient(project="my-proj", location="us-central1")
    try:
        await client.complete(_req())
        assert creds.refresh_calls == 1
        assert route.calls.last.request.headers["authorization"] == "Bearer refreshed-token"
    finally:
        await client.aclose()


@respx.mock
async def test_vertex_global_location_url(monkeypatch: pytest.MonkeyPatch) -> None:
    creds = _FakeCreds(expired=False)
    monkeypatch.setattr("google.auth.default", lambda scopes=None: (creds, "p"))
    url = _vertex_url("my-proj", "global", "gemini-2.5-flash")
    route = respx.post(url).mock(return_value=_ok_response())
    client = VertexClient(project="my-proj", location="global")
    try:
        await client.complete(_req())
        assert str(route.calls.last.request.url) == url
    finally:
        await client.aclose()


@respx.mock
async def test_vertex_concurrent_complete_refreshes_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reviewer correction #4: two concurrent complete() calls observing an
    expired credential must refresh exactly once (asyncio.Lock guards the
    check-and-refresh sequence)."""
    # A small refresh delay widens the race window so an unlocked implementation
    # would deterministically double-refresh.
    creds = _FakeCreds(expired=True, refresh_delay=0.05)
    monkeypatch.setattr("google.auth.default", lambda scopes=None: (creds, "p"))

    url = _vertex_url("my-proj", "us-central1", "gemini-2.5-flash")
    respx.post(url).mock(return_value=_ok_response())
    # Allow both calls to run concurrently (default semaphore is 5).
    client = VertexClient(project="my-proj", location="us-central1")
    try:
        await asyncio.gather(client.complete(_req()), client.complete(_req()))
        assert creds.refresh_calls == 1, (
            f"expected exactly one refresh under concurrency, got {creds.refresh_calls}"
        )
    finally:
        await client.aclose()


def test_vertex_missing_google_auth_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_guardian.llm.vertex as vx
    from agent_guardian.llm.errors import LLMAuthError

    monkeypatch.setattr(vx, "_GOOGLE_AUTH_AVAILABLE", False)
    monkeypatch.setattr(vx, "_GOOGLE_AUTH_IMPORT_ERROR", ImportError("no google-auth"))
    client = VertexClient(project="p", location="us-central1")
    try:
        with pytest.raises(LLMAuthError, match="google-auth"):
            asyncio.run(client.complete(_req()))
    finally:
        asyncio.run(client.aclose())


def test_vertex_missing_project_raises_at_send() -> None:
    from agent_guardian.llm.errors import LLMAuthError

    client = VertexClient(project="", location="us-central1")
    try:
        with pytest.raises(LLMAuthError, match="project"):
            asyncio.run(client.complete(_req()))
    finally:
        asyncio.run(client.aclose())
