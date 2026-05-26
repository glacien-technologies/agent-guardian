"""Tests for the HttpAdapter construction / fingerprint surface.

These tests cover the cheap configuration and validation paths only; the
transport-layer tests (request shape, retries, response parsing) live in
``test_http_production.py``.
"""

from __future__ import annotations

import pytest

from agent_guardian.adapters.http import HttpAdapter


async def test_construct_with_known_shape() -> None:
    adapter = HttpAdapter("https://x.example.com/v1/chat", shape="openai")
    assert adapter.endpoint == "https://x.example.com/v1/chat"
    assert adapter.shape_name == "openai"
    fp = adapter.fingerprint()
    assert fp.mode == "http"
    assert fp.ref == "https://x.example.com/v1/chat"
    assert "Mode C" in fp.notes
    await adapter.aclose()


def test_unknown_shape_raises_keyerror() -> None:
    with pytest.raises(KeyError, match="Unknown HTTP shape"):
        HttpAdapter("https://x", shape="not-a-real-shape")


def test_empty_endpoint_raises() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        HttpAdapter("", shape="openai")


def test_negative_timeout_raises() -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        HttpAdapter("https://x", shape="openai", timeout_seconds=0)


def test_negative_max_retries_raises() -> None:
    with pytest.raises(ValueError, match="max_retries"):
        HttpAdapter("https://x", shape="openai", max_retries=-1)


def test_zero_concurrency_raises() -> None:
    with pytest.raises(ValueError, match="max_concurrency"):
        HttpAdapter("https://x", shape="openai", max_concurrency=0)


async def test_bedrock_shape_call_raises_auth_deferred() -> None:
    adapter = HttpAdapter("https://x.example.com", shape="bedrock")
    with pytest.raises(NotImplementedError, match="SigV4"):
        await adapter.call("hi")
    await adapter.aclose()


async def test_vertex_shape_call_raises_auth_deferred() -> None:
    adapter = HttpAdapter("https://x.example.com", shape="vertex")
    with pytest.raises(NotImplementedError, match="OAuth2"):
        await adapter.call("hi")
    await adapter.aclose()


async def test_agentcore_shape_call_raises_auth_deferred() -> None:
    adapter = HttpAdapter("https://x.example.com", shape="agentcore")
    with pytest.raises(NotImplementedError, match="SigV4"):
        await adapter.call("hi")
    await adapter.aclose()


async def test_custom_ref_used_for_fingerprint() -> None:
    adapter = HttpAdapter("https://x.example.com", shape="generic", ref="my-gateway")
    assert adapter.fingerprint().ref == "my-gateway"
    await adapter.aclose()


async def test_auth_headers_stored() -> None:
    adapter = HttpAdapter("https://x", shape="anthropic", auth_headers={"x-api-key": "k"})
    assert adapter._auth_headers == {"x-api-key": "k"}
    await adapter.aclose()


async def test_all_six_builtin_shapes_construct() -> None:
    for shape in ("openai", "anthropic", "bedrock", "vertex", "agentcore", "generic"):
        adapter = HttpAdapter("https://x", shape=shape)
        assert adapter.shape_name == shape
        await adapter.aclose()


async def test_aclose_is_idempotent() -> None:
    adapter = HttpAdapter("https://x", shape="openai")
    await adapter.aclose()
    await adapter.aclose()


async def test_call_after_aclose_raises() -> None:
    adapter = HttpAdapter("https://x", shape="openai")
    await adapter.aclose()
    with pytest.raises(RuntimeError, match="aclose"):
        await adapter.call("hi")
