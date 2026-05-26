"""Tests for the M4 HttpAdapter stub surface."""

from __future__ import annotations

import pytest

from agent_guardian.adapters.http import HttpAdapter


def test_construct_with_known_shape() -> None:
    adapter = HttpAdapter("https://x.example.com/v1/chat", shape="openai")
    assert adapter.endpoint == "https://x.example.com/v1/chat"
    assert adapter.shape_name == "openai"
    fp = adapter.fingerprint()
    assert fp.mode == "http"
    assert fp.ref == "https://x.example.com/v1/chat"
    assert "M9" in fp.notes


def test_unknown_shape_raises_keyerror() -> None:
    with pytest.raises(KeyError, match="Unknown HTTP shape"):
        HttpAdapter("https://x", shape="not-a-real-shape")


def test_empty_endpoint_raises() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        HttpAdapter("", shape="openai")


async def test_call_raises_not_implemented_with_m9_message() -> None:
    adapter = HttpAdapter("https://x.example.com", shape="openai")
    with pytest.raises(NotImplementedError, match="M9"):
        await adapter.call("hi")


def test_custom_ref_used_for_fingerprint() -> None:
    adapter = HttpAdapter("https://x.example.com", shape="generic", ref="my-gateway")
    assert adapter.fingerprint().ref == "my-gateway"


def test_auth_headers_stored() -> None:
    adapter = HttpAdapter("https://x", shape="anthropic", auth_headers={"x-api-key": "k"})
    # Internal but verifiable — make sure it's not lost.
    assert adapter._auth_headers == {"x-api-key": "k"}


def test_all_six_builtin_shapes_construct() -> None:
    for shape in ("openai", "anthropic", "bedrock", "vertex", "agentcore", "generic"):
        HttpAdapter("https://x", shape=shape)
