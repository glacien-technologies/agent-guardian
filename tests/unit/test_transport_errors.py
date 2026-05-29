"""Tests for the transport error taxonomy and LLM-error mapping."""

from __future__ import annotations

import pytest

from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.transports.errors import (
    TransportError,
    TransportErrorCategory,
    map_llm_error,
)


def test_map_auth_error() -> None:
    te = map_llm_error(LLMAuthError("nope"))
    assert te.category is TransportErrorCategory.AUTH
    assert te.message == "nope"
    assert te.retry_after is None


def test_map_rate_limit_propagates_retry_after() -> None:
    te = map_llm_error(LLMRateLimitError("slow down", retry_after=12.5))
    assert te.category is TransportErrorCategory.RATE_LIMIT
    assert te.retry_after == 12.5


def test_map_timeout_error() -> None:
    te = map_llm_error(LLMTimeoutError("took too long"))
    assert te.category is TransportErrorCategory.TIMEOUT


def test_map_transient_to_unreachable() -> None:
    te = map_llm_error(LLMTransientError("502"))
    assert te.category is TransportErrorCategory.UNREACHABLE


def test_map_response_format_to_parse() -> None:
    te = map_llm_error(LLMResponseFormatError("bad json"))
    assert te.category is TransportErrorCategory.PARSE


def test_map_permanent_error() -> None:
    te = map_llm_error(LLMPermanentError("400"))
    assert te.category is TransportErrorCategory.PERMANENT


def test_map_unknown_base_llm_error() -> None:
    te = map_llm_error(LLMError("mystery"))
    assert te.category is TransportErrorCategory.UNKNOWN
    assert te.message == "mystery"


def test_map_empty_message_uses_default() -> None:
    te = map_llm_error(LLMAuthError())
    assert te.message == "auth failed"


@pytest.mark.parametrize(
    "exc",
    [
        LLMAuthError("a"),
        LLMRateLimitError("b"),
        LLMTimeoutError("c"),
        LLMTransientError("d"),
        LLMResponseFormatError("e"),
        LLMPermanentError("f"),
        LLMError("g"),
    ],
)
def test_map_is_total_over_hierarchy(exc: LLMError) -> None:
    te = map_llm_error(exc)
    assert isinstance(te, TransportError)
    assert isinstance(te.category, TransportErrorCategory)


def test_transport_error_repr_and_fields() -> None:
    te = TransportError(
        TransportErrorCategory.RATE_LIMIT,
        "rl",
        retry_after=3.0,
        status_code=429,
    )
    assert te.status_code == 429
    assert "rate_limit" in repr(te)
    assert "rl" in repr(te)
    assert isinstance(te, Exception)
