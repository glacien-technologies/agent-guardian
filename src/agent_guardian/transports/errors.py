"""Transport error taxonomy and LLM-error mapping (Stage 1A).

A :class:`Transport` never raises for *transport faults*. Instead it returns a
:class:`~agent_guardian.transports.base.Response` whose ``error`` field carries
a :class:`TransportError`. This module defines that error type, the small
:class:`TransportErrorCategory` enum the rest of the framework branches on, and
:func:`map_llm_error` — the bridge from the existing LLM error hierarchy
(:mod:`agent_guardian.llm.errors`) onto our categories.

We reuse the LLM error hierarchy rather than reinventing it because the failure
modes of a hosted HTTP target are semantically identical: auth, rate-limit,
timeout, transient/unreachable, parse, permanent. The HTTP adapter already maps
status codes onto :class:`~agent_guardian.llm.errors.LLMError` subclasses, so
the transport layer just translates those into operator-facing categories.
"""

from __future__ import annotations

from enum import Enum

from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)

__all__ = [
    "TransportError",
    "TransportErrorCategory",
    "map_llm_error",
]


class TransportErrorCategory(str, Enum):
    """Coarse, operator-facing classification of a transport fault."""

    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    PARSE = "parse"
    PERMANENT = "permanent"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class TransportError(Exception):
    """A non-fatal transport fault returned (not raised) from ``Transport.send``.

    Carries a coarse :class:`TransportErrorCategory`, a human-readable message,
    an optional ``retry_after`` (seconds, populated for rate-limit faults), and
    an optional ``status_code`` for HTTP-shaped transports. The original
    exception, when one exists, is chained via ``__cause__``.
    """

    def __init__(
        self,
        category: TransportErrorCategory,
        message: str,
        *,
        retry_after: float | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
        self.retry_after = retry_after
        self.status_code = status_code

    def __repr__(self) -> str:
        return (
            f"TransportError(category={self.category.value!r}, "
            f"message={self.message!r}, retry_after={self.retry_after!r}, "
            f"status_code={self.status_code!r})"
        )


def map_llm_error(exc: LLMError) -> TransportError:
    """Translate an :class:`LLMError` into a categorised :class:`TransportError`.

    The mapping is total over the LLM hierarchy and falls back to
    :attr:`TransportErrorCategory.UNKNOWN` for any future base ``LLMError`` we
    do not recognise. ``retry_after`` is propagated from rate-limit errors so
    the caller (and the backoff helper) can honour the provider's hint.
    """
    if isinstance(exc, LLMRateLimitError):
        return TransportError(
            TransportErrorCategory.RATE_LIMIT,
            str(exc) or "rate limited",
            retry_after=exc.retry_after,
        )
    if isinstance(exc, LLMAuthError):
        return TransportError(TransportErrorCategory.AUTH, str(exc) or "auth failed")
    if isinstance(exc, LLMTimeoutError):
        return TransportError(TransportErrorCategory.TIMEOUT, str(exc) or "timed out")
    if isinstance(exc, LLMTransientError):
        return TransportError(TransportErrorCategory.UNREACHABLE, str(exc) or "transient error")
    if isinstance(exc, LLMResponseFormatError):
        return TransportError(TransportErrorCategory.PARSE, str(exc) or "response parse error")
    if isinstance(exc, LLMPermanentError):
        return TransportError(TransportErrorCategory.PERMANENT, str(exc) or "permanent error")
    return TransportError(TransportErrorCategory.UNKNOWN, str(exc) or "unknown transport error")
