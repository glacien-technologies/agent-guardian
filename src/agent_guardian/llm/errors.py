"""LLM provider exception hierarchy (PRD §14.3).

Every provider client maps HTTP / SDK errors into one of these so the rest of
the framework can decide whether to retry, surface to the operator, or abort
the scan without caring about the underlying transport.
"""

from __future__ import annotations

__all__ = [
    "LLMAuthError",
    "LLMBudgetExceededError",
    "LLMError",
    "LLMPermanentError",
    "LLMRateLimitError",
    "LLMResponseFormatError",
    "LLMTimeoutError",
    "LLMTransientError",
]


class LLMError(Exception):
    """Base class for every LLM provider error."""


class LLMRateLimitError(LLMError):
    """Provider returned 429 / quota exhausted.

    Carries an optional ``retry_after`` (seconds) from the provider's
    ``Retry-After`` header so the backoff helper can honour it.
    """

    def __init__(self, message: str = "rate limited", *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class LLMAuthError(LLMError):
    """Provider returned 401 / 403 — credentials missing or invalid."""


class LLMTimeoutError(LLMError):
    """The request timed out at the transport layer."""


class LLMTransientError(LLMError):
    """5xx / network blip — safe to retry."""


class LLMPermanentError(LLMError):
    """Non-retryable 4xx (bad model, bad payload, …)."""


class LLMResponseFormatError(LLMError):
    """Provider returned 200 but the payload was missing required fields."""


class LLMBudgetExceededError(LLMError):
    """Wall-clock budget exhausted mid-retry (QA-008 guillotine).

    Raised by :func:`agent_guardian.llm.retry.with_backoff` when a
    ``deadline_monotonic`` was supplied and ``time.monotonic()`` has passed
    it before the next retry attempt. Deliberately NOT a subclass of
    :class:`LLMTimeoutError` so callers (and any *outer* retry wrapper) do
    NOT retry it — the whole point is to stop the cascade.

    Carries:
    * ``elapsed`` — seconds since ``scan_start`` when the guillotine fired.
    * ``budget`` — the wall budget the caller asked us to honour.
    * ``cause`` — the most recent retryable exception we were backing off
      on, preserved so the operator can see *why* we were retrying.
    """

    def __init__(
        self,
        message: str = "wall budget exhausted mid-retry",
        *,
        elapsed: float,
        budget: float,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.elapsed = elapsed
        self.budget = budget
        self.cause = cause
