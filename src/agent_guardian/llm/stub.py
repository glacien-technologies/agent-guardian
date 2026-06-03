"""Deterministic canned-response LLM (PRD §14.3).

:class:`StubLLM` is the foundation of AgentGuardian's test isolation: every
unit test from M4 onward uses it instead of a real provider. No network. No
env. No flakes. The same :class:`LLMRequest` always produces the same
:class:`LLMResponse`.

Two matching strategies:

1. **Exact hash match** — keys that look like a 64-char SHA-256 hex string
   are matched against :meth:`StubLLM.hash_request`.
2. **Substring match** — all other keys are matched (case-insensitive)
   against the last user message. Longest match wins.

If nothing matches, ``default`` is returned. Stub never raises; that's
a deliberate property — flaky failures in unit tests are not allowed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage

__all__ = ["StubLLM", "StubScript"]

_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")


def _default_token_estimator(text: str) -> int:
    """Naive token estimate: 4 chars per token. Stable & deterministic."""
    return max(1, len(text) // 4) if text else 0


class StubLLM(BaseLLM):
    """Deterministic canned-response provider.

    Args:
        canned: Either a SHA-256 hex hash → response mapping, OR a substring
            → response mapping. Mixed keys are allowed; hashes match first.
        default: Fallback response text when nothing matches. Set to ``None``
            to make a non-match raise (rare — usually you want determinism).
        token_count_estimator: Function used to populate :class:`LLMUsage`.
            Defaults to ``len(text) // 4``.
    """

    provider = "stub"
    default_max_concurrency = 1_000  # Stub is in-process; concurrency is free.

    def __init__(
        self,
        canned: dict[str, str | LLMResponse] | None = None,
        default: str | None = "STUB_RESPONSE",
        *,
        token_count_estimator: Callable[[str], int] | None = None,
    ) -> None:
        # Stub does no I/O — pass ``owns_client=False`` so BaseLLM skips the
        # httpx.AsyncClient construction but still sets up the semaphore and
        # ``provider`` plumbing for us.
        super().__init__(
            timeout_seconds=0.0,
            max_concurrency=self.default_max_concurrency,
            owns_client=False,
        )

        self._default = default
        self._estimator = token_count_estimator or _default_token_estimator
        self._hash_keyed: dict[str, str | LLMResponse] = {}
        self._substring_keyed: list[tuple[str, str | LLMResponse]] = []

        for key, value in (canned or {}).items():
            if _SHA256_HEX_RE.match(key):
                self._hash_keyed[key] = value
            else:
                self._substring_keyed.append((key, value))
        # Longest substring wins → sort by descending length for the linear scan.
        self._substring_keyed.sort(key=lambda kv: -len(kv[0]))

    @staticmethod
    def hash_request(request: LLMRequest) -> str:
        """SHA-256 hex of a canonical JSON serialization of ``request``.

        Stable across processes, Python versions, and field-ordering.
        """
        payload = request.model_dump(mode="json")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _resolve(self, request: LLMRequest) -> str | LLMResponse | None:
        # 1. Hash match.
        digest = self.hash_request(request)
        if digest in self._hash_keyed:
            return self._hash_keyed[digest]
        # 2. Substring match against the last user message (case-insensitive).
        last_user = next(
            (m.content for m in reversed(request.messages) if m.role == "user"),
            "",
        )
        haystack = last_user.lower()
        for needle, value in self._substring_keyed:
            if needle.lower() in haystack:
                return value
        return None

    def _build_response(self, request: LLMRequest, content: str | LLMResponse) -> LLMResponse:
        if isinstance(content, LLMResponse):
            return content
        prompt_tokens = sum(self._estimator(m.content) for m in request.messages)
        completion_tokens = self._estimator(content)
        return LLMResponse(
            text=content,
            model=request.model,
            provider="stub",
            usage=LLMUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            finish_reason="stop",
            raw=None,
        )

    async def complete(self, request: LLMRequest) -> LLMResponse:
        async with self._semaphore:
            matched = self._resolve(request)
            if matched is None:
                if self._default is None:
                    raise KeyError(
                        f"StubLLM: no canned response matched and no default set "
                        f"(request hash {self.hash_request(request)})"
                    )
                matched = self._default
            return self._build_response(request, matched)

    async def aclose(self) -> None:
        # No-op — stub owns no resources.
        return None


@dataclass
class StubScript:
    """Fluent builder for :class:`StubLLM` test fixtures.

    Example::

        llm = (
            StubScript()
            .respond_to("hello", "world")
            .respond_to("ping", "pong")
            .default("ack")
            .build()
        )
    """

    _canned: dict[str, str | LLMResponse] = field(default_factory=dict)
    _default: str | None = "STUB_RESPONSE"
    _estimator: Callable[[str], int] | None = None

    def respond_to(self, substring: str, response: str | LLMResponse) -> StubScript:
        """Add a substring-keyed canned response."""
        if not substring:
            raise ValueError("substring must be non-empty")
        self._canned[substring] = response
        return self

    def respond_to_hash(self, digest: str, response: str | LLMResponse) -> StubScript:
        """Add an exact-hash canned response."""
        if not _SHA256_HEX_RE.match(digest):
            raise ValueError("digest must be a 64-char SHA-256 hex string")
        self._canned[digest] = response
        return self

    def default(self, response: str) -> StubScript:
        """Set the fallback response when nothing matches."""
        self._default = response
        return self

    def no_default(self) -> StubScript:
        """Make a non-match raise ``KeyError`` instead of returning a default."""
        self._default = None
        return self

    def token_estimator(self, estimator: Callable[[str], int]) -> StubScript:
        """Override the token-count estimator (default: ``len(s) // 4``)."""
        self._estimator = estimator
        return self

    def build(self) -> StubLLM:
        """Materialise the configured :class:`StubLLM`."""
        return StubLLM(
            canned=self._canned,
            default=self._default,
            token_count_estimator=self._estimator,
        )


# Re-export for star-imports / IDE niceness.
_ = (Any,)  # silence unused
