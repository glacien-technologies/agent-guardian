"""Transport core types and the :class:`Transport` abstract base (Stage 1A).

A *transport* is the thinnest possible "send a turn, get a turn back" seam over
a target. It deliberately knows nothing about contracts, scenarios, or scoring
— it speaks in :class:`Request` / :class:`Response` and never raises for
transport faults (it returns a :class:`Response` whose ``error`` is populated
instead). That property is what lets the swarm treat every target uniformly.

Types here are plain ``dataclasses`` (not Pydantic models) on purpose: they are
internal, hot-path value objects exchanged thousands of times per scan, carry no
external/untrusted input that needs validation, and benefit from cheap
construction. The redact-aware :meth:`Response.redacted` view reuses the
project's :func:`agent_guardian.logging_setup.redact_secrets` so receipts and
logs never leak credentials echoed back by a target.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar

from agent_guardian.logging_setup import redact_secrets
from agent_guardian.transports.errors import TransportError

__all__ = [
    "CapabilityReport",
    "Message",
    "ProbeResult",
    "Request",
    "Response",
    "TokenUsage",
    "ToolCall",
    "Transport",
]


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Token accounting for a single turn.

    Mirrors :class:`agent_guardian.llm.base.LLMUsage` but as a frozen dataclass
    so it travels with a :class:`Response` without pulling Pydantic onto the
    hot path. All fields default to ``0`` because many targets report nothing.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True, slots=True)
class Message:
    """A single role/content pair in a multi-turn conversation."""

    role: str
    content: str


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool/function invocation surfaced by the target in its reply."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    raw: Any = None


@dataclass(frozen=True, slots=True)
class Request:
    """One turn to send to a target.

    ``prompt`` is the current user turn; ``conversation`` is the prior history
    (oldest-first) that templating may inline. ``metadata`` is opaque
    pass-through for the transport (e.g. per-request overrides).
    """

    prompt: str
    conversation: tuple[Message, ...] = ()
    session: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Response:
    """One turn received from a target.

    On success ``error`` is ``None`` and ``text`` holds the assistant reply. On
    a transport fault ``error`` is a :class:`TransportError` and ``text`` is the
    empty string. ``tool_calls`` and ``usage`` are best-effort extras. ``raw``
    retains the parsed payload for receipts/debugging — never branch on it in
    production logic.
    """

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    usage: TokenUsage = field(default_factory=TokenUsage)
    error: TransportError | None = None
    session: str | None = None
    raw: Any = None

    @property
    def ok(self) -> bool:
        """True when no transport fault occurred."""
        return self.error is None

    def redacted(self) -> Response:
        """Return a copy with secrets scrubbed from ``text`` (and error message).

        Reuses :func:`agent_guardian.logging_setup.redact_secrets` so a target
        echoing back an API key cannot leak it into a stored receipt. ``raw`` is
        dropped because it may contain arbitrary unredacted nested payloads.
        """
        scrubbed_error: TransportError | None = None
        if self.error is not None:
            scrubbed_error = TransportError(
                self.error.category,
                redact_secrets(self.error.message),
                retry_after=self.error.retry_after,
                status_code=self.error.status_code,
            )
        return replace(
            self,
            text=redact_secrets(self.text),
            error=scrubbed_error,
            raw=None,
        )


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of a transport liveness probe (a single benign round-trip).

    ``ok`` is ``True`` when the target answered without a transport fault;
    ``detail`` holds a short human-readable note (the truncated reply on
    success). ``error`` carries the :class:`TransportError` on failure so the
    caller can surface a category without re-running the probe.
    """

    ok: bool
    detail: str = ""
    error: TransportError | None = None


@dataclass(frozen=True, slots=True)
class CapabilityReport:
    """Static, introspectable description of what a transport can do.

    Returned by :meth:`Transport.describe`; used by operators and the
    discovery surface to render "what is this target" without sending traffic.
    All fields are best-effort and default to the conservative answer.
    """

    kind: str
    streaming: bool = False
    supports_tools: bool = False
    session_modes: tuple[str, ...] = ()
    auth_scheme: str | None = None
    endpoint: str | None = None


# Benign turn used by the default :meth:`Transport.probe` liveness check.
_PROBE_PROMPT = "Hello, please introduce yourself."


class Transport(ABC):
    """Abstract "send a turn, get a turn" seam over a target.

    Concrete transports (HTTP, and later chunked / websocket) implement
    :meth:`send`. The contract is strict: :meth:`send` **never** raises for a
    transport fault — it catches the LLM-error hierarchy, maps it via
    :func:`agent_guardian.transports.errors.map_llm_error`, and returns a
    :class:`Response` carrying the resulting :class:`TransportError`.
    Programming errors (bad config detected at construction, ``NotImplementedError``
    for unsupported features) may still raise.

    The lifecycle surface (:meth:`probe`, :meth:`describe`, :meth:`open_session`,
    :meth:`close_session`) ships with sensible non-abstract defaults so concrete
    transports only override what they can answer better. Defaults never raise.
    """

    kind: ClassVar[str] = "transport"

    @abstractmethod
    async def send(self, request: Request) -> Response:
        """Send one turn and return one turn. Never raises for transport faults."""

    async def probe(self) -> ProbeResult:
        """Liveness check: send one benign turn and map the :class:`Response`.

        Default implementation sends ``"Hello, please introduce yourself."`` via
        :meth:`send` and folds the result into a :class:`ProbeResult`. Because
        :meth:`send` never raises for transport faults, neither does this.
        """
        response = await self.send(Request(prompt=_PROBE_PROMPT))
        if response.ok:
            return ProbeResult(ok=True, detail=response.text[:200])
        return ProbeResult(ok=False, error=response.error)

    def describe(self) -> CapabilityReport:
        """Return a static :class:`CapabilityReport` for this transport.

        Default reports only :attr:`kind`; concrete transports override to add
        endpoint, streaming, tool, session-mode and auth-scheme detail.
        """
        return CapabilityReport(kind=getattr(self, "kind", "transport"))

    async def open_session(self) -> None:
        """Begin a stateful session if the transport supports one. Default no-op."""
        return None

    async def close_session(self) -> None:
        """Tear down a stateful session if one was opened. Default no-op."""
        return None

    async def aclose(self) -> None:
        """Release any underlying resources. Default is a no-op."""
        return None

    async def __aenter__(self) -> Transport:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
