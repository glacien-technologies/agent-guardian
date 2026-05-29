"""OpenTelemetry GenAI observability for AgentGuardian (Stage 1B).

This module emits spans that follow the OpenTelemetry *GenAI* semantic
conventions so an operator can correlate AgentGuardian's adversarial swarm with
their own observability backend. It is **gated** and **degrades to a no-op**:

* If the OTel SDK is not installed, or the experimental-stability opt-in env var
  is not set, every public surface here is a silent no-op. Nothing is imported
  eagerly, nothing raises.
* When active, spans carry GenAI attributes (``gen_ai.agent.name``,
  ``gen_ai.conversation.id``, ``gen_ai.tool.name``, ``gen_ai.tool.type``,
  ``gen_ai.usage.input_tokens`` / ``output_tokens``) and span names follow the
  convention (``invoke_agent {name}``, ``execute_tool {name}``).

Gate (BOTH must hold for a real tracer):

#. ``OTEL_SEMCONV_STABILITY_OPT_IN`` contains ``gen_ai_latest_experimental``.
#. ``opentelemetry`` is importable.

The GenAI conventions are still experimental, so we follow the SDK's own
gating convention rather than silently emitting attributes that may churn.

Design seam: the swarm core is never edited. Observability rides two seams —
a :data:`SwarmObserver` produced by :func:`make_otel_observer` (turns engine
events into agent spans) and adapter-created :func:`transport_span` /
:func:`tool_span` context managers used by the ``ContractTargetAdapter``.

Stage 3 will *consume* spans the target itself emits; :func:`configure_otel`
leaves a documented stub for wiring that exporter.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

if TYPE_CHECKING:
    from agent_guardian.core.swarm import SwarmEvent, SwarmObserver

_LOG = logging.getLogger(__name__)

__all__ = [
    "agent_span",
    "compose_observers",
    "configure_otel",
    "get_tracer",
    "make_otel_observer",
    "set_usage",
    "tool_span",
    "transport_span",
]

# --- GenAI semantic-convention constants ------------------------------------
# Centralised so the attribute keys are spelled exactly once. These mirror the
# OpenTelemetry GenAI semantic conventions (still experimental at the time of
# writing — hence the opt-in gate below).
_ATTR_AGENT_NAME = "gen_ai.agent.name"
_ATTR_CONVERSATION_ID = "gen_ai.conversation.id"
_ATTR_TOOL_NAME = "gen_ai.tool.name"
_ATTR_TOOL_TYPE = "gen_ai.tool.type"
_ATTR_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
_ATTR_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
_ATTR_OPERATION_NAME = "gen_ai.operation.name"

# The stability opt-in token the OTel SDK looks for to enable the experimental
# GenAI conventions. We require the same token so we never emit churning
# attributes unless the operator has explicitly accepted the experimental flag.
_GENAI_OPT_IN_TOKEN = "gen_ai_latest_experimental"
_OPT_IN_ENV_VAR = "OTEL_SEMCONV_STABILITY_OPT_IN"


# --- Span protocol ----------------------------------------------------------
# We type the span surface we actually use (``set_attribute`` / ``add_event``)
# behind a Protocol so mypy --strict is happy whether the real SDK is present or
# not. The no-op span below satisfies it; so does opentelemetry's ``Span``.
@runtime_checkable
class _SpanLike(Protocol):
    def set_attribute(self, key: str, value: Any) -> Any: ...

    def add_event(self, name: str, attributes: dict[str, Any] | None = ...) -> Any: ...


class _NoOpSpan:
    """A span that accepts every call and records nothing.

    Returned by the no-op tracer so callers can use the same span API on both
    the active and inert paths without branching.
    """

    __slots__ = ()

    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        return None

    def end(self) -> None:
        return None


@runtime_checkable
class _TracerLike(Protocol):
    @contextmanager
    def start_as_current_span(self, name: str, **kwargs: Any) -> Iterator[_SpanLike]: ...


class _NoOpTracer:
    """A tracer that yields :class:`_NoOpSpan` and never touches any backend."""

    __slots__ = ()

    @contextmanager
    def start_as_current_span(self, name: str, **kwargs: Any) -> Iterator[_SpanLike]:
        yield _NoOpSpan()


# A single shared instance — the no-op tracer is stateless.
_NOOP_TRACER = _NoOpTracer()


def _genai_opt_in_enabled() -> bool:
    """True iff the experimental GenAI stability opt-in is present in the env.

    The env var is a comma- (and/or space-) separated list of tokens, matching
    the OTel SDK's own parsing. We treat membership of
    ``gen_ai_latest_experimental`` as the switch.
    """
    raw = os.environ.get(_OPT_IN_ENV_VAR, "")
    tokens = {part.strip() for chunk in raw.split(",") for part in chunk.split()}
    return _GENAI_OPT_IN_TOKEN in tokens


def get_tracer() -> _TracerLike:
    """Return a tracer — a real one only when the gate is fully satisfied.

    Returns the no-op tracer unless BOTH (a) the experimental-stability opt-in
    env var contains ``gen_ai_latest_experimental`` AND (b) ``opentelemetry`` is
    importable. NEVER raises if the SDK is absent.
    """
    if not _genai_opt_in_enabled():
        return _NOOP_TRACER
    try:
        from opentelemetry import trace
    except ImportError:
        return _NOOP_TRACER
    # ``get_tracer`` always returns a usable tracer; if no provider is
    # configured it is a no-op-recording one, which is exactly the behaviour we
    # want (gate honoured, but harmless if nothing is wired). The real Tracer
    # satisfies the _TracerLike protocol structurally; ``cast`` records that
    # intent (the import is ``ignore_missing_imports`` so it is typed ``Any``).
    return cast("_TracerLike", trace.get_tracer("agent_guardian.obs"))


def _span_kind_client() -> Any:
    """Return the CLIENT span kind, or ``None`` when the SDK is absent.

    Passing ``kind=None`` to the no-op tracer is harmless (it ignores kwargs),
    and the real SDK accepts ``None`` as "use default". We only resolve the real
    enum value when the SDK is importable so the no-op path imports nothing.
    """
    try:
        from opentelemetry.trace import SpanKind
    except ImportError:
        return None
    return SpanKind.CLIENT


@contextmanager
def agent_span(agent_name: str, conversation_id: str | None = None) -> Iterator[_SpanLike]:
    """Span for one agent invocation: ``invoke_agent {agent_name}`` (CLIENT).

    Sets ``gen_ai.agent.name`` and (when provided) ``gen_ai.conversation.id``.
    No-op safe: yields an inert span when the gate is closed.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(
        f"invoke_agent {agent_name}", kind=_span_kind_client()
    ) as span:
        span.set_attribute(_ATTR_OPERATION_NAME, "invoke_agent")
        span.set_attribute(_ATTR_AGENT_NAME, agent_name)
        if conversation_id is not None:
            span.set_attribute(_ATTR_CONVERSATION_ID, conversation_id)
        yield span


@contextmanager
def transport_span(endpoint: str) -> Iterator[_SpanLike]:
    """Span for one per-turn transport send to ``endpoint`` (CLIENT).

    Wraps the single network call the adapter makes per target turn. No-op safe.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(
        f"transport.send {endpoint}", kind=_span_kind_client()
    ) as span:
        span.set_attribute("server.address", endpoint)
        yield span


@contextmanager
def tool_span(tool_name: str, tool_type: str = "function") -> Iterator[_SpanLike]:
    """Span for one tool call: ``execute_tool {tool_name}``.

    Sets ``gen_ai.tool.name`` and ``gen_ai.tool.type``. No-op safe.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(f"execute_tool {tool_name}") as span:
        span.set_attribute(_ATTR_OPERATION_NAME, "execute_tool")
        span.set_attribute(_ATTR_TOOL_NAME, tool_name)
        span.set_attribute(_ATTR_TOOL_TYPE, tool_type)
        yield span


def set_usage(input_tokens: int | None = None, output_tokens: int | None = None) -> None:
    """Set GenAI token-usage attributes on the *current* span.

    Best-effort: a no-op when the SDK is absent or no span is recording. NEVER
    raises. Either argument may be ``None`` to leave that attribute unset.
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    span = trace.get_current_span()
    # ``get_current_span`` returns a non-recording INVALID span when nothing is
    # active; writing attributes to it is harmless but pointless, so skip it.
    if not span.is_recording():
        return None
    if input_tokens is not None:
        span.set_attribute(_ATTR_USAGE_INPUT_TOKENS, input_tokens)
    if output_tokens is not None:
        span.set_attribute(_ATTR_USAGE_OUTPUT_TOKENS, output_tokens)
    return None


# --- Observer ---------------------------------------------------------------
def make_otel_observer() -> SwarmObserver:
    """Build a :data:`SwarmObserver` that maps engine events to agent spans.

    The returned callable opens an ``invoke_agent`` span on ``agent_start`` and
    closes it on ``agent_done`` / ``agent_skipped`` for the same ``event.agent``.
    Provisional AIVSS values (on any event that carries them) are recorded as a
    span event on the matching open span.

    Spans are started manually (not via the context-manager form) because the
    open/close straddle two separate observer invocations. Open spans are kept
    in a per-observer dict keyed by ``event.agent``. The observer is
    **best-effort** and NEVER raises — any failure (including the SDK being
    absent) is swallowed so it can never break a scan.

    When the gate is closed the tracer is the no-op tracer; we still maintain
    the bookkeeping dict but every span is inert, so the observer remains a
    cheap, safe no-op.
    """
    # Maps agent-name -> (span, context-detach-token). The token is the value
    # returned by ``context.attach`` so we can detach on close; ``None`` when
    # the SDK/context API is unavailable (no-op path).
    open_spans: dict[str, tuple[Any, Any]] = {}

    def _start(agent: str) -> None:
        try:
            from opentelemetry import context as otel_context
            from opentelemetry import trace
        except ImportError:
            return
        if not _genai_opt_in_enabled():
            return
        tracer = trace.get_tracer("agent_guardian.obs")
        from opentelemetry.trace import SpanKind

        span = tracer.start_span(f"invoke_agent {agent}", kind=SpanKind.CLIENT)
        span.set_attribute(_ATTR_OPERATION_NAME, "invoke_agent")
        span.set_attribute(_ATTR_AGENT_NAME, agent)
        token = otel_context.attach(trace.set_span_in_context(span))
        open_spans[agent] = (span, token)

    def _record_aivss(agent: str, aivss: int) -> None:
        entry = open_spans.get(agent)
        if entry is None:
            return
        span, _token = entry
        span.add_event(
            "gen_ai.provisional_aivss",
            attributes={"agent_guardian.provisional_aivss": aivss},
        )

    def _finish(agent: str) -> None:
        entry = open_spans.pop(agent, None)
        if entry is None:
            return
        span, token = entry
        if token is not None:
            try:
                from opentelemetry import context as otel_context
            except ImportError:
                _LOG.debug("otel context API unavailable; skipping detach")
            else:
                otel_context.detach(token)
        span.end()

    def observer(event: SwarmEvent) -> None:
        try:
            agent = event.agent
            if agent is None:
                return
            if event.kind == "agent_start":
                _start(agent)
            if event.provisional_aivss is not None:
                _record_aivss(agent, event.provisional_aivss)
            if event.kind in ("agent_done", "agent_skipped"):
                _finish(agent)
        except Exception:
            # Best-effort by contract: swallow everything so a sick tracing
            # backend can never break a scan. Logged at DEBUG only (never higher)
            # to avoid a noisy failure loop if the backend is persistently sick.
            _LOG.debug("otel observer swallowed an error for event %r", event.kind, exc_info=True)
            return None
        return None

    return observer


def compose_observers(*observers: SwarmObserver) -> SwarmObserver:
    """Combine several :data:`SwarmObserver` callables into one.

    Each observer is invoked in order for every event; a failure in any one is
    swallowed so a sick observer can never starve the others (or the scan).
    """

    def combined(event: SwarmEvent) -> None:
        for obs in observers:
            try:
                obs(event)
            except Exception:
                _LOG.debug("composed observer raised; isolating it", exc_info=True)
                continue
        return None

    return combined


# --- Exporter wiring (Stage 1B: own spans only) -----------------------------
def configure_otel(endpoint: str | None) -> None:
    """Configure an OTLP-HTTP exporter + tracer provider for our own spans.

    When ``endpoint`` is falsy, or the OTel SDK is not installed, this is a
    no-op (so the default install path never pays for tracing infrastructure).

    .. note::
       Stage 1B only exports the spans *AgentGuardian itself* produces. Stage 3
       will additionally **consume** the spans the target emits (correlating the
       target's internal agent/tool spans with our adversarial turns). That
       consumer is intentionally left as a documented stub here.

    NEVER raises if the SDK is absent — the import guard turns it into a no-op.
    """
    if not endpoint:
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return None
    resource = Resource.create({"service.name": "agent-guardian"})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return None
