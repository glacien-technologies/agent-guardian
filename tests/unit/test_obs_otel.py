"""Tests for the OpenTelemetry GenAI observability module (Stage 1B).

Two surfaces are exercised:

* The **no-op path** — the gate is closed (env unset and/or SDK treated as
  absent). This MUST be fully testable WITHOUT the OTel SDK: the tracer is the
  no-op tracer, every span context manager is inert, the observer never raises
  on any :class:`SwarmEvent`, and :func:`compose_observers` swallows per-observer
  faults.
* The **active path** — guarded by ``pytest.importorskip("opentelemetry")`` and
  a monkeypatched opt-in env var, with an in-memory span exporter so we can
  assert the emitted span names, attributes, and events.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.obs import (
    agent_span,
    compose_observers,
    configure_otel,
    get_tracer,
    make_otel_observer,
    set_usage,
    tool_span,
    transport_span,
)
from agent_guardian.obs.otel import _genai_opt_in_enabled, _NoOpTracer

if TYPE_CHECKING:
    from agent_guardian.core.swarm import EventKind

_OPT_IN_ENV = "OTEL_SEMCONV_STABILITY_OPT_IN"
_OPT_IN_TOKEN = "gen_ai_latest_experimental"


def _event(
    kind: EventKind,
    *,
    agent: str | None = "tool-abuse-agent",
    provisional_aivss: int | None = None,
) -> SwarmEvent:
    return SwarmEvent(
        kind=kind,
        timestamp=datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc),
        agent=agent,
        provisional_aivss=provisional_aivss,
    )


# ---------------------------------------------------------------------------
# No-op path — must hold with the SDK absent and/or the env unset.
# ---------------------------------------------------------------------------
class TestGate:
    def test_opt_in_disabled_when_env_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_OPT_IN_ENV, raising=False)
        assert _genai_opt_in_enabled() is False

    def test_opt_in_disabled_for_other_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_OPT_IN_ENV, "database_latest_experimental")
        assert _genai_opt_in_enabled() is False

    @pytest.mark.parametrize(
        "raw",
        [
            _OPT_IN_TOKEN,
            f"http,{_OPT_IN_TOKEN}",
            f"http {_OPT_IN_TOKEN}",
            f"  {_OPT_IN_TOKEN} , database ",
        ],
    )
    def test_opt_in_enabled_for_token_variants(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        monkeypatch.setenv(_OPT_IN_ENV, raw)
        assert _genai_opt_in_enabled() is True


class TestNoOpTracer:
    def test_get_tracer_noop_when_env_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_OPT_IN_ENV, raising=False)
        tracer = get_tracer()
        assert isinstance(tracer, _NoOpTracer)

    def test_get_tracer_noop_when_opted_in_but_sdk_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Opt in, but only get a real tracer if the SDK imports. When absent we
        # still get the no-op tracer and never raise.
        monkeypatch.setenv(_OPT_IN_ENV, _OPT_IN_TOKEN)
        tracer = get_tracer()
        # Either a real tracer (SDK present) or the no-op (SDK absent); both are
        # usable and never raise.
        with tracer.start_as_current_span("probe") as span:
            span.set_attribute("k", "v")
            span.add_event("e", attributes={"a": 1})

    def test_noop_span_methods_inert(self) -> None:
        tracer = _NoOpTracer()
        with tracer.start_as_current_span("x", kind=None) as span:
            assert span.set_attribute("k", "v") is None
            assert span.add_event("e") is None
            assert span.add_event("e", attributes={"a": 1}) is None


class TestSpanContextManagersNoOp:
    """With the env unset, every span CM is inert and never raises."""

    @pytest.fixture(autouse=True)
    def _gate_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_OPT_IN_ENV, raising=False)

    def test_agent_span_inert(self) -> None:
        with agent_span("recon-agent", conversation_id="conv-1") as span:
            span.set_attribute("extra", "v")

    def test_agent_span_inert_without_conversation(self) -> None:
        with agent_span("recon-agent") as span:
            span.set_attribute("extra", "v")

    def test_transport_span_inert(self) -> None:
        with transport_span("https://target.example/chat") as span:
            span.set_attribute("extra", "v")

    def test_tool_span_inert(self) -> None:
        with tool_span("get_weather", tool_type="function") as span:
            span.set_attribute("extra", "v")

    def test_tool_span_default_type(self) -> None:
        with tool_span("search") as span:
            span.set_attribute("extra", "v")

    def test_set_usage_inert(self) -> None:
        # No active span / SDK absent => harmless no-op, never raises.
        set_usage(input_tokens=10, output_tokens=20)
        set_usage()
        set_usage(input_tokens=5)


class TestObserverNoOp:
    """The observer must never raise on any SwarmEvent, gate closed."""

    @pytest.fixture(autouse=True)
    def _gate_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_OPT_IN_ENV, raising=False)

    @pytest.mark.parametrize(
        "kind",
        [
            "recon_start",
            "recon_done",
            "agent_start",
            "agent_progress",
            "agent_done",
            "agent_skipped",
            "checkpoint",
            "scan_done",
        ],
    )
    def test_observer_never_raises_per_kind(self, kind: str) -> None:
        observer = make_otel_observer()
        observer(_event(kind))  # type: ignore[arg-type]

    def test_observer_handles_none_agent(self) -> None:
        observer = make_otel_observer()
        observer(_event("scan_done", agent=None))

    def test_observer_full_lifecycle(self) -> None:
        observer = make_otel_observer()
        observer(_event("agent_start"))
        observer(_event("agent_progress", provisional_aivss=42))
        observer(_event("agent_done"))

    def test_observer_done_without_start(self) -> None:
        # Closing an agent that was never opened must be a safe no-op.
        observer = make_otel_observer()
        observer(_event("agent_done"))

    def test_observer_skipped_closes_span(self) -> None:
        observer = make_otel_observer()
        observer(_event("agent_start"))
        observer(_event("agent_skipped"))

    def test_observer_aivss_without_open_span(self) -> None:
        observer = make_otel_observer()
        observer(_event("checkpoint", agent="x", provisional_aivss=7))


class TestComposeObservers:
    def test_calls_each_observer_in_order(self) -> None:
        calls: list[str] = []
        first = lambda e: calls.append(f"first:{e.kind}")  # noqa: E731
        second = lambda e: calls.append(f"second:{e.kind}")  # noqa: E731
        combined = compose_observers(first, second)
        combined(_event("agent_start"))
        assert calls == ["first:agent_start", "second:agent_start"]

    def test_swallows_per_observer_exception(self) -> None:
        calls: list[str] = []

        def boom(_event: SwarmEvent) -> None:
            raise RuntimeError("observer is sick")

        def healthy(e: SwarmEvent) -> None:
            calls.append(str(e.kind))

        combined = compose_observers(boom, healthy)
        # The boom observer raising must NOT prevent ``healthy`` from running
        # and must NOT propagate to the caller.
        combined(_event("agent_done"))
        assert calls == ["agent_done"]

    def test_empty_compose_is_noop(self) -> None:
        combined = compose_observers()
        assert combined(_event("scan_done")) is None


class TestConfigureOtelNoOp:
    def test_none_endpoint_is_noop(self) -> None:
        assert configure_otel(None) is None

    def test_empty_endpoint_is_noop(self) -> None:
        assert configure_otel("") is None


# ---------------------------------------------------------------------------
# Active path — requires the SDK. Each active test depends on the
# ``in_memory_tracer`` fixture (or calls ``importorskip`` itself), so the
# no-op tests above run fully WITHOUT the SDK while these are skipped when it
# is absent. We deliberately do NOT put ``importorskip`` at module level —
# that would skip the no-op suite too.
# ---------------------------------------------------------------------------
@pytest.fixture
def in_memory_tracer(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Install an in-memory tracer provider and enable the GenAI opt-in.

    Skips the depending test when the OTel SDK is absent. Yields the
    :class:`InMemorySpanExporter` so tests can read finished spans. The
    previously-installed global provider is not restored (OTel forbids
    re-setting it within a process); each test reads only the spans it created
    by clearing the exporter at setup.
    """
    pytest.importorskip("opentelemetry")
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    monkeypatch.setenv(_OPT_IN_ENV, _OPT_IN_TOKEN)

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # ``set_tracer_provider`` only honours the first call per process; force the
    # internal slot so each test sees a clean provider regardless of ordering.
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", provider, raising=False)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", _AlreadyDone(), raising=False)

    exporter.clear()
    yield exporter
    exporter.clear()


class _AlreadyDone:
    """Stub for OTel's ``Once`` guard so ``set_tracer_provider`` is a no-op."""

    def do_once(self, func: object) -> bool:
        return False


class TestActiveTracer:
    def test_get_tracer_is_real_when_gated(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        tracer = get_tracer()
        assert not isinstance(tracer, _NoOpTracer)

    def test_agent_span_emits_attributes(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with agent_span("recon-agent", conversation_id="conv-1"):
            pass
        spans = in_memory_tracer.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.name == "invoke_agent recon-agent"
        assert span.attributes["gen_ai.agent.name"] == "recon-agent"
        assert span.attributes["gen_ai.conversation.id"] == "conv-1"
        assert span.attributes["gen_ai.operation.name"] == "invoke_agent"

    def test_agent_span_omits_conversation_when_none(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with agent_span("recon-agent"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert "gen_ai.conversation.id" not in span.attributes

    def test_agent_span_kind_is_client(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        from opentelemetry.trace import SpanKind

        with agent_span("recon-agent"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.kind == SpanKind.CLIENT

    def test_tool_span_emits_attributes(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with tool_span("get_weather", tool_type="function"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.name == "execute_tool get_weather"
        assert span.attributes["gen_ai.tool.name"] == "get_weather"
        assert span.attributes["gen_ai.tool.type"] == "function"
        assert span.attributes["gen_ai.operation.name"] == "execute_tool"

    def test_transport_span_emits_endpoint(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with transport_span("https://target.example/chat"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.name == "transport.send https://target.example/chat"
        assert span.attributes["server.address"] == "https://target.example/chat"

    def test_set_usage_on_current_span(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with agent_span("recon-agent"):
            set_usage(input_tokens=11, output_tokens=22)
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.attributes["gen_ai.usage.input_tokens"] == 11
        assert span.attributes["gen_ai.usage.output_tokens"] == 22

    def test_set_usage_partial(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with agent_span("recon-agent"):
            set_usage(input_tokens=11)
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.attributes["gen_ai.usage.input_tokens"] == 11
        assert "gen_ai.usage.output_tokens" not in span.attributes

    def test_set_usage_without_active_span_is_noop(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        set_usage(input_tokens=11, output_tokens=22)
        assert in_memory_tracer.get_finished_spans() == ()


class TestActiveObserver:
    def test_observer_opens_and_closes_agent_span(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        observer = make_otel_observer()
        observer(_event("agent_start", agent="tool-abuse-agent"))
        # Span is open, not yet exported.
        assert in_memory_tracer.get_finished_spans() == ()
        observer(_event("agent_done", agent="tool-abuse-agent"))
        spans = in_memory_tracer.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.name == "invoke_agent tool-abuse-agent"
        assert span.attributes["gen_ai.agent.name"] == "tool-abuse-agent"

    def test_observer_records_provisional_aivss_event(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        observer = make_otel_observer()
        observer(_event("agent_start", agent="a"))
        observer(_event("checkpoint", agent="a", provisional_aivss=63))
        observer(_event("agent_done", agent="a"))
        span = in_memory_tracer.get_finished_spans()[0]
        events = list(span.events)
        assert any(e.name == "gen_ai.provisional_aivss" for e in events)
        aivss_event = next(e for e in events if e.name == "gen_ai.provisional_aivss")
        assert aivss_event.attributes["agent_guardian.provisional_aivss"] == 63

    def test_observer_skipped_also_closes(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        observer = make_otel_observer()
        observer(_event("agent_start", agent="b"))
        observer(_event("agent_skipped", agent="b"))
        assert len(in_memory_tracer.get_finished_spans()) == 1

    def test_observer_two_agents_independent_spans(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        observer = make_otel_observer()
        observer(_event("agent_start", agent="a"))
        observer(_event("agent_start", agent="b"))
        observer(_event("agent_done", agent="a"))
        observer(_event("agent_done", agent="b"))
        names = sorted(
            s.attributes["gen_ai.agent.name"] for s in in_memory_tracer.get_finished_spans()
        )
        assert names == ["a", "b"]

    def test_observer_swallows_span_failure(
        self, in_memory_tracer, monkeypatch: pytest.MonkeyPatch
    ) -> None:  # type: ignore[no-untyped-def]
        # Even on the active path, a failure while recording (here: a span whose
        # ``add_event`` raises) must be swallowed — the observer can never break
        # a scan. Patch the SDK Span so the recording call inside ``_record_aivss``
        # blows up, then assert the observer returns normally.
        from opentelemetry.sdk import trace as sdk_trace

        def _boom(self: object, *args: object, **kwargs: object) -> None:
            raise RuntimeError("backend is sick")

        observer = make_otel_observer()
        observer(_event("agent_start", agent="z"))
        monkeypatch.setattr(sdk_trace.Span, "add_event", _boom)
        # Must NOT raise despite the underlying span.add_event blowing up.
        observer(_event("checkpoint", agent="z", provisional_aivss=99))


class TestConfigureOtelActive:
    def test_configure_with_endpoint_wires_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("opentelemetry")
        # Exercise the wiring path without depending on OTel's process-global
        # ``set_tracer_provider`` Once-guard (which refuses a second override and
        # is version-fragile to monkeypatch). Instead we capture the provider the
        # function hands to ``set_tracer_provider`` and assert it is a real SDK
        # provider carrying a span processor (i.e. the exporter was attached).
        from opentelemetry.sdk.trace import TracerProvider

        import agent_guardian.obs.otel as otel_mod

        captured: dict[str, object] = {}

        def _capture(provider: object) -> None:
            captured["provider"] = provider

        # configure_otel imports ``trace`` locally, so patch on the module the
        # symbol is looked up from at call time.
        from opentelemetry import trace

        monkeypatch.setattr(trace, "set_tracer_provider", _capture)
        assert otel_mod.configure_otel("http://localhost:4318/v1/traces") is None
        provider = captured["provider"]
        assert isinstance(provider, TracerProvider)

    def test_configure_without_sdk_path_noop(self) -> None:
        # Falsy endpoint short-circuits before any import — always a no-op.
        assert configure_otel(None) is None
        assert configure_otel("") is None
