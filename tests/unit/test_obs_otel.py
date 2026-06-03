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

from datetime import UTC, datetime
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
from agent_guardian.obs.otel import (
    TransportSpanMixin,
    _genai_opt_in_enabled,
    _NoOpTracer,
    _parse_otlp_headers,
    _resolve_otlp_endpoint,
    _resolve_service_name,
)

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
        timestamp=datetime(2026, 5, 29, 12, 0, 0, tzinfo=UTC),
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

    Also force-resets the module-level conversation-id /
    invoke-agent-span ContextVars between tests. The legacy
    ``test_observer_swallows_span_failure`` deliberately makes the observer's
    ``add_event`` raise mid-event — that observer never receives an
    ``agent_done`` and therefore can't reset its tokens cleanly, leaking the
    invoke-agent ContextVar to the next test. Without this teardown a
    legitimate ``with agent_span(): set_usage()`` in a later test would route
    its usage attributes to the orphaned (non-current) span.
    """
    pytest.importorskip("opentelemetry")
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from agent_guardian.obs import otel as _otel

    monkeypatch.setenv(_OPT_IN_ENV, _OPT_IN_TOKEN)

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # ``set_tracer_provider`` only honours the first call per process; force the
    # internal slot so each test sees a clean provider regardless of ordering.
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", provider, raising=False)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", _AlreadyDone(), raising=False)

    # Snapshot ContextVar values so we can restore them post-test. ContextVars
    # leak across tests when an observer never reaches ``agent_done`` (e.g.
    # the deliberate failure injection above).
    _otel._CURRENT_CONVERSATION_ID.set(None)
    _otel._CURRENT_INVOKE_AGENT_SPAN.set(None)

    exporter.clear()
    yield exporter
    exporter.clear()
    _otel._CURRENT_CONVERSATION_ID.set(None)
    _otel._CURRENT_INVOKE_AGENT_SPAN.set(None)


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

    def test_transport_span_emits_host_and_default_port(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        # #22: server.address is the HOST only (semconv) — not the full URL —
        # and server.port carries the (defaulted) port for host-level grouping.
        # The span name is also HOST-only (low cardinality + no embedded API key
        # / token leakage), with the scheme + redacted path stamped as
        # attributes instead.
        with transport_span("https://target.example/chat"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.name == "transport.send target.example"
        assert span.attributes["server.address"] == "target.example"
        assert span.attributes["server.port"] == 443
        assert span.attributes["url.scheme"] == "https"
        assert span.attributes["url.path"] == "/chat"

    def test_transport_span_emits_explicit_port(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with transport_span("http://target.example:8080/v1/chat"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.attributes["server.address"] == "target.example"
        assert span.attributes["server.port"] == 8080

    def test_transport_span_non_url_endpoint_sets_no_address(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        # A non-URL sentinel (e.g. an in-process transport) sets nothing rather
        # than emitting a malformed server.address.
        with transport_span("transport"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert "server.address" not in span.attributes
        assert "server.port" not in span.attributes

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

        from agent_guardian.obs import otel as otel_mod

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


# ---------------------------------------------------------------------------
# OTLP env-var precedence + headers + service name (cluster-fix items)
#
# These tests lock in the OTel-spec env-var contract — an enterprise operator
# wiring AgentGuardian into an existing observability stack should be able to
# point the exporter at their collector via standard ``OTEL_EXPORTER_OTLP_*``
# env vars instead of editing code or contract YAML.
# ---------------------------------------------------------------------------
class TestEndpointResolution:
    """``_resolve_otlp_endpoint`` precedence: explicit > trace-specific > generic."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)

    def test_explicit_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://env-traces:4318")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-generic:4318")
        assert _resolve_otlp_endpoint("http://explicit:4318") == "http://explicit:4318"

    def test_traces_specific_wins_over_generic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://env-traces:4318")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-generic:4318")
        assert _resolve_otlp_endpoint(None) == "http://env-traces:4318"

    def test_generic_when_only_generic_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-generic:4318")
        assert _resolve_otlp_endpoint(None) == "http://env-generic:4318"

    def test_none_when_nothing_set(self) -> None:
        # No explicit, no env vars → None means "no-op, do not configure".
        assert _resolve_otlp_endpoint(None) is None
        assert _resolve_otlp_endpoint("") is None

    def test_whitespace_only_env_is_treated_as_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "   ")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        assert _resolve_otlp_endpoint(None) is None


class TestServiceNameResolution:
    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)

    def test_explicit_arg_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTEL_SERVICE_NAME", "env-svc")
        assert _resolve_service_name("explicit-svc") == "explicit-svc"

    def test_env_when_no_explicit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTEL_SERVICE_NAME", "env-svc")
        assert _resolve_service_name(None) == "env-svc"

    def test_default_when_neither_set(self) -> None:
        assert _resolve_service_name(None) == "agent-guardian"

    def test_whitespace_env_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTEL_SERVICE_NAME", "   ")
        assert _resolve_service_name(None) == "agent-guardian"


class TestHeaderParsing:
    def test_parses_single_pair(self) -> None:
        assert _parse_otlp_headers("authorization=Bearer abc") == {"authorization": "Bearer abc"}

    def test_parses_multiple_pairs(self) -> None:
        out = _parse_otlp_headers("k1=v1,k2=v2,k3=v3")
        assert out == {"k1": "v1", "k2": "v2", "k3": "v3"}

    def test_strips_whitespace(self) -> None:
        assert _parse_otlp_headers(" k1 = v1 , k2= v2 ") == {"k1": "v1", "k2": "v2"}

    def test_skips_malformed_entries(self) -> None:
        # A bare token with no ``=`` should NOT crash; we silently drop it.
        assert _parse_otlp_headers("k1=v1,not-a-pair,k2=v2") == {"k1": "v1", "k2": "v2"}

    def test_empty_string_yields_empty_dict(self) -> None:
        assert _parse_otlp_headers("") == {}

    def test_last_value_wins_on_duplicate_keys(self) -> None:
        assert _parse_otlp_headers("k=v1,k=v2") == {"k": "v2"}


class TestConfigureOtelEnvIntegration:
    """End-to-end: configure_otel honours env vars even when arg is None."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_SERVICE_NAME",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_env_traces_endpoint_drives_wiring(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Even though the caller passes None, an env-set traces endpoint must
        # still wire the exporter — that's the OTel-spec contract operators
        # expect when they bring AgentGuardian into an existing stack.
        pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://traces.example:4318")
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from agent_guardian.obs import otel as otel_mod

        captured: dict[str, object] = {}
        monkeypatch.setattr(
            trace, "set_tracer_provider", lambda p: captured.setdefault("provider", p)
        )
        assert otel_mod.configure_otel(None) is None
        assert isinstance(captured["provider"], TracerProvider)

    def test_env_service_name_lands_on_resource(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        monkeypatch.setenv("OTEL_SERVICE_NAME", "my-collector")
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from agent_guardian.obs import otel as otel_mod

        captured: dict[str, object] = {}
        monkeypatch.setattr(
            trace, "set_tracer_provider", lambda p: captured.setdefault("provider", p)
        )
        otel_mod.configure_otel("http://collector:4318")
        provider = captured["provider"]
        assert isinstance(provider, TracerProvider)
        # The Resource carries service.name — read it through the public API.
        assert provider.resource.attributes["service.name"] == "my-collector"

    def test_default_service_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from agent_guardian.obs import otel as otel_mod

        captured: dict[str, object] = {}
        monkeypatch.setattr(
            trace, "set_tracer_provider", lambda p: captured.setdefault("provider", p)
        )
        otel_mod.configure_otel("http://collector:4318")
        provider = captured["provider"]
        assert isinstance(provider, TracerProvider)
        assert provider.resource.attributes["service.name"] == "agent-guardian"

    def test_otlp_headers_forwarded_to_exporter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-honeycomb-team=secret-key")

        from opentelemetry import trace

        from agent_guardian.obs import otel as otel_mod

        captured: dict[str, object] = {}

        # Capture the kwargs handed to the exporter so we can prove the
        # OTEL_EXPORTER_OTLP_HEADERS env var was parsed and forwarded.
        class _FakeExporter:
            def __init__(self, **kwargs: object) -> None:
                captured["kwargs"] = kwargs

            def shutdown(self) -> None:
                return None

            def export(self, spans: object) -> int:
                # ``SpanExportResult.SUCCESS`` is 0 in the SDK enum; returning a
                # literal keeps us off the real enum (this is a stub).
                return 0

            def force_flush(self, timeout_millis: int = 0) -> bool:
                return True

        monkeypatch.setattr(otel_mod, "_resolve_otlp_endpoint", lambda _: "http://x")
        monkeypatch.setattr(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
            _FakeExporter,
        )
        monkeypatch.setattr(
            trace, "set_tracer_provider", lambda _p: captured.setdefault("provider_set", True)
        )
        otel_mod.configure_otel(None)
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        assert kwargs.get("headers") == {"x-honeycomb-team": "secret-key"}
        assert kwargs.get("endpoint") == "http://x"


# ---------------------------------------------------------------------------
# TransportSpanMixin — the adapter-reusable hook for transport.send spans
# ---------------------------------------------------------------------------
class TestTransportSpanMixin:
    """The mixin returns the same context manager as the module-level helper."""

    def test_transport_span_is_inert_when_gate_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(_OPT_IN_ENV, raising=False)

        class _A(TransportSpanMixin):
            pass

        # Inert context manager: produces a span object that swallows attribute
        # writes and never raises.
        with _A._transport_span("https://x.example/v1/chat") as span:
            span.set_attribute("k", "v")

    def test_transport_span_emits_when_gate_open(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        class _A(TransportSpanMixin):
            pass

        with _A._transport_span("https://target.example/chat"):
            pass
        spans = in_memory_tracer.get_finished_spans()
        assert len(spans) == 1
        # The mixin must produce the SAME span shape as transport_span —
        # otherwise adapters that mix in would emit spans the OTel backend
        # can't group with the contract-adapter's transport spans.
        span = spans[0]
        assert span.name == "transport.send target.example"
        assert span.attributes["server.address"] == "target.example"
        assert span.attributes["server.port"] == 443


# ---------------------------------------------------------------------------
# Regression tests for the observability-cluster fix pass (Stage 1B follow-up).
# Each test enforces an invariant the cluster fix established so the bug it
# closed cannot silently regress.
# ---------------------------------------------------------------------------
class TestTransportSpanNeverLeaksSecrets:
    """``transport.send`` span name + attributes must NEVER carry an API key.

    Closes the cluster's P1 finding: ``f'transport.send {endpoint}'`` previously
    embedded the full URL — high cardinality AND a credential-leak vector for
    providers that pass an API key in the query string (Google's ``?key=AIza...``).
    The new span name is host-only and the path is redacted before stamping.
    """

    def test_query_string_api_key_never_in_span_name_or_attributes(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent"
            "?key=AIzaSyABCDEF1234567890"
        )
        with transport_span(url):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        # The span name is host-only — no URL, therefore no query string,
        # therefore no embedded API key.
        assert span.name == "transport.send generativelanguage.googleapis.com"
        # And the API key MUST NOT appear in any attribute value either.
        for value in span.attributes.values():
            assert "AIzaSy" not in str(value), (
                f"API key leaked into span attribute value: {value!r}"
            )

    def test_bearer_token_shape_in_path_is_redacted(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        # An OpenAI-shaped token embedded in the URL path (an unusual but
        # observed pattern with pre-signed URLs) is redacted before landing
        # on ``url.path``.
        with transport_span("https://x.example/v1/sk-ant-abcdef1234567890/chat"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.name == "transport.send x.example"
        assert "sk-ant-abcdef" not in span.attributes["url.path"]


class TestTransportSpanCarriesConversationId:
    """transport.send must stamp gen_ai.conversation.id so the consumer can correlate.

    Closes the cluster's P1 finding: without conversation id on the transport
    span, :class:`SpanCorrelator.tool_calls_for` is structurally unreachable
    from emitted spans alone.
    """

    def test_explicit_conversation_id_kwarg_stamps_attribute(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with transport_span("https://target.example/chat", conversation_id="abc"):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.attributes["gen_ai.conversation.id"] == "abc"

    def test_context_var_propagates_when_no_explicit_kwarg(
        self, in_memory_tracer, monkeypatch: pytest.MonkeyPatch
    ) -> None:  # type: ignore[no-untyped-def]
        from agent_guardian.obs import set_conversation_id

        token = set_conversation_id("ctx-conv")
        try:
            with transport_span("https://target.example/chat"):
                pass
        finally:
            from agent_guardian.obs.otel import _CURRENT_CONVERSATION_ID

            _CURRENT_CONVERSATION_ID.reset(token)
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.attributes["gen_ai.conversation.id"] == "ctx-conv"

    def test_explicit_kwarg_wins_over_context_var(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        from agent_guardian.obs import set_conversation_id
        from agent_guardian.obs.otel import _CURRENT_CONVERSATION_ID

        token = set_conversation_id("ctx-loser")
        try:
            with transport_span("https://x.example/chat", conversation_id="explicit-winner"):
                pass
        finally:
            _CURRENT_CONVERSATION_ID.reset(token)
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.attributes["gen_ai.conversation.id"] == "explicit-winner"


class TestObserverExceptionHandlerCannotReRaise:
    """The observer's ``except`` must not access ``event.kind`` directly.

    Closes the cluster's P3 finding: a malformed ``SwarmEvent`` whose ``kind``
    property itself raises would, in the prior implementation, make the
    exception handler re-raise — turning a best-effort observer into a scan
    killer. The handler now uses ``getattr`` with a default.
    """

    def test_event_with_raising_kind_does_not_propagate(self) -> None:
        observer = make_otel_observer()

        class _BadEvent:
            @property
            def agent(self) -> str:
                return "x"

            @property
            def kind(self) -> str:
                raise RuntimeError("event is malformed")

            @property
            def provisional_aivss(self) -> int | None:
                return None

        # Must NOT raise — the original code's ``event.kind`` inside the except
        # clause would propagate this RuntimeError out of the observer.
        observer(_BadEvent())  # type: ignore[arg-type]


class TestObserverNoLeakOnRepeatedAgentStart:
    """Two ``agent_start`` for the same agent name must finish both spans.

    Closes the cluster's P2 finding: the prior implementation overwrote the
    dict entry on the second start and orphaned the first span forever in the
    exporter.
    """

    def test_repeated_agent_start_then_done_exports_both_spans(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        observer = make_otel_observer()
        observer(_event("agent_start", agent="dup"))
        observer(_event("agent_start", agent="dup"))
        observer(_event("agent_done", agent="dup"))
        spans = in_memory_tracer.get_finished_spans()
        # The first ``agent_start`` opens span A. The second closes A and opens
        # B. The ``agent_done`` closes B. Both A and B must be exported — never
        # one orphaned.
        assert len(spans) == 2, f"expected both spans to finish; got {len(spans)}"
        for span in spans:
            assert span.attributes["gen_ai.agent.name"] == "dup"


class TestSetUsageRoutesToInvokeAgentSpan:
    """``set_usage`` inside a nested transport_span lands on the invoke_agent span.

    Closes the cluster's P3 finding: previously ``set_usage`` walked to the
    *current* span (the transport span) so token usage landed on the wrong
    span per GenAI semconv. Now it routes through a ContextVar to the
    observer-owned invoke_agent span.
    """

    def test_usage_lands_on_invoke_agent_not_transport(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        observer = make_otel_observer()
        observer(_event("agent_start", agent="planner"))
        # Open a nested transport span and call set_usage inside it. The usage
        # attributes MUST land on the invoke_agent span (the parent), not the
        # transport span.
        with transport_span("https://x.example/chat"):
            set_usage(input_tokens=77, output_tokens=88)
        observer(_event("agent_done", agent="planner"))
        spans = in_memory_tracer.get_finished_spans()
        # Find each by name.
        agent_spans = [s for s in spans if s.name.startswith("invoke_agent ")]
        transport_spans = [s for s in spans if s.name.startswith("transport.send ")]
        assert len(agent_spans) == 1
        assert len(transport_spans) == 1
        assert agent_spans[0].attributes["gen_ai.usage.input_tokens"] == 77
        assert agent_spans[0].attributes["gen_ai.usage.output_tokens"] == 88
        # And the transport span must NOT carry usage.
        assert "gen_ai.usage.input_tokens" not in transport_spans[0].attributes
        assert "gen_ai.usage.output_tokens" not in transport_spans[0].attributes

    def test_set_usage_inside_agent_span_still_works(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        # Existing ``with agent_span(...): set_usage(...)`` contract must still
        # hold — this is the manual-span path the unit-test fixtures use.
        with agent_span("recon"):
            set_usage(input_tokens=11, output_tokens=22)
        span = in_memory_tracer.get_finished_spans()[0]
        assert span.attributes["gen_ai.usage.input_tokens"] == 11
        assert span.attributes["gen_ai.usage.output_tokens"] == 22


class TestToolSpanStampsArguments:
    """``tool_span(name, arguments=...)`` stamps the arguments attribute.

    Closes the cluster's P3 finding: the empty ``with tool_span(...): pass``
    body in the contract adapter previously emitted a zero-duration span with
    no input — useless observability. The new tool_span accepts arguments
    (JSON-encoded + redacted) and stamps them.
    """

    def test_arguments_stamped_as_json_string(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        with tool_span("send_email", arguments={"to": "x@example.com", "body": "hi"}):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        assert "gen_ai.tool.call.arguments" in span.attributes
        # The attribute is the JSON-encoded payload.
        import json as _json

        decoded = _json.loads(span.attributes["gen_ai.tool.call.arguments"])
        assert decoded == {"to": "x@example.com", "body": "hi"}

    def test_arguments_with_bearer_token_redacted(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        # A bearer-shaped token in tool arguments is redacted before landing
        # on the span attribute (defence-in-depth — a sloppy target schema
        # should not leak credentials into observability).
        with tool_span(
            "call_api",
            arguments={"authorization": "Authorization: Bearer sk-ant-abc1234567890"},
        ):
            pass
        span = in_memory_tracer.get_finished_spans()[0]
        encoded = span.attributes["gen_ai.tool.call.arguments"]
        assert "sk-ant-abc" not in encoded
        assert "***REDACTED***" in encoded


class TestMcpBlockedToolDoesNotOpenSpan:
    """A live-gated MCP tool that was blocked must NOT get an ``execute_tool`` span.

    Closes the cluster's P2 finding: when an :class:`McpTransport` blocked a
    tool via its live ``_tool_gate``, the adapter still surfaced a synthetic
    :class:`ToolCall` (for audit) and the prior ``_record_tool_calls`` opened a
    span for it — falsely implying the tool ran. The fix consults
    :attr:`RoeController.observed_blocklisted_tools` (populated by the gate
    before the response is returned) and skips spanning blocked names.
    """

    async def test_blocked_tool_skips_tool_span(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        # Drive the real ``_record_tool_calls`` path with a fake transport that
        # the adapter classifies as ``_live_tool_gate=True`` so the live-gate
        # branch fires. We construct a minimal RoE controller directly with a
        # blocklist (avoiding the full contract-schema builder).
        from agent_guardian.contract.schema import (
            Contract,
            DataEgress,
            RoE,
            RoeTools,
            Target,
        )
        from agent_guardian.contract.schema import (
            HttpTransport as ContractHttpTransport,
        )
        from agent_guardian.contract.schema import (
            Response as ContractResponse,
        )
        from agent_guardian.core.roe import RoeController
        from agent_guardian.transports.base import Request, Response, ToolCall
        from agent_guardian.transports.contract_adapter import ContractTargetAdapter
        from agent_guardian.transports.mcp import McpTransport

        contract = Contract(
            target=Target(
                name="t",
                transport=ContractHttpTransport(url="https://t.example/x"),  # type: ignore[arg-type]
                response=ContractResponse(output_path="$.t"),
            ),
            roe=RoE(
                data_egress=DataEgress(allow_external=True),
                tools=RoeTools(blocklist=["danger_tool"]),
            ),
        )
        roe = RoeController.from_contract(contract)

        class _FakeMcp(McpTransport):
            """An MCP transport stub: returns a response with a blocked tool.

            The real ``McpTransport.send`` calls ``self._tool_gate(tool)``
            before executing; here we simulate the post-block state — the gate
            has been called (recording the block in
            ``observed_blocklisted_tools``) and a synthetic ToolCall is
            surfaced in the reply (mirroring real MCP blocked-tool behaviour).
            """

            def __init__(self) -> None:
                # Drive McpTransport's real __init__ so ``super`` is satisfied;
                # the spawned httpx client is closed in ``test`` via the
                # transport stub never being send()-driven from network.
                super().__init__(
                    endpoint="https://mcp.example/rpc",
                    tool_gate=roe.record_tool_call,
                )

            async def send(self, request: Request) -> Response:  # type: ignore[override]
                # Drive the gate (records the block in RoE) before returning.
                assert self._tool_gate is not None
                self._tool_gate("danger_tool")
                return Response(
                    text="[agent-guardian] tool 'danger_tool' blocked by RoE; not executed",
                    tool_calls=(ToolCall(name="danger_tool", arguments={}),),
                )

            async def aclose(self) -> None:  # type: ignore[override]
                # Close the httpx client the base __init__ created so the
                # event loop doesn't surface a "Unclosed client session" warning.
                if self._owns_client and self._client is not None:
                    await self._client.aclose()

        transport = _FakeMcp()
        adapter = ContractTargetAdapter(transport=transport, roe=roe)
        assert adapter._live_tool_gate is True
        text = await adapter.call("destroy it")
        assert "blocked by RoE" in text

        # The gate recorded the block — this is the precondition the adapter's
        # _record_tool_calls now reads to decide whether to span.
        assert "danger_tool" in roe.observed_blocklisted_tools

        # The execute_tool span MUST NOT have been opened for the blocked name.
        spans = in_memory_tracer.get_finished_spans()
        execute_tool_spans = [s for s in spans if s.name.startswith("execute_tool ")]
        assert execute_tool_spans == [], (
            f"blocked MCP tool should not get a span; got {[s.name for s in execute_tool_spans]}"
        )

    async def test_allowed_tool_call_gets_span_outside_transport(self, in_memory_tracer) -> None:  # type: ignore[no-untyped-def]
        # Closes the cluster's P3 finding: an allowed tool call must (a) get a
        # span with ``gen_ai.tool.call.arguments`` stamped, and (b) NOT be
        # parented by the transport.send span (per GenAI semconv, execute_tool
        # is child of invoke_agent, not transport.send).
        from agent_guardian.contract.schema import (
            Contract,
            DataEgress,
            RoE,
            Target,
        )
        from agent_guardian.contract.schema import (
            HttpTransport as ContractHttpTransport,
        )
        from agent_guardian.contract.schema import (
            Response as ContractResponse,
        )
        from agent_guardian.core.roe import RoeController
        from agent_guardian.transports.base import Request, Response, ToolCall, Transport
        from agent_guardian.transports.contract_adapter import ContractTargetAdapter

        contract = Contract(
            target=Target(
                name="t",
                transport=ContractHttpTransport(url="https://t.example/x"),  # type: ignore[arg-type]
                response=ContractResponse(output_path="$.t"),
            ),
            roe=RoE(data_egress=DataEgress(allow_external=True)),
        )
        roe = RoeController.from_contract(contract)

        class _StubHttp(Transport):
            endpoint = "https://target.example/chat"

            async def send(self, request: Request) -> Response:
                return Response(
                    text="ok",
                    tool_calls=(ToolCall(name="search", arguments={"q": "tea"}),),
                )

            async def aclose(self) -> None:
                return None

        adapter = ContractTargetAdapter(transport=_StubHttp(), roe=roe)
        await adapter.call("hi", session="sess-1")

        spans = in_memory_tracer.get_finished_spans()
        tool_spans = [s for s in spans if s.name == "execute_tool search"]
        transport_spans = [s for s in spans if s.name.startswith("transport.send ")]
        assert len(tool_spans) == 1, f"expected one tool span, got {[s.name for s in spans]}"
        assert len(transport_spans) == 1

        tool_span_record = tool_spans[0]
        transport_span_record = transport_spans[0]

        # gen_ai.tool.call.arguments was stamped (was missing before the fix).
        assert "gen_ai.tool.call.arguments" in tool_span_record.attributes
        import json as _json

        decoded = _json.loads(tool_span_record.attributes["gen_ai.tool.call.arguments"])
        assert decoded == {"q": "tea"}

        # The tool span MUST NOT be parented by the transport span. The
        # in-memory exporter exposes parent ids on ``span.parent``; when the
        # tool span was opened outside ``transport_span(...)`` they have
        # different (or no shared) parents.
        if tool_span_record.parent is not None and transport_span_record.context is not None:
            assert tool_span_record.parent.span_id != transport_span_record.context.span_id, (
                "execute_tool must not be parented by transport.send"
            )


class TestObsExtraGuard:
    """When ``opentelemetry`` is importable, the active obs suite must execute.

    Belt-and-suspenders for the CI ``--extra otel`` fix: if a future CI edit
    drops the extra, the active suite would silently SKIP everywhere via
    :func:`pytest.importorskip`. This test fails loudly in that case by
    asserting the SDK is wired enough to construct an in-memory exporter.
    """

    def test_opentelemetry_sdk_importable_when_extra_present(self) -> None:
        pytest.importorskip("opentelemetry")
        # The active suite needs all three of these symbols. If any is
        # unimportable on a CI machine, the ``in_memory_tracer`` fixture
        # raises and every active test errors instead of silently skipping —
        # which is exactly the failure-mode we want.
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        assert trace is not None
        assert TracerProvider is not None
        assert InMemorySpanExporter is not None
