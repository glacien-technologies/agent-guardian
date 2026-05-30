"""Observability — OpenTelemetry GenAI spans for AgentGuardian (Stage 1B).

This package emits OTel spans following the GenAI semantic conventions. It is
gated (an explicit experimental-stability opt-in plus the optional ``otel``
extra) and degrades to a silent no-op when either is missing, so the default
install never pays for tracing infrastructure and nothing here ever raises if
the SDK is absent.

See :mod:`agent_guardian.obs.otel` for the public surface.
"""

from __future__ import annotations

from agent_guardian.obs.otel import (
    agent_span,
    compose_observers,
    configure_otel,
    get_tracer,
    make_otel_observer,
    set_conversation_id,
    set_usage,
    tool_span,
    transport_span,
)

__all__ = [
    "agent_span",
    "compose_observers",
    "configure_otel",
    "get_tracer",
    "make_otel_observer",
    "set_conversation_id",
    "set_usage",
    "tool_span",
    "transport_span",
]
