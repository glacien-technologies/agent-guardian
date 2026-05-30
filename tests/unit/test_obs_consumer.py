"""Tests for the target-span consumer / correlator (Stage 3).

Everything here runs on **synthetic** span data — no OTel SDK and no live
collector are required. We exercise:

* :func:`parse_span` against the OTLP/JSON wire shape (list-of-kv attributes,
  proto int64-as-string timestamps) and against a flat ``{key: value}`` dict.
* :class:`SpanCorrelator` bucketing by ``gen_ai.conversation.id`` and the
  ``tool_calls_for`` / ``summary`` queries.
* :func:`ingest_otlp_json` over a multi-span, multi-resource payload and its
  robustness to missing / mistyped levels.
"""

from __future__ import annotations

from typing import Any

from agent_guardian.obs.otel_consumer import (
    SpanCorrelator,
    TargetSpanRecord,
    ingest_otlp_json,
    parse_span,
)


def _kv(key: str, string_value: str) -> dict[str, Any]:
    """One OTLP/JSON attribute entry with a stringValue."""
    return {"key": key, "value": {"stringValue": string_value}}


def _otlp_tool_span(
    *,
    name: str,
    conversation_id: str,
    tool_name: str,
    tool_type: str = "function",
) -> dict[str, Any]:
    """A synthetic OTLP/JSON tool span carrying the GenAI correlation attrs."""
    return {
        "name": name,
        "startTimeUnixNano": "1700000000000000000",
        "endTimeUnixNano": "1700000000500000000",
        "attributes": [
            _kv("gen_ai.conversation.id", conversation_id),
            _kv("gen_ai.tool.name", tool_name),
            _kv("gen_ai.tool.type", tool_type),
        ],
    }


# ---------------------------------------------------------------------------
# parse_span
# ---------------------------------------------------------------------------
class TestParseSpan:
    def test_parses_otlp_json_tool_span(self) -> None:
        span = _otlp_tool_span(
            name="execute_tool send_email",
            conversation_id="sess-abc",
            tool_name="send_email",
        )
        record = parse_span(span)
        assert record.name == "execute_tool send_email"
        assert record.conversation_id == "sess-abc"
        assert record.tool_name == "send_email"
        assert record.tool_type == "function"
        assert record.is_tool_call is True
        # raw timestamps decoded from proto int64-as-string.
        assert record.start_unix_nano == 1700000000000000000
        assert record.end_unix_nano == 1700000000500000000
        # full attribute bag is flattened and retained.
        assert record.attributes["gen_ai.tool.name"] == "send_email"

    def test_parses_flat_attribute_dict(self) -> None:
        span = {
            "name": "invoke_agent planner",
            "attributes": {
                "gen_ai.conversation.id": "sess-flat",
                "gen_ai.tool.name": "search",
            },
        }
        record = parse_span(span)
        assert record.conversation_id == "sess-flat"
        assert record.tool_name == "search"

    def test_non_tool_span_has_no_tool_name(self) -> None:
        span = {
            "name": "invoke_agent planner",
            "attributes": [_kv("gen_ai.conversation.id", "sess-1")],
        }
        record = parse_span(span)
        assert record.conversation_id == "sess-1"
        assert record.tool_name is None
        assert record.tool_type is None
        assert record.is_tool_call is False

    def test_missing_fields_are_safe(self) -> None:
        record = parse_span({})
        assert record.name == ""
        assert record.conversation_id is None
        assert record.tool_name is None
        assert record.start_unix_nano is None
        assert record.end_unix_nano is None
        assert record.attributes == {}

    def test_decodes_int_bool_double_and_array_values(self) -> None:
        span = {
            "name": "execute_tool x",
            "attributes": [
                {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "42"}},
                {"key": "agent_guardian.suppressed", "value": {"boolValue": True}},
                {"key": "score", "value": {"doubleValue": 1.5}},
                {
                    "key": "tags",
                    "value": {
                        "arrayValue": {"values": [{"stringValue": "a"}, {"stringValue": "b"}]}
                    },
                },
            ],
        }
        record = parse_span(span)
        assert record.attributes["gen_ai.usage.input_tokens"] == 42
        assert record.attributes["agent_guardian.suppressed"] is True
        assert record.attributes["score"] == 1.5
        assert record.attributes["tags"] == ["a", "b"]

    def test_malformed_attribute_entries_are_skipped(self) -> None:
        span = {
            "name": "execute_tool x",
            "attributes": [
                "not-a-dict",
                {"no_key": "field"},
                {"key": 123, "value": {"stringValue": "ignored"}},
                _kv("gen_ai.tool.name", "search"),
            ],
        }
        record = parse_span(span)
        assert record.tool_name == "search"
        assert record.attributes == {"gen_ai.tool.name": "search"}

    def test_unparseable_int_falls_back_to_raw(self) -> None:
        span = {"attributes": [{"key": "n", "value": {"intValue": "not-a-number"}}]}
        record = parse_span(span)
        assert record.attributes["n"] == "not-a-number"

    def test_garbage_timestamp_coerces_to_none(self) -> None:
        record = parse_span({"startTimeUnixNano": "abc", "endTimeUnixNano": None})
        assert record.start_unix_nano is None
        assert record.end_unix_nano is None

    def test_non_dict_attribute_value_passes_through(self) -> None:
        # A ``value`` that is not the wire AnyValue object is returned verbatim.
        span = {"attributes": [{"key": "raw", "value": "bare-string"}]}
        record = parse_span(span)
        assert record.attributes["raw"] == "bare-string"

    def test_unknown_any_value_shape_is_preserved(self) -> None:
        # An AnyValue one-of we don't decode (e.g. kvlistValue) is kept raw so
        # no information is silently dropped.
        kvlist = {"kvlistValue": {"values": [{"key": "k", "value": {"stringValue": "v"}}]}}
        span = {"attributes": [{"key": "nested", "value": kvlist}]}
        record = parse_span(span)
        assert record.attributes["nested"] == kvlist

    def test_malformed_array_value_yields_empty_list(self) -> None:
        span = {"attributes": [{"key": "tags", "value": {"arrayValue": "not-a-dict"}}]}
        record = parse_span(span)
        assert record.attributes["tags"] == []


# ---------------------------------------------------------------------------
# SpanCorrelator
# ---------------------------------------------------------------------------
class TestSpanCorrelator:
    def test_buckets_by_conversation_and_returns_tool_names(self) -> None:
        corr = SpanCorrelator()
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="execute_tool search",
                    conversation_id="conv-1",
                    tool_name="search",
                )
            )
        )
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="execute_tool send_email",
                    conversation_id="conv-1",
                    tool_name="send_email",
                )
            )
        )
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="execute_tool read_file",
                    conversation_id="conv-2",
                    tool_name="read_file",
                )
            )
        )
        assert corr.tool_calls_for("conv-1") == ["search", "send_email"]
        assert corr.tool_calls_for("conv-2") == ["read_file"]
        assert sorted(corr.conversation_ids) == ["conv-1", "conv-2"]

    def test_tool_calls_for_unknown_conversation_is_empty(self) -> None:
        assert SpanCorrelator().tool_calls_for("nope") == []

    def test_preserves_duplicate_tool_invocations(self) -> None:
        corr = SpanCorrelator()
        for _ in range(3):
            corr.ingest(
                parse_span(
                    _otlp_tool_span(
                        name="execute_tool search",
                        conversation_id="c",
                        tool_name="search",
                    )
                )
            )
        assert corr.tool_calls_for("c") == ["search", "search", "search"]

    def test_non_tool_spans_excluded_from_tool_calls(self) -> None:
        corr = SpanCorrelator()
        corr.ingest(
            parse_span(
                {
                    "name": "invoke_agent planner",
                    "attributes": [_kv("gen_ai.conversation.id", "c")],
                }
            )
        )
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="execute_tool search",
                    conversation_id="c",
                    tool_name="search",
                )
            )
        )
        assert corr.tool_calls_for("c") == ["search"]
        # but the non-tool span is still bucketed.
        assert len(corr.records_for("c")) == 2

    def test_uncorrelated_spans_are_separated(self) -> None:
        corr = SpanCorrelator()
        corr.ingest(
            parse_span(
                {
                    "name": "execute_tool orphan",
                    "attributes": [_kv("gen_ai.tool.name", "orphan")],
                }
            )
        )
        # no conversation id -> kept under the dedicated bucket, never surfaced
        # as a real conversation.
        assert corr.conversation_ids == []
        assert corr.tool_calls_for(SpanCorrelator.UNCORRELATED) == ["orphan"]
        summary = corr.summary()
        assert summary["uncorrelated_spans"] == 1
        assert summary["conversations"] == 0
        # the orphan tool is NOT reported under any real conversation.
        assert summary["tool_calls_by_conversation"] == {}

    def test_ingest_many(self) -> None:
        corr = SpanCorrelator()
        corr.ingest_many(
            [
                parse_span(
                    _otlp_tool_span(
                        name="t",
                        conversation_id="c",
                        tool_name="search",
                    )
                ),
                parse_span(
                    _otlp_tool_span(
                        name="t",
                        conversation_id="c",
                        tool_name="lookup",
                    )
                ),
            ]
        )
        assert corr.tool_calls_for("c") == ["search", "lookup"]

    def test_summary_shape_and_counts(self) -> None:
        corr = SpanCorrelator()
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="t",
                    conversation_id="c1",
                    tool_name="search",
                )
            )
        )
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="t",
                    conversation_id="c1",
                    tool_name="search",
                )
            )
        )
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="t",
                    conversation_id="c2",
                    tool_name="send_email",
                )
            )
        )
        corr.ingest(
            parse_span(
                {  # non-tool span, still counted in total
                    "name": "invoke_agent x",
                    "attributes": [_kv("gen_ai.conversation.id", "c1")],
                }
            )
        )
        summary = corr.summary()
        assert set(summary) == {
            "conversations",
            "total_spans",
            "uncorrelated_spans",
            "tool_calls_by_conversation",
            "tool_call_counts",
        }
        assert summary["conversations"] == 2
        assert summary["total_spans"] == 4
        assert summary["uncorrelated_spans"] == 0
        assert summary["tool_calls_by_conversation"] == {
            "c1": ["search", "search"],
            "c2": ["send_email"],
        }
        assert summary["tool_call_counts"] == {"search": 2, "send_email": 1}

    def test_summary_omits_conversations_without_tool_calls(self) -> None:
        corr = SpanCorrelator()
        corr.ingest(
            parse_span(
                {
                    "name": "invoke_agent x",
                    "attributes": [_kv("gen_ai.conversation.id", "c-no-tools")],
                }
            )
        )
        summary = corr.summary()
        assert summary["conversations"] == 1
        assert summary["tool_calls_by_conversation"] == {}


# ---------------------------------------------------------------------------
# ingest_otlp_json
# ---------------------------------------------------------------------------
class TestIngestOtlpJson:
    def test_walks_multi_span_payload(self) -> None:
        payload = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                _otlp_tool_span(
                                    name="execute_tool search",
                                    conversation_id="conv-1",
                                    tool_name="search",
                                ),
                                _otlp_tool_span(
                                    name="execute_tool send_email",
                                    conversation_id="conv-1",
                                    tool_name="send_email",
                                ),
                            ]
                        }
                    ]
                },
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                _otlp_tool_span(
                                    name="execute_tool read_file",
                                    conversation_id="conv-2",
                                    tool_name="read_file",
                                ),
                            ]
                        }
                    ]
                },
            ]
        }
        corr = ingest_otlp_json(payload)
        assert corr.tool_calls_for("conv-1") == ["search", "send_email"]
        assert corr.tool_calls_for("conv-2") == ["read_file"]
        assert corr.summary()["total_spans"] == 3

    def test_reuses_supplied_correlator(self) -> None:
        corr = SpanCorrelator()
        corr.ingest(
            parse_span(
                _otlp_tool_span(
                    name="t",
                    conversation_id="conv-1",
                    tool_name="prior",
                )
            )
        )
        returned = ingest_otlp_json(
            {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {
                                "spans": [
                                    _otlp_tool_span(
                                        name="t", conversation_id="conv-1", tool_name="search"
                                    ),
                                ]
                            }
                        ]
                    }
                ]
            },
            correlator=corr,
        )
        assert returned is corr
        assert corr.tool_calls_for("conv-1") == ["prior", "search"]

    def test_empty_payload_yields_empty_correlator(self) -> None:
        corr = ingest_otlp_json({})
        assert corr.summary()["total_spans"] == 0
        assert corr.conversation_ids == []

    def test_missing_and_mistyped_levels_are_skipped(self) -> None:
        payload = {
            "resourceSpans": [
                "not-a-dict",
                {"scopeSpans": "not-a-list"},
                {"scopeSpans": ["not-a-dict"]},
                {"scopeSpans": [{"spans": "not-a-list"}]},
                {"scopeSpans": [{"spans": ["not-a-dict-span"]}]},
                {"scopeSpans": [{}]},  # missing spans key
                {},  # missing scopeSpans key
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                _otlp_tool_span(
                                    name="execute_tool ok",
                                    conversation_id="conv-ok",
                                    tool_name="ok_tool",
                                ),
                            ]
                        }
                    ]
                },
            ]
        }
        corr = ingest_otlp_json(payload)
        # only the one well-formed span survives.
        assert corr.tool_calls_for("conv-ok") == ["ok_tool"]
        assert corr.summary()["total_spans"] == 1

    def test_non_list_resource_spans_is_safe(self) -> None:
        corr = ingest_otlp_json({"resourceSpans": "garbage"})
        assert corr.summary()["total_spans"] == 0


def test_target_span_record_is_directly_constructible() -> None:
    """The dataclass can be built directly (e.g. by a future OTLP/proto path)."""
    record = TargetSpanRecord(
        name="execute_tool x",
        conversation_id="c",
        tool_name="x",
        tool_type="function",
    )
    assert record.is_tool_call is True
    assert record.attributes == {}


# ---------------------------------------------------------------------------
# End-to-end correlation: spans we EMIT must be ingestible by the consumer.
#
# This closes the cluster's P1 finding — without ``gen_ai.conversation.id`` on
# the transport.send span the correlator's primary query
# (``SpanCorrelator.tool_calls_for(session)``) was structurally unreachable
# even when both sides used the same SDK. The test below is a true end-to-end:
# it drives the real :func:`agent_guardian.obs.otel.transport_span` and
# :func:`tool_span` to populate an in-memory exporter, hand-converts the
# exported spans into OTLP/JSON shape, and asserts the correlator can answer
# ``tool_calls_for(session)``.
# ---------------------------------------------------------------------------
import pytest  # noqa: E402  - kept after module-level functions for clarity.


@pytest.fixture
def _active_tracer(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    pytest.importorskip("opentelemetry")
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    monkeypatch.setenv("OTEL_SEMCONV_STABILITY_OPT_IN", "gen_ai_latest_experimental")
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    class _AlreadyDone:
        def do_once(self, func: object) -> bool:
            return False

    monkeypatch.setattr(trace, "_TRACER_PROVIDER", provider, raising=False)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", _AlreadyDone(), raising=False)
    exporter.clear()
    yield exporter
    exporter.clear()


def _span_to_otlp_json(span: Any) -> dict[str, Any]:
    """Convert one in-memory ReadableSpan to the OTLP/JSON wire shape."""
    attributes_list = []
    for key, value in (span.attributes or {}).items():
        if isinstance(value, bool):
            attributes_list.append({"key": key, "value": {"boolValue": value}})
        elif isinstance(value, int):
            attributes_list.append({"key": key, "value": {"intValue": str(value)}})
        elif isinstance(value, float):
            attributes_list.append({"key": key, "value": {"doubleValue": value}})
        else:
            attributes_list.append({"key": key, "value": {"stringValue": str(value)}})
    return {
        "name": span.name,
        "startTimeUnixNano": str(span.start_time or 0),
        "endTimeUnixNano": str(span.end_time or 0),
        "attributes": attributes_list,
    }


class TestEndToEndConversationCorrelation:
    """transport.send + tool spans we emit are correlator-ingestible."""

    def test_transport_span_carries_conversation_id_to_correlator(self, _active_tracer) -> None:  # type: ignore[no-untyped-def]
        from agent_guardian.obs.otel import tool_span, transport_span

        # Emit a transport.send + an execute_tool span, both stamped with the
        # same conversation id (which is how the real adapter wires it).
        with (
            transport_span("https://target.example/chat", conversation_id="sess-abc"),
            tool_span("send_email"),
        ):
            pass

        finished = list(_active_tracer.get_finished_spans())
        assert len(finished) == 2

        # Convert to OTLP/JSON and feed the consumer.
        payload = {
            "resourceSpans": [
                {"scopeSpans": [{"spans": [_span_to_otlp_json(s) for s in finished]}]}
            ]
        }
        corr = ingest_otlp_json(payload)

        # The correlator must answer with the tools that were called for the
        # session — the very query that was structurally unreachable before
        # the conversation id reached transport.send.
        assert corr.tool_calls_for("sess-abc") == ["send_email"]
