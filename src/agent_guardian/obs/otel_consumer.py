"""Consume the TARGET's own OpenTelemetry spans and correlate them (Stage 3).

Stage 1B taught AgentGuardian to *emit* spans (see :mod:`agent_guardian.obs.otel`).
Stage 3 closes the loop: when the contract sets ``observability.otel_endpoint``,
the target under test may *also* emit GenAI spans for the agent turns and tool
calls it runs internally. Those spans are ground-truth evidence of which tools
the target actually invoked during a scan — far stronger than parsing tool calls
out of the reply text. This module ingests those spans and correlates them with
our adversarial turns.

Correlation key
---------------
Both sides speak the GenAI semantic conventions, so the join key is the
conversation id. AgentGuardian stamps ``gen_ai.conversation.id`` on every
``invoke_agent`` / ``transport.send`` span (see :func:`agent_guardian.obs.otel.agent_span`),
using the *session id* the adapter drives the target with. A correctly
instrumented target stamps the **same** ``gen_ai.conversation.id`` on the spans
it emits for the work it does in response. Bucketing both sides by that id lets
:class:`SpanCorrelator` answer "for conversation X, which tools did the target
*actually* invoke?" with the target's own telemetry.

Scope of this module
--------------------
The full collector / receiver infrastructure (an OTLP/gRPC or OTLP/HTTP server,
batching, retries, auth) is intentionally **out of scope** here. What ships is:

* the correlation core (:class:`TargetSpanRecord`, :class:`SpanCorrelator`),
* a parser from a span dict — either the wire OTLP/JSON shape, or a flat dict of
  ``gen_ai.*`` attributes — into a :class:`TargetSpanRecord`
  (:func:`parse_span`), and
* a minimal ingestion entrypoint :func:`ingest_otlp_json` that walks an
  OTLP/JSON ``resourceSpans`` document and feeds a correlator.

Production receiver (documented stub)
------------------------------------
In production an operator points the target's OTLP/HTTP exporter at a receiver
endpoint AgentGuardian (or a sidecar collector) owns. The receiver is a thin
HTTP handler::

    async def handle_export(request: Request) -> Response:
        payload = await request.json()       # OTLP/JSON ExportTraceServiceRequest
        ingest_otlp_json(payload, correlator=correlator)
        return Response(status_code=200)

i.e. the receiver does nothing but decode the body and hand it to
:func:`ingest_otlp_json`. We deliberately do **not** ship that HTTP server: it is
deployment-specific (framework, TLS, auth, backpressure) and untestable without
a live socket. The correlation core below is fully unit-testable with synthetic
span dictionaries and needs no live collector.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

_LOG = logging.getLogger(__name__)

__all__ = [
    "SpanCorrelator",
    "TargetSpanRecord",
    "ingest_otlp_json",
    "parse_span",
]

# --- GenAI semantic-convention attribute keys -------------------------------
# Mirrors the constants in :mod:`agent_guardian.obs.otel`; duplicated (rather
# than imported) so this consumer never depends on the emitter's internals and
# the keys it reads are spelled exactly once here.
_ATTR_CONVERSATION_ID = "gen_ai.conversation.id"
_ATTR_TOOL_NAME = "gen_ai.tool.name"
_ATTR_TOOL_TYPE = "gen_ai.tool.type"


@dataclass(frozen=True)
class TargetSpanRecord:
    """One span the target emitted, reduced to the fields we correlate on.

    ``conversation_id`` is the GenAI ``gen_ai.conversation.id`` join key (the
    session id our adapter drives the target with). ``tool_name`` /
    ``tool_type`` come from ``gen_ai.tool.name`` / ``gen_ai.tool.type`` and are
    ``None`` for non-tool spans (e.g. an ``invoke_agent`` span). ``attributes``
    keeps the full flattened GenAI attribute bag for downstream inspection.
    ``start_unix_nano`` / ``end_unix_nano`` are the raw OTLP timestamps when the
    span carried them, else ``None``.
    """

    name: str
    conversation_id: str | None
    tool_name: str | None = None
    tool_type: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    start_unix_nano: int | None = None
    end_unix_nano: int | None = None

    @property
    def is_tool_call(self) -> bool:
        """True iff this span reports a tool invocation (has a tool name)."""
        return self.tool_name is not None


# --- OTLP/JSON attribute decoding -------------------------------------------
# OTLP/JSON encodes each attribute as ``{"key": ..., "value": <AnyValue>}`` where
# AnyValue is a one-of: ``stringValue`` / ``intValue`` / ``doubleValue`` /
# ``boolValue`` / ``arrayValue`` / ``kvlistValue``. ``intValue`` is a *string* on
# the wire (proto int64-as-string). We decode the scalar forms we care about and
# fall back to the raw value object for anything exotic.
def _decode_any_value(value: Any) -> Any:
    """Decode a single OTLP/JSON ``AnyValue`` object to a Python scalar.

    Robust to a non-dict ``value`` (returned verbatim) and to unknown shapes
    (the raw dict is returned so no information is silently dropped).
    """
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "intValue" in value:
        raw = value["intValue"]
        try:
            return int(raw)
        except (TypeError, ValueError):
            return raw
    if "doubleValue" in value:
        return value["doubleValue"]
    if "arrayValue" in value:
        items = (
            value["arrayValue"].get("values", []) if isinstance(value["arrayValue"], dict) else []
        )
        return [_decode_any_value(item) for item in items]
    return value


def _flatten_attributes(raw: Any) -> dict[str, Any]:
    """Flatten an OTLP attribute container into a plain ``{key: value}`` dict.

    Accepts either the OTLP/JSON wire form (a list of ``{"key", "value"}``
    objects) or an already-flat ``dict``; anything else yields an empty dict.
    Never raises on a malformed entry — it is skipped (and logged at DEBUG).
    """
    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, list):
        return {}
    flat: dict[str, Any] = {}
    for entry in raw:
        if not isinstance(entry, dict) or "key" not in entry:
            _LOG.debug("skipping malformed OTLP attribute entry: %r", entry)
            continue
        key = entry["key"]
        if not isinstance(key, str):
            _LOG.debug("skipping OTLP attribute with non-string key: %r", key)
            continue
        flat[key] = _decode_any_value(entry.get("value"))
    return flat


def _coerce_nano(value: Any) -> int | None:
    """Coerce an OTLP timestamp (int or proto int64-as-string) to int, else None."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_span(span: dict[str, Any]) -> TargetSpanRecord:
    """Turn one span dict into a :class:`TargetSpanRecord`.

    Accepts either the OTLP/JSON span shape (``{"name", "attributes": [...],
    "startTimeUnixNano", "endTimeUnixNano"}`` with list-of-kv attributes) or a
    simplified flat dict where ``attributes`` is already ``{key: value}``. Robust
    to missing fields: an absent name becomes ``""`` and absent attributes yield
    an empty record (``conversation_id`` / ``tool_name`` left ``None``).
    """
    attributes = _flatten_attributes(span.get("attributes"))
    conversation_id = attributes.get(_ATTR_CONVERSATION_ID)
    tool_name = attributes.get(_ATTR_TOOL_NAME)
    tool_type = attributes.get(_ATTR_TOOL_TYPE)
    return TargetSpanRecord(
        name=str(span.get("name", "")),
        conversation_id=str(conversation_id) if conversation_id is not None else None,
        tool_name=str(tool_name) if tool_name is not None else None,
        tool_type=str(tool_type) if tool_type is not None else None,
        attributes=attributes,
        start_unix_nano=_coerce_nano(span.get("startTimeUnixNano")),
        end_unix_nano=_coerce_nano(span.get("endTimeUnixNano")),
    )


class SpanCorrelator:
    """Bucket target spans by conversation id and answer correlation queries.

    The correlator is fed :class:`TargetSpanRecord` instances (via
    :meth:`ingest`) and buckets them by ``conversation_id``. Spans with no
    conversation id are kept under a dedicated :data:`UNCORRELATED` bucket so
    they are counted but never confused with a real conversation.

    The primary query, :meth:`tool_calls_for`, returns the ``gen_ai.tool.name``
    values the target reported for one conversation — the ground-truth set of
    tools the target actually invoked while we were driving that session. Because
    our adapter stamps ``gen_ai.conversation.id`` with the session id, the caller
    passes that same session id to join the two sides.
    """

    #: Bucket key for spans the target emitted without a conversation id. Kept
    #: separate so uncorrelated spans are auditable but never merged into a real
    #: conversation's tool list.
    UNCORRELATED = "<uncorrelated>"

    def __init__(self) -> None:
        # conversation_id (or UNCORRELATED) -> spans, in ingest order.
        self._by_conversation: dict[str, list[TargetSpanRecord]] = defaultdict(list)

    def ingest(self, record: TargetSpanRecord) -> None:
        """Bucket one record by its conversation id (or :data:`UNCORRELATED`)."""
        key = record.conversation_id if record.conversation_id is not None else self.UNCORRELATED
        self._by_conversation[key].append(record)

    def ingest_many(self, records: list[TargetSpanRecord]) -> None:
        """Bucket several records, preserving order. Convenience over :meth:`ingest`."""
        for record in records:
            self.ingest(record)

    @property
    def conversation_ids(self) -> list[str]:
        """The real conversation ids seen so far (excludes :data:`UNCORRELATED`)."""
        return [key for key in self._by_conversation if key != self.UNCORRELATED]

    def records_for(self, conversation_id: str) -> list[TargetSpanRecord]:
        """All spans bucketed under ``conversation_id`` (empty list if none)."""
        return list(self._by_conversation.get(conversation_id, []))

    def tool_calls_for(self, conversation_id: str) -> list[str]:
        """Tool names the target reported for ``conversation_id``, in span order.

        Returns ``gen_ai.tool.name`` for every tool span bucketed under the id.
        Duplicates are preserved (the target may invoke the same tool more than
        once) — callers that want a unique set can dedupe. An unknown id yields
        an empty list.
        """
        return [
            record.tool_name
            for record in self._by_conversation.get(conversation_id, [])
            if record.tool_name is not None
        ]

    def summary(self) -> dict[str, Any]:
        """Compact, JSON-serialisable correlation summary for the scan report.

        Shape::

            {
              "conversations": int,            # distinct real conversation ids
              "total_spans": int,              # every span ingested
              "uncorrelated_spans": int,       # spans with no conversation id
              "tool_calls_by_conversation": {  # id -> ordered tool-name list
                  "<conv-id>": ["search", "send_email", ...],
              },
              "tool_call_counts": {            # tool name -> total invocations
                  "search": 3, "send_email": 1, ...
              },
            }
        """
        tool_calls_by_conversation: dict[str, list[str]] = {}
        tool_call_counts: dict[str, int] = defaultdict(int)
        total_spans = 0
        for key, records in self._by_conversation.items():
            total_spans += len(records)
            if key == self.UNCORRELATED:
                continue
            names = [r.tool_name for r in records if r.tool_name is not None]
            if names:
                tool_calls_by_conversation[key] = names
            for name in names:
                tool_call_counts[name] += 1
        uncorrelated = len(self._by_conversation.get(self.UNCORRELATED, []))
        return {
            "conversations": len(self.conversation_ids),
            "total_spans": total_spans,
            "uncorrelated_spans": uncorrelated,
            "tool_calls_by_conversation": tool_calls_by_conversation,
            "tool_call_counts": dict(tool_call_counts),
        }


def ingest_otlp_json(
    payload: dict[str, Any],
    *,
    correlator: SpanCorrelator | None = None,
) -> SpanCorrelator:
    """Walk an OTLP/JSON trace document and feed every span to a correlator.

    ``payload`` is the OTLP/JSON ``ExportTraceServiceRequest`` shape::

        {"resourceSpans": [
            {"scopeSpans": [
                {"spans": [ {<span>}, ... ]}
            ]}
        ]}

    When ``correlator`` is ``None`` a fresh :class:`SpanCorrelator` is created;
    either way the (populated) correlator is returned. Robust to missing or
    mistyped levels: a missing ``resourceSpans`` / ``scopeSpans`` / ``spans``
    list, a non-list where a list is expected, or a non-dict span are all
    skipped rather than raised on, so a partially-malformed export still yields
    whatever well-formed spans it contained.
    """
    correlator = correlator if correlator is not None else SpanCorrelator()
    for resource_span in _as_list(payload.get("resourceSpans")):
        if not isinstance(resource_span, dict):
            continue
        for scope_span in _as_list(resource_span.get("scopeSpans")):
            if not isinstance(scope_span, dict):
                continue
            for span in _as_list(scope_span.get("spans")):
                if not isinstance(span, dict):
                    _LOG.debug("skipping non-dict span in OTLP payload: %r", span)
                    continue
                correlator.ingest(parse_span(span))
    return correlator


def _as_list(value: Any) -> list[Any]:
    """Return ``value`` if it is a list, else an empty list (never raises)."""
    return value if isinstance(value, list) else []
