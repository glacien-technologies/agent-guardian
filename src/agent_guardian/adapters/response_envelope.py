"""Response normalizer — one envelope shape for an HTTP snapshot OR plain text.

A target reply reaches recon in one of two shapes: a structured
:class:`~agent_guardian.adapters.http.HttpAdapterLastResponse` snapshot (the
HTTP transport stashes text + tool blocks + the parsed body per turn) or a
bare ``str`` (every non-HTTP adapter — PromptAdapter, CodeAdapter,
FrameworkAdapter — returns a plain assistant string). This module projects
EITHER into one :class:`ResponseEnvelope` so the recon engine reads a single
normalized shape instead of branching on adapter type at every signal site.

It is a pure, opt-in **projection layer**: nothing in the default scan path
builds an envelope. The HTTP adapter does NOT import this module — the
dependency runs one way (this module reaches *into* an HTTP snapshot via a
duck-typed read, and the runtime ``HttpAdapter`` isinstance check in
:func:`envelope_from_target` is done with a LAZY import to avoid an import
cycle). Path extraction reuses the same ``$.a.b.c`` walker the adapter's own
tool-call extractor uses (:func:`agent_guardian.adapters.http_shapes.generic_shape.walk_jsonpath`)
so there is one JSONPath mechanism in the package, not two.

Text auto-detect order (first non-empty wins, provider-ordered) and the
tool-call auto-detect order are documented on ``_TEXT_AUTODETECT`` /
``_TOOLCALLS_AUTODETECT`` below; an operator who knows the target's shape can
override the heuristics with an explicit :class:`ResponseMapping`.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath

_LOG = logging.getLogger(__name__)

if TYPE_CHECKING:
    from agent_guardian.adapters.base import TargetAdapter
    from agent_guardian.adapters.http import HttpAdapterLastResponse, HttpAdapterToolCall

__all__ = [
    "EnvelopeToolCall",
    "ResponseEnvelope",
    "ResponseMapping",
    "envelope_from_target",
    "has_planted_token",
    "project_http_last_response",
    "project_json_response",
    "project_text_response",
    "tool_names_from_envelope",
]


# First-match-wins text projection paths, ordered by provider so the most
# specific structured shapes are tried before the bare generic fallbacks:
# OpenAI-style nested output, Chat Completions ``message.content``, Anthropic
# ``content[0].text``, Vertex ``candidates[...].parts[...].text``, then the
# generic ``$.text`` / ``$.output`` / ``$.message`` / ``$.response`` keys.
_TEXT_AUTODETECT: tuple[str, ...] = (
    "$.output.text",
    "$.choices[0].message.content",
    "$.content[0].text",
    "$.candidates[0].content.parts[0].text",
    "$.text",
    "$.output",
    "$.message",
    "$.response",
)

# First-match-wins tool-call container paths. Each resolves to a list (or a
# single dict, coerced to a one-item list) of tool blocks; the per-item
# name/args paths from the mapping then lift the handle + kwargs out of each
# block, exactly as the adapter-level extractor does.
_TOOLCALLS_AUTODETECT: tuple[str, ...] = (
    "$.tool_calls",
    "$.choices[0].message.tool_calls",
    "$.content",
    "$.output.message.content",
    "$.candidates[0].content.parts",
)

# Cap on the JSON-serialised raw body stored in :meth:`ResponseEnvelope.to_dict`.
# A body larger than this (or one that is not JSON-serialisable) is replaced
# with a truncated ``repr`` so the probe-log line stays bounded.
_RAW_BODY_CAP = 16384


@dataclass(frozen=True, slots=True)
class EnvelopeToolCall:
    """One normalized tool invocation lifted out of a response.

    Mirrors :class:`agent_guardian.adapters.http.HttpAdapterToolCall` but lives
    in the envelope layer so a recon consumer has a single tool-call type to
    import regardless of whether the evidence came from an HTTP snapshot or a
    projected JSON body.
    """

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    raw: Any = None

    @classmethod
    def from_http_tool_call(cls, tc: HttpAdapterToolCall) -> EnvelopeToolCall:
        """Adopt an adapter-level tool call without re-parsing it."""
        return cls(name=tc.name, arguments=dict(tc.arguments), raw=tc.raw)


@dataclass(frozen=True, slots=True)
class ResponseMapping:
    """Optional operator override for where text / tool calls live in a body.

    Every non-``None`` path must start with ``$`` (the
    :func:`~agent_guardian.adapters.http_shapes.generic_shape.walk_jsonpath`
    contract); we validate up front in ``__post_init__`` so a malformed mapping
    fails fast at construction rather than swallowing the bad path mid-probe.
    ``tool_name_path`` / ``tool_args_path`` are applied per tool block.
    """

    text_path: str | None = None
    tool_calls_path: str | None = None
    citations_path: str | None = None
    tool_name_path: str = "$.name"
    tool_args_path: str = "$.arguments"

    def __post_init__(self) -> None:
        for path in (
            self.text_path,
            self.tool_calls_path,
            self.citations_path,
            self.tool_name_path,
            self.tool_args_path,
        ):
            if path is not None and not path.startswith("$"):
                raise ValueError(f"ResponseMapping jsonpath must start with '$' (got {path!r})")


@dataclass(frozen=True, slots=True)
class ResponseEnvelope:
    """Normalized view of a single target reply.

    ``text`` is the assistant message; ``tool_calls`` the structured
    invocations; ``format`` records how the reply was shaped (``json`` /
    ``text`` / ``empty`` / ``unknown``). ``parse_success`` is ``True`` when a
    text OR tool-calls path resolved; ``empty`` is ``True`` when neither a
    message nor a tool call was found. The optional transport metadata
    (``content_type`` / ``status_code`` / ``latency_ms``) is preserved when a
    caller has it and dropped from :meth:`to_dict` when ``None``.
    """

    text: str
    format: Literal["text", "json", "empty", "unknown"]
    empty: bool
    parse_success: bool
    raw_body: Any = None
    content_type: str | None = None
    status_code: int | None = None
    latency_ms: float | None = None
    extracted_fields: dict[str, Any] = field(default_factory=dict)
    tool_calls: tuple[EnvelopeToolCall, ...] = ()
    citations: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def is_error(self) -> bool:
        """True when the text is the audit's ``[target call failed: ...]`` sentinel.

        Derived (not a stored field) so the foundation envelope shape stays
        flat; the capability audit writes the sentinel as the reply text on a
        target exception and reads it back through this property.
        """
        return self.text.startswith("[target call failed:")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection for the probe-log line.

        ``raw_body`` is guarded: if it is not JSON-serialisable OR exceeds
        :data:`_RAW_BODY_CAP` it is replaced with a truncated ``repr`` and a
        warning is appended. ``None``-valued top-level optional keys are dropped
        so the log line carries only the fields a turn actually produced.
        """
        warnings = list(self.warnings)
        raw_body: Any = self.raw_body
        if raw_body is not None:
            try:
                serialised = json.dumps(raw_body)
                if len(serialised) > _RAW_BODY_CAP:
                    raise ValueError("raw_body exceeds cap")
            except (TypeError, ValueError):
                raw_body = {"_truncated_repr": repr(self.raw_body)[:_RAW_BODY_CAP]}
                warnings.append("raw_body truncated (exceeded cap)")

        out: dict[str, Any] = {
            "text": _json_safe(self.text),
            "format": self.format,
            "empty": self.empty,
            "parse_success": self.parse_success,
            "is_error": self.is_error,
            "raw_body": _json_safe(raw_body),
            "content_type": self.content_type,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "extracted_fields": _json_safe(self.extracted_fields),
            "tool_calls": [
                {"name": tc.name, "arguments": _json_safe(tc.arguments), "raw": _json_safe(tc.raw)}
                for tc in self.tool_calls
            ],
            "citations": list(self.citations),
            "errors": list(self.errors),
            "warnings": warnings,
        }
        # Drop None-valued top-level optional keys.
        return {k: v for k, v in out.items() if v is not None}


def _json_safe(value: Any) -> Any:
    """Coerce a value to JSON-safe primitives (mirrors scan_store._json_safe)."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list | tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return str(value)


def _decode_tool_args(args: Any, warnings: list[str]) -> dict[str, Any]:
    """Best-effort decode of tool arguments (mirrors http._extract_tool_calls).

    ``arguments`` over the wire is sometimes a JSON-encoded string (notably
    OpenAI tool_calls). Decode best-effort; on failure record a warning and
    fall back to an empty dict so the call still surfaces its name.
    """
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            decoded = json.loads(args)
        except (json.JSONDecodeError, ValueError) as exc:
            _LOG.debug("response_envelope: tool_call args not JSON-decodable (%s)", exc)
            warnings.append("tool_call arguments not JSON-decodable -- preserved as empty")
            return {}
        if isinstance(decoded, dict):
            return decoded
    return {}


def _extract_tool_calls_from_body(
    body: dict[str, Any],
    *,
    container_path: str,
    name_path: str,
    args_path: str,
    errors: list[str],
    warnings: list[str],
) -> tuple[EnvelopeToolCall, ...]:
    """Walk a tool-call container path and lift each block into an EnvelopeToolCall."""
    try:
        raw = walk_jsonpath(body, container_path)
    except ValueError as exc:
        _LOG.debug("response_envelope: bad tool-calls path %r (%s)", container_path, exc)
        errors.append(str(exc))
        return ()
    if raw is None:
        return ()
    items = raw if isinstance(raw, list) else [raw]
    calls: list[EnvelopeToolCall] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            name = walk_jsonpath(item, name_path)
            args = walk_jsonpath(item, args_path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if name is None:
            continue
        calls.append(
            EnvelopeToolCall(
                name=str(name),
                arguments=_decode_tool_args(args, warnings),
                raw=item,
            )
        )
    return tuple(calls)


def project_json_response(
    body: dict[str, Any],
    *,
    mapping: ResponseMapping | None = None,
    content_type: str | None = None,
    status_code: int | None = None,
    latency_ms: float | None = None,
) -> ResponseEnvelope:
    """Project a parsed JSON body into a :class:`ResponseEnvelope`.

    PURE and never raises: every :func:`walk_jsonpath` ``ValueError`` is caught
    into ``errors`` and an envelope is still returned. When ``mapping`` is
    ``None`` the text and tool-call locations are auto-detected from the
    provider-ordered ``_TEXT_AUTODETECT`` / ``_TOOLCALLS_AUTODETECT`` paths.
    """
    errors: list[str] = []
    warnings: list[str] = []
    text_resolved = False
    text_value: str = ""

    if not isinstance(body, dict):
        return ResponseEnvelope(
            text="",
            format="unknown",
            empty=True,
            parse_success=False,
            raw_body=body,
            content_type=content_type,
            status_code=status_code,
            latency_ms=latency_ms,
        )

    name_path = mapping.tool_name_path if mapping is not None else "$.name"
    args_path = mapping.tool_args_path if mapping is not None else "$.arguments"

    # Text projection.
    text_paths = (
        (mapping.text_path,)
        if mapping is not None and mapping.text_path is not None
        else _TEXT_AUTODETECT
    )
    for path in text_paths:
        try:
            value = walk_jsonpath(body, path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if value is not None and str(value) != "":
            text_value = str(value)
            text_resolved = True
            break

    # Tool-call projection.
    tool_calls: tuple[EnvelopeToolCall, ...] = ()
    tool_resolved = False
    tool_paths = (
        (mapping.tool_calls_path,)
        if mapping is not None and mapping.tool_calls_path is not None
        else _TOOLCALLS_AUTODETECT
    )
    for path in tool_paths:
        if path is None:
            continue
        calls = _extract_tool_calls_from_body(
            body,
            container_path=path,
            name_path=name_path,
            args_path=args_path,
            errors=errors,
            warnings=warnings,
        )
        if calls:
            tool_calls = calls
            tool_resolved = True
            break

    # Citations projection (optional).
    citations: tuple[str, ...] = ()
    if mapping is not None and mapping.citations_path is not None:
        try:
            cited = walk_jsonpath(body, mapping.citations_path)
        except ValueError as exc:
            errors.append(str(exc))
            cited = None
        if isinstance(cited, list):
            citations = tuple(str(c) for c in cited)

    empty = not text_resolved and not tool_calls
    parse_success = text_resolved or tool_resolved
    if text_resolved:
        fmt: Literal["text", "json", "empty", "unknown"] = "json"
    elif empty:
        fmt = "empty"
    else:
        fmt = "json"

    return ResponseEnvelope(
        text=text_value,
        format=fmt,
        empty=empty,
        parse_success=parse_success,
        raw_body=body,
        content_type=content_type,
        status_code=status_code,
        latency_ms=latency_ms,
        tool_calls=tool_calls,
        citations=citations,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def project_text_response(text: str, *, latency_ms: float | None = None) -> ResponseEnvelope:
    """Project a bare assistant string into a :class:`ResponseEnvelope`."""
    return ResponseEnvelope(
        text=text,
        format="text",
        empty=(text == ""),
        parse_success=True,
        raw_body=None,
        latency_ms=latency_ms,
        tool_calls=(),
    )


def project_http_last_response(
    snapshot: HttpAdapterLastResponse,
    *,
    mapping: ResponseMapping | None = None,
    latency_ms: float | None = None,
) -> ResponseEnvelope:
    """Project an HTTP per-turn snapshot, reusing its already-extracted fields.

    Consumes the duck-typed ``.text`` / ``.tool_calls`` / ``.raw`` triple. The
    snapshot's tool calls were already lifted by the adapter, so we adopt them
    directly rather than re-walking the body. ``mapping.citations_path`` is the
    only reason we re-walk ``snapshot.raw`` here.
    """
    # An explicit text / tool-call override means the operator wants the body
    # re-read from a known location, so re-project from the raw body rather than
    # trusting the adapter shape's auto-extracted text. (Citations-only mappings
    # fall through to the cheap adopt-the-snapshot path below.)
    if (
        mapping is not None
        and (mapping.text_path is not None or mapping.tool_calls_path is not None)
        and isinstance(snapshot.raw, dict)
    ):
        return project_json_response(snapshot.raw, mapping=mapping, latency_ms=latency_ms)

    tool_calls = tuple(EnvelopeToolCall.from_http_tool_call(tc) for tc in snapshot.tool_calls)
    citations: tuple[str, ...] = ()
    errors: list[str] = []
    if mapping is not None and mapping.citations_path is not None and snapshot.raw is not None:
        try:
            cited = walk_jsonpath(snapshot.raw, mapping.citations_path)
        except ValueError as exc:
            errors.append(str(exc))
            cited = None
        if isinstance(cited, list):
            citations = tuple(str(c) for c in cited)

    fmt: Literal["text", "json", "empty", "unknown"] = (
        "json" if snapshot.raw is not None else "text"
    )
    return ResponseEnvelope(
        text=snapshot.text,
        format=fmt,
        empty=(snapshot.text == "" and not snapshot.tool_calls),
        parse_success=True,
        raw_body=snapshot.raw,
        latency_ms=latency_ms,
        tool_calls=tool_calls,
        citations=citations,
        errors=tuple(errors),
    )


def envelope_from_target(
    target: TargetAdapter,
    reply_text: str,
    *,
    mapping: ResponseMapping | None = None,
    latency_ms: float | None = None,
) -> ResponseEnvelope:
    """Normalize a target reply into a :class:`ResponseEnvelope`.

    When ``target`` is an :class:`~agent_guardian.adapters.http.HttpAdapter`
    with a stashed per-turn snapshot, project that (text + structured tool
    blocks + raw body). Otherwise project the plain ``reply_text``. The
    ``HttpAdapter`` import is LAZY so this module never participates in an
    import cycle with the transport layer.

    ``mapping`` is the operator's optional shape override; it is forwarded to
    :func:`project_http_last_response` (which honours a text / tool-call path by
    re-reading the raw body, and a citations path by walking it). A bare-text
    target carries no structured body, so ``mapping`` does not apply there.
    """
    from agent_guardian.adapters.http import HttpAdapter

    if isinstance(target, HttpAdapter) and target._last_response is not None:
        return project_http_last_response(
            target._last_response, mapping=mapping, latency_ms=latency_ms
        )
    return project_text_response(reply_text, latency_ms=latency_ms)


def tool_names_from_envelope(env: ResponseEnvelope) -> tuple[str, ...]:
    """Return the non-empty tool-call handles surfaced in an envelope."""
    return tuple(tc.name for tc in env.tool_calls if tc.name)


def has_planted_token(reply: str, token: str) -> bool:
    """True when ``token`` appears in ``reply`` as a standalone reference code.

    Anchored so a trailing ``.`` still matches but a different / embedded /
    extended ``MEM-``-shaped token does not (avoids a hallucinated-token
    false-positive in the cross-session memory recall check).
    """
    pattern = r"(?<![A-Za-z0-9-])" + re.escape(token) + r"(?![A-Za-z0-9-])"
    return re.search(pattern, reply) is not None
