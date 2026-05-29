"""OpenAPI 3.1 -> request/response shape generator (Stage 4).

``agent-guardian init --from-openapi spec.{yaml,json}`` lets an operator point
the wizard at an OpenAPI document instead of answering the transport / request /
response questions by hand. This module is the pure-Python engine behind that
flow: given the *already-parsed* spec mapping (the caller loads YAML/JSON), it
picks an operation and derives a contract fragment the wizard can splice in:

* ``transport`` — an HTTP transport (``url`` = ``servers[0].url`` + path,
  ``method``);
* ``request`` — a Jinja ``body`` template that maps the AgentGuardian ``prompt``
  variable onto the operation's most-likely *text* request field, plus the
  request ``content_type``;
* ``response`` — the JSONPath (``output_path``) into the 200 response schema
  pointing at the most-likely *text* reply field.

Design rules:

* **No new dependency.** We walk the spec mapping directly and resolve only
  *simple local* ``$ref`` pointers (``#/components/...``) within the same
  document — enough for the common hand-written / tool-emitted spec, and
  deterministic. Remote / recursive refs are out of scope (a recursive ref is
  detected and stopped rather than looping forever).
* **Deterministic.** Operation selection and field selection are stable for a
  given spec: candidates are walked in document order and the field heuristics
  use a fixed priority list, so the same spec always yields the same fragment.
* **Loud on missing pieces.** A spec with no servers, no usable operation, or no
  request body raises :class:`ValueError` naming exactly what was missing — the
  wizard surfaces that to the operator rather than emitting a broken contract.

Nothing here renders or validates against the contract schema; the wizard owns
that wiring. We only produce the plain mapping fragment.
"""

from __future__ import annotations

import logging
from typing import Any

_LOG = logging.getLogger(__name__)

__all__ = [
    "OperationCandidate",
    "generate_http_shapes",
    "list_operations",
]

# HTTP methods OpenAPI recognises on a Path Item Object, in the order we prefer
# them when heuristically picking an operation (POST first — that is where a
# chat / completion endpoint almost always lives).
_HTTP_METHODS: tuple[str, ...] = (
    "post",
    "put",
    "patch",
    "get",
    "delete",
    "options",
    "head",
    "trace",
)

# Method preference for the *heuristic* (no explicit path) pick: a body-bearing
# write verb is far more likely to be the chat endpoint than a GET.
_PREFERRED_METHODS: tuple[str, ...] = ("post", "put", "patch")

# Field-name heuristics: a property whose (lower-cased) name contains one of
# these substrings is a strong candidate for the text field, tried in order. The
# first list drives both the request prompt field and the response text field.
_TEXT_FIELD_HINTS: tuple[str, ...] = (
    "prompt",
    "message",
    "query",
    "question",
    "input",
    "text",
    "content",
    "output",
    "answer",
    "reply",
    "response",
    "completion",
    "result",
)

# JSON media types we understand for a request/response body, in preference
# order. ``application/json`` is the overwhelming common case; the ``+json``
# suffix covers vendor media types (``application/vnd.foo+json``).
_JSON_MEDIA_TYPES: tuple[str, ...] = ("application/json",)

# A hard cap on local ``$ref`` resolution depth — defends against a recursive
# schema sending us into an infinite loop while still resolving any realistic
# hand-written chain.
_MAX_REF_DEPTH = 64


class OperationCandidate:
    """A selectable operation discovered in an OpenAPI document.

    Carries just enough for a wizard to render a pick-list (``path``,
    ``method``, ``summary``, ``operation_id``, ``has_json_body``) plus the raw
    operation mapping so the chosen candidate can be turned into shapes without
    re-walking the spec.
    """

    __slots__ = ("has_json_body", "method", "operation", "operation_id", "path", "summary")

    def __init__(
        self,
        *,
        path: str,
        method: str,
        operation: dict[str, Any],
        has_json_body: bool,
        operation_id: str | None,
        summary: str | None,
    ) -> None:
        self.path = path
        self.method = method
        self.operation = operation
        self.has_json_body = has_json_body
        self.operation_id = operation_id
        self.summary = summary

    def __repr__(self) -> str:  # pragma: no cover — debugging aid
        return (
            f"OperationCandidate(method={self.method!r}, path={self.path!r}, "
            f"has_json_body={self.has_json_body!r}, operation_id={self.operation_id!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OperationCandidate):
            return NotImplemented
        return (
            self.path == other.path
            and self.method == other.method
            and self.has_json_body == other.has_json_body
            and self.operation_id == other.operation_id
            and self.summary == other.summary
        )


# ---------------------------------------------------------------------------
# $ref resolution
# ---------------------------------------------------------------------------


def _resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    """Resolve a *simple local* ``$ref`` pointer against ``spec``.

    Only ``#/...`` JSON-pointer references into the same document are supported;
    anything else (a remote URL, a non-fragment) raises :class:`ValueError`. The
    ``~1`` / ``~0`` JSON-pointer escapes for ``/`` and ``~`` are honoured.
    """
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported $ref {ref!r}: only local '#/...' references are resolvable")
    node: Any = spec
    for raw_token in ref[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or token not in node:
            raise ValueError(f"$ref {ref!r} does not resolve within the document")
        node = node[token]
    if not isinstance(node, dict):
        raise ValueError(f"$ref {ref!r} resolves to a non-object node")
    return node


def _deref(spec: dict[str, Any], node: Any, *, depth: int = 0) -> dict[str, Any]:
    """Return ``node`` with a top-level ``$ref`` resolved (one hop, chased).

    Follows a chain of ``$ref`` indirections up to :data:`_MAX_REF_DEPTH`; a
    non-mapping node yields an empty mapping (callers treat that as "no schema").
    """
    if depth >= _MAX_REF_DEPTH:
        raise ValueError("$ref chain too deep (possible recursive reference)")
    if not isinstance(node, dict):
        return {}
    ref = node.get("$ref")
    if isinstance(ref, str):
        return _deref(spec, _resolve_ref(spec, ref), depth=depth + 1)
    return node


# ---------------------------------------------------------------------------
# Schema property walking
# ---------------------------------------------------------------------------


def _is_string_schema(spec: dict[str, Any], schema: dict[str, Any]) -> bool:
    """True iff ``schema`` describes a (possibly nullable) JSON string."""
    schema = _deref(spec, schema)
    type_ = schema.get("type")
    if type_ == "string":
        return True
    # OpenAPI 3.1 allows a list of types (e.g. ["string", "null"]).
    return isinstance(type_, list) and "string" in type_


def _object_properties(spec: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Return the ``properties`` mapping of an object schema (deref'd).

    Collapses ``allOf`` by merging member properties (later members win) so a
    composed schema still exposes its fields; returns ``{}`` when the schema has
    no discoverable properties.
    """
    schema = _deref(spec, schema)
    props: dict[str, Any] = {}
    for sub in schema.get("allOf", []) or []:
        if isinstance(sub, dict):
            props.update(_object_properties(spec, sub))
    raw = schema.get("properties")
    if isinstance(raw, dict):
        props.update(raw)
    return props


def _select_text_field(
    spec: dict[str, Any], schema: dict[str, Any]
) -> tuple[list[str], dict[str, Any]] | None:
    """Find the most-likely *text* field in an object ``schema``.

    Returns ``(path_segments, field_schema)`` where ``path_segments`` is the
    dotted route from the schema root to the chosen string property, or ``None``
    when no string property exists anywhere reachable.

    Heuristic (deterministic):

    1. Among the *top-level* string properties, prefer one whose name matches a
       :data:`_TEXT_FIELD_HINTS` hint (earliest hint wins); else the first
       string property in document order.
    2. Failing that, recurse into nested object properties (one whose name
       matches a hint first, then document order) and return the first text
       field found there, prefixing the parent segment.
    """
    props = _object_properties(spec, schema)
    if not props:
        return None

    string_props = {
        name: sub
        for name, sub in props.items()
        if isinstance(sub, dict) and _is_string_schema(spec, sub)
    }

    # 1a. hinted top-level string property
    for hint in _TEXT_FIELD_HINTS:
        for name, sub in string_props.items():
            if hint in name.lower():
                return [name], _deref(spec, sub)
    # 1b. first top-level string property (document order)
    for name, sub in string_props.items():
        return [name], _deref(spec, sub)

    # 2. recurse into nested objects — hinted children first, then doc order.
    object_props = [
        (name, sub)
        for name, sub in props.items()
        if isinstance(sub, dict) and not _is_string_schema(spec, sub)
    ]
    ordered = sorted(
        object_props,
        key=lambda item: _hint_rank(item[0]),
    )
    for name, sub in ordered:
        nested = _select_text_field(spec, sub)
        if nested is not None:
            segments, field_schema = nested
            return [name, *segments], field_schema
    return None


def _hint_rank(name: str) -> int:
    """Sort key: index of the earliest matching hint (``len`` = no match).

    Used to make nested-object descent prefer a hinted container (``output``,
    ``message``) before an arbitrary one, while keeping the sort stable for
    equally-ranked names.
    """
    lower = name.lower()
    for index, hint in enumerate(_TEXT_FIELD_HINTS):
        if hint in lower:
            return index
    return len(_TEXT_FIELD_HINTS)


# ---------------------------------------------------------------------------
# Operation discovery
# ---------------------------------------------------------------------------


def _json_body_schema(
    spec: dict[str, Any], operation: dict[str, Any]
) -> tuple[dict[str, Any], str] | None:
    """Return ``(schema, media_type)`` for the operation's JSON request body.

    ``None`` when the operation has no JSON-typed ``requestBody`` content.
    """
    request_body = _deref(spec, operation.get("requestBody"))
    content = request_body.get("content")
    if not isinstance(content, dict):
        return None
    for media_type in _JSON_MEDIA_TYPES:
        media = content.get(media_type)
        if isinstance(media, dict):
            schema = media.get("schema")
            if isinstance(schema, dict):
                return _deref(spec, schema), media_type
    # vendor +json media types as a fallback (deterministic: sorted by name)
    for media_type in sorted(content):
        if media_type.endswith("+json"):
            media = content[media_type]
            if isinstance(media, dict):
                schema = media.get("schema")
                if isinstance(schema, dict):
                    return _deref(spec, schema), media_type
    return None


def _success_response_schema(
    spec: dict[str, Any], operation: dict[str, Any]
) -> dict[str, Any] | None:
    """Return the JSON schema for the operation's 2xx response (``None`` if none).

    Prefers ``200``, then ``201``, then the first ``2xx`` code in sorted order,
    then a ``default`` response — mirroring how a client picks the success body.
    """
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return None
    keys = [str(k) for k in responses]
    ordered: list[str] = []
    for preferred in ("200", "201"):
        if preferred in responses:
            ordered.append(preferred)
    ordered.extend(sorted(k for k in keys if k.startswith("2") and k not in ordered))
    if "default" in responses and "default" not in ordered:
        ordered.append("default")
    for code in ordered:
        response = _deref(spec, responses[code])
        content = response.get("content")
        if not isinstance(content, dict):
            continue
        for media_type in (*_JSON_MEDIA_TYPES, *sorted(content)):
            media = content.get(media_type)
            if media_type not in _JSON_MEDIA_TYPES and not media_type.endswith("+json"):
                continue
            if isinstance(media, dict):
                schema = media.get("schema")
                if isinstance(schema, dict):
                    return _deref(spec, schema)
    return None


def list_operations(spec: dict[str, Any]) -> list[OperationCandidate]:
    """Enumerate the operations in ``spec`` so a caller can present a pick-list.

    Walks ``paths`` in document order; for each path item walks the HTTP methods
    in :data:`_HTTP_METHODS` order. Returns one :class:`OperationCandidate` per
    operation, flagging whether it carries a JSON request body. Raises
    :class:`ValueError` only when the document has no ``paths`` mapping at all.
    """
    paths = spec.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("OpenAPI spec has no 'paths' — nothing to generate from")

    candidates: list[OperationCandidate] = []
    for path, raw_item in paths.items():
        if not isinstance(raw_item, str) and not isinstance(raw_item, dict):
            continue
        item = _deref(spec, raw_item) if isinstance(raw_item, dict) else {}
        if not item:
            continue
        for method in _HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            has_body = _json_body_schema(spec, operation) is not None
            summary = operation.get("summary")
            operation_id = operation.get("operationId")
            candidates.append(
                OperationCandidate(
                    path=str(path),
                    method=method,
                    operation=operation,
                    has_json_body=has_body,
                    operation_id=str(operation_id) if isinstance(operation_id, str) else None,
                    summary=str(summary) if isinstance(summary, str) else None,
                )
            )
    return candidates


def _pick_operation(spec: dict[str, Any], *, path: str | None, method: str) -> OperationCandidate:
    """Select the operation to generate shapes from.

    With an explicit ``path`` the matching ``path`` + ``method`` operation is
    required (raises :class:`ValueError` if absent). Without ``path`` the first
    operation — in document order — on a preferred (body-bearing) method that
    actually carries a JSON request body is chosen; failing that, any JSON-body
    operation; failing that a clear :class:`ValueError`.
    """
    candidates = list_operations(spec)
    method_lc = method.lower()

    if path is not None:
        for candidate in candidates:
            if candidate.path == path and candidate.method == method_lc:
                return candidate
        available = ", ".join(f"{c.method.upper()} {c.path}" for c in candidates) or "none"
        raise ValueError(
            f"no {method_lc.upper()} operation at path {path!r} in the spec "
            f"(available: {available})"
        )

    # Heuristic pick: preferred verb with a JSON body, in document order.
    for preferred in _PREFERRED_METHODS:
        for candidate in candidates:
            if candidate.method == preferred and candidate.has_json_body:
                return candidate
    # Any JSON-body operation at all.
    for candidate in candidates:
        if candidate.has_json_body:
            return candidate
    raise ValueError(
        "no operation with a JSON request body found in the spec; pass an explicit "
        "path/method or supply a spec with a request body"
    )


# ---------------------------------------------------------------------------
# Body template + output path assembly
# ---------------------------------------------------------------------------


def _server_base_url(spec: dict[str, Any]) -> str:
    """Return the first server URL, stripped of a trailing slash."""
    servers = spec.get("servers")
    if not isinstance(servers, list) or not servers:
        raise ValueError("OpenAPI spec has no 'servers' entry — cannot derive the transport URL")
    first = servers[0]
    if not isinstance(first, dict):
        raise ValueError("OpenAPI 'servers[0]' is not an object")
    url = first.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("OpenAPI 'servers[0].url' is missing or empty")
    return url.rstrip("/")


def _join_url(base: str, path: str) -> str:
    """Join a server ``base`` and an operation ``path`` with exactly one slash."""
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _build_body_template(prompt_segments: list[str]) -> str:
    """Build a Jinja request-body template mapping ``prompt`` to a nested field.

    For ``["messages"]`` -> ``{"messages": "{{ prompt }}"}``; for
    ``["input", "text"]`` -> ``{"input": {"text": "{{ prompt }}"}}``. The
    rendered value is a JSON object with the AgentGuardian ``prompt`` variable
    quoted as a string at the chosen leaf.
    """
    body: Any = "{{ prompt }}"
    for segment in reversed(prompt_segments):
        body = {segment: body}
    return _emit_json_template(body)


def _emit_json_template(node: Any) -> str:
    """Serialise a nested mapping to a JSON-ish string, leaving ``{{ prompt }}`` raw.

    We cannot use :func:`json.dumps` because the leaf is the *unquoted* Jinja
    expression wrapped in quotes (``"{{ prompt }}"``) — a deterministic
    hand-emit keeps the template readable and stable.
    """
    if isinstance(node, dict):
        parts = [f'"{key}": {_emit_json_template(value)}' for key, value in node.items()]
        return "{" + ", ".join(parts) + "}"
    # Leaf — the prompt expression, quoted as a JSON string.
    return f'"{node}"'


def _segments_to_jsonpath(segments: list[str]) -> str:
    """Turn ``["output", "text"]`` into the JSONPath ``$.output.text``."""
    return "$" + "".join(f".{segment}" for segment in segments)


def generate_http_shapes(
    spec: dict[str, Any],
    *,
    path: str | None = None,
    method: str = "post",
) -> dict[str, Any]:
    """Derive an HTTP contract fragment from an OpenAPI 3.1 ``spec`` mapping.

    Picks the operation (explicit ``path`` + ``method`` when given, else the
    first body-bearing operation heuristically) and returns a mapping::

        {
            "transport": {"kind": "http", "url": ..., "method": "POST"},
            "request": {"body": "<jinja>", "content_type": "application/json"},
            "response": {"output_path": "$.<...>"},
        }

    The request ``body`` maps the AgentGuardian ``prompt`` variable onto the
    operation request schema's most-likely text field; ``output_path`` points at
    the most-likely text field of the 200 (success) response schema. When no
    text field can be located on either side a sensible fallback is emitted
    (``{{ prompt }}`` at top-level / ``$``) rather than failing — the operator
    can refine it in the wizard.

    Raises :class:`ValueError` (naming the missing piece) when the spec lacks
    ``servers``, ``paths``, or any operation with a JSON request body.
    """
    if not isinstance(spec, dict) or not spec:
        raise ValueError("OpenAPI spec is empty or not a mapping")

    base_url = _server_base_url(spec)
    candidate = _pick_operation(spec, path=path, method=method)

    body_schema_pair = _json_body_schema(spec, candidate.operation)
    if body_schema_pair is None:
        raise ValueError(
            f"operation {candidate.method.upper()} {candidate.path} has no JSON request "
            "body to map the prompt onto"
        )
    body_schema, content_type = body_schema_pair

    prompt_field = _select_text_field(spec, body_schema)
    if prompt_field is None:
        _LOG.debug(
            "openapi: no string field found in request schema for %s %s; "
            "falling back to top-level {{ prompt }}",
            candidate.method.upper(),
            candidate.path,
        )
        prompt_segments: list[str] = []
        body_template = "{{ prompt }}"
    else:
        prompt_segments, _ = prompt_field
        body_template = _build_body_template(prompt_segments)

    response_schema = _success_response_schema(spec, candidate.operation)
    if response_schema is None:
        _LOG.debug(
            "openapi: no JSON 2xx response schema for %s %s; defaulting output_path to '$'",
            candidate.method.upper(),
            candidate.path,
        )
        output_path = "$"
    else:
        output_field = _select_text_field(spec, response_schema)
        if output_field is None:
            _LOG.debug(
                "openapi: no string field in response schema for %s %s; "
                "defaulting output_path to '$'",
                candidate.method.upper(),
                candidate.path,
            )
            output_path = "$"
        else:
            output_segments, _ = output_field
            output_path = _segments_to_jsonpath(output_segments)

    return {
        "transport": {
            "kind": "http",
            "url": _join_url(base_url, candidate.path),
            "method": candidate.method.upper(),
        },
        "request": {
            "body": body_template,
            "content_type": content_type,
        },
        "response": {
            "output_path": output_path,
        },
    }
