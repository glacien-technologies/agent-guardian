"""HttpAdapter — Mode C: hosted HTTP API target (PRD §7).

Production transport for the six provider-shaped HTTP targets:

* ``openai`` — Chat Completions
* ``anthropic`` — Messages API
* ``bedrock`` — Converse API (NotImplementedError: SigV4 deferred)
* ``vertex`` — generateContent (NotImplementedError: OAuth2 deferred)
* ``agentcore`` — AgentCore Runtime ``POST /invocations`` (NotImplementedError: SigV4 deferred)
* ``generic`` — custom ``request_template`` + ``response_jsonpath``

The shape-specific request-build / response-extract logic lives in pure
functions under :mod:`agent_guardian.adapters.http_shapes`. This module owns
the transport: an :class:`httpx.AsyncClient`, retry/backoff using M3's
:func:`with_backoff`, and mapping of HTTP errors onto the LLM error
hierarchy (which we reuse for HTTP target errors since the failure modes —
auth, rate limit, timeout, transient, permanent — are semantically the
same).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.adapters.http_shapes.base import HttpShape, get_shape
from agent_guardian.adapters.http_shapes.generic_shape import (
    extract_response_text as generic_extract_response_text,
)
from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    TargetTimeoutError,
    TargetTransientError,
)
from agent_guardian.llm.retry import with_backoff
from agent_guardian.models.multimodal import ProbeAttachment

__all__ = ["HttpAdapter", "HttpAdapterLastResponse", "HttpAdapterToolCall"]

_LOG = logging.getLogger(__name__)

# Shapes whose authentication scheme (SigV4 / OAuth2) is too heavyweight to
# implement in M9. The build_request / extract_response_text pure functions
# remain usable for unit tests, but ``HttpAdapter.call()`` refuses to send.
_AUTH_DEFERRED_SHAPES: frozenset[str] = frozenset({"bedrock", "vertex", "agentcore"})


# rc38 P0-#4 (#262) sibling to PR #248 — provider-internal error envelopes
# embedded in the assistant text get parroted into recon's tool-extraction
# regex AND the judge's system prompt verbatim. Normalise them to a stable
# ``[TARGET_UNAVAILABLE: <code>]`` sentinel BEFORE the text crosses out of
# the transport layer so downstream stages never see the raw envelope.
# Captures the status code (digits) when present so the diagnostic is
# preserved.
_ADAPTER_ERROR_RE = re.compile(
    r"\[adapter_error:\s*(?P<code>\d{3})?[^\]]*\]",
    re.IGNORECASE,
)


def _normalize_adapter_error_text(text: str | None) -> str | None:
    """Replace any ``[adapter_error: ...]`` span with a stable public sentinel.

    The sentinel format is ``[TARGET_UNAVAILABLE: <code>]`` when the original
    span carried a 3-digit status code, otherwise ``[TARGET_UNAVAILABLE]``.
    Benign text is returned unchanged. ``None`` passes through.

    This runs at the transport layer so recon's parser, the judge LLM, and
    every other downstream consumer all see the same stable sentinel instead
    of raw provider-internal prose.
    """
    if not text:
        return text

    def _sub(m: re.Match[str]) -> str:
        code = m.group("code")
        return f"[TARGET_UNAVAILABLE: {code}]" if code else "[TARGET_UNAVAILABLE]"

    return _ADAPTER_ERROR_RE.sub(_sub, text)


# Per-shape (response_path, name_path, args_path) triples used by the
# adapter-level tool-call extractor. Mirrors the higher-level
# :class:`agent_guardian.transports.http.HttpTransport` extractor so a recon
# pass that talks to the adapter directly (no transport wrap) still surfaces
# tool invocations the target performed. The transport layer overrides these
# defaults via its own configurable jsonpaths; the adapter exposes the same
# shape-keyed defaults so recon's ``has_tools_observed`` flag flips on the
# first turn a real provider returns a structured tool_call.
# ``response_path`` resolves to either a list of tool blocks OR (for shapes
# whose tool blocks share a container with text blocks, e.g. Anthropic
# ``content``) a list of mixed items the extractor walks itself. When a
# nested key is required to lift the tool block out of a container entry
# (e.g. Bedrock ``content[*].toolUse``), ``container_child`` names it; the
# extractor pulls ``item[container_child]`` for each container entry and
# skips entries missing that key. ``container_child=None`` means the
# container entries are the tool blocks themselves.
_SHAPE_TOOL_PATHS: dict[str, tuple[str, str, str, str | None]] = {
    "openai": (
        "$.choices[0].message.tool_calls",
        "$.function.name",
        "$.function.arguments",
        None,
    ),
    "anthropic": ("$.content", "$.name", "$.input", None),
    "generic": ("$.tool_calls", "$.name", "$.arguments", None),
    "bedrock": ("$.output.message.content", "$.name", "$.input", "toolUse"),
    "vertex": (
        "$.candidates[0].content.parts",
        "$.name",
        "$.args",
        "functionCall",
    ),
    "agentcore": ("$.tool_calls", "$.name", "$.arguments", None),
}


@dataclass(frozen=True, slots=True)
class HttpAdapterToolCall:
    """Structured tool invocation surfaced by the adapter from a response body.

    Mirrors :class:`agent_guardian.transports.base.ToolCall` but kept local to
    the adapter package so importers (e.g. recon) don't have to depend on the
    transports layer. ``name`` is the function/tool handle; ``arguments`` is
    the kwargs dict the target passed; ``raw`` keeps the original block for
    forensic replay.
    """

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    raw: Any = None


@dataclass(frozen=True, slots=True)
class HttpAdapterLastResponse:
    """Snapshot of the most recent successful response.

    Stashed on :attr:`HttpAdapter._last_response` after every successful
    :meth:`HttpAdapter.call` so callers (recon, capability audit) can read
    structured ``tool_calls`` alongside the assistant text. ``raw`` is the
    parsed JSON body and is kept only for the duration of the next call —
    the adapter overwrites the snapshot per turn rather than accumulating
    history (the swarm memory owns longer-lived turn records).
    """

    text: str
    tool_calls: tuple[HttpAdapterToolCall, ...] = ()
    raw: dict[str, Any] | None = None


def _extract_tool_calls(
    response_json: dict[str, Any],
    *,
    shape_name: str,
) -> tuple[HttpAdapterToolCall, ...]:
    """Extract structured tool calls from a parsed response body.

    Mirrors :meth:`agent_guardian.transports.http.HttpTransport._extract_tool_calls`
    (transports/http.py:223-243) so the adapter-level call path surfaces the
    same evidence the transport layer does. Returns an empty tuple when the
    shape has no tool path defined, when the path resolves to nothing, or when
    the extracted entries do not have the expected dict shape — never raises.
    """
    paths = _SHAPE_TOOL_PATHS.get(shape_name)
    if paths is None:
        return ()
    response_path, name_path, args_path, container_child = paths
    try:
        raw = walk_jsonpath(response_json, response_path)
    except ValueError:
        # Malformed shape path -- treat as "no tool block" rather than raise.
        return ()
    if raw is None:
        return ()
    items = raw if isinstance(raw, list) else [raw]
    calls: list[HttpAdapterToolCall] = []
    for outer in items:
        if not isinstance(outer, dict):
            continue
        # For container shapes (Bedrock / Vertex) the tool block is nested
        # under a key; the container entry itself may not have the tool
        # fields, so we lift it out before applying the name/args paths.
        if container_child is not None:
            item = outer.get(container_child)
            if not isinstance(item, dict):
                continue
        else:
            item = outer
        try:
            name = walk_jsonpath(item, name_path)
            args = walk_jsonpath(item, args_path)
        except ValueError:
            continue
        if name is None:
            # Skip non-tool blocks (e.g. an Anthropic ``content`` text item).
            continue
        # ``arguments`` over the wire is sometimes a JSON-encoded string
        # (notably OpenAI's tool_calls). Decode best-effort; ignore failures.
        if isinstance(args, str):
            try:
                decoded = json.loads(args)
                if isinstance(decoded, dict):
                    args = decoded
            except (json.JSONDecodeError, ValueError) as exc:
                _LOG.debug(
                    "http: tool_call arguments not JSON-decodable (%s) -- "
                    "preserving the raw string",
                    exc,
                )
        calls.append(
            HttpAdapterToolCall(
                name=str(name),
                arguments=args if isinstance(args, dict) else {},
                raw=outer,
            )
        )
    return tuple(calls)


class HttpAdapter(TargetAdapter):
    """Wraps a hosted HTTP/JSON API endpoint.

    Constructed with a shape name (``openai``, ``anthropic``, ``generic``,
    …), an endpoint URL, optional auth headers, and per-shape extras
    (``model`` for shapes that need it, ``request_template`` /
    ``response_jsonpath`` for the generic shape).

    ``call()`` is fully wired for ``openai``, ``anthropic``, and ``generic``.
    ``bedrock``, ``vertex``, and ``agentcore`` raise
    :class:`NotImplementedError` from ``call()`` — see ``M-future`` note in
    the docstring above — because SigV4 / OAuth2 helpers are out of scope
    for M9. The pure-function shapes continue to work for unit tests.
    """

    mode = "http"

    def __init__(
        self,
        endpoint: str,
        *,
        shape: str = "generic",
        auth_headers: dict[str, str] | None = None,
        request_template: str | None = None,
        response_jsonpath: str | None = None,
        ref: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
        verify: bool | str = True,
        attachments_field: str = "attachments",
        attachments_key_map: dict[str, str] | None = None,
        supports_vision: bool = False,
    ) -> None:
        super().__init__()
        if not endpoint:
            raise ValueError("HttpAdapter requires a non-empty endpoint")
        if timeout_seconds <= 0:
            raise ValueError("HttpAdapter timeout_seconds must be > 0")
        if max_retries < 0:
            raise ValueError("HttpAdapter max_retries must be >= 0")
        if max_concurrency <= 0:
            raise ValueError("HttpAdapter max_concurrency must be > 0")

        self._endpoint = endpoint
        self._shape_name = shape
        self._auth_headers = dict(auth_headers or {})
        self._request_template = request_template
        self._response_jsonpath = response_jsonpath
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._shape: HttpShape = get_shape(shape)
        # Multimodal: the body key under which attachments are added when a
        # probe carries any, and the per-field rename map for the per-
        # attachment dict (defaults below match the testbench shape:
        # ``{"input": str, "attachments": [{"mime_type", "b64", "alt"}]}``).
        self._attachments_field = attachments_field
        self._attachments_key_map: dict[str, str] = {
            "mime_type": "mime_type",
            "b64_payload": "b64",
            "alt_text": "alt",
            "size_bytes": "size_bytes",
        }
        if attachments_key_map:
            self._attachments_key_map.update(attachments_key_map)
        self._supports_vision = supports_vision

        self._owns_client = client is None
        # ``verify`` is honoured only for a client we build ourselves; an
        # injected client carries its own TLS config. ``verify=False`` disables
        # certificate verification (insecure — for self-signed/dev targets);
        # ``verify="<path>"`` pins a private CA bundle. A CA-bundle *path* is
        # lifted into an ``ssl.SSLContext`` (httpx deprecates ``verify=<str>``).
        verify_arg: bool | ssl.SSLContext = (
            ssl.create_default_context(cafile=verify) if isinstance(verify, str) else verify
        )
        self._client: httpx.AsyncClient = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds), verify=verify_arg
        )
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._closed = False
        # Snapshot of the most recent successful response (text + structured
        # tool_calls). Read by recon / capability audit to flip
        # ``has_tools_observed`` when the target returns real tool blocks the
        # plain ``call() -> str`` interface would otherwise hide. Always
        # overwritten per turn — see :class:`HttpAdapterLastResponse`.
        self._last_response: HttpAdapterLastResponse | None = None

        self._fingerprint = TargetFingerprint(
            mode="http",
            ref=ref or endpoint,
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            notes=f"Mode C — production HTTP transport. shape={shape}.",
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def shape_name(self) -> str:
        return self._shape_name

    @property
    def supports_vision(self) -> bool:
        """Whether the operator has declared the target accepts image attachments."""
        return self._supports_vision

    def _serialise_attachment(self, att: ProbeAttachment) -> dict[str, Any]:
        """Render one ProbeAttachment using the configured key map."""
        return {
            self._attachments_key_map["mime_type"]: att.mime_type,
            self._attachments_key_map["b64_payload"]: att.b64_payload,
            self._attachments_key_map["alt_text"]: att.alt_text,
            self._attachments_key_map["size_bytes"]: att.size_bytes,
        }

    def _build_headers(self) -> dict[str, str]:
        """Compose request headers from defaults + caller-supplied auth."""
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        headers.update(self._auth_headers)
        return headers

    def _build_body(
        self,
        prompt: str,
        *,
        session: str | None,
        attachments: tuple[ProbeAttachment, ...] = (),
    ) -> dict[str, Any]:
        """Build the per-shape request body, optionally merging attachments."""
        if self._shape_name == "generic" and self._request_template is not None:
            # Operator supplied a JSON template; substitute ``{prompt}`` /
            # ``{session}`` placeholders and use that as the body verbatim.
            body = _render_request_template(self._request_template, prompt=prompt, session=session)
        else:
            body = self._shape.build_request(
                prompt,
                model=self._model,
                session=session,
            )
        if attachments:
            body[self._attachments_field] = [self._serialise_attachment(a) for a in attachments]
        return body

    def _extract_text(self, response_json: dict[str, Any]) -> str:
        """Extract the assistant text from a parsed response body."""
        try:
            if self._shape_name == "generic" and self._response_jsonpath is not None:
                return generic_extract_response_text(
                    response_json, jsonpath=self._response_jsonpath
                )
            return self._shape.extract_response_text(response_json)
        except ValueError as exc:
            msg = str(exc)
            # "produced no value" → format error with "no value" phrase.
            raise LLMResponseFormatError(msg) from exc

    async def _send_once(
        self,
        prompt: str,
        *,
        session: str | None,
        attachments: tuple[ProbeAttachment, ...] = (),
    ) -> str:
        """One attempt: build, POST, parse, extract. Raises mapped LLM errors.

        On success the parsed body is also fed through the shape-specific
        tool-call extractor and stashed on :attr:`_last_response`. Recon
        reads that snapshot per-turn to flip ``has_tools_observed`` based on
        the real structured invocations the target performed, not a
        substring-matched guess against the assistant text.
        """
        body = self._build_body(prompt, session=session, attachments=attachments)
        headers = self._build_headers()
        try:
            resp = await self._client.post(self._endpoint, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            raise TargetTimeoutError(f"http: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise TargetTransientError(f"http: network error: {exc}") from exc
        _raise_for_status(resp)
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise LLMResponseFormatError(f"http: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise LLMResponseFormatError(
                f"http: expected JSON object at top level, got {type(data).__name__}"
            )
        text = self._extract_text(data)
        # rc38 P0-#4 (#262) sibling to PR #248 — strip provider-internal
        # ``[adapter_error: ...]`` envelopes before the text reaches recon /
        # the judge LLM context. Normalisation is a no-op for benign replies.
        text = _normalize_adapter_error_text(text) or ""
        # Capture structured tool_calls into the per-turn snapshot so callers
        # that walk ``adapter._last_response.tool_calls`` see real evidence.
        # Extraction never raises (returns ``()`` on malformed paths).
        self._last_response = HttpAdapterLastResponse(
            text=text,
            tool_calls=_extract_tool_calls(data, shape_name=self._shape_name),
            raw=data,
        )
        return text

    async def call(
        self,
        prompt: str,
        *,
        session: str | None = None,
        attachments: tuple[ProbeAttachment, ...] = (),
    ) -> str:
        """Send a prompt (with optional attachments) and return assistant text.

        Wires the shape's request builder + extractor through an httpx POST
        with retry/backoff. When ``attachments`` is non-empty the body grows
        an attachments array under the configured ``attachments_field``
        (default ``"attachments"``) using the configured key map (default
        ``{mime_type, b64, alt, size_bytes}``). Raises an :class:`LLMError`
        subclass on failure (auth, rate limit, timeout, transient,
        permanent, format).
        """
        if self._closed:
            raise RuntimeError("HttpAdapter.call() after aclose()")
        if self._shape_name in _AUTH_DEFERRED_SHAPES:
            raise NotImplementedError(
                f"HttpAdapter shape={self._shape_name!r} requires SigV4 / OAuth2 "
                "auth which is deferred beyond M9. The pure-function shape under "
                "agent_guardian.adapters.http_shapes is still usable for unit "
                "tests; production transport for AWS / GCP signed requests is "
                "an M-future milestone."
            )
        # WHY: refuse to silently strip attachments against a text-only target.
        if attachments and not self._supports_vision:
            raise LLMPermanentError(
                "HttpAdapter.call() received attachments but supports_vision=False — "
                "construct the adapter with supports_vision=True to dispatch vision probes"
            )

        async with self._semaphore:
            return await with_backoff(
                lambda: self._send_once(prompt, session=session, attachments=attachments),
                max_retries=self._max_retries,
            )

    async def send_raw(
        self,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Public transport seam: POST a pre-built body, return the parsed JSON.

        Unlike :meth:`call`, this performs **no** shape-specific request build
        or response extraction — it is the low-level "send these exact bytes,
        give me back the parsed object" primitive that the
        :mod:`agent_guardian.transports` layer wraps. It reuses the same
        concurrency semaphore, retry/backoff, and HTTP→LLM error mapping as
        :meth:`call`, so callers get identical resilience without the opinionated
        provider shaping.

        Raises an :class:`~agent_guardian.llm.errors.LLMError` subclass on any
        transport fault (auth, rate limit, timeout, transient, format).
        """
        if self._closed:
            raise RuntimeError("HttpAdapter.send_raw() after aclose()")

        async def _attempt() -> dict[str, Any]:
            try:
                resp = await self._client.post(self._endpoint, json=body, headers=headers)
            except httpx.TimeoutException as exc:
                raise TargetTimeoutError(f"http: timeout: {exc}") from exc
            except httpx.HTTPError as exc:
                raise TargetTransientError(f"http: network error: {exc}") from exc
            _raise_for_status(resp)
            try:
                data = resp.json()
            except (ValueError, json.JSONDecodeError) as exc:
                raise LLMResponseFormatError(f"http: invalid JSON: {exc}") from exc
            if not isinstance(data, dict):
                raise LLMResponseFormatError(
                    f"http: expected JSON object at top level, got {type(data).__name__}"
                )
            return data

        # Issue #224 — belt-and-suspenders wall-clock cap on the entire
        # send_raw call (across all retries). Pre-fix the retry path
        # could burn (max_retries + 1) * timeout_seconds + backoff if
        # the target stalled hard on every retry, because with_backoff
        # accepts a ``cancel_event`` / ``deadline_monotonic`` but the
        # adapter never wired one through. On the rc35 matrix scan #06
        # (seed=12345) this manifested as a 300s wallclock burn against
        # a 60s per-call timeout. The cap below kills a runaway
        # ``send_raw`` after roughly ``(max_retries + 1) * timeout +
        # backoff_sum + safety_buffer`` seconds even when the outer
        # cancel_event was never plumbed, surfacing as a clean
        # ``TargetTimeoutError`` rather than a frozen scan.
        #
        # The fuller fix (thread the swarm's ``cancel_event`` /
        # ``deadline_monotonic`` through every transport caller) is
        # tracked for a follow-up milestone — touches 6+ files across
        # cli.py + factory + transports.
        outer_cap = self._timeout_seconds * (self._max_retries + 1) + 30.0
        async with self._semaphore:
            try:
                return await asyncio.wait_for(
                    with_backoff(_attempt, max_retries=self._max_retries),
                    timeout=outer_cap,
                )
            except TimeoutError as exc:
                raise TargetTimeoutError(
                    f"http: send_raw exceeded outer wall cap of {outer_cap:.1f}s "
                    f"(timeout_seconds={self._timeout_seconds}, max_retries={self._max_retries}) "
                    f"-- target stalled across every retry (#224)"
                ) from exc

    async def aclose(self) -> None:
        """Close the underlying httpx client if we own it."""
        if self._closed:
            return
        self._closed = True
        if self._owns_client:
            await self._client.aclose()


def _render_request_template(template: str, *, prompt: str, session: str | None) -> dict[str, Any]:
    """Render a JSON request template by substituting ``{prompt}`` / ``{session}``.

    The template is parsed as JSON *after* substitution. Both placeholders
    are escaped via :func:`json.dumps` so prompts that include quotes or
    newlines do not break the template.
    """
    safe_prompt = json.dumps(prompt)[1:-1]  # strip the surrounding quotes
    safe_session = json.dumps(session if session is not None else "")[1:-1]
    rendered = template.replace("{prompt}", safe_prompt).replace("{session}", safe_session)
    try:
        body = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise LLMPermanentError(
            f"http: generic request_template is not valid JSON after substitution: {exc}"
        ) from exc
    if not isinstance(body, dict):
        raise LLMPermanentError("http: generic request_template must render to a JSON object")
    return body


def _raise_for_status(resp: httpx.Response) -> None:
    """Map an HTTP response status to our LLM error hierarchy."""
    if resp.status_code < 400:
        return
    body_preview = resp.text[:512]
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"http: auth failed: {resp.status_code} {body_preview}")
    if resp.status_code == 429:
        retry_after_hdr = resp.headers.get("retry-after")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "http: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("http target 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("http: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise TargetTransientError(f"http: transient {resp.status_code}: {body_preview}")
    raise LLMPermanentError(f"http: {resp.status_code} {body_preview}")
