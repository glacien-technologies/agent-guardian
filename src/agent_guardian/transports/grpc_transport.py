"""gRPC transport (Stage 4, optional) — a generic unary call to a service.

A :class:`GrpcTransport` drives one adversarial turn through a single gRPC
*unary-unary* call. Like every other transport it is built from **primitives**
(a target ``host:port``, a fully-qualified ``service_method``, an optional TLS
flag, an auth provider) — never from a Contract; the contract→transport wiring
is the factory's job.

**The descriptor problem.** A typed gRPC stub needs the service's compiled
protobuf descriptors, which a black-box scanner does not have. Rather than
require operators to vendor ``*_pb2`` modules, this transport uses ``grpc``'s
*generic* call machinery: ``grpc.Channel.unary_unary`` with **identity**
(byte-passthrough) serializers. We send the request bytes we are handed and
hand back the response bytes verbatim. Two request encodings are supported:

* ``json`` (default) — the rendered ``send_template`` JSON is UTF-8 encoded and
  sent as the request bytes; the reply bytes are decoded as UTF-8 and (when an
  ``output_field`` JSONPath is configured) parsed through the project's
  dotted-JSONPath walker. This matches gRPC servers that accept/return a JSON
  body (e.g. a ``google.protobuf.Value`` / ``StringValue`` wrapper, or a
  transcoding gateway).
* ``bytes`` — the prompt is UTF-8 encoded raw and the reply bytes are returned
  as decoded text. No JSON shaping is applied.

This is a deliberate, documented limitation: arbitrary binary protobufs without
descriptors cannot be introspected here. The channel + call scaffolding,
TLS/insecure selection, metadata (auth) injection, deadline handling and
status-code → :class:`TransportError` mapping are all implemented and tested.

``grpc`` is an OPTIONAL dependency: imported lazily, and when absent the
constructor raises a clear :class:`ImportError` naming the ``agent-guardian[grpc]``
extra. :meth:`send` never raises for a transport fault — a gRPC ``RpcError`` is
mapped onto our :class:`TransportError` taxonomy and returned in the
:class:`Response`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, ClassVar, Literal

from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    Transport,
)
from agent_guardian.transports.errors import map_llm_error
from agent_guardian.transports.templating import render_body

__all__ = ["GrpcTransport"]

_LOG = logging.getLogger(__name__)

_DEFAULT_TEMPLATE = '{"input": "{{ prompt }}"}'

# Remediation surfaced when the optional ``grpc`` dependency is absent.
_MISSING_DEP_MSG = (
    "GrpcTransport requires the 'grpcio' package, which is not installed. "
    "Install it with: pip install 'agent-guardian[grpc]'"
)

RequestEncoding = Literal["json", "bytes"]


def _auth_scheme_name(auth: AuthProvider) -> str | None:
    """Derive a readable auth-scheme label (see the HTTP transport helper)."""
    if isinstance(auth, NoAuth):
        return None
    name = type(auth).__name__
    return name[:-4] if name.endswith("Auth") else name


def _load_grpc() -> Any:
    """Import and return the ``grpc`` (async ``aio``) module, or raise clearly.

    The dependency is optional (extra ``grpc``); we import it lazily so the base
    install never pays the cost. When absent we raise an :class:`ImportError`
    whose message names the remediation extra.
    """
    try:
        import grpc
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        _LOG.debug("grpc transport: 'grpc' import failed (%s)", exc)
        raise ImportError(_MISSING_DEP_MSG) from exc
    return grpc


def _identity(value: bytes) -> bytes:
    """Byte-passthrough (de)serializer for ``grpc`` generic unary calls."""
    return value


def _map_status_code(grpc_mod: Any, code: Any, detail: str) -> LLMError:
    """Map a gRPC ``StatusCode`` onto our LLM error hierarchy.

    The mapping mirrors the HTTP status mapping: auth → :class:`LLMAuthError`,
    resource-exhausted → :class:`LLMRateLimitError`, deadline → timeout,
    unavailable → transient, and everything else → permanent (with
    invalid-argument treated as a permanent config fault). Unknown codes fall
    back to permanent.
    """
    status = grpc_mod.StatusCode
    if code in (status.UNAUTHENTICATED, status.PERMISSION_DENIED):
        return LLMAuthError(f"grpc: auth failed: {code} {detail}")
    if code == status.RESOURCE_EXHAUSTED:
        return LLMRateLimitError(f"grpc: resource exhausted: {detail}")
    if code == status.DEADLINE_EXCEEDED:
        return LLMTimeoutError(f"grpc: deadline exceeded: {detail}")
    if code in (status.UNAVAILABLE, status.ABORTED):
        return LLMTransientError(f"grpc: transient {code}: {detail}")
    return LLMPermanentError(f"grpc: {code}: {detail}")


class GrpcTransport(Transport):
    """Generic unary-unary gRPC transport with byte-passthrough codecs."""

    kind: ClassVar[str] = "grpc"

    def __init__(
        self,
        *,
        target: str,
        service_method: str,
        output_field: str | None = None,
        request_encoding: RequestEncoding = "json",
        send_template: str = _DEFAULT_TEMPLATE,
        use_tls: bool = True,
        auth: AuthProvider | None = None,
        metadata: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        channel: Any = None,
    ) -> None:
        if not target:
            raise ValueError("GrpcTransport requires a non-empty target (host:port)")
        if not service_method or not service_method.startswith("/"):
            raise ValueError(
                "GrpcTransport service_method must be a fully-qualified method path "
                f"like '/package.Service/Method' (got {service_method!r})"
            )
        # Fail fast at construction when the optional dependency is missing.
        self._grpc = _load_grpc()

        self._target = target
        self._service_method = service_method
        self._output_field = output_field
        self._request_encoding: RequestEncoding = request_encoding
        self._send_template = send_template
        self._use_tls = use_tls
        self._auth: AuthProvider = auth or NoAuth()
        self._metadata = dict(metadata or {})
        self._timeout_seconds = timeout_seconds

        # An injected channel (tests) is not owned and is never closed here.
        self._owns_channel = channel is None
        self._channel: Any = channel
        self._channel_lock = asyncio.Lock()

    @property
    def target(self) -> str:
        return self._target

    # ---- channel plumbing --------------------------------------------------

    async def _ensure_channel(self) -> Any:
        """Lazily create (and cache) the gRPC ``aio`` channel.

        A secure channel is built with default SSL credentials when ``use_tls``
        is set; otherwise an insecure channel is used (plaintext — appropriate
        only for localhost / a trusted mesh). The creation is guarded so two
        concurrent first-sends do not race to build two channels.
        """
        if self._channel is not None:
            return self._channel
        async with self._channel_lock:
            if self._channel is None:
                if self._use_tls:
                    creds = self._grpc.ssl_channel_credentials()
                    self._channel = self._grpc.aio.secure_channel(self._target, creds)
                else:
                    self._channel = self._grpc.aio.insecure_channel(self._target)
        return self._channel

    async def _build_metadata(self, request: Request) -> list[tuple[str, str]]:
        """Compose call metadata (base metadata + applied auth headers).

        Auth providers operate on HTTP-style headers; gRPC metadata is the
        equivalent key/value list, so we run the provider against a synthetic
        :class:`AuthContext` and lower the resulting headers into metadata
        tuples (lower-cased keys, per the gRPC metadata convention). Per-request
        metadata overrides from ``request.metadata['grpc_metadata']`` are merged
        last when present.
        """
        headers: dict[str, str] = dict(self._metadata)
        ctx = AuthContext(method="POST", url=f"grpc://{self._target}", headers=headers)
        await self._auth.apply(ctx)
        merged = dict(ctx.headers)
        extra = request.metadata.get("grpc_metadata")
        if isinstance(extra, dict):
            for key, value in extra.items():
                merged[str(key)] = str(value)
        return [(key.lower(), str(value)) for key, value in merged.items()]

    def _encode_request(self, request: Request) -> bytes:
        """Encode the outbound request to bytes per ``request_encoding``."""
        if self._request_encoding == "bytes":
            return request.prompt.encode("utf-8")
        body = render_body(
            self._send_template,
            prompt=request.prompt,
            session=request.session,
            conversation=request.conversation,
        )
        return json.dumps(body).encode("utf-8")

    def _decode_response(self, payload: bytes) -> str:
        """Decode the reply bytes to the final reply text.

        With ``output_field`` set the reply is parsed as JSON and the dotted
        path extracted; without it the raw decoded UTF-8 is returned verbatim.
        """
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LLMResponseFormatError(f"grpc: reply bytes are not valid UTF-8: {exc}") from exc
        if self._output_field is None:
            return text
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMResponseFormatError(
                f"grpc: reply is not JSON but output_field {self._output_field!r} is set: {exc}"
            ) from exc
        value = walk_jsonpath(parsed, self._output_field)
        if value is None:
            raise LLMResponseFormatError(
                f"grpc: output_field {self._output_field!r} produced no value"
            )
        return str(value)

    async def _unary_call(self, payload: bytes, metadata: list[tuple[str, str]]) -> bytes:
        """Issue the generic unary-unary call and return the reply bytes.

        Maps a gRPC :class:`grpc.aio.AioRpcError` onto our LLM error hierarchy.
        """
        channel = await self._ensure_channel()
        callable_ = channel.unary_unary(
            self._service_method,
            request_serializer=_identity,
            response_deserializer=_identity,
        )
        try:
            reply = await callable_(
                payload,
                metadata=tuple(metadata) or None,
                timeout=self._timeout_seconds,
            )
            return bytes(reply)
        except self._grpc.aio.AioRpcError as exc:
            code = exc.code()
            detail = exc.details() or ""
            raise _map_status_code(self._grpc, code, detail) from exc
        except self._grpc.RpcError as exc:  # pragma: no cover - non-aio fallback
            code = getattr(exc, "code", lambda: None)()
            detail = getattr(exc, "details", lambda: "")() or str(exc)
            raise _map_status_code(self._grpc, code, detail) from exc

    # ---- Transport surface -------------------------------------------------

    async def send(self, request: Request) -> Response:
        """Send one unary turn. Never raises for transport faults."""
        try:
            payload = self._encode_request(request)
        except LLMError as exc:
            _LOG.debug("grpc transport: request encode failed (%s)", exc)
            return Response(error=map_llm_error(exc))

        try:
            metadata = await self._build_metadata(request)
            reply_bytes = await self._unary_call(payload, metadata)
            text = self._decode_response(reply_bytes)
            return Response(text=text, raw=text)
        except LLMError as exc:
            _LOG.debug("grpc transport: call failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    def describe(self) -> CapabilityReport:
        """Report this gRPC transport's static capabilities.

        gRPC is unary here (no streaming), tool calls are not parsed, and only
        the stateless / client-history session modes apply (a unary call carries
        no server-side session).
        """
        return CapabilityReport(
            kind=self.kind,
            streaming=False,
            supports_tools=False,
            session_modes=("stateless", "client_history"),
            auth_scheme=_auth_scheme_name(self._auth),
            endpoint=self._target,
        )

    async def aclose(self) -> None:
        """Release transport resources, cascading to the auth provider.

        Closes the owned gRPC channel (if this transport built it) and then
        awaits :meth:`AuthProvider.aclose` so any token-fetch client the
        provider holds (OAuth2 / Entra) cannot leak. The auth ``aclose`` runs
        in the ``finally`` so a channel-close error does not suppress provider
        cleanup.
        """
        try:
            if self._owns_channel and self._channel is not None:
                await self._channel.close()
                self._channel = None
        finally:
            await self._auth.aclose()
