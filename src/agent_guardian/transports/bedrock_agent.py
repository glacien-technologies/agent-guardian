"""AWS Bedrock Agent Runtime ``InvokeAgent`` transport (Stage 2).

Invokes a Bedrock *agent* via the Agent Runtime data-plane endpoint:

``POST https://bedrock-agent-runtime.{region}.amazonaws.com/agents/{agent_id}/agentAliases/{alias_id}/sessions/{session_id}/text``

The request body is ``{"inputText": <prompt>, "enableTrace": <bool>}``. The
``sessionId`` is part of the URL path, so the *session* doubles as the route:
this is the ``server_session`` pattern. We reuse :attr:`Request.session` as the
``sessionId`` when present (otherwise mint one) and surface the id back on
:attr:`Response.session`, so the
:class:`~agent_guardian.transports.session.SessionMachine` (SERVER_SESSION mode)
replays the same session on every turn.

**Response decoding.** ``InvokeAgent`` returns an AWS *event stream*
(``application/vnd.amazon.eventstream``): a framed sequence of events whose
``chunk`` events carry a ``bytes`` payload of completion text. We decode the
frames with botocore's :class:`~botocore.eventstream.EventStreamBuffer` and
accumulate every chunk's UTF-8 bytes into the final reply. If the server
instead returns a plain JSON object (some gateways/mocks aggregate the stream),
we fall back to reading ``completion`` / ``output.text``.

**Auth.** SigV4 signing is performed by an injected
:class:`~agent_guardian.transports.auth.base.AuthProvider` (the factory wires a
SigV4 provider in a later phase). This transport never holds AWS credentials.

The botocore dependency ships under the ``[aws]`` extra; importing it lazily
keeps the base install free of it.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, ClassVar

import httpx

from agent_guardian.llm.errors import (
    LLMError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import CapabilityReport, Request, Response, Transport
from agent_guardian.transports.errors import map_llm_error

__all__ = ["BedrockAgentTransport"]

_LOG = logging.getLogger(__name__)


class BedrockAgentTransport(Transport):
    """Bedrock Agent Runtime ``InvokeAgent`` transport (``server_session``)."""

    kind: ClassVar[str] = "bedrock_agent"

    def __init__(
        self,
        *,
        region: str,
        agent_id: str,
        agent_alias_id: str,
        enable_trace: bool = False,
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not region:
            raise ValueError("BedrockAgentTransport requires a non-empty region")
        if not agent_id:
            raise ValueError("BedrockAgentTransport requires a non-empty agent_id")
        if not agent_alias_id:
            raise ValueError("BedrockAgentTransport requires a non-empty agent_alias_id")
        self._region = region
        self._agent_id = agent_id
        self._agent_alias_id = agent_alias_id
        self._enable_trace = enable_trace
        self._auth: AuthProvider = auth or NoAuth()
        self._base_headers = dict(base_headers or {})
        self._host = f"bedrock-agent-runtime.{region}.amazonaws.com"

        self._owns_client = client is None
        self._client: httpx.AsyncClient = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds)
        )

    def _endpoint(self, session_id: str) -> str:
        return (
            f"https://{self._host}/agents/{self._agent_id}"
            f"/agentAliases/{self._agent_alias_id}"
            f"/sessions/{session_id}/text"
        )

    def describe(self) -> CapabilityReport:
        return CapabilityReport(
            kind=self.kind,
            streaming=True,
            session_modes=("server_session",),
            auth_scheme="sigv4",
            endpoint=f"https://{self._host}",
        )

    def _build_body(self) -> dict[str, Any]:
        return {"inputText": "", "enableTrace": self._enable_trace}

    async def _build_headers(self, url: str, body: bytes) -> dict[str, str]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/vnd.amazon.eventstream",
        }
        headers.update(self._base_headers)
        ctx = AuthContext(method="POST", url=url, headers=headers, body=body)
        await self._auth.apply(ctx)
        return ctx.headers

    @staticmethod
    def _decode_event_stream(payload: bytes) -> str:
        """Decode an AWS event-stream payload, accumulating ``chunk`` bytes.

        Each ``chunk`` event's payload is JSON ``{"bytes": "<base64>"}`` per the
        botocore wire format; :class:`EventStreamBuffer` base64-decodes it for us
        when we read ``event.payload``. We concatenate every chunk's UTF-8 text.
        """
        from botocore.eventstream import EventStreamBuffer

        buffer = EventStreamBuffer()
        buffer.add_data(payload)
        parts: list[str] = []
        for event in buffer:
            event_type = event.headers.get(":event-type")
            if event_type is not None and event_type != "chunk":
                continue
            raw = event.payload
            if not raw:
                continue
            # A chunk frame wraps the model bytes in {"bytes": "..."} (base64);
            # botocore returns the already-decoded inner bytes via .payload only
            # for the outer frame, so unwrap the JSON envelope when present.
            text = BedrockAgentTransport._chunk_text(raw)
            if text:
                parts.append(text)
        if not parts:
            raise LLMResponseFormatError(
                "bedrock_agent: event stream contained no decodable chunk text"
            )
        return "".join(parts)

    @staticmethod
    def _chunk_text(raw: bytes) -> str:
        """Extract completion text from a single chunk frame payload."""
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Not a JSON envelope — treat the raw bytes as the text directly.
            return raw.decode("utf-8", errors="replace")
        if isinstance(envelope, dict):
            inner = envelope.get("bytes")
            if isinstance(inner, str):
                import base64

                try:
                    return base64.b64decode(inner).decode("utf-8", errors="replace")
                except (ValueError, TypeError):
                    return inner
            text = envelope.get("text")
            if isinstance(text, str):
                return text
        return raw.decode("utf-8", errors="replace")

    @staticmethod
    def _text_from_json(data: dict[str, Any]) -> str:
        completion = data.get("completion")
        if isinstance(completion, str):
            return completion
        output = data.get("output")
        if isinstance(output, dict):
            text = output.get("text")
            if isinstance(text, str):
                return text
        raise LLMResponseFormatError(
            "bedrock_agent: aggregated JSON had no 'completion' or 'output.text'"
        )

    async def send(self, request: Request) -> Response:
        session_id = request.session or uuid.uuid4().hex
        url = self._endpoint(session_id)
        body_obj = self._build_body()
        body_obj["inputText"] = request.prompt
        body_bytes = json.dumps(body_obj).encode("utf-8")

        try:
            headers = await self._build_headers(url, body_bytes)
            try:
                resp = await self._client.post(url, content=body_bytes, headers=headers)
            except httpx.TimeoutException as exc:
                raise LLMTimeoutError(f"bedrock_agent: timeout: {exc}") from exc
            except httpx.HTTPError as exc:
                raise LLMTransientError(f"bedrock_agent: network error: {exc}") from exc
            _raise_for_status(resp)

            content_type = resp.headers.get("content-type", "")
            if "json" in content_type and "eventstream" not in content_type:
                try:
                    data = resp.json()
                except (ValueError, json.JSONDecodeError) as exc:
                    raise LLMResponseFormatError(f"bedrock_agent: invalid JSON: {exc}") from exc
                if not isinstance(data, dict):
                    raise LLMResponseFormatError("bedrock_agent: expected JSON object at top level")
                text = self._text_from_json(data)
                raw: Any = data
            else:
                text = self._decode_event_stream(resp.content)
                raw = None

            return Response(text=text, session=session_id, raw=raw)
        except LLMError as exc:
            _LOG.debug("bedrock_agent transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _raise_for_status(resp: httpx.Response) -> None:
    """Map a Bedrock HTTP response status onto the LLM error hierarchy."""
    from agent_guardian.adapters.http import _raise_for_status as _shared

    _shared(resp)
