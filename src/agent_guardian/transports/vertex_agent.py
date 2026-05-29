"""Google Vertex AI Reasoning Engine (Agent Engine) transport (Stage 2).

Queries a deployed Vertex *reasoning engine* (Agent Engine) via:

``POST https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/reasoningEngines/{engine_id}:query``

The request body is ``{"input": {"input": <prompt>}, "config": {"configurable":
{"session_id": <session>}}}``. The ``session_id`` carries conversation state on
the server — the ``server_session`` pattern: we reuse :attr:`Request.session`
as the ``session_id`` (minting one on the first turn) and surface it back on
:attr:`Response.session`, so the
:class:`~agent_guardian.transports.session.SessionMachine` (SERVER_SESSION mode)
replays the same id every turn.

**Response parsing.** The ``:query`` response wraps the engine output under an
``output`` key. We accept a few common shapes — ``output`` as a plain string, a
``{"output": ...}`` envelope, or a LangChain-style ``{"output": {"output":
...}}`` — and stringify the innermost text.

**Auth.** A GCP OAuth2 bearer
:class:`~agent_guardian.transports.auth.base.AuthProvider` is injected by the
factory in a later phase; no Google credentials are constructed here.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, ClassVar

import httpx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.llm.errors import LLMError, LLMResponseFormatError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import CapabilityReport, Request, Response, Transport
from agent_guardian.transports.errors import map_llm_error

__all__ = ["VertexAgentTransport"]

_LOG = logging.getLogger(__name__)


class VertexAgentTransport(Transport):
    """Vertex AI Reasoning Engine ``:query`` transport (``server_session``)."""

    kind: ClassVar[str] = "vertex_agent"

    def __init__(
        self,
        *,
        project: str,
        location: str,
        engine_id: str,
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
        adapter: HttpAdapter | None = None,
    ) -> None:
        if not project:
            raise ValueError("VertexAgentTransport requires a non-empty project")
        if not location:
            raise ValueError("VertexAgentTransport requires a non-empty location")
        if not engine_id:
            raise ValueError("VertexAgentTransport requires a non-empty engine_id")
        self._project = project
        self._location = location
        self._engine_id = engine_id
        self._endpoint = (
            f"https://{location}-aiplatform.googleapis.com/v1"
            f"/projects/{project}/locations/{location}"
            f"/reasoningEngines/{engine_id}:query"
        )
        self._auth: AuthProvider = auth or NoAuth()
        self._base_headers = dict(base_headers or {})

        self._owns_adapter = adapter is None
        self._adapter = adapter or HttpAdapter(
            self._endpoint,
            shape="generic",
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            max_concurrency=max_concurrency,
            client=client,
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def describe(self) -> CapabilityReport:
        return CapabilityReport(
            kind=self.kind,
            session_modes=("server_session",),
            auth_scheme="oauth2",
            endpoint=self._endpoint,
        )

    def _build_body(self, request: Request, session_id: str) -> dict[str, Any]:
        return {
            "input": {"input": request.prompt},
            "config": {"configurable": {"session_id": session_id}},
        }

    async def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        headers.update(self._base_headers)
        ctx = AuthContext(method="POST", url=self._endpoint, headers=headers)
        await self._auth.apply(ctx)
        return ctx.headers

    @staticmethod
    def _extract_text(data: dict[str, Any]) -> str:
        output = data.get("output")
        # Plain string output.
        if isinstance(output, str):
            return output
        # LangChain-style nested {"output": {"output": "..."}}.
        if isinstance(output, dict):
            inner = output.get("output")
            if isinstance(inner, str):
                return inner
            text = output.get("text")
            if isinstance(text, str):
                return text
        raise LLMResponseFormatError(
            "vertex_agent: response had no string 'output', 'output.output', or 'output.text'"
        )

    def _parse_response(self, data: dict[str, Any], session_id: str) -> Response:
        text = self._extract_text(data)
        return Response(text=text, session=session_id, raw=data)

    async def send(self, request: Request) -> Response:
        session_id = request.session or uuid.uuid4().hex
        try:
            body = self._build_body(request, session_id)
            headers = await self._build_headers()
            data = await self._adapter.send_raw(body, headers)
            return self._parse_response(data, session_id)
        except LLMError as exc:
            _LOG.debug("vertex_agent transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    async def aclose(self) -> None:
        if self._owns_adapter:
            await self._adapter.aclose()
