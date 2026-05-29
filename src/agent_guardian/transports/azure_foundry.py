"""Azure AI Foundry Agent Service transport (Stage 2).

Drives an Azure AI Foundry *agent* over its thread/run data plane:

``POST {endpoint}/threads/runs?api-version={api_version}``

The body carries the agent id plus the new user turn and, when continuing a
conversation, the existing ``thread_id``:
``{"assistant_id": <agent_id>, "thread": {"messages": [{"role": "user",
"content": <prompt>}]}}`` on the first turn, or ``{"assistant_id": <agent_id>,
"thread_id": <thread>, "additional_messages": [...]}`` on subsequent turns.

The *thread* id is the server-side conversation handle — the ``server_session``
pattern. We reuse :attr:`Request.session` as the ``thread_id`` when present and
surface the (new or echoed) thread id back on :attr:`Response.session`, so the
:class:`~agent_guardian.transports.session.SessionMachine` (SERVER_SESSION mode)
replays it on every turn.

**Response parsing.** Foundry's create-thread-and-run returns a run object; for
the synchronous-style endpoint the assistant text is read from the first
``content[].text.value`` block of the run's output message
(``output.message.content[].text.value``), falling back to a top-level
``content`` list. The thread id comes from ``thread_id`` (or ``thread.id``).

**Auth.** An Azure Entra (AAD) bearer
:class:`~agent_guardian.transports.auth.base.AuthProvider` is injected by the
factory; this transport constructs no Azure credentials.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import httpx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.llm.errors import LLMError, LLMResponseFormatError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import CapabilityReport, Request, Response, Transport
from agent_guardian.transports.errors import map_llm_error

__all__ = ["AzureFoundryAgentTransport"]

_LOG = logging.getLogger(__name__)

_DEFAULT_API_VERSION = "2024-12-01-preview"


class AzureFoundryAgentTransport(Transport):
    """Azure AI Foundry Agent Service transport (``server_session`` via thread id)."""

    kind: ClassVar[str] = "azure_foundry"

    def __init__(
        self,
        *,
        endpoint: str,
        agent_id: str,
        api_version: str = _DEFAULT_API_VERSION,
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
        adapter: HttpAdapter | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("AzureFoundryAgentTransport requires a non-empty endpoint")
        if not agent_id:
            raise ValueError("AzureFoundryAgentTransport requires a non-empty agent_id")
        base = endpoint.rstrip("/")
        self._base = base
        self._agent_id = agent_id
        self._api_version = api_version
        self._endpoint = f"{base}/threads/runs?api-version={api_version}"
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
            auth_scheme="azure_entra",
            endpoint=self._base,
        )

    def _build_body(self, request: Request) -> dict[str, Any]:
        message = {"role": "user", "content": request.prompt}
        body: dict[str, Any] = {"assistant_id": self._agent_id}
        if request.session is not None:
            # Continue an existing thread (server keeps the prior turns).
            body["thread_id"] = request.session
            body["additional_messages"] = [message]
        else:
            # First turn: create a fresh thread inline with the run.
            body["thread"] = {"messages": [message]}
        return body

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
    def _extract_thread_id(data: dict[str, Any]) -> str | None:
        thread_id = data.get("thread_id")
        if isinstance(thread_id, str):
            return thread_id
        thread = data.get("thread")
        if isinstance(thread, dict):
            inner = thread.get("id")
            if isinstance(inner, str):
                return inner
        return None

    @staticmethod
    def _text_from_content(content: Any) -> str | None:
        if not isinstance(content, list):
            return None
        parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if isinstance(text, dict):
                value = text.get("value")
                if isinstance(value, str):
                    parts.append(value)
            elif isinstance(text, str):
                parts.append(text)
        return "".join(parts) if parts else None

    @classmethod
    def _extract_text(cls, data: dict[str, Any]) -> str:
        # Preferred: output.message.content[].text.value
        output = data.get("output")
        if isinstance(output, dict):
            message = output.get("message")
            if isinstance(message, dict):
                text = cls._text_from_content(message.get("content"))
                if text is not None:
                    return text
        # Fallback: top-level content list.
        text = cls._text_from_content(data.get("content"))
        if text is not None:
            return text
        raise LLMResponseFormatError(
            "azure_foundry: no assistant text "
            "(expected output.message.content[].text.value or content[])"
        )

    def _parse_response(self, data: dict[str, Any], request: Request) -> Response:
        text = self._extract_text(data)
        session = self._extract_thread_id(data) or request.session
        return Response(text=text, session=session, raw=data)

    async def send(self, request: Request) -> Response:
        try:
            body = self._build_body(request)
            headers = await self._build_headers()
            data = await self._adapter.send_raw(body, headers)
            return self._parse_response(data, request)
        except LLMError as exc:
            _LOG.debug("azure_foundry transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    async def aclose(self) -> None:
        if self._owns_adapter:
            await self._adapter.aclose()
