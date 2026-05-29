"""Transports — the "send a turn, get a turn" seam over a target (Stage 1A).

A :class:`Transport` is the thinnest possible interface over a target: it speaks
:class:`Request` / :class:`Response` and never raises for transport faults. The
HTTP transport (:class:`HttpTransport`) is built from primitives and wraps the
existing :class:`agent_guardian.adapters.http.HttpAdapter` via its public
``send_raw`` seam.

DECOUPLING: this package does **not** import ``agent_guardian.contract`` and
must never. Building a transport from a contract is a later, separate wiring
stage.
"""

from __future__ import annotations

from agent_guardian.transports.base import (
    Message,
    Request,
    Response,
    TokenUsage,
    ToolCall,
    Transport,
)
from agent_guardian.transports.errors import (
    TransportError,
    TransportErrorCategory,
    map_llm_error,
)
from agent_guardian.transports.http import HttpTransport
from agent_guardian.transports.registry import (
    build_transport,
    get_transport_factory,
    list_transport_kinds,
    register_transport,
)
from agent_guardian.transports.session import SessionMachine, SessionMode
from agent_guardian.transports.streaming import (
    StreamFormat,
    StreamResult,
    accumulate_sse,
    accumulate_sse_async,
)
from agent_guardian.transports.templating import render_body

__all__ = [
    "HttpTransport",
    "Message",
    "Request",
    "Response",
    "SessionMachine",
    "SessionMode",
    "StreamFormat",
    "StreamResult",
    "TokenUsage",
    "ToolCall",
    "Transport",
    "TransportError",
    "TransportErrorCategory",
    "accumulate_sse",
    "accumulate_sse_async",
    "build_transport",
    "get_transport_factory",
    "list_transport_kinds",
    "map_llm_error",
    "register_transport",
    "render_body",
]
