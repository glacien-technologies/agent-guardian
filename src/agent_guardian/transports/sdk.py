"""SDK transport — scan an in-process agent object (Stage 4).

A :class:`SdkTransport` is the thinnest possible seam over a Python *callable*
living in the same process as the swarm. It exists so an operator can point
AgentGuardian at an in-memory agent — a LangGraph ``run`` coroutine, a CrewAI
``kickoff``, a plain ``def reply(prompt) -> str`` — without standing up an HTTP
server or a subprocess.

The transport is built from **primitives**: either a dotted ``"module:callable"``
entrypoint (resolved with the same logic the legacy
:class:`agent_guardian.adapters.code.CodeAdapter` uses) or a direct callable.
On :meth:`send` it invokes the entrypoint with ``request.prompt`` and wraps the
string reply in a :class:`Response`. Both sync and async callables are
supported: a sync callable runs on a worker thread (so a blocking integration
cannot stall the event loop), and any awaitable it returns is awaited.

As with every transport, :meth:`send` **never** raises for a fault. The
entrypoint is user code, so any exception it raises is caught and folded into a
:class:`Response` carrying an :class:`agent_guardian.transports.errors.TransportError`.
Resolution / construction errors (a bad dotted path, a non-callable target) are
programming errors and raise at construction time, matching the rule the
:class:`~agent_guardian.transports.base.Transport` base documents.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar, cast

from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    Transport,
)
from agent_guardian.transports.errors import TransportError, TransportErrorCategory

__all__ = ["SdkTransport"]

_LOG = logging.getLogger(__name__)


class SdkTransport(Transport):
    """In-process transport wrapping a Python callable.

    Construct from a dotted ``"module:callable"`` entrypoint string or a direct
    callable (sync or async). The callable is invoked with the prompt as its
    single positional argument; its string return (or anything coercible via
    ``str``) becomes the reply text.
    """

    kind: ClassVar[str] = "sdk"

    def __init__(self, entrypoint: Callable[..., Any] | str) -> None:
        if isinstance(entrypoint, str):
            resolved, ref = _resolve_dotted_path(entrypoint)
        else:
            resolved = entrypoint
            ref = _describe_callable(resolved)
        if not callable(resolved):
            raise TypeError(
                f"SdkTransport entrypoint is not callable after resolution: {resolved!r}"
            )
        self._target: Callable[..., Any] = resolved
        self._ref = ref
        # A class instance with a ``__call__`` needs that bound method
        # introspected for async-ness, not the instance itself.
        call_attr = inspect.getattr_static(resolved, "__call__", None)
        self._is_coroutine_fn = inspect.iscoroutinefunction(
            resolved
        ) or inspect.iscoroutinefunction(call_attr)

    @property
    def ref(self) -> str:
        """Human-readable ``module:qualname`` label for the wrapped callable."""
        return self._ref

    async def _invoke(self, prompt: str) -> Any:
        """Call the entrypoint, awaiting it whether it is sync or async."""
        if self._is_coroutine_fn:
            return await cast(Awaitable[Any], self._target(prompt))
        # Hop to a worker thread so a blocking callable cannot stall the loop;
        # if it turns out to return an awaitable, await that too.
        raw = await asyncio.to_thread(self._target, prompt)
        if inspect.isawaitable(raw):
            return await raw
        return raw

    async def send(self, request: Request) -> Response:
        """Invoke the in-process callable and wrap its reply. Never raises."""
        try:
            result = await self._invoke(request.prompt)
        except Exception as exc:  # user code; fold any fault into a Response
            _LOG.debug("sdk transport: entrypoint %s raised (%s)", self._ref, exc)
            return Response(
                error=TransportError(
                    TransportErrorCategory.UNREACHABLE,
                    f"sdk entrypoint {self._ref} raised {type(exc).__name__}: {exc}",
                )
            )
        text = result if isinstance(result, str) else str(result)
        return Response(text=text, raw=result)

    def describe(self) -> CapabilityReport:
        """Report this SDK transport's static capabilities.

        An in-process callable surfaces no tool calls and no server session; it
        can run stateless or replay client history (the swarm inlines prior
        turns into the prompt).
        """
        return CapabilityReport(
            kind=self.kind,
            supports_tools=False,
            session_modes=("stateless", "client_history"),
            endpoint=self._ref,
        )


def _resolve_dotted_path(path: str) -> tuple[Callable[..., Any], str]:
    """Resolve ``module:attr.subattr`` → callable + ref string.

    Mirrors :func:`agent_guardian.adapters.code._resolve_dotted_path`: the part
    before ``:`` is an importable module, the part after is walked
    attribute-by-attribute, and a terminal (or mid-walk) class with a default
    constructor is instantiated so its ``__call__`` becomes the target.
    """
    if ":" not in path:
        raise ValueError(
            f"SdkTransport entrypoint must contain ':' separator (got {path!r}). "
            "Example: 'my_agent:run' or 'my_pkg.crew:MyCrew.kickoff'."
        )
    module_path, attr_path = path.split(":", 1)
    if not module_path or not attr_path:
        raise ValueError(f"SdkTransport entrypoint is malformed: {path!r}")
    module = importlib.import_module(module_path)
    obj: Any = module
    parts = attr_path.split(".")
    for i, part in enumerate(parts):
        next_obj = getattr(obj, part)
        if inspect.isclass(next_obj) and i < len(parts) - 1:
            try:
                next_obj = next_obj()
            except TypeError as exc:
                _LOG.debug(
                    "sdk transport: mid-walk class %r needs ctor args (%s) — "
                    "treating next segment as classmethod/staticmethod",
                    next_obj,
                    exc,
                )
        obj = next_obj
    if inspect.isclass(obj):
        try:
            obj = obj()
        except TypeError as exc:
            _LOG.debug(
                "sdk transport: terminal class %r needs ctor args (%s) — "
                "using class itself as callable",
                obj,
                exc,
            )
    if not callable(obj):
        raise TypeError(f"SdkTransport entrypoint {path!r} resolves to non-callable {obj!r}")
    return cast(Callable[..., Any], obj), path


def _describe_callable(fn: Callable[..., Any]) -> str:
    module = getattr(fn, "__module__", "<unknown>")
    qualname = getattr(fn, "__qualname__", None) or getattr(fn, "__name__", repr(fn))
    return f"{module}:{qualname}"
