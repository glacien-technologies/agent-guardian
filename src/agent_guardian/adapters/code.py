"""CodeAdapter — Mode B: wrap a Python callable (PRD §7).

Accepts a target as:

1. A direct callable (sync function, async function, class instance with
   ``__call__``).
2. A dotted-path string such as ``"my_agent:run"`` or
   ``"my_pkg.crew:MyCrew.kickoff"``. The portion before ``:`` is the
   importable module; the portion after is walked attribute-by-attribute.
   If the final attribute is a class, it is instantiated with no args; if
   that fails, the adapter falls back to treating it as a classmethod.
3. A class object (instantiated immediately with no args).

Signature introspection drives the actual invocation:

* ``async`` coroutines are awaited directly.
* Sync callables run inside :func:`asyncio.to_thread` to avoid blocking
  the event loop.
* The adapter inspects the callable's signature and only passes
  ``session`` if the callable declares a ``session`` parameter.
* If the callable returns a non-string value, the adapter calls
  ``str(...)`` on the result and emits a :mod:`warnings` warning so the
  operator can tighten their integration.

Tier-hint detection is a best-effort heuristic — :attr:`has_tools`,
:attr:`has_memory`, and friends are populated from common attribute
names (``tools``, ``memory``, ``agents``, ``crew_members``). The
recon-agent (M5) refines these signals before the scoring phase.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import warnings
from collections.abc import Awaitable, Callable
from typing import Any, cast

from agent_guardian.adapters.base import (
    ProfileEvidence,
    TargetAdapter,
    TargetFingerprint,
    safe_source_and_root,
)

__all__ = ["CodeAdapter"]

_LOG = logging.getLogger(__name__)


_TOOL_ATTRS = ("tools", "registered_tools", "available_tools")
_MEMORY_ATTRS = ("memory", "memory_store", "state")
_MULTI_AGENT_ATTRS = ("agents", "crew_members", "subagents", "sub_agents")


class CodeAdapter(TargetAdapter):
    """Wraps a Python callable defined in user code."""

    mode = "code"

    def __init__(
        self,
        target: Callable[..., Any] | str | type,
        *,
        ref: str | None = None,
    ) -> None:
        super().__init__()
        if isinstance(target, str):
            resolved, resolved_ref = _resolve_dotted_path(target)
        else:
            resolved = _instantiate_if_class(target)
            resolved_ref = ref or _describe_callable(resolved)
        if not callable(resolved):
            raise TypeError(f"CodeAdapter target is not callable after resolution: {resolved!r}")
        self._target: Callable[..., Any] = resolved
        # If ``resolved`` is a class instance with a ``__call__`` method we
        # also need to introspect that bound method for async-ness — hence
        # the manual ``__call__`` lookup instead of a simple ``callable()``
        # check (which only returns a bool).
        call_attr = inspect.getattr_static(resolved, "__call__", None)
        self._is_coroutine_fn = inspect.iscoroutinefunction(
            resolved
        ) or inspect.iscoroutinefunction(call_attr)
        self._accepts_session = _signature_accepts_session(resolved)

        declared_tools = _extract_string_list(resolved, _TOOL_ATTRS)
        declared_memory_keys = _extract_string_list(resolved, _MEMORY_ATTRS)
        has_multi = any(_has_truthy_attr(resolved, a) for a in _MULTI_AGENT_ATTRS)

        self._fingerprint = TargetFingerprint(
            mode="code",
            ref=ref or resolved_ref,
            has_tools=bool(declared_tools)
            or any(_has_truthy_attr(resolved, a) for a in _TOOL_ATTRS),
            has_memory=bool(declared_memory_keys)
            or any(_has_truthy_attr(resolved, a) for a in _MEMORY_ATTRS),
            touches_pii=False,
            is_multi_agent=has_multi,
            declared_tools=declared_tools,
            declared_memory_keys=declared_memory_keys,
            notes="Mode B: Python callable. Heuristic tier hints; refined by recon-agent.",
        )

    @classmethod
    def from_dotted_path(cls, path: str) -> CodeAdapter:
        """Construct an adapter from a ``module:attr`` dotted path."""
        return cls(path)

    def profile_evidence(self) -> ProfileEvidence:
        # White-box: read the implementation. The defining module usually
        # carries the agent + its tool definitions; ``source_root`` lets the
        # profiler grep/read deeper for large targets. Fall back to black-box
        # when source is unavailable (C-extension / REPL / lambda).
        text, root = safe_source_and_root(self._target)
        if text is None:
            return ProfileEvidence(box="black")
        return ProfileEvidence(box="white", text=text, source_root=root)

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        kwargs: dict[str, Any] = {}
        if self._accepts_session:
            kwargs["session"] = session

        if self._is_coroutine_fn:
            result = await cast(Awaitable[Any], self._target(prompt, **kwargs))
        else:
            # Hop to a worker thread first; if the target turns out to be
            # async despite the static check, await the awaitable it
            # returned.
            raw = await asyncio.to_thread(self._target, prompt, **kwargs)
            if inspect.isawaitable(raw):
                result = await raw
            else:
                result = raw

        if isinstance(result, str):
            return result
        warnings.warn(
            f"CodeAdapter target returned {type(result).__name__!s}, coercing via str(); "
            "consider returning a str directly.",
            stacklevel=2,
        )
        return str(result)


def _instantiate_if_class(target: Callable[..., Any] | type) -> Callable[..., Any]:
    if inspect.isclass(target):
        try:
            return cast(Callable[..., Any], target())
        except TypeError as exc:
            raise TypeError(
                f"CodeAdapter cannot instantiate {target!r} with no args: {exc}"
            ) from exc
    return target


def _resolve_dotted_path(path: str) -> tuple[Callable[..., Any], str]:
    """Resolve ``module:attr.subattr`` → callable + ref string."""
    if ":" not in path:
        raise ValueError(
            f"CodeAdapter dotted path must contain ':' separator (got {path!r}). "
            "Example: 'my_agent:run' or 'my_pkg.crew:MyCrew.kickoff'."
        )
    module_path, attr_path = path.split(":", 1)
    if not module_path or not attr_path:
        raise ValueError(f"CodeAdapter dotted path is malformed: {path!r}")
    module = importlib.import_module(module_path)
    obj: Any = module
    parts = attr_path.split(".")
    for i, part in enumerate(parts):
        next_obj = getattr(obj, part)
        # If we encounter a class mid-walk (i.e. there are more attribute
        # segments to follow), instantiate it so the next ``getattr`` yields
        # a bound method rather than the unbound function.
        if inspect.isclass(next_obj) and i < len(parts) - 1:
            # If the class needs ctor args, fall through and treat the next
            # segment as a classmethod / staticmethod on the class itself.
            try:
                next_obj = next_obj()
            except TypeError as exc:
                _LOG.debug(
                    "code adapter: mid-walk class %r needs ctor args (%s) — "
                    "treating next segment as classmethod/staticmethod",
                    next_obj,
                    exc,
                )
        obj = next_obj
    if inspect.isclass(obj):
        try:
            # Final segment is a class with a default ctor — build an
            # instance so its ``__call__`` (or implicit ctor) is the target.
            obj = obj()
        except TypeError as exc:
            _LOG.debug(
                "code adapter: terminal class %r needs ctor args (%s) — "
                "using class itself as callable",
                obj,
                exc,
            )
    if not callable(obj):
        raise TypeError(f"Dotted path {path!r} resolves to non-callable {obj!r}")
    return cast(Callable[..., Any], obj), path


def _signature_accepts_session(fn: Callable[..., Any]) -> bool:
    # ``inspect.signature`` already unwraps ``__call__`` for class
    # instances, so we don't have to peek at ``__call__`` ourselves.
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError) as exc:
        _LOG.debug(
            "code adapter: inspect.signature(%r) failed (%s) — assuming no session parameter",
            fn,
            exc,
        )
        return False
    return "session" in sig.parameters


def _has_truthy_attr(obj: Any, name: str) -> bool:
    val = getattr(obj, name, None)
    return bool(val)


def _extract_string_list(obj: Any, names: tuple[str, ...]) -> list[str]:
    for name in names:
        val = getattr(obj, name, None)
        if not val:
            continue
        if isinstance(val, (list, tuple, set)):
            out: list[str] = []
            for item in val:
                if isinstance(item, str):
                    out.append(item)
                else:
                    label = (
                        getattr(item, "name", None) or getattr(item, "__name__", None) or repr(item)
                    )
                    out.append(str(label))
            return out
        if isinstance(val, dict):
            return [str(k) for k in val]
    return []


def _describe_callable(fn: Callable[..., Any]) -> str:
    module = getattr(fn, "__module__", "<unknown>")
    qualname = getattr(fn, "__qualname__", None) or getattr(fn, "__name__", repr(fn))
    return f"{module}:{qualname}"
