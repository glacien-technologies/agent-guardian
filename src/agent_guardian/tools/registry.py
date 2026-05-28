"""Narrow typed tools — registry + base class (M2 Pattern 5).

Each agent-callable action is a :class:`TypedTool` with Pydantic input/output
schemas. This is the AIxCC "narrow typed tools" pattern: agents get a
constrained, schema-validated action API instead of open-ended shell access,
so an LLM cannot smuggle a destructive call through a free-form string. There
is deliberately **no** ``Bash`` / ``shell.exec`` tool.

The :class:`ToolRegistry` is the single dispatch point. The Commander enforces
each agent's closed allowlist (``AsiAgent.allowed_tools``) at dispatch: a
tool-call whose name is outside the agent's allowlist raises
:class:`ToolNotAllowed` and is counted as a malformed turn rather than
executed.

Concrete tools live in :mod:`agent_guardian.tools.actions`. The indicator- and
finding-coupled tools (``assert_indicator``, ``emit_finding``) land with the
PoV harness (Pattern 2), since they depend on the ``SuccessIndicator`` and
``Finding`` shapes that work defines.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel

__all__ = [
    "ToolError",
    "ToolNotAllowed",
    "ToolNotFound",
    "ToolRegistry",
    "TypedTool",
]

_LOG = logging.getLogger(__name__)


class ToolError(Exception):
    """Base class for typed-tool errors."""


class ToolNotFound(ToolError):
    """Raised when a tool name is not registered."""


class ToolNotAllowed(ToolError):
    """Raised when a tool is invoked outside the caller's allowlist.

    The Commander treats this as a malformed turn — the call is dropped, not
    executed — so an LLM that hallucinates a tool outside its declared
    allowlist cannot reach a real action.
    """


class TypedTool(ABC):
    """A single, schema-validated agent action.

    Subclasses set :attr:`name`, :attr:`description`, :attr:`InputSchema`,
    :attr:`OutputSchema` and implement :meth:`execute`. Inputs are validated
    through ``InputSchema`` and outputs through ``OutputSchema`` on every call
    (see :meth:`__call__`), so a malformed argument raises a Pydantic
    ``ValidationError`` instead of executing.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    InputSchema: ClassVar[type[BaseModel]]
    OutputSchema: ClassVar[type[BaseModel]]

    @abstractmethod
    async def execute(self, inputs: BaseModel) -> BaseModel:
        """Run the action on already-validated ``inputs``; return an OutputSchema."""

    async def __call__(self, **kwargs: Any) -> BaseModel:
        """Validate ``kwargs`` → execute → validate output. The safe entrypoint."""
        validated_in = self.InputSchema.model_validate(kwargs)
        result = await self.execute(validated_in)
        if isinstance(result, self.OutputSchema):
            return result
        # ``execute`` returned a dict or a different BaseModel — coerce through
        # the declared OutputSchema so the contract holds regardless.
        payload = result.model_dump() if isinstance(result, BaseModel) else result
        return self.OutputSchema.model_validate(payload)

    @classmethod
    def json_schema(cls) -> dict[str, Any]:
        """OpenAPI-style schema (name + description + IO) generated from Pydantic."""
        return {
            "name": cls.name,
            "description": cls.description,
            "input_schema": cls.InputSchema.model_json_schema(),
            "output_schema": cls.OutputSchema.model_json_schema(),
        }


class ToolRegistry:
    """Holds registered tools and enforces per-agent allowlists at dispatch."""

    def __init__(self) -> None:
        self._tools: dict[str, TypedTool] = {}

    def register(self, tool: TypedTool) -> None:
        name = tool.name
        if name in self._tools:
            raise ToolError(f"tool {name!r} already registered")
        self._tools[name] = tool
        _LOG.debug("tool registered: %s", name)

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def get(self, name: str, *, allowed: frozenset[str] | None = None) -> TypedTool:
        """Look up a tool, enforcing ``allowed`` if provided.

        ``allowed=None`` means "no allowlist gate" (used by tests / direct
        callers). Production dispatch always passes the agent's
        ``allowed_tools`` so a tool outside it raises :class:`ToolNotAllowed`.
        """
        if allowed is not None and name not in allowed:
            raise ToolNotAllowed(
                f"tool {name!r} is not in the caller's allowlist {sorted(allowed)}"
            )
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFound(
                f"tool {name!r} is not registered (have: {sorted(self._tools)})"
            ) from exc

    async def invoke(
        self, name: str, *, allowed: frozenset[str] | None = None, **kwargs: Any
    ) -> BaseModel:
        """Allowlist-gated dispatch: look up + call in one step."""
        tool = self.get(name, allowed=allowed)
        return await tool(**kwargs)
