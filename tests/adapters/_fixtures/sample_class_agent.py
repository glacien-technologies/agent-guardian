"""Class-based target callables for CodeAdapter tests."""

from __future__ import annotations

from typing import ClassVar


class CallableAgent:
    """Instance is callable via ``__call__``."""

    tools: ClassVar[list[str]] = ["search"]
    memory: ClassVar[dict[str, list[str]]] = {"history": []}
    agents: ClassVar[list[str]] = ["alice", "bob"]

    def __call__(self, prompt: str, session: str | None = None) -> str:
        return f"call:{prompt}:{session}"


class AsyncCallableAgent:
    """Async-callable agent."""

    tools: ClassVar[list[str]] = ["search"]

    async def __call__(self, prompt: str) -> str:
        return f"acall:{prompt}"


class AgentWithKickoff:
    """Class with a regular method used as the target."""

    tools: ClassVar[list[str]] = ["search"]

    def kickoff(self, prompt: str) -> str:
        return f"kickoff:{prompt}"


class CtorRequired:
    """Class that needs constructor args — exercises the classmethod path."""

    def __init__(self, x: int) -> None:
        self.x = x

    @classmethod
    def factory(cls, prompt: str) -> str:
        return f"factory:{prompt}"
