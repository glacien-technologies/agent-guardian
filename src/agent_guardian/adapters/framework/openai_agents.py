"""OpenAI Agents SDK adapter (PRD §7).

Wraps an OpenAI Agents SDK ``Agent``-like object via the SDK's
``Runner.run(agent, input=...)`` entrypoint. We duck-type both pieces — the
SDK is **not** a dependency. The caller may supply either:

* an object that exposes ``run_async(input=...)`` / ``run(input=...)`` directly
  (a small wrapper around ``Runner.run`` is convenient for tests), or
* an actual ``Agent`` instance plus a ``runner=`` keyword.

The adapter prefers the async path. The result's ``.final_output`` (string)
is returned; if absent, we stringify the result.

Hook firing from inside the SDK is best-effort — full runtime
instrumentation is an M-future milestone.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["OpenAIAgentsAdapter"]


class OpenAIAgentsAdapter(FrameworkAdapter):
    """Wraps an OpenAI Agents SDK ``Agent`` (with optional ``runner``)."""

    framework_name = "openai_agents"

    def __init__(
        self,
        agent: Any,
        *,
        runner: Any | None = None,
        ref: str | None = None,
    ) -> None:
        super().__init__()
        if agent is None:
            raise ValueError("OpenAIAgentsAdapter requires a non-None agent")
        if runner is None and not any(hasattr(agent, m) for m in ("run_async", "run")):
            raise TypeError(
                "OpenAIAgentsAdapter needs either an agent exposing "
                ".run_async()/.run() or a Runner via runner=...; got "
                f"agent={type(agent).__name__}"
            )
        if runner is not None and not any(hasattr(runner, m) for m in ("run", "run_async")):
            raise TypeError(
                "OpenAIAgentsAdapter runner= must expose .run() or .run_async(); "
                f"got {type(runner).__name__}"
            )
        self._agent = agent
        self._runner = runner
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"openai_agents:{type(agent).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            notes=("Mode D — OpenAI Agents SDK production adapter. Hook firing is best-effort."),
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        del session
        result = await self._run(prompt)
        return _stringify_agents_result(result)

    async def _run(self, prompt: str) -> Any:
        """Invoke the SDK using whichever entrypoint is available."""
        if self._runner is not None:
            if hasattr(self._runner, "run") and asyncio.iscoroutinefunction(self._runner.run):
                return await self._runner.run(self._agent, input=prompt)
            if hasattr(self._runner, "run_async"):
                return await self._runner.run_async(self._agent, input=prompt)
            return await asyncio.to_thread(self._runner.run, self._agent, input=prompt)
        agent = self._agent
        if hasattr(agent, "run_async"):
            return await agent.run_async(input=prompt)
        if asyncio.iscoroutinefunction(agent.run):
            return await agent.run(input=prompt)
        return await asyncio.to_thread(agent.run, input=prompt)


def _stringify_agents_result(result: Any) -> str:
    """Pull the assistant text out of a Runner result."""
    if result is None:
        raise ValueError("OpenAIAgentsAdapter: runner returned None")
    final = getattr(result, "final_output", None)
    if isinstance(final, str):
        return final
    if isinstance(result, str):
        return result
    # Some SDK variants put the message in result.messages[-1].
    messages = getattr(result, "messages", None)
    if isinstance(messages, list) and messages:
        last = messages[-1]
        content = (
            getattr(last, "content", None) if not isinstance(last, dict) else last.get("content")
        )
        if isinstance(content, str):
            return content
    return str(result)
