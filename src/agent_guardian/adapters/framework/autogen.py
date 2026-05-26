"""Microsoft AutoGen adapter (PRD §7).

Wraps an AutoGen ``GroupChat`` / agent-pair-like object. We duck-type —
AutoGen is **not** a dependency. The adapter accepts anything with one of:

* ``a_initiate_chat(recipient, message=...)`` async (AutoGen >=0.2)
* ``initiate_chat(recipient, message=...)`` sync
* a callable ``run(message)`` / ``run_async(message)`` (autogen-core 0.4+)

We pick the most async-friendly method present.

Hook firing from inside AutoGen is best-effort — full runtime
instrumentation is an M-future milestone.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["AutoGenAdapter"]


class AutoGenAdapter(FrameworkAdapter):
    """Wraps an AutoGen ``GroupChat`` / agent."""

    framework_name = "autogen"

    def __init__(self, group_chat: Any, *, ref: str | None = None) -> None:
        super().__init__()
        if group_chat is None:
            raise ValueError("AutoGenAdapter requires a non-None group_chat")
        if not any(
            hasattr(group_chat, m) for m in ("a_initiate_chat", "initiate_chat", "run_async", "run")
        ):
            raise TypeError(
                "AutoGenAdapter expected a chat/agent with one of "
                "{a_initiate_chat, initiate_chat, run_async, run}; got "
                f"{type(group_chat).__name__}"
            )
        self._chat = group_chat
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"autogen:{type(group_chat).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=True,
            notes="Mode D — AutoGen production adapter. Hook firing is best-effort.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        del session
        chat = self._chat
        if hasattr(chat, "a_initiate_chat"):
            result = await chat.a_initiate_chat(message=prompt)
        elif hasattr(chat, "run_async"):
            result = await chat.run_async(message=prompt)
        elif hasattr(chat, "initiate_chat"):
            result = await asyncio.to_thread(chat.initiate_chat, message=prompt)
        else:
            result = await asyncio.to_thread(chat.run, message=prompt)
        return _stringify_autogen_result(result)


def _stringify_autogen_result(result: Any) -> str:
    """Pull plain text out of an AutoGen ChatResult-or-similar."""
    if result is None:
        raise ValueError("AutoGenAdapter: chat returned None")
    if isinstance(result, str):
        return result
    # AutoGen 0.2 ChatResult exposes .summary or chat_history[-1]["content"].
    summary = getattr(result, "summary", None)
    if isinstance(summary, str) and summary:
        return summary
    history = getattr(result, "chat_history", None)
    if isinstance(history, list) and history:
        last = history[-1]
        if isinstance(last, dict):
            content = last.get("content")
            if isinstance(content, str):
                return content
        else:
            content = getattr(last, "content", None)
            if isinstance(content, str):
                return content
    # autogen-core TaskResult exposes .messages[-1].content.
    messages = getattr(result, "messages", None)
    if isinstance(messages, list) and messages:
        last_msg = messages[-1]
        content = (
            getattr(last_msg, "content", None)
            if not isinstance(last_msg, dict)
            else last_msg.get("content")
        )
        if isinstance(content, str):
            return content
    return str(result)
