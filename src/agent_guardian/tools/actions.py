"""Concrete typed tools (M2 Pattern 5).

These wrap the :class:`~agent_guardian.adapters.base.TargetAdapter` transport —
they never touch a shell. Each tool is constructed with the adapter it drives,
so the input schema only carries the per-call arguments.

Initial set (the transport-coupled, immediately-useful tools):

* :class:`SendUserMessageTool` — send one user turn, get the reply.
* :class:`MeasureTokenUsageTool` — send one turn and report input/output token
  estimates + the amplification factor (output/input), the core measurement for
  the denial-of-wallet specialist.

The indicator/finding-coupled tools (``assert_indicator``, ``emit_finding``)
land with the PoV harness (Pattern 2).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, Field

from agent_guardian.adapters.base import TargetAdapter
from agent_guardian.tools.registry import TypedTool

__all__ = [
    "MeasureTokenUsageTool",
    "SendUserMessageInput",
    "SendUserMessageOutput",
    "SendUserMessageTool",
]


def _estimate_tokens(text: str) -> int:
    """~4 chars/token, matching the estimate used across the codebase
    (``AgentBudget`` deduction, ``StubLLM`` usage)."""
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# send_user_message
# ---------------------------------------------------------------------------


class SendUserMessageInput(BaseModel):
    message: str = Field(min_length=1)
    session: str | None = None


class SendUserMessageOutput(BaseModel):
    response: str


class SendUserMessageTool(TypedTool):
    """Send one user turn to the target and return its text reply."""

    name: ClassVar[str] = "send_user_message"
    description: ClassVar[str] = "Send one user-turn message to the target and return its reply."
    InputSchema: ClassVar[type[BaseModel]] = SendUserMessageInput
    OutputSchema: ClassVar[type[BaseModel]] = SendUserMessageOutput

    def __init__(self, target: TargetAdapter) -> None:
        self._target = target

    async def execute(self, inputs: BaseModel) -> BaseModel:
        assert isinstance(inputs, SendUserMessageInput)
        reply = await self._target.call(inputs.message, session=inputs.session)
        return SendUserMessageOutput(response=reply)


# ---------------------------------------------------------------------------
# measure_token_usage
# ---------------------------------------------------------------------------


class MeasureTokenUsageInput(BaseModel):
    message: str = Field(min_length=1)
    session: str | None = None


class MeasureTokenUsageOutput(BaseModel):
    response: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    amplification_factor: float = Field(ge=0.0)
    """output_tokens / input_tokens — the denial-of-wallet (LLM10) signal."""


class MeasureTokenUsageTool(TypedTool):
    """Send one turn and report input/output token estimates + amplification.

    The amplification factor (output/input) is the core observable for the
    denial-of-wallet specialist: a benign-looking input that yields a large
    response is a cost-amplification vulnerability.
    """

    name: ClassVar[str] = "measure_token_usage"
    description: ClassVar[str] = (
        "Send one turn and report input/output token estimates and the "
        "output/input amplification factor."
    )
    InputSchema: ClassVar[type[BaseModel]] = MeasureTokenUsageInput
    OutputSchema: ClassVar[type[BaseModel]] = MeasureTokenUsageOutput

    def __init__(self, target: TargetAdapter) -> None:
        self._target = target

    async def execute(self, inputs: BaseModel) -> BaseModel:
        assert isinstance(inputs, MeasureTokenUsageInput)
        reply = await self._target.call(inputs.message, session=inputs.session)
        in_tok = _estimate_tokens(inputs.message)
        out_tok = _estimate_tokens(reply)
        af = out_tok / in_tok if in_tok else 0.0
        return MeasureTokenUsageOutput(
            response=reply,
            input_tokens=in_tok,
            output_tokens=out_tok,
            amplification_factor=af,
        )
