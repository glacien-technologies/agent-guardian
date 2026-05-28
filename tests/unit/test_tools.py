"""Tests for the narrow typed-tools package + the specialist contract (M2 P5/P8)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.tools import (
    MeasureTokenUsageTool,
    SendUserMessageTool,
    ToolError,
    ToolNotAllowed,
    ToolNotFound,
    ToolRegistry,
)


class _EchoTarget(TargetAdapter):
    """Minimal adapter that echoes a fixed (or length-scaled) reply."""

    mode = "code"

    def __init__(self, reply: str = "ack") -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="code", ref="echo:target")
        self._reply = reply
        self.received: list[tuple[str, str | None]] = []

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        self.received.append((prompt, session))
        return self._reply


# ---------------------------------------------------------------------------
# TypedTool input/output validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_user_message_validates_and_calls_target() -> None:
    target = _EchoTarget(reply="hello back")
    tool = SendUserMessageTool(target)
    out = await tool(message="hi there", session="s1")
    assert out.response == "hello back"
    assert target.received == [("hi there", "s1")]


@pytest.mark.asyncio
async def test_send_user_message_rejects_empty_message() -> None:
    tool = SendUserMessageTool(_EchoTarget())
    with pytest.raises(ValidationError):
        await tool(message="")


@pytest.mark.asyncio
async def test_measure_token_usage_computes_amplification() -> None:
    # input ~ "x"*40 -> 10 tokens; reply 80 chars -> 20 tokens -> AF 2.0
    target = _EchoTarget(reply="y" * 80)
    tool = MeasureTokenUsageTool(target)
    out = await tool(message="x" * 40)
    assert out.input_tokens == 10
    assert out.output_tokens == 20
    assert out.amplification_factor == pytest.approx(2.0)


def test_typed_tool_json_schema_shape() -> None:
    schema = SendUserMessageTool.json_schema()
    assert schema["name"] == "send_user_message"
    assert "description" in schema
    assert "properties" in schema["input_schema"]
    assert "properties" in schema["output_schema"]


# ---------------------------------------------------------------------------
# ToolRegistry + allowlist enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_register_and_invoke() -> None:
    reg = ToolRegistry()
    reg.register(SendUserMessageTool(_EchoTarget(reply="r")))
    out = await reg.invoke("send_user_message", message="hi")
    assert out.response == "r"
    assert reg.names() == frozenset({"send_user_message"})


def test_registry_duplicate_registration_raises() -> None:
    reg = ToolRegistry()
    reg.register(SendUserMessageTool(_EchoTarget()))
    with pytest.raises(ToolError):
        reg.register(SendUserMessageTool(_EchoTarget()))


def test_registry_unknown_tool_raises_not_found() -> None:
    reg = ToolRegistry()
    with pytest.raises(ToolNotFound):
        reg.get("does_not_exist")


def test_registry_allowlist_blocks_out_of_scope_tool() -> None:
    reg = ToolRegistry()
    reg.register(SendUserMessageTool(_EchoTarget()))
    # Tool exists but is outside the caller's allowlist.
    with pytest.raises(ToolNotAllowed):
        reg.get("send_user_message", allowed=frozenset({"some_other_tool"}))


@pytest.mark.asyncio
async def test_registry_allowlist_permits_listed_tool() -> None:
    reg = ToolRegistry()
    reg.register(SendUserMessageTool(_EchoTarget(reply="ok")))
    out = await reg.invoke(
        "send_user_message", allowed=frozenset({"send_user_message"}), message="hi"
    )
    assert out.response == "ok"


# ---------------------------------------------------------------------------
# Pattern 8 — every registered specialist declares the contract
# ---------------------------------------------------------------------------


def test_all_specialists_declare_contract() -> None:
    from agent_guardian.core.swarm import _ASI_AGENT_CLASSES

    assert _ASI_AGENT_CLASSES, "expected a non-empty agent slate"
    for cls in _ASI_AGENT_CLASSES:
        assert isinstance(cls.allowed_tools, frozenset), f"{cls.__name__}.allowed_tools"
        assert isinstance(cls.estimated_cost_per_run_usd, float), f"{cls.__name__} cost"
        assert cls.estimated_cost_per_run_usd >= 0.0, f"{cls.__name__} cost >= 0"
