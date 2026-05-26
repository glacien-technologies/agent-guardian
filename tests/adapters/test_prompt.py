"""Tests for PromptAdapter (Mode A)."""

from __future__ import annotations

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.llm.stub import StubLLM


def _build_adapter(canned: dict[str, str] | None = None) -> PromptAdapter:
    llm = StubLLM(canned=canned or {"hello": "hi back"}, default="STUB_DEFAULT")
    return PromptAdapter(
        "You are a helpful assistant.",
        llm=llm,
        model="gpt-4o-mini",
        ref="sys-prompts/test.txt",
    )


async def test_returns_canned_response() -> None:
    adapter = _build_adapter()
    out = await adapter.call("hello there")
    assert out == "hi back"


async def test_system_prompt_is_injected_once_per_session() -> None:
    captured: list[list[str]] = []

    class CapturingStub(StubLLM):
        async def complete(self, request):  # type: ignore[override]
            captured.append([f"{m.role}:{m.content}" for m in request.messages])
            return await super().complete(request)

    llm = CapturingStub(canned={"q": "a"}, default="A")
    adapter = PromptAdapter("SYS", llm=llm)
    await adapter.call("q1")
    await adapter.call("q2")
    # First call sees [system, user]; second sees [system, user, assistant, user].
    assert captured[0][0] == "system:SYS"
    assert captured[0][1].startswith("user:")
    assert captured[1][0] == "system:SYS"  # system injected only once
    assert sum(1 for m in captured[1] if m == "system:SYS") == 1
    assert captured[1][-1].startswith("user:")


async def test_sessions_are_isolated() -> None:
    captured: list[list[str]] = []

    class CapturingStub(StubLLM):
        async def complete(self, request):  # type: ignore[override]
            captured.append([f"{m.role}" for m in request.messages])
            return await super().complete(request)

    llm = CapturingStub(canned={}, default="ok")
    adapter = PromptAdapter("SYS", llm=llm)
    await adapter.call("first", session="alpha")
    await adapter.call("first", session="beta")
    # Both sessions start clean: system + user, two messages each.
    assert captured[0] == ["system", "user"]
    assert captured[1] == ["system", "user"]


async def test_fingerprint_is_t4_correct() -> None:
    adapter = _build_adapter()
    fp = adapter.fingerprint()
    assert fp.mode == "prompt"
    assert fp.ref == "sys-prompts/test.txt"
    assert fp.has_tools is False
    assert fp.has_memory is False
    assert fp.touches_pii is False
    assert fp.is_multi_agent is False


async def test_aclose_closes_llm() -> None:
    llm = StubLLM(default="x")
    closed = {"flag": False}
    orig = llm.aclose

    async def track() -> None:
        closed["flag"] = True
        await orig()

    llm.aclose = track  # type: ignore[method-assign]
    adapter = PromptAdapter("p", llm=llm)
    await adapter.aclose()
    assert closed["flag"] is True


async def test_fingerprint_default_ref() -> None:
    adapter = PromptAdapter("p", llm=StubLLM(default="x"))
    assert adapter.fingerprint().ref == "<inline-prompt>"


async def test_observed_surface_projection() -> None:
    adapter = _build_adapter()
    obs = adapter.fingerprint().to_observed_surface()
    assert obs.has_tools is False
    assert obs.has_memory is False
