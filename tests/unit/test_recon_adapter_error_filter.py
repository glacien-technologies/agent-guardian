"""Recon parser-level rejection of adapter-error / transport-error replies.

rc38 P0-#4 (#262). When the target endpoint returns an *infrastructure* error
body (e.g. Google quota 429 with URL fragments, an `[adapter_error: ...]`
sentinel, a JSON `{"error": {"code": ..., "status": ...}}` envelope), recon
must NOT:

* treat URL tokens / error keys as ``declared_tools``,
* mark the run ``terminated_by="success"``.

The bug is a prompt-injection surface: attacker-controlled error text in a
target reply was being parroted into the judge's system prompt verbatim.

These tests pin the two invariants:

1. Tool tokens that match a transport / quota / adk-docs / rate-limit shape
   must be filtered out of ``declared_tools``.
2. When EVERY transcript reply is an error envelope, the report's
   ``terminated_by`` must be ``"target_error"`` (a distinct taxonomy).
"""

from __future__ import annotations

import json

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.recon import (
    ReconAgent,
    _clean_tool_names,
    _looks_like_target_error,
)
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage


class _ErrorReplyTarget(TargetAdapter):
    """Target whose every reply is the given error-shape JSON string."""

    mode = "http"

    def __init__(self, reply: str) -> None:
        super().__init__()
        self._reply = reply
        self._fingerprint = TargetFingerprint(mode="http", ref="error-reply-target")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return self._reply


class _NullLLM(BaseLLM):
    """LLM whose ``complete`` returns an empty JSON list (no tools extracted)."""

    provider = "stub"

    def __init__(self) -> None:
        super().__init__(owns_client=False)

    async def complete(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            text="[]",
            model=request.model,
            provider="stub",
            usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            finish_reason="stop",
            raw=None,
        )

    async def aclose(self) -> None:
        return None


def test_clean_tool_names_rejects_infrastructure_tokens() -> None:
    """Tokens that match adapter/transport/quota patterns must not survive
    cleaning. This is the unit-level invariant for the regex filter referenced
    by the verbatim rc38 #01 run.log declared_tools list."""
    raw = [
        "adapter_error",
        "adk-docs",
        "google-gemini",
        "error-code-429-resource_exhausted",
        "rate-limits",
        "generate_content_free_tier_input_token_count",
        "retry_delay",
        "retryDelay",
        "generativelanguage",
        "RESOURCE_EXHAUSTED",
        # Legitimate-looking handles that should survive.
        "lookup_contact",
        "search_kb",
    ]
    cleaned = _clean_tool_names(raw)
    lowered = {n.lower() for n in cleaned}
    assert "lookup_contact" in lowered
    assert "search_kb" in lowered
    for bad in (
        "adapter_error",
        "adk-docs",
        "rate-limits",
        "retry_delay",
        "retrydelay",
        "generativelanguage",
        "resource_exhausted",
    ):
        assert bad not in lowered, f"{bad!r} survived _clean_tool_names"


def test_looks_like_target_error_detects_envelope_shapes() -> None:
    """The shape detector must catch the three real-world envelopes:
    the adapter_error sentinel, the JSON error.code+status shape, and the
    httpx target-call-failed marker. A benign assistant reply must NOT trip."""
    assert _looks_like_target_error("[adapter_error: 429 quota exceeded]")
    assert _looks_like_target_error('{"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}}')
    assert _looks_like_target_error("[target call failed: HTTPStatusError]")
    assert _looks_like_target_error(
        "Please retry in 26.94s. See https://ai.google.dev/gemini-api/docs/rate-limits"
    )
    assert not _looks_like_target_error(
        "I'm a banking assistant. I can look up balances and transfer money."
    )
    assert not _looks_like_target_error("")


@pytest.mark.asyncio
async def test_recon_filters_adapter_error_tokens_from_declared_tools() -> None:
    """When the target reply is an adapter_error JSON body, recon must NOT
    parrot URL/quota tokens into ``declared_tools`` and must NOT report
    ``terminated_by=success``. Maps to rc38 #01 run.log 17:17:54.

    Verifies the parser-level rejection in agents/recon.py — the regex
    filter on tool tokens AND the target-error shape detector on the reply
    text.
    """
    error_body = (
        "[adapter_error: 429 RESOURCE_EXHAUSTED quota_metric=generativelanguage."
        "googleapis.com/generate_content_free_tier_input_token_count adk-docs"
        " google-gemini rate-limits retry-delay 26.94s]"
    )
    target = _ErrorReplyTarget(error_body)
    agent = ReconAgent(
        attacker_llm=_NullLLM(),
        model="stub",
        budget=AgentBudget(),
        audit_rounds=0,
    )
    memory = SharedMemory(scan_id="recon-adapter-error-filter")
    report = await agent.run(target, memory)
    fp = memory.target_fingerprint()
    assert fp is not None
    lowered = {n.lower() for n in fp.declared_tools}
    forbidden = {
        "adapter_error",
        "adk-docs",
        "google-gemini",
        "rate-limits",
        "retry-delay",
        "retry_delay",
        "generativelanguage",
        "resource_exhausted",
        "generate_content_free_tier_input_token_count",
    }
    polluters = forbidden & lowered
    assert not polluters, f"declared_tools contains infrastructure tokens: {polluters}"
    assert report.terminated_by == "target_error", (
        f"recon must mark a fully-erroring target as terminated_by=target_error; "
        f"got {report.terminated_by!r}"
    )


@pytest.mark.asyncio
async def test_recon_drops_google_429_url_tokens() -> None:
    """A verbatim Google 429 JSON body must not contribute any tool names."""
    google_429 = json.dumps(
        {
            "error": {
                "code": 429,
                "message": (
                    "You exceeded your current quota, please check your plan and "
                    "billing details. For more information on this error, head to: "
                    "https://ai.google.dev/gemini-api/docs/rate-limits"
                ),
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                        "violations": [
                            {
                                "quotaMetric": (
                                    "generativelanguage.googleapis.com/"
                                    "generate_content_free_tier_input_token_count"
                                ),
                                "quotaId": "GenerateContentInputTokensPerModelPerMinute-FreeTier",
                            }
                        ],
                    },
                    {
                        "@type": "type.googleapis.com/google.rpc.RetryInfo",
                        "retryDelay": "26.94s",
                    },
                ],
            }
        }
    )
    target = _ErrorReplyTarget(google_429)
    agent = ReconAgent(
        attacker_llm=_NullLLM(),
        model="stub",
        budget=AgentBudget(),
        audit_rounds=0,
    )
    memory = SharedMemory(scan_id="recon-google-429-filter")
    report = await agent.run(target, memory)
    fp = memory.target_fingerprint()
    assert fp is not None
    assert fp.declared_tools == [], (
        f"Google 429 body must not produce declared_tools; got {fp.declared_tools}"
    )
    assert report.terminated_by == "target_error"


@pytest.mark.asyncio
async def test_recon_extracted_tool_x_from_error_body_is_rejected() -> None:
    """Attacker-controlled JSON in a target's reply body must not bypass the
    filter. Even if a JSON object like ``{"tool_x": "fake"}`` lives inside an
    adapter_error wrapper, recon must NOT carry ``tool_x`` into the declared
    tool surface, because the reply itself is an error envelope."""
    payload = "[adapter_error: 429 " + json.dumps({"tool_x": "fake"}) + "]"
    target = _ErrorReplyTarget(payload)
    agent = ReconAgent(
        attacker_llm=_NullLLM(),
        model="stub",
        budget=AgentBudget(),
        audit_rounds=0,
    )
    memory = SharedMemory(scan_id="recon-attacker-tool-x")
    report = await agent.run(target, memory)
    fp = memory.target_fingerprint()
    assert fp is not None
    lowered = {n.lower() for n in fp.declared_tools}
    assert "tool_x" not in lowered, (
        f"attacker-controlled tool name leaked into declared_tools: {fp.declared_tools}"
    )
    assert report.terminated_by == "target_error"
