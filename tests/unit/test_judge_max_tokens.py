"""Judge output budget — the verdict JSON must not be truncated mid-object.

Root cause of the verify-lane "arming stuck at ~4" bug: ``gemini-3.5-flash`` is
a *thinking* model whose internal reasoning tokens count against
``maxOutputTokens``. With the framework-default 1024 cap, ~42% of judge calls
finished with ``finish=length`` — the visible JSON was cut off mid-object
(e.g. at ``"evaluator``), :func:`_parse_verdict_payload` returned ``None``, and
the heuristic fallback produced ``needs_followup`` *with no* ``followup_probe``.
A probe-less ``needs_followup`` cannot arm a verify turn, so arming flat-lined —
and, far worse, ~42% of ALL verdicts silently degraded to a conf=0.30 fallback.

The fix is to give the judge call an explicit, generous output budget so the
JSON always completes even with a thinking model's reasoning overhead.
"""

from __future__ import annotations

from agent_guardian.agents.base import _JUDGE_MAX_TOKENS, Judge, JudgeRubric
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.models.asi import AsiCategory


class _CapturingLLM(BaseLLM):
    """Record the exact :class:`LLMRequest` the judge issues."""

    provider = "capture"

    def __init__(self) -> None:
        self.last_request: LLMRequest | None = None

    async def _send(self, request: LLMRequest) -> LLMResponse:  # pragma: no cover - unused
        raise NotImplementedError

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.last_request = request
        return LLMResponse(
            text='{"verdict": "defended", "confidence": 0.9, "reasoning": "ok"}',
            model=request.model,
            provider=self.provider,
            usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            finish_reason="stop",
        )


def _rubric() -> JudgeRubric:
    return JudgeRubric(category=AsiCategory.ASI01, success_criteria="leaked instructions")


async def test_judge_request_uses_generous_output_budget() -> None:
    llm = _CapturingLLM()
    judge = Judge(llm=llm, model="gemini:gemini-3.5-flash", rubric=_rubric())

    await judge.verdict("attack prompt", "target response")

    assert llm.last_request is not None
    # The judge MUST request its explicit, generous budget — not the 1024
    # framework default that a thinking model truncates.
    assert llm.last_request.max_tokens == _JUDGE_MAX_TOKENS
    assert _JUDGE_MAX_TOKENS >= 2048


def test_judge_max_tokens_constant_is_generous() -> None:
    # Guard the constant itself so a future "tidy-up" cannot quietly drop it
    # back near the truncating default.
    assert _JUDGE_MAX_TOKENS >= 2048
