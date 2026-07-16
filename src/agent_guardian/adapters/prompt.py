"""PromptAdapter — Mode A: wrap a system prompt around an LLM (PRD §7).

Used for *pre-deployment* prompt review: the operator hasn't yet built an
agent, just a system prompt. The adapter pairs the prompt with any
:class:`BaseLLM` (typically :class:`StubLLM` in tests, a real provider in
production) and auto-tiers to T4 — no tools, no memory, no PII.
"""

from __future__ import annotations

from collections.abc import Callable

from agent_guardian.adapters.base import ProfileEvidence, TargetAdapter, TargetFingerprint
from agent_guardian.core.budget import BudgetExhausted, BudgetLedger
from agent_guardian.llm.base import BaseLLM, LLMMessage, LLMRequest
from agent_guardian.llm.budget_admission import with_budget_admission
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM

__all__ = ["PromptAdapter"]


class PromptAdapter(TargetAdapter):
    """Wraps a user-supplied system prompt around a :class:`BaseLLM`.

    Args:
        prompt: The system prompt to evaluate. Frozen at construction time.
        llm: Any :class:`BaseLLM` implementation. The adapter takes ownership
            and closes it via :meth:`aclose`.
        model: Model identifier forwarded to the LLM.
        ref: Optional source reference (path, URL, etc.) recorded on the
            fingerprint. Defaults to ``"<inline-prompt>"``.
    """

    mode = "prompt"

    def __init__(
        self,
        prompt: str,
        *,
        llm: BaseLLM,
        model: str = "gemini-3.5-flash",
        ref: str = "<inline-prompt>",
    ) -> None:
        super().__init__()
        self._prompt = prompt
        # Instrumentation decorators do not own their inner client. Keep the
        # exact client accepted at construction as the adapter-owned resource
        # so replacing ``_llm`` never loses the provider lifecycle.
        self._owned_llm = llm
        self._llm = llm
        self._closed = False
        self._model = model
        self._sessions: dict[str, list[LLMMessage]] = {}
        self._fingerprint = TargetFingerprint(
            mode="prompt",
            ref=ref,
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            notes="Mode A: system prompt with no tools or memory.",
        )

    def profile_evidence(self) -> ProfileEvidence:
        # White-box: the system prompt is the spec — declares persona, tools,
        # and rules. Read it directly instead of interrogating the model.
        return ProfileEvidence(box="white", text=self._prompt)

    def instrument_paid_llm(
        self,
        *,
        ledger: BudgetLedger | None,
        on_exhausted: Callable[[BudgetExhausted], None] | None = None,
    ) -> UsageCounter:
        """Attach scan-scoped admission and usage accounting to the target."""
        instrumented = self._llm
        if ledger is not None:
            instrumented = with_budget_admission(
                instrumented,
                ledger=ledger,
                agent_id="target",
                on_exhausted=on_exhausted,
            )
        if isinstance(instrumented, UsageTrackingLLM):
            counter = instrumented.counter
        else:
            counter = UsageCounter()
            instrumented = UsageTrackingLLM(instrumented, counter=counter)
        self._llm = instrumented
        return counter

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        key = session or "_default"
        msgs = self._sessions.get(key)
        if msgs is None:
            msgs = [LLMMessage(role="system", content=self._prompt)]
            self._sessions[key] = msgs
        msgs.append(LLMMessage(role="user", content=prompt))
        req = LLMRequest(
            messages=list(msgs),
            model=self._model,
            max_tokens=1024,
            temperature=0.7,
        )
        resp = await self._llm.complete(req)
        msgs.append(LLMMessage(role="assistant", content=resp.text))
        return resp.text

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._owned_llm.aclose()
