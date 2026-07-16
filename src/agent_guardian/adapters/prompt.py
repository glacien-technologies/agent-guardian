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
from agent_guardian.llm.budget_admission import BudgetAdmissionLLM, with_budget_admission
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM

__all__ = ["PromptAdapter"]


def _uninstrumented_transport(llm: BaseLLM) -> BaseLLM:
    """Peel only AgentGuardian's non-owning instrumentation decorators."""
    transport = llm
    while isinstance(transport, (UsageTrackingLLM, BudgetAdmissionLLM)):
        transport = transport._inner
    return transport


def _resolved_pricing_model_spec(llm: BaseLLM, model: str) -> str:
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="")],
        model=model,
        max_tokens=1,
    )
    delegate = getattr(llm, "pricing_model_spec", None)
    return delegate(request) if callable(delegate) else request.model


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
        # Built-in accounting decorators are non-owning scan state. Retain a
        # stable transport beneath them so every scan can build a fresh wrapper
        # chain and the adapter can close the actual provider it owns.
        self._transport_llm = _uninstrumented_transport(llm)
        self._owned_llm = self._transport_llm
        self._llm = self._transport_llm
        self._closed = False
        self._model = model
        self._pricing_model_spec = _resolved_pricing_model_spec(self._transport_llm, model)
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

    @property
    def pricing_model_spec(self) -> str:
        """Resolved provider/model/location identity used for target pricing."""
        return self._pricing_model_spec

    @property
    def owned_llm_ids(self) -> frozenset[int]:
        """Object identities the adapter closes during :meth:`aclose`."""
        return frozenset((id(self._owned_llm),))

    def instrument_paid_llm(
        self,
        *,
        ledger: BudgetLedger | None,
        on_exhausted: Callable[[BudgetExhausted], None] | None = None,
    ) -> UsageCounter:
        """Attach scan-scoped admission and usage accounting to the target."""
        counter = UsageCounter()
        instrumented = self._transport_llm
        if ledger is not None:
            instrumented = with_budget_admission(
                instrumented,
                ledger=ledger,
                agent_id="target",
                on_exhausted=on_exhausted,
            )
        self._llm = UsageTrackingLLM(instrumented, counter=counter)
        self._sessions.clear()
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
