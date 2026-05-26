"""Strategy base types (PRD §3.1, M6).

A :class:`Strategy` is a per-attack-thread state machine that emits prompts
for the swarm to send to the target. The caller drives the loop:

.. code-block:: python

    strategy = MyStrategy(ctx)
    history: list[Turn] = []
    response: str | None = None
    while True:
        result = await strategy.generate_next(history, response)
        if isinstance(result, StrategyDone):
            break
        prompt = result.text
        response = await target.call(prompt)
        history.append(Turn(prompt=prompt, response=response))

Every concrete strategy must be **stateful within one attack thread**,
**deterministic given a seeded RNG**, and **pure** with respect to the
outside world — no clocks, env, sockets. LLM access goes through the
injected :class:`agent_guardian.llm.base.BaseLLM` (the *attacker* LLM,
distinct from the target).

The M7 agent layer wires Strategies into the swarm. M6 ships the four
references: TAP, Crescendo, MAD-MAX, PAIR.
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.base import BaseLLM

__all__ = [
    "NextPrompt",
    "Strategy",
    "StrategyContext",
    "StrategyDone",
    "StrategyResult",
    "Turn",
]


@dataclass(frozen=True)
class Turn:
    """One round-trip in an attack conversation.

    ``metadata`` is strategy-specific (judge verdict, depth, escalation
    level, etc.) and exists for transcripts / receipts.
    """

    prompt: str
    response: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class NextPrompt:
    """The strategy wants to send another prompt to the target."""

    text: str
    rationale: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class StrategyDone:
    """The strategy has stopped emitting prompts.

    ``reason`` semantics:

    * ``"success"`` — strategy believes the goal has been achieved.
    * ``"exhausted"`` — turn / depth / critique budget consumed.
    * ``"refused"`` — target's refusals form a stable loop (e.g. all
      candidate refinements scored as off-topic, or escalation level
      collapsed to zero after consecutive refusals).
    * ``"budget"`` — the caller's :class:`BudgetController` signalled stop.
    """

    reason: Literal["success", "exhausted", "refused", "budget"]
    findings_count: int = 0


StrategyResult = NextPrompt | StrategyDone


@dataclass
class StrategyContext:
    """Per-attack context the strategy may consult.

    Attributes:
        attacker_llm: The LLM the strategy uses to generate / refine /
            critique prompts. Tests inject :class:`StubLLM`; production
            wires a real provider.
        attacker_model: Model name passed through on every
            :class:`LLMRequest`.
        goal: Natural-language attack objective.
        seeds: Static probe payloads to start the attack from.
        memory: Shared swarm memory (M5). Strategies read recent
            reflections / attempted seeds; the agent layer in M7 owns
            writes.
        rng: Seeded RNG for any randomised choice the strategy makes.
            **Must** be the only source of randomness — no
            ``random.choice`` on the module-level RNG.
        max_turns: Per-strategy hard cap. The default 10 matches PRD §3.1.
    """

    attacker_llm: BaseLLM
    attacker_model: str
    goal: str
    seeds: list[str]
    memory: SharedMemory
    rng: random.Random
    max_turns: int = 10


class Strategy(ABC):
    """Per-attack-thread state machine.

    A :class:`Strategy` instance is bound to ONE attack conversation. The
    caller drives the loop, appending turns to ``history`` and feeding
    the target's latest response back in. The strategy emits either a
    :class:`NextPrompt` to keep going, or :class:`StrategyDone` to stop.

    On the very first call ``target_response`` is ``None`` (no response
    has been collected yet) and ``history`` is empty.

    Idempotent given ``(history, target_response, rng-seed)``. No clock,
    no network beyond the injected attacker_llm.
    """

    name: str = ""

    def __init__(self, ctx: StrategyContext) -> None:
        self.ctx = ctx
        self._turn_count = 0

    @abstractmethod
    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        """Emit the next prompt or stop.

        Implementations MUST update :attr:`_turn_count` whenever they
        return a :class:`NextPrompt`. The base class does NOT auto-track
        this — strategies sometimes increment more than once per call
        (e.g. MAD-MAX delegating to a child).
        """

    def turn_count(self) -> int:
        """Number of NextPrompts emitted so far on this attack thread."""
        return self._turn_count
