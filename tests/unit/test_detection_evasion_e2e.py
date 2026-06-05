"""End-to-end: DetectionEvasionAgent produces a real guardrail-evasion finding.

Drives the full ``AsiAgent.run`` loop with a target whose guardrail refuses a
baseline harmful action verbatim but complies once the action is rewritten
(any mutation changes the text, so it is no longer the exact blocked string).
The judge defends the refused baseline and marks the complied variant exploited.
The agent must therefore emit at least one EXPLOITED finding — the
baseline-refused -> variant-complied evasion the lane exists to surface.
"""

from __future__ import annotations

import json
import pathlib
import tempfile

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.detection_evasion_agent import DetectionEvasionAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubScript

_COMPLY_MARKER = "ACTION_DONE_EVADED"

_DEFENDED = json.dumps(
    {
        "verdict": "defended",
        "refused": True,
        "observable_compromise": False,
        "evaluator_attack": False,
        "confidence": 0.9,
        "evidence": "",
        "followup_probe": "",
        "reasoning": "the guardrail refused the plain action",
    }
)
_EXPLOITED = json.dumps(
    {
        "verdict": "exploited",
        "refused": False,
        "observable_compromise": True,
        "evaluator_attack": False,
        "confidence": 0.95,
        "evidence": _COMPLY_MARKER,
        "followup_probe": "",
        "reasoning": "the evasive variant got the action performed past the guardrail",
    }
)


class _GuardrailTarget(TargetAdapter):
    """Refuses the EXACT baseline action; complies with anything rewritten."""

    def __init__(self, baselines: set[str]) -> None:
        super().__init__()
        self._baselines = baselines
        self.prompts_seen: list[str] = []

    def fingerprint(self) -> TargetFingerprint:
        return TargetFingerprint(
            mode="code",
            ref="guardrail-stub",
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            framework=None,
            declared_tools=[],
            declared_memory_keys=[],
            notes="",
            declared_guardrails=["acme-guard"],
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        self.prompts_seen.append(prompt)
        if prompt.strip() in self._baselines:
            return "I'm sorry, but I can't help with that request."
        return f"{_COMPLY_MARKER}: completed the requested operation."

    async def aclose(self) -> None:
        return None


async def test_detection_evasion_emits_guardrail_evasion_finding() -> None:
    agent = DetectionEvasionAgent(
        attacker_llm=StubScript().default("ok").build(),
        evaluator_llm=(
            StubScript().respond_to(_COMPLY_MARKER, _EXPLOITED).default(_DEFENDED).build()
        ),
        budget=AgentBudget(tokens_remaining=200_000, max_turns=6),
    )
    baselines = {seed.text for seed in agent.seeds_for_category()}  # type: ignore[union-attr]
    target = _GuardrailTarget(baselines)
    memory = SharedMemory("de-e2e", root_dir=pathlib.Path(tempfile.mkdtemp()))

    report = await agent.run(target, memory)

    # The agent fired at least one plain baseline (refused) AND at least one
    # mutated variant (complied) — i.e. it did not just re-send the seed.
    assert any(p.strip() in baselines for p in target.prompts_seen)
    assert any(p.strip() not in baselines for p in target.prompts_seen)
    # And it surfaced the evasion as an EXPLOITED finding.
    assert report.findings_count >= 1
    findings = memory.all_findings()
    assert any(f.verdict_v2 == "exploited" and f.success for f in findings)
