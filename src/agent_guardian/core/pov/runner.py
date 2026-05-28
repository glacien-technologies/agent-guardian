"""PoV runner — N-fold replay + reliability scoring (M2 Pattern 2).

Re-runs a :class:`PoVScript` against the transport N times and scores
reliability as the Wilson-score lower bound of the success rate (so a 5/5 run
isn't naively reported as 1.0 — the lower bound is honest about small N). A
finding is only credible if reliability clears the gate (default 0.8).

The runner replays through a :class:`~agent_guardian.adapters.base.TargetAdapter`
with a fresh session per run so cross-run state never leaks. For code-execution
targets the adapter itself is expected to run under
:mod:`agent_guardian.core.sandbox` (egress allowlist + subprocess timeout); the
runner does not re-implement isolation.
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from dataclasses import dataclass, field

from agent_guardian.adapters.base import TargetAdapter
from agent_guardian.core.pov.harness import PoVScript, SemanticJudge

__all__ = ["PoVResult", "PoVRunner", "wilson_lower_bound"]

_LOG = logging.getLogger(__name__)

DEFAULT_RELIABILITY_GATE = 0.8


def wilson_lower_bound(successes: int, n: int, z: float = 1.96) -> float:
    """Wilson score interval lower bound for a binomial success rate.

    Honest about small samples: 5/5 → ~0.57, 50/50 → ~0.93. ``n == 0`` → 0.0.
    """
    if n <= 0:
        return 0.0
    phat = successes / n
    denom = 1.0 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt((phat * (1.0 - phat) + z * z / (4 * n)) / n)
    return max(0.0, (centre - margin) / denom)


@dataclass(frozen=True)
class PoVResult:
    """Outcome of an N-fold PoV replay."""

    scenario_id: str
    runs: int
    successes: int
    reliability: float
    """Observed success rate (successes / runs) — the gate is applied to this."""
    wilson_lower: float
    """Wilson-score lower bound — honest confidence given small N (annotation)."""
    passed: bool
    wall_time_s: float
    evidence: list[str] = field(default_factory=list)


class PoVRunner:
    """Sandboxed N-fold reproducer runner with reliability scoring."""

    def __init__(
        self,
        *,
        reliability_gate: float = DEFAULT_RELIABILITY_GATE,
        per_run_timeout_s: float = 60.0,
    ) -> None:
        self._gate = reliability_gate
        self._timeout = per_run_timeout_s

    async def run(
        self,
        script: PoVScript,
        target: TargetAdapter,
        *,
        n: int = 5,
        judge: SemanticJudge | None = None,
    ) -> PoVResult:
        if n < 1:
            raise ValueError("n must be >= 1")
        start = time.monotonic()
        successes = 0
        evidence: list[str] = []
        for i in range(n):
            session = f"pov-{script.scenario_id}-{i}-{uuid.uuid4().hex[:6]}"
            ok, last = await self._run_once(script, target, session, judge)
            if ok:
                successes += 1
                if len(evidence) < 3:  # keep a few exemplar transcripts
                    evidence.append(last[:500])
        reliability = successes / n
        result = PoVResult(
            scenario_id=script.scenario_id,
            runs=n,
            successes=successes,
            reliability=reliability,
            wilson_lower=wilson_lower_bound(successes, n),
            passed=reliability >= self._gate,
            wall_time_s=time.monotonic() - start,
            evidence=evidence,
        )
        _LOG.info(
            "pov %s: %d/%d succeeded, reliability=%.3f wilson_lower=%.3f (gate=%.2f) -> %s",
            script.scenario_id,
            successes,
            n,
            reliability,
            result.wilson_lower,
            self._gate,
            "PASS" if result.passed else "DROP",
        )
        return result

    async def _run_once(
        self,
        script: PoVScript,
        target: TargetAdapter,
        session: str,
        judge: SemanticJudge | None,
    ) -> tuple[bool, str]:
        """One replay: send setup then trigger; check the indicator on the
        concatenated trigger responses. Returns (matched, last_response)."""
        for msg in script.setup:
            await target.call(msg, session=session)
        trigger_responses: list[str] = []
        for msg in script.trigger:
            reply = await target.call(msg, session=session)
            trigger_responses.append(reply)
        observation = "\n".join(trigger_responses)
        matched = await script.indicator.matches(observation, judge=judge)
        return matched, observation
