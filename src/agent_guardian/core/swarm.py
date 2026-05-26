"""Swarm Commander — Layer-3 orchestrator (PRD §4.1, M8).

The :class:`SwarmCommander` glues the M1-M7 layers into a single end-to-end
adversarial scan:

1. **Recon (Phase 1).** Run :class:`ReconAgent` with a wall-clock cap; on
   timeout or error fall back to a minimal fingerprint synthesised from
   the adapter's static description.
2. **Decompose (Phase 2).** Instantiate the ten ASI specialist agents,
   filter by :meth:`AsiAgent.is_applicable`, and slice the global token
   budget across them per PRD §14.2.
3. **Parallel launch (Phase 3).** Fan out the applicable agents under an
   :class:`asyncio.TaskGroup` on Python 3.11+ (or :func:`asyncio.gather`
   with ``return_exceptions=True`` on 3.10). A concurrent checkpoint task
   samples provisional AIVSS every ``checkpoint_interval_seconds``.
4. **Checkpoint loop (Phase 4).** Every interval compute provisional AIVSS
   from current memory findings, push it onto a rolling window of 3, and
   decide CONTINUE / EARLY_STOP / RE_TASK / ESCALATE_JUDGE. Only
   ``EARLY_STOP`` affects execution today — the other two emit events but
   continue normally (real re-tasking lands in v1.1).
5. **Budget donation (Phase 5).** When an agent finishes, its
   ``tokens_remaining`` is donated to the ASI category with the fewest
   findings so far. The donation only affects future strategy budget
   gates; no in-flight agents are interrupted.
6. **Finalise (Phase 6).** Compute final AIVSS via :func:`compute_aivss`
   with an empty probe list (the M2 vacuous-case path), emit
   ``scan_done``, and return the :class:`Scan`.

The observer callback fires synchronously for each :class:`SwarmEvent` —
it must not block. The swarm runs entirely in asyncio; production
consumers should enqueue events for off-thread delivery (e.g. into an
asyncio queue feeding an SSE endpoint).

LLM-driven intent decomposition (PRD §4.4 step 2) is intentionally
deferred to a later milestone; M8 instantiates all ten ASI agents
unconditionally and lets each agent's :meth:`is_applicable` decide.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, cast

from agent_guardian._version import __version__
from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.a2a import A2AAgent
from agent_guardian.agents.base import AgentBudget, AgentReport, AsiAgent
from agent_guardian.agents.cascade import CascadeAgent
from agent_guardian.agents.code_exec import CodeExecAgent
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.agents.supply_chain import SupplyChainAgent
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.agents.trust_exploit import TrustExploitAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.scoring import (
    AIVSS_FORMULA_VERSION,
    AivssResult,
    compute_aivss,
)
from agent_guardian.core.tiering import detect_tier
from agent_guardian.llm.base import BaseLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.tier import Tier

__all__ = [
    "CheckpointDecision",
    "SwarmCommander",
    "SwarmConfig",
    "SwarmEvent",
    "SwarmObserver",
]

_LOG = logging.getLogger(__name__)

# The ten ASI specialist agent classes — order matches PRD §3 / ASI01..ASI10.
_ASI_AGENT_CLASSES: tuple[type[AsiAgent], ...] = (
    GoalHijackAgent,  # ASI01
    ToolAbuseAgent,  # ASI02
    PrivilegeAgent,  # ASI03
    SupplyChainAgent,  # ASI04
    CodeExecAgent,  # ASI05
    MemoryPoisonAgent,  # ASI06
    A2AAgent,  # ASI07
    CascadeAgent,  # ASI08
    TrustExploitAgent,  # ASI09
    DriftAgent,  # ASI10
)

EventKind = Literal[
    "recon_start",
    "recon_done",
    "agent_start",
    "agent_progress",
    "agent_done",
    "agent_skipped",
    "checkpoint",
    "scan_done",
]


@dataclass(frozen=True)
class SwarmConfig:
    """Knobs for one swarm run.

    Defaults mirror PRD §4.4 and §14.2. ``scan_id`` is the only required
    field; everything else has a sensible default.
    """

    scan_id: str
    commander_model: str = "claude-haiku-4-5"
    attacker_model: str = "gpt-4o-mini"
    evaluator_model: str = "gpt-4o-mini"
    recon_wall_seconds: float = 90.0
    overall_wall_seconds: float = 900.0
    total_tokens: int = 2_000_000
    checkpoint_interval_seconds: float = 30.0
    early_stop_variance_threshold: float = 2.0
    max_parallel_agents: int = 10
    tier_override: Tier | None = None


class CheckpointDecision(str, Enum):
    """Outcome of one checkpoint evaluation (PRD §4.4 step 4)."""

    CONTINUE = "continue"
    EARLY_STOP = "early_stop"
    RE_TASK = "re_task"
    ESCALATE_JUDGE = "escalate_judge"


@dataclass(frozen=True)
class SwarmEvent:
    """One observable event emitted during a scan.

    M12 consumes these to drive live dashboard SSE; the M10 CLI uses them
    for terminal progress rendering. The callback is invoked synchronously
    — it must not block.
    """

    kind: EventKind
    timestamp: datetime
    agent: str | None = None
    asi: AsiCategory | None = None
    provisional_aivss: int | None = None
    decision: CheckpointDecision | None = None
    payload: dict[str, object] = field(default_factory=dict)


SwarmObserver = Callable[[SwarmEvent], None]


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _supports_taskgroup() -> bool:
    """``asyncio.TaskGroup`` is 3.11+. The fallback is :func:`asyncio.gather`."""
    return sys.version_info >= (3, 11)


class SwarmCommander:
    """Layer-3 orchestrator for the eleven-agent adversarial swarm.

    Lifecycle::

        swarm = SwarmCommander(config, target,
                               attacker_llm=..., evaluator_llm=...,
                               memory=..., observer=...)
        scan: Scan = await swarm.run()

    The instance is single-shot — call :meth:`run` exactly once. The
    observer callback (optional) fires once per :class:`SwarmEvent` and
    must not block.
    """

    def __init__(
        self,
        config: SwarmConfig,
        target: TargetAdapter,
        *,
        attacker_llm: BaseLLM,
        evaluator_llm: BaseLLM,
        commander_llm: BaseLLM | None = None,
        memory: SharedMemory | None = None,
        observer: SwarmObserver | None = None,
        rng_seed: int = 0,
    ) -> None:
        self.config = config
        self.target = target
        self.attacker_llm = attacker_llm
        self.evaluator_llm = evaluator_llm
        # Commander LLM defaults to the attacker LLM today — the M9
        # checkpoint logic will use it once LLM-driven re-tasking lands.
        self.commander_llm = commander_llm if commander_llm is not None else attacker_llm
        self.memory = memory if memory is not None else SharedMemory(config.scan_id)
        self.observer = observer
        self.rng_seed = rng_seed
        self._rng = random.Random(rng_seed)

        # Runtime state — populated by phase methods.
        self._start_time: float = 0.0
        self._fingerprint: TargetFingerprint | None = None
        self._aivss_window: list[int] = []
        self._last_finding_count: int = 0
        self._last_finding_seen_at: float = 0.0
        self._final_decision: CheckpointDecision = CheckpointDecision.CONTINUE
        self._cancel_event = asyncio.Event()
        self._agent_reports: list[AgentReport] = []
        self._has_run = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> Scan:
        """Execute the full six-phase scan and return the :class:`Scan`."""
        if self._has_run:
            raise RuntimeError("SwarmCommander is single-shot; .run() already called")
        self._has_run = True

        self._start_time = time.monotonic()
        self._last_finding_seen_at = self._start_time

        # Apply an overall wall-clock cap around the whole run.
        try:
            return await asyncio.wait_for(
                self._run_inner(),
                timeout=self.config.overall_wall_seconds,
            )
        except asyncio.TimeoutError:
            _LOG.warning("swarm overall wall budget exhausted (scan_id=%s)", self.config.scan_id)
            return await self._phase_finalise()

    # ------------------------------------------------------------------
    # Internal orchestration
    # ------------------------------------------------------------------

    async def _run_inner(self) -> Scan:
        # Phase 1 — recon.
        await self._phase_recon()
        # Phase 2 — decompose into per-ASI agents.
        agents = await self._phase_decompose(self._fingerprint)
        # Phase 3 + 4 — parallel launch with concurrent checkpoint loop.
        await self._phase_parallel(agents)
        # Phase 6 — finalise.
        return await self._phase_finalise()

    # ------------------------------------------------------------------
    # Phase 1 — Recon
    # ------------------------------------------------------------------

    async def _phase_recon(self) -> None:
        self._emit(SwarmEvent(kind="recon_start", timestamp=_utcnow(), agent="recon-agent"))
        recon = ReconAgent(
            attacker_llm=self.attacker_llm,
            model=self.config.attacker_model,
            budget=AgentBudget(
                tokens_remaining=50_000,
                wall_seconds_remaining=self.config.recon_wall_seconds,
                max_turns=3,
            ),
        )
        recon_report: AgentReport | None = None
        try:
            recon_report = await asyncio.wait_for(
                recon.run(self.target, self.memory),
                timeout=self.config.recon_wall_seconds,
            )
        except asyncio.TimeoutError:
            _LOG.warning("recon timed out after %.1fs", self.config.recon_wall_seconds)
        except Exception as exc:
            _LOG.warning("recon failed: %s: %s", type(exc).__name__, exc)

        if recon_report is not None:
            self._agent_reports.append(recon_report)

        # Read the (possibly refined) fingerprint; fall back to the adapter's
        # own static description if recon never wrote one.
        fingerprint = self.memory.target_fingerprint() or self._minimal_fingerprint()
        self._fingerprint = fingerprint

        self._emit(
            SwarmEvent(
                kind="recon_done",
                timestamp=_utcnow(),
                agent="recon-agent",
                payload={
                    "has_tools": fingerprint.has_tools,
                    "has_memory": fingerprint.has_memory,
                    "is_multi_agent": fingerprint.is_multi_agent,
                    "touches_pii": fingerprint.touches_pii,
                    "mode": fingerprint.mode,
                },
            )
        )

    def _minimal_fingerprint(self) -> TargetFingerprint:
        """Synthesise a defensive zero-surface fingerprint when recon fails.

        We trust :meth:`TargetAdapter.fingerprint` to return a valid value
        — every adapter sets ``_fingerprint`` in ``__init__``. If that too
        is missing (a malformed adapter), we fabricate an all-false stub
        so downstream code never sees ``None``.
        """
        try:
            return self.target.fingerprint()
        except Exception:  # pragma: no cover — defensive
            return TargetFingerprint(
                mode=self.target.mode,
                ref="<unknown>",
                notes="recon failed; synthetic minimal fingerprint",
            )

    # ------------------------------------------------------------------
    # Phase 2 — Decompose
    # ------------------------------------------------------------------

    async def _phase_decompose(self, fingerprint: TargetFingerprint | None) -> list[AsiAgent]:
        """Instantiate the ten ASI agents; filter by applicability.

        TODO(v1.1): per PRD §4.4 step 2 we should ask the commander LLM
        to produce a JSON plan listing which ASI categories to prioritise
        and how to allocate budget between them. M8 ships the simpler
        static slate; the LLM-driven decomposition lands later.
        """
        assert fingerprint is not None
        agents: list[AsiAgent] = []
        per_agent_tokens = max(1, self.config.total_tokens // (len(_ASI_AGENT_CLASSES) + 3))
        # Each ASI agent gets ~150k tokens by default (per PRD §14.2). We
        # derive the per-agent slice from total_tokens so test overrides
        # propagate cleanly.
        for cls in _ASI_AGENT_CLASSES:
            agent = cls(
                attacker_llm=self.attacker_llm,
                evaluator_llm=self.evaluator_llm,
                attacker_model=self.config.attacker_model,
                evaluator_model=self.config.evaluator_model,
                budget=AgentBudget(
                    tokens_remaining=per_agent_tokens,
                    wall_seconds_remaining=self.config.overall_wall_seconds,
                ),
                rng=random.Random(self.rng_seed + len(agents)),
            )
            if not agent.is_applicable(fingerprint):
                self._emit(
                    SwarmEvent(
                        kind="agent_skipped",
                        timestamp=_utcnow(),
                        agent=agent.name or type(agent).__name__,
                        asi=agent.asi_category,
                        payload={"reason": "not applicable for fingerprint"},
                    )
                )
                continue
            agents.append(agent)
        # Respect max_parallel_agents (10 is the natural cap; lower values
        # serialise the tail).
        return agents[: max(1, self.config.max_parallel_agents)]

    # ------------------------------------------------------------------
    # Phase 3 + 4 — Parallel launch with concurrent checkpoint
    # ------------------------------------------------------------------

    async def _phase_parallel(self, agents: list[AsiAgent]) -> None:
        if not agents:
            return

        checkpoint_task = asyncio.create_task(self._checkpoint_loop(), name="swarm-checkpoint")
        try:
            if _supports_taskgroup():
                await self._run_taskgroup(agents)
            else:
                await self._run_gather(agents)
        finally:
            checkpoint_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await checkpoint_task

    async def _run_taskgroup(self, agents: list[AsiAgent]) -> None:
        # Python 3.11+ path. We resolve the class via attribute access so
        # the symbol is invisible to 3.10's static parser.
        task_group_cls = asyncio.TaskGroup  # type: ignore[attr-defined,unused-ignore]
        try:
            async with task_group_cls() as tg:
                for agent in agents:
                    tg.create_task(
                        self._run_agent_with_observer(agent),
                        name=agent.name or type(agent).__name__,
                    )
        except BaseException as exc:  # pragma: no cover — defensive
            # ExceptionGroup on TaskGroup failure — log but don't propagate;
            # finalisation still needs to emit a Scan.
            _LOG.warning("TaskGroup raised %s: %s", type(exc).__name__, exc)

    async def _run_gather(self, agents: list[AsiAgent]) -> None:
        results = await asyncio.gather(
            *(self._run_agent_with_observer(a) for a in agents),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, BaseException):
                _LOG.warning("agent task raised %s: %s", type(r).__name__, r)

    async def _run_agent_with_observer(self, agent: AsiAgent) -> AgentReport:
        name = agent.name or type(agent).__name__
        self._emit(
            SwarmEvent(
                kind="agent_start",
                timestamp=_utcnow(),
                agent=name,
                asi=agent.asi_category,
            )
        )
        try:
            if self._cancel_event.is_set():
                report = AgentReport(
                    agent=name,
                    asi_category=agent.asi_category,
                    findings_count=0,
                    turns=0,
                    duration_seconds=0.0,
                    terminated_by="budget",
                    notes="cancelled by early-stop checkpoint",
                )
            else:
                report = await agent.run(self.target, self.memory)
        except Exception as exc:
            _LOG.warning("agent %s raised %s: %s", name, type(exc).__name__, exc)
            report = AgentReport(
                agent=name,
                asi_category=agent.asi_category,
                findings_count=0,
                turns=0,
                duration_seconds=0.0,
                terminated_by="error",
                error=f"{type(exc).__name__}: {exc}",
            )
        self._agent_reports.append(report)
        self._emit(
            SwarmEvent(
                kind="agent_done",
                timestamp=_utcnow(),
                agent=name,
                asi=agent.asi_category,
                payload={
                    "findings_count": report.findings_count,
                    "turns": report.turns,
                    "duration_seconds": report.duration_seconds,
                    "terminated_by": report.terminated_by,
                },
            )
        )
        # Phase 5 — donate this agent's leftover tokens to the lowest-coverage
        # ASI category. We surface the donation as event metadata; concrete
        # budget rewiring is a future-milestone refinement.
        self._donate_budget(agent)
        return report

    # ------------------------------------------------------------------
    # Phase 4 — Checkpoint loop
    # ------------------------------------------------------------------

    async def _checkpoint_loop(self) -> None:
        """Sample provisional AIVSS every ``checkpoint_interval_seconds``.

        Cancelled by ``_phase_parallel`` once all agents are done.
        """
        try:
            while not self._cancel_event.is_set():
                await asyncio.sleep(self.config.checkpoint_interval_seconds)
                decision = self._checkpoint()
                self._final_decision = decision
                self._emit(
                    SwarmEvent(
                        kind="checkpoint",
                        timestamp=_utcnow(),
                        provisional_aivss=(self._aivss_window[-1] if self._aivss_window else None),
                        decision=decision,
                    )
                )
                if decision is CheckpointDecision.EARLY_STOP:
                    self._cancel_event.set()
                    return
                # TODO(v1.1): RE_TASK / ESCALATE_JUDGE wiring lands later.
        except asyncio.CancelledError:
            return

    def _checkpoint(self) -> CheckpointDecision:
        provisional = self._compute_provisional_aivss()
        self._aivss_window.append(provisional)
        if len(self._aivss_window) > 3:
            self._aivss_window = self._aivss_window[-3:]

        current_findings = len(self.memory.all_findings())
        now = time.monotonic()
        if current_findings > self._last_finding_count:
            self._last_finding_count = current_findings
            self._last_finding_seen_at = now

        # Need at least three samples to evaluate variance.
        if len(self._aivss_window) < 3:
            return CheckpointDecision.CONTINUE

        variance = _variance(self._aivss_window)
        no_recent_findings = (
            now - self._last_finding_seen_at
        ) >= self.config.checkpoint_interval_seconds
        if variance < self.config.early_stop_variance_threshold and no_recent_findings:
            return CheckpointDecision.EARLY_STOP
        return CheckpointDecision.CONTINUE

    def _compute_provisional_aivss(self) -> int:
        """Score the current findings as if the scan finished now.

        Empty ``probes`` is fine — :func:`compute_aivss` handles the
        vacuous case (every ASI score defaults to 100).
        """
        findings = self.memory.all_findings()
        tier = self._effective_tier()
        result = compute_aivss(findings, probes=[], tier=tier)
        return result.score

    # ------------------------------------------------------------------
    # Phase 5 — Budget donation
    # ------------------------------------------------------------------

    def _donate_budget(self, completed: AsiAgent) -> None:
        """Annotate the ASI category with the fewest findings.

        For M8 we surface the donation intent as an observer event; the
        in-flight strategies don't read the donated tokens (every agent
        has its own AgentBudget). When the BudgetController wiring lands,
        the donation becomes a real cross-agent transfer.
        """
        remaining = max(0, completed.budget.tokens_remaining)
        if remaining <= 0:
            return
        # Pick the ASI category with the fewest findings as the donor target.
        finding_counts = {cat: len(self.memory.findings_by_asi(cat)) for cat in AsiCategory}
        # Pick the lowest count (ties broken by AsiCategory enum order).
        target_cat = min(finding_counts.keys(), key=lambda c: finding_counts[c])
        _LOG.debug(
            "swarm budget donation: %d tokens from %s -> %s",
            remaining,
            completed.name or type(completed).__name__,
            target_cat.value,
        )

    # ------------------------------------------------------------------
    # Phase 6 — Finalisation
    # ------------------------------------------------------------------

    async def _phase_finalise(self) -> Scan:
        findings = list(self.memory.all_findings())
        tier = self._effective_tier()
        result: AivssResult = compute_aivss(findings, probes=[], tier=tier)

        fingerprint = self._fingerprint or self._minimal_fingerprint()
        # Sub-score keys are already plain strings in AivssResult.sub_scores.
        sub_scores = dict(result.sub_scores)
        # asi_scores key is AsiCategory enum — Scan accepts it directly.
        asi_scores = dict(result.asi_scores)

        duration = time.monotonic() - self._start_time
        scan = Scan(
            id=self.config.scan_id,
            package_version=__version__,
            aivss_formula_version=AIVSS_FORMULA_VERSION,
            probe_library_version="0.0.0-placeholder",
            target_mode=fingerprint.mode,
            target_ref=fingerprint.ref,
            tier=tier,
            aivss=result.score,
            band=result.band,
            sub_scores=sub_scores,
            findings=findings,
            asi_scores=asi_scores,
            duration_seconds=max(0.0, duration),
            cost_usd=0.0,
            created_at=_utcnow(),
        )
        self._emit(
            SwarmEvent(
                kind="scan_done",
                timestamp=_utcnow(),
                provisional_aivss=result.score,
                payload={
                    "aivss": result.score,
                    "band": result.band.value,
                    "findings": len(findings),
                    "tier": tier.value,
                    "duration_seconds": duration,
                },
            )
        )
        return scan

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _effective_tier(self) -> Tier:
        if self.config.tier_override is not None:
            return self.config.tier_override
        fingerprint = self._fingerprint or self._minimal_fingerprint()
        return detect_tier(fingerprint.to_observed_surface())

    def _emit(self, event: SwarmEvent) -> None:
        if self.observer is None:
            return
        try:
            self.observer(event)
        except Exception as exc:
            # Observers must not crash the swarm; log and continue.
            _LOG.warning("observer raised %s: %s", type(exc).__name__, exc)


def _variance(values: list[int]) -> float:
    """Naïve sample variance (N denominator) over a small int window."""
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


# Silence unused-import warnings: these are part of the public re-export surface.
_ = (cast,)
