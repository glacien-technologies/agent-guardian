"""Recon-loop re-entry hook (Phase C, C5).

The :class:`ReconReentryHook` watches the agent reflection stream for evidence
that the target has revealed tool handles the original :class:`ReconAgent`
fingerprint did not declare. When such a diff appears it kicks off a single
non-blocking recon refresh pass that updates the swarm-shared fingerprint.

WHY this exists
---------------
The one-shot recon pass at the start of a scan can only see the surface the
target chose to reveal in the audit's ~10 deepening rounds. Tool-aware HTTP
adapters (OpenAI, Anthropic, Vertex, …) frequently surface *new* tool names
mid-scan — a downstream ``tool_calls`` block that the audit never elicited.
Those tools open ASI02 / ASI03 / ASI05 attack surface that the swarm would
otherwise leave untouched.

The hook is intentionally cheap:

* Fires AT MOST ONCE per scan (idempotent — re-tasking the recon loop more
  often than that would double-count attacker-LLM spend and risks racing
  the parallel ASI agents on shared fingerprint state).
* Runs as a background task; the agent that produced the diff is NEVER
  blocked waiting for the refresh.
* Caps its own LLM call at a single non-blocking probe (5-second budget at
  the per-call level — explicit operator opt-in via the ``call_budget_seconds``
  knob; the default is uncapped per project policy on hidden caps).

Invariants
----------
* The hook does not mutate ``TargetFingerprint`` directly — it goes through
  :meth:`SharedMemory.set_target_fingerprint` so persistence + observers stay
  consistent with the Phase 1 ``ReconAgent`` write.
* ``fired`` is monotonic: once True it never flips back.
* A reflection payload missing ``strategy_metadata.declared_tools`` is a
  no-op (NOT an error). Only tool-aware adapters populate that field; the
  hook MUST gracefully degrade against legacy / black-box adapters.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.core.memory import SharedMemory

__all__ = ["ReconReentryHook", "extract_declared_tools"]

_LOG = logging.getLogger(__name__)


def _normalize_tool_names(names: Iterable[Any]) -> list[str]:
    """Strip / dedup / case-fold tool name strings.

    The case-fold key keeps the canonical (input-cased) string for display
    but uses a lower-case key for deduplication, mirroring the convention
    in :mod:`agent_guardian.agents.recon`.
    """
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in names:
        if not isinstance(raw, str):
            continue
        n = raw.strip().strip("`'\".,").strip()
        if not n or len(n) > 200:
            continue
        key = n.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(n)
    return cleaned


def extract_declared_tools(payload: Mapping[str, Any]) -> list[str]:
    """Pull tool-name strings out of a turn-reflection record.

    Looks first at the canonical ``strategy_metadata.declared_tools`` key —
    populated by tool-aware adapters / strategies that surface a structured
    ``tool_calls`` block on the response. Falls back to ``tool_calls`` at
    payload-root (Recon's reflection shape).

    Returns the de-duplicated, normalized list. Empty list when the payload
    has nothing recognisable — callers treat that as "no diff".
    """
    candidates: list[Any] = []
    strat = payload.get("strategy_metadata")
    if isinstance(strat, Mapping):
        declared = strat.get("declared_tools")
        if isinstance(declared, list):
            candidates.extend(declared)
    # Recon's reflection shape — list of {name, arguments} dicts.
    tool_calls = payload.get("tool_calls")
    if isinstance(tool_calls, list):
        for entry in tool_calls:
            if isinstance(entry, Mapping):
                name = entry.get("name")
                if isinstance(name, str):
                    candidates.append(name)
            elif isinstance(entry, str):
                candidates.append(entry)
    return _normalize_tool_names(candidates)


class ReconReentryHook:
    """Watch for tool-name diffs against the recon fingerprint and refresh.

    Construction is cheap; the hook is reusable across the lifetime of a
    single :class:`SwarmCommander`. The hook publishes only one method an
    observer cares about — :meth:`on_reflection` — plus a lazily-attached
    :meth:`bind` that wires the memory + fingerprint baseline once Phase 1
    has run.

    The refresh callable signature is ``(new_tools: list[str]) ->
    Awaitable[TargetFingerprint | None]``. The hook awaits the callable
    inside its own background task; raising / returning ``None`` is fine
    (the hook just gives up — fingerprint stays unchanged).
    """

    def __init__(
        self,
        *,
        refresh_fn: Callable[[list[str]], Awaitable[TargetFingerprint | None]],
        call_budget_seconds: float | None = None,
    ) -> None:
        self._refresh_fn = refresh_fn
        self._call_budget_seconds = call_budget_seconds
        self._memory: SharedMemory | None = None
        self._baseline_tools: frozenset[str] = frozenset()
        self._fired: bool = False
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[Any] | None = None

    @property
    def fired(self) -> bool:
        """Whether the reentry has already triggered for this scan."""
        return self._fired

    @property
    def baseline_tools(self) -> frozenset[str]:
        """Tool-name baseline established at :meth:`bind` time (lower-cased)."""
        return self._baseline_tools

    def bind(self, memory: SharedMemory, fingerprint: TargetFingerprint) -> None:
        """Record the post-recon baseline and the memory handle.

        Must be called exactly once, after Phase 1 (recon) has written the
        refined fingerprint. Calling :meth:`on_reflection` before ``bind``
        is a programmer error — log + ignore (do NOT crash mid-scan).
        """
        self._memory = memory
        self._baseline_tools = frozenset(
            n.lower() for n in _normalize_tool_names(fingerprint.declared_tools)
        )
        self._fired = False
        _LOG.debug(
            "PhaseC.C5 recon_reentry.bind: baseline_tools=%s",
            sorted(self._baseline_tools),
        )

    def on_reflection(self, payload: Mapping[str, Any]) -> None:
        """Reflection-sink entry point. Inspect payload, schedule refresh.

        Best-effort: every failure mode is swallowed so a misbehaving
        observer cannot kill the scan.
        """
        if self._memory is None:
            _LOG.debug("PhaseC.C5 recon_reentry.on_reflection: hook not bound — ignoring")
            return
        if self._fired:
            return
        try:
            observed = extract_declared_tools(payload)
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.debug(
                "PhaseC.C5 recon_reentry.on_reflection: extract failed (%s) — skip",
                exc,
            )
            return
        new_tools = [n for n in observed if n.lower() not in self._baseline_tools]
        if not new_tools:
            return
        # Schedule the refresh as a background task on the running loop. We
        # use ``ensure_future`` so the hook works whether ``on_reflection``
        # was invoked from a coroutine or a synchronous observer thread that
        # happens to share the loop (the swarm reflection sink is sync).
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            _LOG.debug("PhaseC.C5 recon_reentry.on_reflection: no running loop — skip")
            return
        trigger = payload.get("agent") or "<unknown>"
        _LOG.info(
            "PhaseC.C5 recon_reentry: trigger=%s new_tools=%s",
            trigger,
            new_tools,
        )
        self._fired = True  # idempotency BEFORE scheduling
        self._task = loop.create_task(self._run_refresh(new_tools))

    async def _run_refresh(self, new_tools: list[str]) -> None:
        async with self._lock:
            try:
                if self._call_budget_seconds is not None:
                    refined = await asyncio.wait_for(
                        self._refresh_fn(new_tools),
                        timeout=self._call_budget_seconds,
                    )
                else:
                    refined = await self._refresh_fn(new_tools)
            except asyncio.TimeoutError:
                _LOG.warning(
                    "PhaseC.C5 recon_reentry: refresh timed out after %.1fs — "
                    "fingerprint unchanged",
                    self._call_budget_seconds or 0.0,
                )
                return
            except Exception as exc:  # pragma: no cover -- defensive
                _LOG.warning(
                    "PhaseC.C5 recon_reentry: refresh raised %s: %s — fingerprint unchanged",
                    type(exc).__name__,
                    exc,
                )
                return
            if refined is None:
                _LOG.debug("PhaseC.C5 recon_reentry: refresh returned None — fingerprint unchanged")
                return
            memory = self._memory
            if memory is None:  # pragma: no cover -- defensive, bind sets it
                return
            try:
                await memory.set_target_fingerprint(refined)
            except Exception as exc:  # pragma: no cover -- defensive
                _LOG.warning(
                    "PhaseC.C5 recon_reentry: set_target_fingerprint raised "
                    "%s: %s — fingerprint not persisted",
                    type(exc).__name__,
                    exc,
                )
                return
            # Update baseline so a third tool-name reveal (in a future
            # operator-driven multi-fire mode) would diff against the
            # refreshed set. Today the hook is one-shot so this is mainly
            # for forensic clarity.
            self._baseline_tools = frozenset(
                n.lower() for n in _normalize_tool_names(refined.declared_tools)
            )
            _LOG.debug(
                "PhaseC.C5 recon_reentry: refresh complete declared_tools=%s",
                refined.declared_tools,
            )

    async def wait_for_pending_refresh(self) -> None:
        """Await any in-flight refresh task.

        Used by the swarm at scan teardown so the refresh's persistence
        write completes before the finalise phase reads the fingerprint.
        """
        task = self._task
        if task is None or task.done():
            return
        try:
            await task
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.debug(
                "PhaseC.C5 recon_reentry.wait_for_pending_refresh: task raised %s",
                exc,
            )
