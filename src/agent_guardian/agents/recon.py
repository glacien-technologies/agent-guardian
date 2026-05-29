"""ReconAgent — phase-1 attack-surface + intent mapper (PRD §3, M7; redesign).

ReconAgent is the swarm's first move. It produces a structured profile (intent
+ surface) on shared memory so downstream agents attack what the target is for
and the report scores honestly. It reads the richest evidence available:

* **White-box** (system prompt / in-process source / framework introspection):
  one schema-constrained LLM extraction via
  :func:`~agent_guardian.core.profiler.profile_from_material`.
* **Black-box** (HTTP endpoint): an adaptive capability audit
  (:func:`~agent_guardian.core.capability_audit.run_capability_audit`) that makes
  the target take observable actions + a cross-session planted-token memory test,
  then structures the transcript via
  :func:`~agent_guardian.core.profiler.profile_from_audit`. Heuristic keyword
  flags remain a reliable boolean fallback.

Unlike the 10 ASI-aligned agents, ReconAgent does NOT subclass
:class:`~agent_guardian.agents.base.AsiAgent`: it has no ASI category, no attack
strategy, and writes no findings — only the refined fingerprint. Every audit
turn is persisted as a structured reflection for forensic replay.
"""

from __future__ import annotations

import json
import logging
import re
import time

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget, AgentReport
from agent_guardian.core.capability_audit import run_capability_audit
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.profiler import TargetProfile, profile_from_audit, profile_from_material
from agent_guardian.llm.base import BaseLLM, LLMMessage, LLMRequest
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM

__all__ = ["ReconAgent"]

_LOG = logging.getLogger(__name__)


_TOOL_HINTS = (
    "tool",
    "function",
    "api",
    "call ",
    "search",
    "browse",
    "execute",
    "interpreter",
    "file_read",
    "file_write",
)

_MEMORY_HINTS = (
    "remember",
    "recall",
    "memory",
    "earlier in our conversation",
    "previous message",
    "history",
    "context window",
)

# OWASP-2026 signal-hint dictionaries. Recon parses target responses for any
# of these keywords to flip the corresponding evidence-backed bool on
# TargetFingerprint (distinct from the heuristic has_tools/has_memory flags).
_EXTERNAL_SYSTEMS_HINTS = (
    "api",
    "external",
    "endpoint",
    "database",
    "knowledge base",
    "search",
    "fetch",
    "http",
)

_MULTI_AGENT_HINTS = (
    "delegate",
    "sub-agent",
    "subagent",
    "other agent",
    "orchestrate",
    "coordinator",
    "subordinate",
)

_CROSS_SESSION_DATA_HINTS = (
    "remember",
    "persist",
    "across sessions",
    "user profile",
    "history",
    "contacts",
    "calendar",
)


def _looks_like_tools(text: str) -> bool:
    lowered = text.lower()
    return any(h in lowered for h in _TOOL_HINTS)


def _looks_like_memory(text: str) -> bool:
    lowered = text.lower()
    return any(h in lowered for h in _MEMORY_HINTS)


def _looks_like_external_systems(text: str) -> bool:
    lowered = text.lower()
    return any(h in lowered for h in _EXTERNAL_SYSTEMS_HINTS)


def _looks_like_multi_agent(text: str) -> bool:
    lowered = text.lower()
    return any(h in lowered for h in _MULTI_AGENT_HINTS)


def _looks_like_cross_session_data(text: str) -> bool:
    lowered = text.lower()
    return any(h in lowered for h in _CROSS_SESSION_DATA_HINTS)


# Tool-name discovery (2026.06). The tool-inventory probe already asks the
# target to list its tools; pre-2026.06 the reply was only checked for a
# boolean hint match and the actual names were discarded, leaving
# ``declared_tools`` empty. That left the recon-adaptive attacker + the
# tool-exfil strategy inert on every target exposing a plain ``run(prompt)``
# entry point (the common LangGraph case). We now extract usable tool handles
# from the reply. A black-box attack does not need the exact function name —
# a natural-language handle ("knowledge base search tool") is enough for the
# attacker to craft a tool-invoking payload that the target maps back to its
# real tool.

_TOOL_EXTRACTION_SYSTEM = (
    "You extract tool / function / capability handles from an AI agent's "
    "self-description of what it can do. Return ONLY a compact JSON array of "
    'short strings (e.g. ["search_kb", "knowledge base search"]) naming tools '
    "the assistant EXPLICITLY said it has access to. Do not invent tools. If "
    "the assistant named none, return []. Output only the JSON array."
)

_TOOL_EXTRACTION_USER = (
    "The agent was asked what tools it has. It replied:\n\n{reply}\n\n"
    "Extract the tool/capability handles as a JSON array of short strings."
)

# snake_case / camelCase identifiers and backtick-quoted names, used as the
# deterministic fallback when the LLM extraction returns nothing parseable.
_IDENT_RE = re.compile(r"`([^`]{2,60})`|\b([a-z][a-z0-9]*(?:[_-][a-z0-9]+)+)\b")


def _parse_tool_list(text: str) -> list[str]:
    """Parse a JSON array of tool names from the LLM extraction reply.

    Tolerates markdown fences / preamble by grabbing the first ``[...]`` span.
    """
    stripped = text.strip()
    for candidate in (stripped, _first_bracket_span(stripped)):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, list):
            return [str(x) for x in parsed if isinstance(x, str | int | float)]
    return []


def _first_bracket_span(text: str) -> str | None:
    match = re.search(r"\[.*\]", text, re.DOTALL)
    return match.group(0) if match else None


def _regex_tool_names(reply: str) -> list[str]:
    """Deterministic fallback: pull backtick-quoted + snake/kebab identifiers."""
    names: list[str] = []
    for m in _IDENT_RE.finditer(reply):
        names.append(m.group(1) or m.group(2))
    return names


def _clean_tool_names(names: list[str]) -> list[str]:
    """Dedup, strip quoting/whitespace, drop empties + sentence-length noise."""
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in names:
        n = raw.strip().strip("`'\".,").strip()
        if n and 1 < len(n) <= 60 and n.lower() not in seen:
            seen.add(n.lower())
            cleaned.append(n)
    return cleaned[:12]


async def _extract_tool_names(reply: str, llm: BaseLLM, model: str) -> list[str]:
    """Extract usable tool handles from a free-text tool-inventory reply.

    LLM extraction first (the reply is usually prose, e.g. "I can search our
    knowledge base"); deterministic regex fallback if the LLM returns nothing
    parseable. Never raises — recon must not abort on an extraction hiccup.
    """
    names: list[str] = []
    try:
        resp = await llm.complete(
            LLMRequest(
                messages=[
                    LLMMessage(role="system", content=_TOOL_EXTRACTION_SYSTEM),
                    LLMMessage(
                        role="user",
                        content=_TOOL_EXTRACTION_USER.format(reply=reply[:2000]),
                    ),
                ],
                model=model,
                max_tokens=200,
                temperature=0.0,
            )
        )
        names = _parse_tool_list(resp.text)
    except Exception as exc:  # pragma: no cover — defensive; recon must not abort
        _LOG.debug("recon: LLM tool extraction failed (%s) — using regex fallback", exc)
    if not names:
        names = _regex_tool_names(reply)
    return _clean_tool_names(names)


def _fingerprint_from_profile(
    base: TargetFingerprint, profile: TargetProfile, *, source: str
) -> TargetFingerprint:
    """Merge an LLM-extracted :class:`TargetProfile` onto the base fingerprint.

    Surface booleans are OR-ed with whatever the adapter already declared (we
    only ever *add* evidence); intent fields come straight from the profile.
    """
    note = "recon: LLM profile"
    return TargetFingerprint(
        mode=base.mode,
        ref=base.ref,
        has_tools=profile.has_tools or base.has_tools,
        has_memory=profile.has_memory or base.has_memory,
        touches_pii=base.touches_pii,
        is_multi_agent=profile.is_multi_agent or base.is_multi_agent,
        external_systems_detected=profile.external_systems or base.external_systems_detected,
        multi_agent_detected=profile.is_multi_agent or base.multi_agent_detected,
        cross_session_data_detected=profile.cross_session_data or base.cross_session_data_detected,
        framework=base.framework,
        declared_tools=profile.declared_tools or list(base.declared_tools),
        declared_memory_keys=list(base.declared_memory_keys),
        notes=f"{base.notes} | {note}" if base.notes else note,
        inferred_goal=profile.inferred_goal,
        domain=profile.domain,
        sensitive_actions=list(profile.sensitive_actions),
        declared_guardrails=list(profile.declared_guardrails),
        profile_source=source,  # type: ignore[arg-type]
        profile_confidence=profile.confidence,
    )


class ReconAgent:
    """Phase-1 attack-surface mapper.

    Does not subclass :class:`~agent_guardian.agents.base.AsiAgent` because
    recon has no ASI category. The returned :class:`AgentReport` carries
    ``asi_category=None``.
    """

    name = "recon-agent"

    def __init__(
        self,
        *,
        attacker_llm: BaseLLM,
        model: str = "gpt-4o-mini",
        budget: AgentBudget | None = None,
        audit_rounds: int = 10,
    ) -> None:
        # The attacker LLM drives white-box profile extraction + the black-box
        # capability-audit deepening loop; wrapped in a usage-tracking decorator
        # so its spend is observable. ``audit_rounds`` caps the adaptive
        # deepening rounds in the black-box audit.
        self._usage = (
            attacker_llm.counter if isinstance(attacker_llm, UsageTrackingLLM) else UsageCounter()
        )
        self._llm: BaseLLM = (
            attacker_llm
            if isinstance(attacker_llm, UsageTrackingLLM)
            else UsageTrackingLLM(attacker_llm, counter=self._usage)
        )
        self._model = model
        self._audit_rounds = audit_rounds
        self.budget = budget if budget is not None else AgentBudget(max_turns=25)

    async def run(self, target: TargetAdapter, memory: SharedMemory) -> AgentReport:
        start = time.monotonic()
        # Seed the fingerprint from the adapter's static description.
        base = memory.target_fingerprint() or target.fingerprint()

        # Best-evidence-first: when the target is white-box (system prompt /
        # in-process source / framework introspection), read it directly with
        # one schema-constrained LLM call instead of interrogating it. On
        # success this is the primary fingerprint and we skip the probes.
        evidence = target.profile_evidence()
        if evidence.box == "white":
            profile = await profile_from_material(evidence, llm=self._llm, model=self._model)
            if profile is not None:
                source = base.mode if base.mode in ("prompt", "code", "framework") else "heuristic"
                refined = _fingerprint_from_profile(base, profile, source=source)
                try:
                    await memory.set_target_fingerprint(refined)
                except Exception as exc:  # pragma: no cover -- defensive
                    _LOG.error("recon: white-box set_target_fingerprint failed: %s", exc)
                _LOG.info(
                    "recon_done(white-box): source=%s goal=%r tools=%s memory=%s confidence=%.2f",
                    source,
                    (refined.inferred_goal or "")[:80],
                    refined.has_tools,
                    refined.has_memory,
                    refined.profile_confidence,
                )
                return AgentReport(
                    agent=self.name,
                    asi_category=None,
                    findings_count=0,
                    turns=0,
                    duration_seconds=time.monotonic() - start,
                    terminated_by="success",
                    notes=refined.notes,
                    tokens_consumed=self._tokens_snapshot(),
                )
            _LOG.info("recon: white-box extraction returned no profile -- falling back to probes")

        _LOG.info(
            "recon_start: black-box capability audit against %s (mode=%s, "
            "deepen_rounds<=%d, wall_budget=%.1fs)",
            base.ref,
            base.mode,
            self._audit_rounds,
            self.budget.wall_seconds_remaining,
        )

        has_tools_observed = base.has_tools
        has_memory_observed = base.has_memory
        # OWASP-2026 evidence-backed signals. Start from whatever the
        # fingerprint already carries (a future adapter may pre-declare
        # them); recon flips them ``True`` on positive evidence and
        # otherwise leaves them as the inherited value.
        external_systems_observed = base.external_systems_detected
        multi_agent_observed = base.multi_agent_detected
        cross_session_data_observed = base.cross_session_data_detected
        # Tool handles discovered from the tool-inventory probe reply. Starts
        # from whatever the adapter pre-declared (usually empty for code
        # targets behind a plain run() entry point) and is replaced by the
        # extracted names when the probe elicits them.
        declared_tools_observed: list[str] = list(base.declared_tools)
        notes_parts: list[str] = [base.notes] if base.notes else []
        # (probe, reply) pairs fed to the black-box profiler after the loop so
        # intent is extracted semantically rather than via substring matching.
        transcript: list[tuple[str, str]] = []
        turns = 0
        terminated_by = "success"
        error: str | None = None

        # Black-box: adaptive capability audit -- make the target take observable
        # actions (tool / fetch / delegation), run a cross-session planted-token
        # memory test, and let the LLM adaptively deepen. Replaces the old
        # self-report probe interview; refusals are kept, never fatal.
        audit_result = await run_capability_audit(
            target,
            llm=self._llm,
            model=self._model,
            max_deepen_rounds=self._audit_rounds,
            cancel_event=getattr(self, "_cancel_event", None),
        )
        transcript = audit_result.transcript
        turns = len(transcript)
        # Deterministic memory signals from the planted-token test.
        if audit_result.memory_conversational:
            has_memory_observed = True
        if audit_result.memory_cross_session:
            cross_session_data_observed = True
        # Heuristic surface flags over every reply (reliable boolean signal); the
        # LLM profiler below adds intent + may confirm flags. A refusal simply
        # matches nothing here -- the profiler still reasons about it.
        for question, reply in transcript:
            if _looks_like_tools(reply):
                has_tools_observed = True
                if not declared_tools_observed:
                    extracted = await _extract_tool_names(reply, self._llm, self._model)
                    if extracted:
                        declared_tools_observed = extracted
            if _looks_like_memory(reply):
                has_memory_observed = True
            if _looks_like_external_systems(reply):
                external_systems_observed = True
            if _looks_like_multi_agent(reply):
                multi_agent_observed = True
            if _looks_like_cross_session_data(reply):
                cross_session_data_observed = True
            try:
                await memory.write_reflection(
                    self.name,
                    json.dumps(
                        {"event": "recon_audit", "prompt": question, "target_response": reply}
                    ),
                    embed=False,
                )
            except Exception as exc:  # pragma: no cover -- defensive
                _LOG.warning("recon audit: write_reflection failed (%s) -- continuing", exc)

        # Black-box intent: structure the audit transcript with the LLM (no
        # substring matching). Heuristic surface flags above are kept as the
        # reliable boolean signal; the profile adds intent + may confirm flags.
        audit = (
            await profile_from_audit(transcript, llm=self._llm, model=self._model)
            if transcript
            else None
        )
        if audit is not None:
            notes_parts.append("recon: black-box capability audit")
        refined = TargetFingerprint(
            mode=base.mode,
            ref=base.ref,
            has_tools=has_tools_observed or (audit.has_tools if audit else False),
            has_memory=has_memory_observed or (audit.has_memory if audit else False),
            touches_pii=base.touches_pii,
            is_multi_agent=base.is_multi_agent or (audit.is_multi_agent if audit else False),
            external_systems_detected=external_systems_observed
            or (audit.external_systems if audit else False),
            multi_agent_detected=multi_agent_observed or (audit.is_multi_agent if audit else False),
            cross_session_data_detected=cross_session_data_observed
            or (audit.cross_session_data if audit else False),
            framework=base.framework,
            declared_tools=declared_tools_observed or (audit.declared_tools if audit else []),
            declared_memory_keys=list(base.declared_memory_keys),
            notes=" | ".join(p for p in notes_parts if p) or base.notes,
            inferred_goal=audit.inferred_goal if audit else None,
            domain=audit.domain if audit else None,
            sensitive_actions=list(audit.sensitive_actions) if audit else [],
            declared_guardrails=list(audit.declared_guardrails) if audit else [],
            profile_source="endpoint" if audit else "heuristic",
            profile_confidence=audit.confidence if audit else 0.0,
        )
        try:
            await memory.set_target_fingerprint(refined)
        except Exception as exc:  # pragma: no cover — defensive
            terminated_by = "error"
            error = f"memory.set_target_fingerprint raised {type(exc).__name__}: {exc}"
            _LOG.error(
                "recon: memory.set_target_fingerprint raised %s: %s — fingerprint not persisted",
                type(exc).__name__,
                exc,
            )

        duration = time.monotonic() - start
        _LOG.info(
            "recon_done: tools=%s memory=%s pii=%s external_systems=%s multi_agent=%s cross_session=%s "
            "declared_tools=%s (probes=%d, duration=%.1fs, terminated_by=%s)",
            refined.has_tools,
            refined.has_memory,
            refined.touches_pii,
            refined.external_systems_detected,
            refined.multi_agent_detected,
            refined.cross_session_data_detected,
            refined.declared_tools,
            turns,
            duration,
            terminated_by,
        )

        return AgentReport(
            agent=self.name,
            asi_category=None,
            findings_count=0,
            turns=turns,
            duration_seconds=time.monotonic() - start,
            terminated_by=terminated_by,  # type: ignore[arg-type]
            error=error,
            notes=refined.notes,
            tokens_consumed=self._tokens_snapshot(),
        )

    def _tokens_snapshot(self) -> dict[str, int]:
        """Per-role token totals for the AgentReport (recon uses only attacker)."""
        return {
            "attacker_input": self._usage.prompt_tokens,
            "attacker_output": self._usage.completion_tokens,
            "attacker_total": self._usage.total_tokens,
            "attacker_calls": self._usage.calls,
            "evaluator_input": 0,
            "evaluator_output": 0,
            "evaluator_total": 0,
            "evaluator_calls": 0,
            "input": self._usage.prompt_tokens,
            "output": self._usage.completion_tokens,
            "total": self._usage.total_tokens,
        }
