"""Coverage reconstruction from on-disk swarm memory (M13 follow-up).

The :class:`~agent_guardian.models.scan.Scan` summary counts findings by
severity but says nothing about *attempts* — a scan that produced zero
findings is indistinguishable from a scan that never ran. The reflection
records :class:`~agent_guardian.agents.base.AsiAgent` writes per turn fix
that: this module replays the JSONL and computes a coverage roll-up.

Reflections are written by ``AsiAgent.run`` as JSON-encoded payloads with
fixed keys (see ``base.py``). The roll-up reports:

* ``attempts_total`` — number of judged turns across all specialist agents.
* ``asi_categories`` — sorted unique ASI category values exercised.
* ``mitre_techniques`` — sorted unique MITRE ATLAS techniques touched.
* ``csa_categories`` — sorted unique CSA categories touched.
* ``agents`` — per-agent attempt count.
* ``probes_attempted`` — sorted unique probe ids the strategies seeded
  from (T4 validation follow-up — was always null pre-2026.05).
* ``attacker_refused_turns`` / ``attacker_refusal_rate`` — number and
  fraction of turns where the attacker LLM refused to generate adversarial
  content and the strategy fell back to a static seed. A high rate means
  the attacker provider's safety alignment is dampening the scan; the
  AIVSS score should be read with that in mind.

The function is intentionally tolerant: malformed JSONL lines, non-reflection
records, and unparseable reflection payloads are skipped silently rather
than raising — coverage is best-effort over whatever survived on disk.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agent_guardian.models.scan import Scan

__all__ = ["NOT_TESTED_EVENTS", "compute_coverage_from_memory", "default_memory_path"]

_LOG = logging.getLogger(__name__)

# Per-turn lifecycle markers for turns that never reached the target (#4). They
# are persisted as reflections so the raw stream is complete, but they are NOT
# adversarial attempts and must be excluded from attempt accounting (coverage)
# and from the per-agent probe turn list (export). ``egress_refused``: the
# egress gate dropped the prompt before send; ``attacker_refused``: the probe
# was the attacker LLM's own refusal and was never dispatched.
NOT_TESTED_EVENTS: frozenset[str] = frozenset({"egress_refused", "attacker_refused"})


def default_memory_path(scan_id: str, root_dir: Path | None = None) -> Path:
    """Resolve the JSONL path used by :class:`SharedMemory` for ``scan_id``."""
    base = root_dir if root_dir is not None else Path.home() / ".agentguardian" / "scans"
    return base / scan_id / "memory.jsonl"


# Marker every :class:`~agent_guardian.llm.stub.StubLLM` reply carries
# (``[stub:<role>] ...``). A turn whose attacker prompt starts with this was
# not a real attack — the attacker LLM is a no-op stub (#16).
_STUB_ATTACKER_MARKER = "[stub:"


def _is_noop_attacker_prompt(prompt: object) -> bool:
    """True when ``prompt`` is a stub/no-op attacker reply (#16)."""
    return isinstance(prompt, str) and prompt.lstrip().startswith(_STUB_ATTACKER_MARKER)


def _empty_coverage(unseeded_llm_calls: int = 0) -> dict[str, Any]:
    return {
        "attempts_total": 0,
        "asi_categories": [],
        "mitre_techniques": [],
        "csa_categories": [],
        "agents": {},
        "probes_attempted": [],
        "attacker_refused_turns": 0,
        "attacker_refusal_rate": 0.0,
        "noop_attacker_turns": 0,
        "attacker_active": True,
        "skipped_agents": [],
        "strategies_used": {},
        "strategies_flattened": {},
        # #231 point 5 — LLM calls dispatched with seed=None during a seeded
        # scan (a self-diagnosing signal that seed-threading missed a path).
        # Always present and defaults to 0; populated from the dispatch-layer
        # usage counter via ``unseeded_llm_calls`` when the scan was seeded.
        "unseeded_llm_calls": int(unseeded_llm_calls),
    }


def compute_coverage_from_memory(
    scan: Scan | None = None,
    *,
    memory_path: Path | None = None,
    root_dir: Path | None = None,
    unseeded_llm_calls: int = 0,
) -> dict[str, Any]:
    """Replay the scan's memory.jsonl and roll-up coverage statistics.

    Parameters
    ----------
    scan:
        The :class:`Scan` whose ``id`` is used to locate the JSONL when
        ``memory_path`` is not provided. May be ``None`` when ``memory_path``
        is given explicitly — the swarm finalize gate (issue #76) needs the
        roll-up *before* the :class:`Scan` is constructed, so it passes the
        memory path directly.
    memory_path:
        Optional explicit JSONL path (used by tests that write to a tmp
        directory, and by the finalize gate).
    root_dir:
        Optional ``~/.agentguardian/scans``-style root used to derive
        ``memory_path`` from ``scan.id``.
    unseeded_llm_calls:
        #231 point 5 — the count of LLM calls dispatched with ``seed=None``
        during a *seeded* scan (a self-diagnosing seed-threading-miss signal).
        Sourced from the dispatch-layer usage counter and threaded in here so
        the value rides inside the ``coverage`` block. Defaults to 0 (the
        correct value for unseeded scans and hand-built ``Scan`` test fixtures,
        where every call is trivially unseeded and not a defect).

    Returns
    -------
    dict
        Coverage roll-up. Returns the empty shape when no memory file is
        found so callers can always emit a stable JSON key.
    """
    if memory_path is None:
        if scan is None:
            raise ValueError("compute_coverage_from_memory needs either scan or memory_path")
        memory_path = default_memory_path(scan.id, root_dir)
    path = memory_path
    if not path.exists():
        return _empty_coverage(unseeded_llm_calls)

    asi: set[str] = set()
    mitre: set[str] = set()
    csa: set[str] = set()
    agents: dict[str, int] = {}
    probes_attempted: set[str] = set()
    refused_turns = 0
    # #16 — turns whose attacker prompt was a stub/no-op canned reply (the
    # ``[stub:...]`` marker emitted by :class:`StubLLM`). These are NOT real
    # adversarial attacks; counting them as landed attacks (and reporting a
    # 0.0 refusal rate) hides a non-attacking attacker. Surfaced separately so
    # operators can see "the attacker generated nothing real".
    noop_attacker_turns = 0
    attempts = 0
    skipped_agents: list[dict[str, Any]] = []
    # IMPORTANT #6 — strategy attribution. ``strategies_used`` counts the
    # top-level strategy as reported on each turn (``mad_max`` for the
    # mixer itself, ``pair`` / ``tap`` / ``crescendo`` for direct picks).
    # ``strategies_flattened`` re-attributes MAD-MAX turns to their
    # chosen child via ``strategy_metadata.chosen_strategy`` so operators
    # see the effective strategy mix instead of an opaque MAD-MAX bucket.
    strategies_used: dict[str, int] = {}
    strategies_flattened: dict[str, int] = {}

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover — defensive
        _LOG.warning(
            "coverage: could not read memory file %s (%s) — returning empty coverage",
            path,
            exc,
        )
        return _empty_coverage(unseeded_llm_calls)

    malformed_lines = 0
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:  # pragma: no cover — defensive
            malformed_lines += 1
            _LOG.debug("coverage: skipping malformed JSONL line %d (%s)", line_no, exc)
            continue
        if not isinstance(rec, dict):  # pragma: no cover — defensive
            _LOG.debug(
                "coverage: skipping non-object JSONL line %d (got %s)",
                line_no,
                type(rec).__name__,
            )
            continue
        # Pluck agent_skipped records out into their own facet — they're
        # not reflections and shouldn't be folded into attempt counts.
        if rec.get("record_type") == "agent_skipped":
            payload = rec.get("payload")
            if isinstance(payload, dict):
                skipped_agents.append(
                    {
                        "agent": str(payload.get("agent", "")),
                        "asi": payload.get("asi"),
                        "reason": str(payload.get("reason", "")),
                    }
                )
            continue
        if rec.get("record_type") != "reflection":
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            continue
        content = payload.get("content")
        if not isinstance(content, str) or not content:
            continue
        try:
            turn = json.loads(content)
        except json.JSONDecodeError as exc:  # pragma: no cover — defensive
            # Old-style free-text reflections aren't part of coverage —
            # we only count structured per-turn records.
            _LOG.debug("coverage: reflection content is not structured JSON (%s); skipping", exc)
            continue
        if not isinstance(turn, dict):
            continue
        # Recon traffic (IMPORTANT #4) is persisted as reflections too but
        # they're benign fingerprint queries, not adversarial attempts.
        # Don't count them in attempts_total / agents / strategies — they
        # belong to a separate "recon probes" facet that downstream tools
        # can render off of the raw JSONL. The recon agent writes
        # ``event="recon_audit"``; ``recon_probe`` is kept for back-compat
        # with any older on-disk memory (#15 — the dead ``recon_probe``-only
        # check let ~47% recon traffic inflate attempts_total).
        if turn.get("event") in ("recon_audit", "recon_probe"):
            continue
        # Not-tested markers (#4) never reached the target, so they must not
        # count as adversarial attempts (egress_refused / attacker_refused).
        if turn.get("event") in NOT_TESTED_EVENTS:
            continue
        attempts += 1
        agent = turn.get("agent") or payload.get("agent")
        if isinstance(agent, str) and agent:
            agents[agent] = agents.get(agent, 0) + 1
        asi_val = turn.get("asi_category")
        if isinstance(asi_val, str) and asi_val:
            asi.add(asi_val)
        for t in turn.get("mitre_techniques", []) or []:
            if isinstance(t, str) and t:
                mitre.add(t)
        csa_val = turn.get("csa_category")
        if isinstance(csa_val, str) and csa_val:
            csa.add(csa_val)
        seed_id = turn.get("seed_id")
        if isinstance(seed_id, str) and seed_id:
            probes_attempted.add(seed_id)
        if turn.get("attacker_refused"):
            refused_turns += 1
        # #16 — a stub/no-op attacker emits a canned ``[stub:attacker] ...``
        # string instead of generating an attack. Detect it from the recorded
        # prompt so a non-attacking attacker is visible rather than silently
        # scoring as a landed attack with a misleading 0.0 refusal rate.
        if _is_noop_attacker_prompt(turn.get("prompt")):
            noop_attacker_turns += 1

        # Strategy attribution (IMPORTANT #6). Top-level count first.
        strategy = turn.get("strategy")
        if isinstance(strategy, str) and strategy:
            strategies_used[strategy] = strategies_used.get(strategy, 0) + 1
            # Flattened: if the top-level strategy is mad_max we follow
            # the chosen_strategy hint to credit the actual child. For
            # everything else the flattened bucket equals the top-level.
            if strategy == "mad_max":
                meta = turn.get("strategy_metadata") or {}
                chosen = meta.get("chosen_strategy") if isinstance(meta, dict) else None
                if isinstance(chosen, str) and chosen:
                    strategies_flattened[chosen] = strategies_flattened.get(chosen, 0) + 1
                else:
                    # No chosen_strategy hint → fall back to crediting
                    # the mad_max bucket so totals reconcile.
                    strategies_flattened["mad_max"] = strategies_flattened.get("mad_max", 0) + 1
            else:
                strategies_flattened[strategy] = strategies_flattened.get(strategy, 0) + 1

    # #16 — the refusal rate must reflect every turn on which the attacker
    # produced no real adversarial content: explicit refusals AND stub/no-op
    # canned replies. Counting only explicit refusals let a stub attacker (no
    # refusal, but no attack either) report 0.0 and look like a healthy scan.
    inactive_turns = refused_turns + noop_attacker_turns
    refusal_rate = inactive_turns / attempts if attempts else 0.0
    # The attacker is "active" only if at least one judged turn carried a real
    # (non-stub) attack prompt. An all-stub/all-refused scan is non-attacking.
    attacker_active = attempts > 0 and noop_attacker_turns < attempts

    # Sort the skipped-agent rollup for stable JSON output. Multiple entries
    # for the same agent shouldn't happen today but we deduplicate by name
    # for safety in case a future code path retries the applicability gate.
    skipped_dedup: dict[str, dict[str, Any]] = {}
    for entry in skipped_agents:
        key = entry.get("agent") or ""
        if key and key not in skipped_dedup:
            skipped_dedup[key] = entry
    sorted_skipped = [skipped_dedup[k] for k in sorted(skipped_dedup)]

    _LOG.debug(
        "coverage computed: attempts=%d asi_categories=%d probes_used=%d refusal_rate=%.2f "
        "noop_attacker=%d attacker_active=%s skipped_agents=%d strategies=%s (malformed_lines=%d)",
        attempts,
        len(asi),
        len(probes_attempted),
        refusal_rate,
        noop_attacker_turns,
        attacker_active,
        len(sorted_skipped),
        list(strategies_used),
        malformed_lines,
    )

    return {
        "attempts_total": attempts,
        "asi_categories": sorted(asi),
        "mitre_techniques": sorted(mitre),
        "csa_categories": sorted(csa),
        "agents": dict(sorted(agents.items())),
        "probes_attempted": sorted(probes_attempted),
        "attacker_refused_turns": refused_turns,
        "attacker_refusal_rate": round(refusal_rate, 4),
        "noop_attacker_turns": noop_attacker_turns,
        "attacker_active": attacker_active,
        "skipped_agents": sorted_skipped,
        "strategies_used": dict(sorted(strategies_used.items())),
        "strategies_flattened": dict(sorted(strategies_flattened.items())),
        # #231 point 5 — dispatch-layer seed-threading-miss signal (0 unless a
        # seeded scan dispatched seed=None calls).
        "unseeded_llm_calls": int(unseeded_llm_calls),
    }
