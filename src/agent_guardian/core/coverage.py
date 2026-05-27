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

__all__ = ["compute_coverage_from_memory", "default_memory_path"]

_LOG = logging.getLogger(__name__)


def default_memory_path(scan_id: str, root_dir: Path | None = None) -> Path:
    """Resolve the JSONL path used by :class:`SharedMemory` for ``scan_id``."""
    base = root_dir if root_dir is not None else Path.home() / ".agentguardian" / "scans"
    return base / scan_id / "memory.jsonl"


def _empty_coverage() -> dict[str, Any]:
    return {
        "attempts_total": 0,
        "asi_categories": [],
        "mitre_techniques": [],
        "csa_categories": [],
        "agents": {},
        "probes_attempted": [],
        "attacker_refused_turns": 0,
        "attacker_refusal_rate": 0.0,
        "skipped_agents": [],
        "strategies_used": {},
        "strategies_flattened": {},
    }


def compute_coverage_from_memory(
    scan: Scan,
    *,
    memory_path: Path | None = None,
    root_dir: Path | None = None,
) -> dict[str, Any]:
    """Replay the scan's memory.jsonl and roll-up coverage statistics.

    Parameters
    ----------
    scan:
        The :class:`Scan` whose ``id`` is used to locate the JSONL when
        ``memory_path`` is not provided.
    memory_path:
        Optional explicit JSONL path (used by tests that write to a tmp
        directory).
    root_dir:
        Optional ``~/.agentguardian/scans``-style root used to derive
        ``memory_path`` from ``scan.id``.

    Returns
    -------
    dict
        Coverage roll-up. Returns the empty shape when no memory file is
        found so callers can always emit a stable JSON key.
    """
    path = memory_path if memory_path is not None else default_memory_path(scan.id, root_dir)
    if not path.exists():
        return _empty_coverage()

    asi: set[str] = set()
    mitre: set[str] = set()
    csa: set[str] = set()
    agents: dict[str, int] = {}
    probes_attempted: set[str] = set()
    refused_turns = 0
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
    except OSError as exc:
        _LOG.warning(
            "coverage: could not read memory file %s (%s) — returning empty coverage",
            path,
            exc,
        )
        return _empty_coverage()

    malformed_lines = 0
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            malformed_lines += 1
            _LOG.debug("coverage: skipping malformed JSONL line %d (%s)", line_no, exc)
            continue
        if not isinstance(rec, dict):
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
        except json.JSONDecodeError as exc:
            # Old-style free-text reflections aren't part of coverage —
            # we only count structured per-turn records.
            _LOG.debug("coverage: reflection content is not structured JSON (%s); skipping", exc)
            continue
        if not isinstance(turn, dict):
            continue
        # Recon probes (IMPORTANT #4) are persisted as reflections too but
        # they're benign fingerprint queries, not adversarial attempts.
        # Don't count them in attempts_total / agents / strategies — they
        # belong to a separate "recon probes" facet that downstream tools
        # can render off of the raw JSONL.
        if turn.get("event") == "recon_probe":
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

    refusal_rate = refused_turns / attempts if attempts else 0.0

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
        "skipped_agents=%d strategies=%s (malformed_lines=%d)",
        attempts,
        len(asi),
        len(probes_attempted),
        refusal_rate,
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
        "skipped_agents": sorted_skipped,
        "strategies_used": dict(sorted(strategies_used.items())),
        "strategies_flattened": dict(sorted(strategies_flattened.items())),
    }
