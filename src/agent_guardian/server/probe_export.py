"""Authoritative per-probe JSON export persisted under ``scans/<id>/probe/``.

The dashboard's "JSONL events" view and the per-turn INFO log render *previews*
of long prompts / responses (elided with ``…``) for scannability. That preview
is lossy, so it must never be the system of record. This module writes the
authoritative, **untruncated** per-probe record to disk: every turn for a probe
(verbatim prompt, full target response, full judge reasoning) grouped from
``memory.jsonl``, the complete raw event stream for that probe from
``events.jsonl`` / ``recon_probes.jsonl``, and the worst-case rolled-up verdict
(so a single ``info_leak`` turn is never hidden behind an earlier ``defended``).

Layout written under ``<scan_dir>/probe/``::

    probe/
      index.json                # [{probe_id, agent, asi, verdict, turn_count, ...}]
      <probe_id>.json           # one authoritative file per probe

Nothing is capped or truncated — this is the complete record the operator
asked for. Never raises on a missing/corrupt file (best-effort, logged at
DEBUG): a single bad line is skipped, the rest export.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from agent_guardian.core.coverage import NOT_TESTED_EVENTS

__all__ = ["build_probe_exports", "write_probe_exports"]

_LOG = logging.getLogger(__name__)

# Worst-case verdict precedence — mirrors ``dashboard_view._VERDICT_RANK`` so the
# export's rolled-up verdict can never disagree with the Probes-table pill.
# Higher == worse; the strongest turn wins the group verdict.
_VERDICT_RANK: dict[str, int] = {
    "fail": 6,
    "exploited": 6,
    "info_leak": 5,
    "weakness_observed": 4,
    "simulated_or_unverified": 3,
    "inconclusive": 2,
    "needs_followup": 2,
    "pass": 1,
    "defended": 1,
}


def _safe_filename(probe_id: str) -> str:
    """Map a probe id onto a filesystem-safe stem (defensive — ids are already
    safe, but never let a crafted seed id escape the probe dir)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", probe_id) or "_"


def _iter_turn_records(scan_dir: Path) -> list[dict[str, Any]]:
    """Decode every ``record_type=reflection`` turn record from memory.jsonl.

    Each is the full ``turn_record`` written by ``agents/base.py`` — verbatim
    prompt, full target response, full judge reasoning, no truncation.
    """
    path = scan_dir / "memory.jsonl"
    out: list[dict[str, Any]] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rec = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict) or rec.get("record_type") != "reflection":
            continue
        content = (rec.get("payload") or {}).get("content")
        if not isinstance(content, str):
            continue
        try:
            turn = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(turn, dict):
            # Skip not-tested lifecycle markers (egress_refused / attacker_refused):
            # they carry no verdict and never reached the target, so they must not
            # surface as a junk turn-0 row or inflate the agent's run count.
            if turn.get("event") in NOT_TESTED_EVENTS:
                continue
            out.append(turn)
    return out


def _events_for_agent(scan_dir: Path, agent: str) -> list[dict[str, Any]]:
    """Return every raw event record referencing ``agent``, verbatim.

    Substring match on the raw line (captures the agent's own events —
    agent_start / agent_progress / reflection / agent_done / finding — plus any
    log line that names it). No cap: this is the authoritative stream.
    """
    out: list[dict[str, Any]] = []
    if not agent:
        return out
    for fname in ("events.jsonl", "recon_probes.jsonl"):
        try:
            raw = (scan_dir / fname).read_text(encoding="utf-8")
        except OSError:
            continue
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or agent not in stripped:
                continue
            try:
                rec = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            out.append(rec)
    return out


def _turn_index(t: dict[str, Any]) -> int:
    """Sort key = the turn number; turns without one (recon audits) keep their
    file order via the stable sort."""
    raw = t.get("turn")
    return int(raw) if isinstance(raw, int) else 0


def _rollup(turns: list[dict[str, Any]]) -> tuple[str, int | None]:
    """Worst-case verdict across the turns + the 1-based turn number that
    produced it (first occurrence). Empty thread → ``("", None)``."""
    best_verdict = ""
    best_rank = 0
    best_turn: int | None = None
    for i, t in enumerate(turns, start=1):
        v = str(t.get("verdict") or "")
        rank = _VERDICT_RANK.get(v, 0)
        if rank > best_rank:
            best_rank = rank
            best_verdict = v
            raw_turn = t.get("turn")
            best_turn = int(raw_turn) if isinstance(raw_turn, int) else i
    return best_verdict, best_turn


def build_probe_exports(scan_dir: Path) -> dict[str, dict[str, Any]]:
    """Build the authoritative per-AGENT export map (agent → record).

    One entry per agent (matching the dashboard's one-row-per-agent grouping):
    ALL of an agent's memory.jsonl turn records, ordered by turn number and each
    carrying its own ``turn`` number + source ``seed_id``, plus the complete raw
    event stream that names the agent and the worst-case rolled-up verdict. The
    ``probe_ids`` list records every probe id the agent fired. Never truncates.
    """
    if not scan_dir.is_dir():
        return {}
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for turn in _iter_turn_records(scan_dir):
        agent = str(turn.get("agent") or "").strip()
        if not agent:
            continue
        if agent not in groups:
            groups[agent] = []
            order.append(agent)
        groups[agent].append(turn)

    exports: dict[str, dict[str, Any]] = {}
    for agent in order:
        turns = sorted(groups[agent], key=_turn_index)
        verdict, best_turn = _rollup(turns)
        asi = next((str(t.get("asi_category") or "") for t in turns if t.get("asi_category")), "")
        probe_ids = sorted({str(t.get("seed_id") or "").strip() for t in turns if t.get("seed_id")})
        exports[agent] = {
            "agent": agent,
            "group_key": agent,
            "asi_category": asi,
            "verdict": verdict,
            "turn_count": len(turns),
            "best_evidence_turn": best_turn,
            "probe_ids": probe_ids,
            "turns": turns,
            "events": _events_for_agent(scan_dir, agent),
        }
    return exports


def write_probe_exports(scan_dir: Path) -> Path:
    """Persist the per-AGENT exports under ``<scan_dir>/probe/`` and return that
    directory. Writes one ``<agent>.json`` per agent (all of its turns) plus an
    ``index.json`` summary. Idempotent (overwrites). Best-effort: a write error
    on one file is logged and skipped so the rest still land.
    """
    probe_dir = scan_dir / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    exports = build_probe_exports(scan_dir)
    index_rows: list[dict[str, Any]] = []
    # Track what we write so we can prune stale files (e.g. a re-run after the
    # per-probe→per-agent layout change, which would otherwise leave the old
    # ``<probe_id>.json`` files behind). ``summaries.json`` is written by
    # ``probe_summary`` separately, so never prune it.
    written: set[str] = {"index.json", "summaries.json"}
    for key, exp in exports.items():
        stem = _safe_filename(key)
        written.add(f"{stem}.json")
        try:
            (probe_dir / f"{stem}.json").write_text(
                json.dumps(exp, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except OSError as exc:  # pragma: no cover — disk-level failure
            _LOG.debug("probe_export: failed to write %s (%s)", stem, exc)
            continue
        index_rows.append(
            {
                "agent": exp["agent"],
                "group_key": exp["group_key"],
                "file": f"{stem}.json",
                "asi_category": exp["asi_category"],
                "verdict": exp["verdict"],
                "turn_count": exp["turn_count"],
                "best_evidence_turn": exp["best_evidence_turn"],
                "probe_ids": exp["probe_ids"],
            }
        )
    try:
        (probe_dir / "index.json").write_text(
            json.dumps({"probes": index_rows}, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
    except OSError as exc:  # pragma: no cover — disk-level failure
        _LOG.debug("probe_export: failed to write index.json (%s)", exc)
    # Prune any stale .json files from a prior layout / run.
    for old in probe_dir.glob("*.json"):
        if old.name not in written:
            with contextlib.suppress(OSError):  # pragma: no cover — best-effort
                old.unlink()
    return probe_dir
