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

import json
import logging
import re
from pathlib import Path
from typing import Any

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

# Records with no probe id (e.g. recon capability turns) are bucketed under
# this agent-derived key so the export skips NOTHING.
_NO_PROBE_PREFIX = "agent:"


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
            out.append(turn)
    return out


def _events_for(scan_dir: Path, probe_id: str) -> list[dict[str, Any]]:
    """Return every raw event record referencing ``probe_id``, verbatim.

    Substring match on the raw line (robust across the id's several nested
    positions: ``probe_id`` / ``seed_id`` / message body) — the same join the
    ``/events/view`` page uses. No cap: this is the authoritative stream.
    """
    out: list[dict[str, Any]] = []
    for fname in ("events.jsonl", "recon_probes.jsonl"):
        try:
            raw = (scan_dir / fname).read_text(encoding="utf-8")
        except OSError:
            continue
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or probe_id not in stripped:
                continue
            try:
                rec = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            out.append(rec)
    return out


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
    """Build the authoritative per-probe export map (probe_id → record).

    Groups every memory.jsonl turn record by its ``seed_id`` (probe id);
    turns with no probe id are bucketed under ``agent:<agent>`` so nothing is
    dropped. Each group carries its full turns, the complete raw event stream
    referencing the id, and the worst-case rolled-up verdict. Never truncates.
    """
    if not scan_dir.is_dir():
        return {}
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for turn in _iter_turn_records(scan_dir):
        seed = str(turn.get("seed_id") or "").strip()
        agent = str(turn.get("agent") or "").strip()
        key = seed or (f"{_NO_PROBE_PREFIX}{agent}" if agent else "")
        if not key:
            continue
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(turn)

    exports: dict[str, dict[str, Any]] = {}
    for key in order:
        turns = groups[key]
        verdict, best_turn = _rollup(turns)
        agent = next((str(t.get("agent") or "") for t in turns if t.get("agent")), "")
        asi = next((str(t.get("asi_category") or "") for t in turns if t.get("asi_category")), "")
        is_probe = not key.startswith(_NO_PROBE_PREFIX)
        events = _events_for(scan_dir, key) if is_probe else []
        exports[key] = {
            "probe_id": key if is_probe else "",
            "group_key": key,
            "agent": agent,
            "asi_category": asi,
            "verdict": verdict,
            "turn_count": len(turns),
            "best_evidence_turn": best_turn,
            "turns": turns,
            "events": events,
        }
    return exports


def write_probe_exports(scan_dir: Path) -> Path:
    """Persist the per-probe exports under ``<scan_dir>/probe/`` and return that
    directory. Writes one ``<probe_id>.json`` per probe plus an ``index.json``
    summary. Idempotent (overwrites). Best-effort: a write error on one file is
    logged and skipped so the rest still land.
    """
    probe_dir = scan_dir / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    exports = build_probe_exports(scan_dir)
    index_rows: list[dict[str, Any]] = []
    for key, exp in exports.items():
        stem = _safe_filename(key)
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
                "probe_id": exp["probe_id"],
                "group_key": exp["group_key"],
                "file": f"{stem}.json",
                "agent": exp["agent"],
                "asi_category": exp["asi_category"],
                "verdict": exp["verdict"],
                "turn_count": exp["turn_count"],
                "best_evidence_turn": exp["best_evidence_turn"],
            }
        )
    try:
        (probe_dir / "index.json").write_text(
            json.dumps({"probes": index_rows}, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
    except OSError as exc:  # pragma: no cover — disk-level failure
        _LOG.debug("probe_export: failed to write index.json (%s)", exc)
    return probe_dir
