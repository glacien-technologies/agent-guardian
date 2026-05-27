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

The function is intentionally tolerant: malformed JSONL lines, non-reflection
records, and unparseable reflection payloads are skipped silently rather
than raising — coverage is best-effort over whatever survived on disk.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_guardian.models.scan import Scan

__all__ = ["compute_coverage_from_memory", "default_memory_path"]


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
    attempts = 0

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return _empty_coverage()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or rec.get("record_type") != "reflection":
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            continue
        content = payload.get("content")
        if not isinstance(content, str) or not content:
            continue
        try:
            turn = json.loads(content)
        except json.JSONDecodeError:
            # Old-style free-text reflections aren't part of coverage —
            # we only count structured per-turn records.
            continue
        if not isinstance(turn, dict):
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

    return {
        "attempts_total": attempts,
        "asi_categories": sorted(asi),
        "mitre_techniques": sorted(mitre),
        "csa_categories": sorted(csa),
        "agents": dict(sorted(agents.items())),
    }
