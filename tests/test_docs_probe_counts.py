"""Docs probe-count guard — keep docs/attacks/*.mdx in sync with the corpus.

The user-facing attack docs state authoritative per-category probe counts
("ASI01 ... covers **20 probes**") and a library total ("ships **96 probes**").
These had silently drifted from the live corpus (ASI01 said 9 but ships 20;
ASI07 said 8 but ships 15; the total said 96 but ships 124). This guard pins the
DOCUMENTED counts to ``load_probes_for_asi`` / ``load_all_probes`` so adding a
probe forces the matching doc update instead of letting the numbers rot.

These are the *authoritative corpus-size* claims only — illustrative CLI sample
outputs elsewhere (e.g. ``goal_hijack  probes=9`` in a demo transcript) are a
different metric (probes attempted in one capped run) and are intentionally not
checked here.
"""

from __future__ import annotations

from pathlib import Path

from agent_guardian.models.asi import AsiCategory
from agent_guardian.probes.loader import load_all_probes, load_probes_for_asi

REPO_ROOT = Path(__file__).resolve().parents[1]
ATTACKS = REPO_ROOT / "docs" / "attacks"


def _count(cat: AsiCategory) -> int:
    return len(load_probes_for_asi(cat))


def _read(name: str) -> str:
    return (ATTACKS / name).read_text(encoding="utf-8")


def test_overview_total_matches_corpus() -> None:
    total = len(load_all_probes())
    assert f"**{total} probes**" in _read("overview.mdx"), (
        f"overview.mdx total probe count is stale; corpus ships {total}"
    )


def test_prompt_injection_asi01_count() -> None:
    n = _count(AsiCategory.ASI01)
    assert f"covers **{n} probes**" in _read("prompt-injection.mdx"), (
        f"prompt-injection.mdx ASI01 count is stale; corpus has {n}"
    )


def test_overview_card_asi01_count() -> None:
    n = _count(AsiCategory.ASI01)
    assert f"{n} probes. Direct goal redirect" in _read("overview.mdx"), (
        f"overview.mdx ASI01 card count is stale; corpus has {n}"
    )


def test_multi_agent_asi07_count() -> None:
    n = _count(AsiCategory.ASI07)
    assert f"**{n} probes**" in _read("multi-agent-exploitation.mdx"), (
        f"multi-agent-exploitation.mdx ASI07 count is stale; corpus has {n}"
    )


def test_memory_poisoning_asi06_count() -> None:
    n = _count(AsiCategory.ASI06)
    assert f"**{n} probes**" in _read("memory-poisoning.mdx"), (
        f"memory-poisoning.mdx ASI06 count is stale; corpus has {n}"
    )


def test_cascading_asi08_count() -> None:
    n = _count(AsiCategory.ASI08)
    assert f"**{n} probes**" in _read("cascading-failure.mdx"), (
        f"cascading-failure.mdx ASI08 count is stale; corpus has {n}"
    )


def test_data_exfiltration_asi03_and_asi09_counts() -> None:
    de = _read("data-exfiltration.mdx")
    n3 = _count(AsiCategory.ASI03)
    n9 = _count(AsiCategory.ASI09)
    assert f"({n3} probes)" in de, f"data-exfiltration.mdx ASI03 count stale; corpus has {n3}"
    assert f"({n9} probes" in de, f"data-exfiltration.mdx ASI09 count stale; corpus has {n9}"
