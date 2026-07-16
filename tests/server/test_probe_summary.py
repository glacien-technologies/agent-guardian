"""AI-written per-agent Probes-table SUMMARY (probe_summary.py).

The SUMMARY column is synthesised by an LLM from ALL of an agent's turns plus
its rolled-up verdict, generated once at scan finalization and persisted to
``probe/summaries.json``. These tests pin: the prompt carries the turns +
verdict; generation summarises graded groups (and skips recon); the file is
written + read back; and the dashboard group prefers the AI summary.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.llm.stub import StubLLM
from agent_guardian.server.dashboard_view import _assemble_probe_groups, _load_probe_summaries
from agent_guardian.server.probe_summary import (
    build_summary_prompt,
    generate_probe_summaries,
    write_probe_summaries,
)


def _turn(agent: str, asi: str, seed_id: str, turn: int, verdict: str) -> dict:
    return {
        "agent": agent,
        "asi_category": asi,
        "turn": turn,
        "seed_id": seed_id,
        "prompt": f"attacker move {turn}",
        "target_response": f"target reply {turn}",
        "verdict": verdict,
        "reasoning": f"reasoning {turn}",
    }


def _reflection(turn: dict) -> str:
    return json.dumps({"record_type": "reflection", "payload": {"content": json.dumps(turn)}})


def _seed(scan_dir: Path) -> None:
    scan_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        _turn("identity-leak-agent", "ASI03", "ASI03-PII-001", 1, "defended"),
        _turn("identity-leak-agent", "ASI03", "ASI03-PII-001", 2, "exploited"),
        # recon: no verdict → must be skipped by the summariser.
        {"agent": "recon-agent", "asi_category": "", "turn": 1, "seed_id": "", "verdict": ""},
    ]
    (scan_dir / "memory.jsonl").write_text(
        "\n".join(_reflection(t) for t in rows) + "\n", encoding="utf-8"
    )


def test_build_summary_prompt_carries_turns_and_verdict() -> None:
    exp = {
        "agent": "identity-leak-agent",
        "asi_category": "ASI03",
        "verdict": "exploited",
        "turns": [_turn("identity-leak-agent", "ASI03", "ASI03-PII-001", 1, "defended")],
    }
    prompt = build_summary_prompt(exp)
    assert "exploited" in prompt
    assert "ASI03" in prompt
    assert "attacker move 1" in prompt
    assert "target reply 1" in prompt


async def test_generate_summarises_graded_groups_and_skips_recon(tmp_path: Path) -> None:
    scan_dir = tmp_path / "cli-x"
    _seed(scan_dir)
    llm = StubLLM(default="The target leaked another tenant's balance on turn 2.")
    summaries = await generate_probe_summaries(scan_dir, llm, model="stub")
    assert "identity-leak-agent" in summaries
    assert (
        summaries["identity-leak-agent"] == "The target leaked another tenant's balance on turn 2."
    )
    # Recon (no verdict) is skipped — and never keyed under agent:recon-agent.
    assert not any(k.startswith("agent:") for k in summaries)


async def test_awrite_works_inside_event_loop(tmp_path: Path) -> None:
    # Regression: the CLI finalization runs inside a running event loop, where
    # the sync asyncio.run() path raised "cannot be called from a running loop"
    # and silently produced an empty summaries.json. awrite_* awaits directly.
    from agent_guardian.server.probe_summary import awrite_probe_summaries

    scan_dir = tmp_path / "cli-async"
    _seed(scan_dir)
    llm = StubLLM(default="Async summary landed correctly for this agent.")
    out = await awrite_probe_summaries(scan_dir, llm, model="stub")
    loaded = _load_probe_summaries(scan_dir)
    assert out == scan_dir / "probe" / "summaries.json"
    assert loaded.get("identity-leak-agent") == "Async summary landed correctly for this agent."


def test_write_and_load_round_trip(tmp_path: Path) -> None:
    scan_dir = tmp_path / "cli-y"
    _seed(scan_dir)
    llm = StubLLM(default="Target disclosed cross-tenant data.")
    out = write_probe_summaries(scan_dir, llm, model="stub")
    assert out == scan_dir / "probe" / "summaries.json"
    loaded = _load_probe_summaries(scan_dir)
    assert loaded.get("identity-leak-agent") == "Target disclosed cross-tenant data."


def test_write_empty_probe_summaries_persists_empty_document(tmp_path: Path) -> None:
    from agent_guardian.server.probe_summary import write_empty_probe_summaries

    out = write_empty_probe_summaries(tmp_path)

    assert out == tmp_path / "probe" / "summaries.json"
    assert json.loads(out.read_text(encoding="utf-8")) == {"summaries": {}}


def test_probe_groups_sorted_by_asi_recon_first(tmp_path: Path) -> None:
    from agent_guardian.server.dashboard_view import _assemble_probe_groups

    # Seed agents OUT of ASI order, including recon and two ASI09 agents.
    rows = [
        _turn("trust-exploit-agent", "ASI09", "ASI09-TE-001", 1, "vulnerable"),
        _turn("goal-hijack-agent", "ASI01", "ASI01-GH-001", 1, "exploited"),
        {"agent": "recon-agent", "asi_category": "", "turn": 1, "seed_id": "", "verdict": ""},
        _turn("output-handling-agent", "ASI09", "ASI09-OH-001", 1, "exploited"),
        _turn("tool-abuse-agent", "ASI02", "ASI02-TA-001", 1, "defended"),
    ]
    probes: list[dict] = []
    for r in rows:
        probes.append(
            {
                "agent": r["agent"],
                "asi_category": r["asi_category"],
                "seed_id": r.get("seed_id", ""),
                **r,
            }
        )
    groups = _assemble_probe_groups(probes)
    order = [g["agent"] for g in groups]
    # recon first, then ASI ascending; the two ASI09 agents are adjacent.
    assert order == [
        "recon-agent",
        "goal-hijack-agent",  # ASI01
        "tool-abuse-agent",  # ASI02
        "output-handling-agent",  # ASI09 (agent-name tiebreak: o < t)
        "trust-exploit-agent",  # ASI09
    ]


def test_is_usable_summary_rejects_garbage_and_truncation() -> None:
    from agent_guardian.server.probe_summary import is_usable_summary

    # Garbage / truncated (weak / safety-filtered model output) → rejected.
    for bad in (
        "The target",
        "The target was",
        "3:** No preamble,",
        ":** Describe the target'",
        "The target leaked sensitive transaction",  # truncated: no terminal period
    ):
        assert is_usable_summary(bad) is False, bad
    # A clean, complete sentence → accepted.
    assert is_usable_summary(
        "The target complied with the unauthorized wire-transfer request without any confirmation."
    )


def test_load_summaries_drops_unusable_entries(tmp_path: Path) -> None:
    scan_dir = tmp_path / "cli-junk"
    (scan_dir / "probe").mkdir(parents=True)
    (scan_dir / "probe" / "summaries.json").write_text(
        json.dumps(
            {
                "summaries": {
                    "goal-hijack-agent": "The target",  # truncated → dropped
                    "identity-leak-agent": "The target leaked another tenant's balance in full.",
                }
            }
        ),
        encoding="utf-8",
    )
    loaded = _load_probe_summaries(scan_dir)
    assert "goal-hijack-agent" not in loaded
    assert loaded["identity-leak-agent"] == "The target leaked another tenant's balance in full."


def test_summarize_one_discards_truncated_model_output(tmp_path: Path) -> None:
    # A stub model returning a truncated fragment yields NO summary (→ fallback).
    scan_dir = tmp_path / "cli-trunc"
    _seed(scan_dir)
    llm = StubLLM(default="The target")  # truncated junk
    import asyncio

    summaries = asyncio.run(generate_probe_summaries(scan_dir, llm, model="stub"))
    assert summaries == {}


def test_missing_summaries_file_is_safe(tmp_path: Path) -> None:
    assert _load_probe_summaries(tmp_path / "nope") == {}
    assert _load_probe_summaries(None) == {}


def test_group_prefers_ai_summary_over_reasoning_gloss(tmp_path: Path) -> None:
    scan_dir = tmp_path / "cli-z"
    _seed(scan_dir)
    from agent_guardian.server.dashboard_view import _assemble_probes_list

    probes = _assemble_probes_list(scan_dir)
    groups = _assemble_probe_groups(probes, {"identity-leak-agent": "AI: tenant balance leaked"})
    idl = next(g for g in groups if g["agent"] == "identity-leak-agent")
    assert idl["ai_summary"] == "AI: tenant balance leaked"
    # And without a summaries map the group has no AI summary (falls back later).
    groups2 = _assemble_probe_groups(probes)
    idl2 = next(g for g in groups2 if g["agent"] == "identity-leak-agent")
    assert idl2["ai_summary"] == ""
