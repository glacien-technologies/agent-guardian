"""End-to-end provenance: the dedicated fuzz corpus must reach runtime.

A dedicated ``ASI02-FUZZ-*`` corpus is worthless if its probe ids never reach
reflections / coverage / findings. ``FuzzStrategy`` previously stripped
``ProbeSeed`` objects to plain strings and emitted ``_build_seed_metadata(None)``,
so every fuzz turn carried no ``seed_id`` and findings collapsed to the synthetic
``fuzzing-agent-ASI02`` id. These tests pin the fix: each corpus entry's parent
probe id survives mutation + coverage-promotion and is emitted as a stable
``seed_id`` on every fuzz turn.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime
from pathlib import Path

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.fuzzing_agent import FuzzingAgent
from agent_guardian.core.coverage import compute_coverage_from_memory
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.strategies.base import ProbeSeed, StrategyContext
from agent_guardian.strategies.fuzz import FuzzStrategy

# --- direct strategy unit test --------------------------------------------------


async def _ctx(tmp_path: Path) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ok"),
        attacker_model="stub",
        goal="fuzz",
        seeds=[
            ProbeSeed(probe_id="ASI02-FUZZ-TYPE-01", text="payload one", asi="ASI02"),
            ProbeSeed(probe_id="ASI02-FUZZ-BOUND-02", text="payload two", asi="ASI02"),
        ],
        memory=SharedMemory("scan-fuzz-unit", root_dir=tmp_path),
        rng=random.Random(0),
        max_turns=5,
    )


async def test_fuzz_strategy_emits_parent_probe_provenance(tmp_path: Path) -> None:
    strat = FuzzStrategy(await _ctx(tmp_path))
    seen_seed_ids: list[str] = []
    prev_response: str | None = None
    for _ in range(5):
        result = await strat.generate_next([], prev_response)
        meta = getattr(result, "metadata", {}) or {}
        sid = meta.get("seed_id")
        assert sid, "every fuzz turn must carry a seed_id"
        seen_seed_ids.append(str(sid))
        prev_response = "some target reply of varying length " * 3
    # Every emitted seed_id must attribute back to a dedicated fuzz parent.
    for sid in seen_seed_ids:
        parent = sid.split("-mutant-", 1)[0]
        assert parent in {"ASI02-FUZZ-TYPE-01", "ASI02-FUZZ-BOUND-02"}, sid


# --- end-to-end provenance through the agent loop -------------------------------


class _ToolTarget(TargetAdapter):
    """Tool-bearing target (so FuzzingAgent.is_applicable passes) with a reply
    that trips an error marker → the judge stub yields a finding."""

    def fingerprint(self) -> TargetFingerprint:
        return TargetFingerprint(
            mode="code",
            ref="tool-target",
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            framework=None,
            declared_tools=["search", "file_read"],
            declared_memory_keys=[],
            notes="tool stub",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return "Traceback (most recent call last): ValueError: schema violation in arg"

    async def aclose(self) -> None:
        return None


def _stub_scan(scan_id: str) -> Scan:
    return Scan(
        id=scan_id,
        package_version="0.0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="0.0.0",
        target_mode="code",
        target_ref="stub",
        tier=Tier.T4_LOW,
        aivss=0,
        band=SeverityBand.EXCELLENT,
        sub_scores={},
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=0.0,
        cost_usd=0.0,
        mode="full",
        created_at=datetime.now(tz=UTC),
    )


async def test_fuzz_corpus_provenance_threads_to_reflections_and_findings(
    tmp_path: Path,
) -> None:
    judge = (
        StubScript()
        .default(
            json.dumps(
                {
                    "verdict": "fail",
                    "confidence": 0.9,
                    "reasoning": "schema violation observed",
                    "observable_compromise": True,
                }
            )
        )
        .build()
    )
    budget = AgentBudget(tokens_remaining=200_000, max_turns=4)
    agent = FuzzingAgent(
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=judge,
        attacker_model="stub",
        evaluator_model="stub",
        budget=budget,
        rng=random.Random(0),
    )
    memory = SharedMemory("scan-fuzz-e2e", root_dir=tmp_path)
    report = await agent.run(_ToolTarget(), memory)
    assert report.turns > 0

    memory_file = tmp_path / "scan-fuzz-e2e" / "memory.jsonl"
    valid = {s.probe_id for s in agent.seeds_for_category()}

    reflection_seed_ids: set[str] = set()
    for line in memory_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("record_type") != "reflection":
            continue
        content = rec["payload"].get("content")
        if not isinstance(content, str):
            continue
        try:
            turn = json.loads(content)
        except json.JSONDecodeError:
            continue
        sid = turn.get("seed_id")
        assert sid, f"fuzz reflection missing seed_id: {turn}"
        reflection_seed_ids.add(sid)
        assert sid.split("-mutant-", 1)[0] in valid, f"unattributed fuzz seed_id: {sid!r}"

    assert reflection_seed_ids, "no fuzz seed_ids threaded through"
    # Every seed_id must surface the dedicated corpus, never the synthetic id.
    assert all(s.startswith("ASI02-FUZZ-") for s in reflection_seed_ids)
    assert "fuzzing-agent-ASI02" not in reflection_seed_ids

    # Findings carry the real corpus probe id, not the synthetic fallback.
    findings = list(memory.all_findings())
    assert findings, "expected at least one fuzz finding"
    for f in findings:
        assert f.probe_id.startswith("ASI02-FUZZ-"), f.probe_id

    # Coverage attributes attempted probes to the dedicated corpus.
    cov = compute_coverage_from_memory(_stub_scan("scan-fuzz-e2e"), memory_path=memory_file)
    assert cov["probes_attempted"], "probes_attempted must be populated"
    for pid in cov["probes_attempted"]:
        assert pid.split("-mutant-", 1)[0] in valid
