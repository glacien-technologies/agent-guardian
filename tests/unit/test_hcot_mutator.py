"""Phase B.B5 — H-CoT mutator + YAML probe load tests.

The HCoTMutator class itself is also covered by ``test_mutator.py``. This
module adds the B5-specific assertions:

* the three H-CoT YAML probe files load cleanly under ``Probe`` validation;
* the variant scaffolds for o1 / claude_thinking / gemini_thinking produce
  distinct outputs;
* :meth:`GoalHijackAgent.seeds_for_category` exposes at least 3 H-CoT seeds
  (one per family).
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.probe import load_probe
from agent_guardian.probes.loader import find_corpus_root, seeds_for_asi_with_provenance
from agent_guardian.strategies.mutator import HCoTMutator

# --------------------------------------------------------------------------- #
# Mutator variant assertions
# --------------------------------------------------------------------------- #


def test_hcot_o1_scaffold_contains_thinking_tag() -> None:
    out = HCoTMutator(target_model_family="o1").apply("payload", random.Random(0))
    assert "<thinking>" in out
    assert "payload" in out


def test_hcot_claude_scaffold_contains_extended_thinking_tag() -> None:
    out = HCoTMutator(target_model_family="claude_thinking").apply("payload", random.Random(0))
    assert "<extended_thinking>" in out
    assert "payload" in out


def test_hcot_gemini_scaffold_contains_internal_reasoning_marker() -> None:
    out = HCoTMutator(target_model_family="gemini_thinking").apply("payload", random.Random(0))
    assert "[INTERNAL_REASONING]" in out


def test_hcot_variants_are_distinct() -> None:
    src = "the original ask"
    o1 = HCoTMutator(target_model_family="o1").apply(src, random.Random(0))
    cl = HCoTMutator(target_model_family="claude_thinking").apply(src, random.Random(0))
    gm = HCoTMutator(target_model_family="gemini_thinking").apply(src, random.Random(0))
    assert o1 != cl
    assert cl != gm
    assert o1 != gm


def test_hcot_auto_mode_uses_rng() -> None:
    src = "payload"
    a = HCoTMutator(target_model_family="auto").apply(src, random.Random(0))
    b = HCoTMutator(target_model_family="auto").apply(src, random.Random(5))
    # Both contain the source, and one of the three scaffold markers.
    assert "payload" in a and "payload" in b
    for blob in (a, b):
        assert (
            "<thinking>" in blob or "<extended_thinking>" in blob or "[INTERNAL_REASONING]" in blob
        )


# --------------------------------------------------------------------------- #
# Probe YAML load
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "filename",
    [
        "h-cot-injection-o1.yaml",
        "h-cot-injection-claude-thinking.yaml",
        "h-cot-injection-gemini-thinking.yaml",
    ],
)
def test_hcot_probe_yaml_loads_cleanly(filename: str) -> None:
    path: Path = find_corpus_root() / "asi01" / filename
    assert path.is_file(), f"missing probe file: {path}"
    probe = load_probe(path)
    assert probe.asi == AsiCategory.ASI01
    assert probe.owasp_scenario == "OWASP_ASI01_HCoTInjection"
    assert any(t == "AML.T0054" for t in probe.mitre_atlas)
    assert len(probe.seeds) >= 3


def test_goal_hijack_seeds_include_three_hcot_probes() -> None:
    seeds = seeds_for_asi_with_provenance(AsiCategory.ASI01)
    hcot_ids = sorted({s.probe_id for s in seeds if s.probe_id.startswith("ASI01-HCOT")})
    assert hcot_ids == ["ASI01-HCOT-001", "ASI01-HCOT-002", "ASI01-HCOT-003"]
