"""A1 — per-seed delivery-vector routing.

``Scenario.delivery_vector`` (8 channel types) used to be dropped when a
goal-specific scenario was converted to a ``ProbeSeed`` — every attack went out
as plain user input (or, with the global ``enable_indirect`` toggle, a RANDOM
rotating channel). Now ``ProbeSeed`` carries ``delivery_vector`` and the strategy
renders a TARGETED indirect-delivery directive for that channel, falling back to
the global toggle only when a seed has no vector.
"""

from __future__ import annotations

import pathlib
import random
import tempfile

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import ProbeSeed, StrategyContext
from agent_guardian.strategies.indirect import render_indirect_directive_for
from agent_guardian.strategies.pair import PAIRStrategy


def test_probe_seed_carries_delivery_vector() -> None:
    s = ProbeSeed(probe_id="X-1", text="hi", delivery_vector="rag_doc")
    assert s.delivery_vector == "rag_doc"
    # Default stays None so existing seeds are unaffected.
    assert ProbeSeed(probe_id="X-2", text="hi").delivery_vector is None


def test_render_indirect_directive_for_specific_vector() -> None:
    rng = random.Random(0)
    rag = render_indirect_directive_for("rag_doc", rng).lower()
    assert "document" in rag or "retriev" in rag
    # memory_write (DeliveryVector spelling) maps to the memory-note framing.
    mem = render_indirect_directive_for("memory_write", rng).lower()
    assert "memory" in mem
    # An unknown / code_artifact vector still yields a non-empty targeted frame.
    other = render_indirect_directive_for("code_artifact", rng)
    assert other.strip()
    assert "code_artifact" in other or "code" in other.lower()


def _ctx(seeds: list[ProbeSeed]) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ok"),
        attacker_model="stub",
        goal="redirect the agent",
        seeds=list(seeds),
        memory=SharedMemory("dv", root_dir=pathlib.Path(tempfile.mkdtemp())),
        rng=random.Random(0),
    )


def test_strategy_routes_active_seed_vector() -> None:
    seed = ProbeSeed(probe_id="ASI01-GS-1", text="do the thing", delivery_vector="rag_doc")
    ctx = _ctx([seed])
    strat = PAIRStrategy(ctx)
    # Simulate the strategy picking the seed (captures its delivery vector).
    strat._build_seed_metadata(seed)
    extra = strat._attack_system_extra()
    assert "INDIRECT-INJECTION DELIVERY" in extra
    assert "rag_doc" in extra  # the targeted vector, not a random rotation


def test_no_vector_and_no_global_toggle_means_no_indirect_directive() -> None:
    seed = ProbeSeed(probe_id="ASI01-GS-2", text="do the thing")  # no delivery_vector
    ctx = _ctx([seed])  # enable_indirect defaults False
    strat = PAIRStrategy(ctx)
    strat._build_seed_metadata(seed)
    extra = strat._attack_system_extra()
    assert "INDIRECT-INJECTION DELIVERY" not in extra


def test_refinement_inherits_the_seed_vector() -> None:
    """A refine turn (``_build_seed_metadata(None)``) keeps delivering via the
    seed's channel rather than reverting to direct/global."""
    seed = ProbeSeed(probe_id="ASI01-GS-3", text="do the thing", delivery_vector="email")
    ctx = _ctx([seed])
    strat = PAIRStrategy(ctx)
    strat._build_seed_metadata(seed)  # turn 1 captures the vector
    strat._build_seed_metadata(None)  # a refine turn inherits it
    extra = strat._attack_system_extra()
    assert "email" in extra
