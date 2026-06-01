"""Phase C.C1 — MultiTurnPlan first-class.

Covers: TurnSpec validation + immutability, MultiTurnPlan validation,
MultiTurnPlanStrategy execution semantics (turn-by-turn emission,
success/abort predicates, retry branching, template rendering with
safe-missing-fallback), and the Strategy ABC interface compliance.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import NextPrompt, StrategyContext, StrategyDone
from agent_guardian.strategies.multi_turn_plan import (
    MultiTurnPlan,
    MultiTurnPlanStrategy,
    TurnRecord,
    TurnSpec,
)


def _ctx(tmp_path: Path, *, seed: int = 0) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ack"),
        attacker_model="stub-model",
        goal="extract secret",
        seeds=["seed-1"],
        memory=SharedMemory(f"scan-c1-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=10,
    )


def _never(records: tuple[TurnRecord, ...]) -> bool:
    del records
    return False


# --------------------------------------------------------------------------- #
# TurnSpec
# --------------------------------------------------------------------------- #


class TestTurnSpecValidation:
    def test_minimal_valid_spec(self) -> None:
        spec = TurnSpec(
            role="attacker", prompt_template="ask {goal}", expected_outcome="probe lands"
        )
        assert spec.role == "attacker"
        assert spec.branch_on_failure == "next"  # default

    def test_invalid_role_raises(self) -> None:
        with pytest.raises(ValueError, match="must be 'attacker' or 'verify'"):
            TurnSpec(role="bogus", prompt_template="x", expected_outcome="y")  # type: ignore[arg-type]

    def test_empty_template_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            TurnSpec(role="attacker", prompt_template="", expected_outcome="y")

    def test_invalid_branch_on_failure_raises(self) -> None:
        with pytest.raises(ValueError, match=r"abort.*retry.*next"):
            TurnSpec(
                role="attacker", prompt_template="x", expected_outcome="y", branch_on_failure="loop"
            )  # type: ignore[arg-type]


class TestTurnSpecImmutability:
    def test_cannot_reassign_field(self) -> None:
        spec = TurnSpec(role="attacker", prompt_template="x", expected_outcome="y")
        with pytest.raises(FrozenInstanceError):
            spec.role = "verify"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# MultiTurnPlan
# --------------------------------------------------------------------------- #


class TestMultiTurnPlanValidation:
    def test_minimal_valid_plan(self) -> None:
        plan = MultiTurnPlan(
            goal="extract system prompt",
            planned_turns=(
                TurnSpec(role="attacker", prompt_template="ask", expected_outcome="ok"),
            ),
            success_predicate=_never,
            abort_predicate=_never,
        )
        assert plan.goal == "extract system prompt"
        assert len(plan.planned_turns) == 1

    def test_empty_goal_raises(self) -> None:
        with pytest.raises(ValueError, match="goal must be non-empty"):
            MultiTurnPlan(
                goal="",
                planned_turns=(
                    TurnSpec(role="attacker", prompt_template="x", expected_outcome="y"),
                ),
                success_predicate=_never,
                abort_predicate=_never,
            )

    def test_empty_planned_turns_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one TurnSpec"):
            MultiTurnPlan(
                goal="g",
                planned_turns=(),
                success_predicate=_never,
                abort_predicate=_never,
            )

    def test_non_callable_predicate_raises(self) -> None:
        with pytest.raises(ValueError, match="success_predicate must be callable"):
            MultiTurnPlan(
                goal="g",
                planned_turns=(
                    TurnSpec(role="attacker", prompt_template="x", expected_outcome="y"),
                ),
                success_predicate="not callable",  # type: ignore[arg-type]
                abort_predicate=_never,
            )


class TestMultiTurnPlanImmutability:
    def test_cannot_reassign_field(self) -> None:
        plan = MultiTurnPlan(
            goal="g",
            planned_turns=(TurnSpec(role="attacker", prompt_template="x", expected_outcome="y"),),
            success_predicate=_never,
            abort_predicate=_never,
        )
        with pytest.raises(FrozenInstanceError):
            plan.goal = "different"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# MultiTurnPlanStrategy execution
# --------------------------------------------------------------------------- #


def _plan_3_turns(success_pred=_never, abort_pred=_never) -> MultiTurnPlan:
    """Construct a 3-turn plan with placeholder substitution."""
    return MultiTurnPlan(
        goal="extract secret",
        planned_turns=(
            TurnSpec(role="attacker", prompt_template="Turn1: {goal}", expected_outcome="opener"),
            TurnSpec(
                role="attacker",
                prompt_template="Turn2: ref {prev_response}",
                expected_outcome="follow-up",
            ),
            TurnSpec(
                role="verify",
                prompt_template="Turn3: did target leak?",
                expected_outcome="judge call",
            ),
        ),
        success_predicate=success_pred,
        abort_predicate=abort_pred,
        name="three_turn_test",
    )


class TestStrategyExecution:
    def test_emits_first_turn_with_goal_substituted(self, tmp_path) -> None:
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), _plan_3_turns())
        result = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(result, NextPrompt)
        assert "extract secret" in result.text
        assert result.metadata["turn_index"] == 0
        assert strategy.turn_count() == 1

    def test_advances_through_all_planned_turns_then_exhausts(self, tmp_path) -> None:
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), _plan_3_turns())
        for expected_idx in range(3):
            result = asyncio.run(strategy.generate_next(history=[], target_response=None))
            assert isinstance(result, NextPrompt)
            assert result.metadata["turn_index"] == expected_idx
            strategy.record_observation(
                response=f"target said {expected_idx}", verdict="pass", confidence=0.5
            )
        # 4th call: plan exhausted
        result = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(result, StrategyDone)
        assert result.reason == "exhausted"

    def test_success_predicate_short_circuits(self, tmp_path) -> None:
        strategy = MultiTurnPlanStrategy(
            _ctx(tmp_path), _plan_3_turns(success_pred=lambda rs: len(rs) >= 1)
        )
        # First turn emits.
        r1 = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(r1, NextPrompt)
        strategy.record_observation(response="target leaked", verdict="fail", confidence=0.9)
        # Predicate evaluates True before the second turn → success.
        r2 = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(r2, StrategyDone)
        assert r2.reason == "success"

    def test_abort_predicate_short_circuits(self, tmp_path) -> None:
        strategy = MultiTurnPlanStrategy(
            _ctx(tmp_path), _plan_3_turns(abort_pred=lambda rs: len(rs) >= 1)
        )
        asyncio.run(strategy.generate_next(history=[], target_response=None))
        strategy.record_observation(
            response="target refused cleanly", verdict="pass", confidence=0.9
        )
        r2 = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(r2, StrategyDone)
        assert r2.reason == "refused"

    def test_predicate_exception_treated_as_exhausted(self, tmp_path) -> None:
        def _broken(records: tuple[TurnRecord, ...]) -> bool:
            raise RuntimeError("predicate is buggy")

        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), _plan_3_turns(success_pred=_broken))
        asyncio.run(strategy.generate_next(history=[], target_response=None))
        strategy.record_observation(response="x", verdict="pass", confidence=0.5)
        r = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(r, StrategyDone)
        assert r.reason == "exhausted"

    def test_record_observation_before_emit_raises(self, tmp_path) -> None:
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), _plan_3_turns())
        with pytest.raises(RuntimeError, match="before any generate_next"):
            strategy.record_observation(response="bogus")


class TestTemplateRendering:
    def test_missing_variable_renders_placeholder(self, tmp_path) -> None:
        plan = MultiTurnPlan(
            goal="g",
            planned_turns=(
                TurnSpec(
                    role="attacker", prompt_template="hello {missing_var}", expected_outcome="x"
                ),
            ),
            success_predicate=_never,
            abort_predicate=_never,
        )
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), plan)
        result = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(result, NextPrompt)
        assert "<missing:missing_var>" in result.text

    def test_context_vars_substituted(self, tmp_path) -> None:
        plan = MultiTurnPlan(
            goal="g",
            planned_turns=(
                TurnSpec(role="attacker", prompt_template="ctx={mykey}", expected_outcome="x"),
            ),
            success_predicate=_never,
            abort_predicate=_never,
        )
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), plan, context_vars={"mykey": "VALUE"})
        result = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(result, NextPrompt)
        assert "ctx=VALUE" in result.text

    def test_prev_response_threaded_through(self, tmp_path) -> None:
        plan = MultiTurnPlan(
            goal="g",
            planned_turns=(
                TurnSpec(role="attacker", prompt_template="opener", expected_outcome="x"),
                TurnSpec(
                    role="attacker",
                    prompt_template="reply was: {prev_response}",
                    expected_outcome="y",
                ),
            ),
            success_predicate=_never,
            abort_predicate=_never,
        )
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), plan)
        asyncio.run(strategy.generate_next(history=[], target_response=None))
        strategy.record_observation(response="HELLO_FROM_TARGET", verdict="pass", confidence=0.5)
        r2 = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(r2, NextPrompt)
        assert "HELLO_FROM_TARGET" in r2.text


class TestStrategyAbcCompliance:
    def test_records_is_immutable_tuple(self, tmp_path) -> None:
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), _plan_3_turns())
        asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(strategy.records, tuple)

    def test_strategy_name_set(self, tmp_path) -> None:
        assert MultiTurnPlanStrategy.name == "multi_turn_plan"

    def test_done_state_is_terminal(self, tmp_path) -> None:
        # Exhaust the plan, then call again — must keep returning StrategyDone.
        strategy = MultiTurnPlanStrategy(_ctx(tmp_path), _plan_3_turns())
        for _ in range(3):
            asyncio.run(strategy.generate_next(history=[], target_response=None))
            strategy.record_observation(response="x", verdict="pass", confidence=0.5)
        r1 = asyncio.run(strategy.generate_next(history=[], target_response=None))
        r2 = asyncio.run(strategy.generate_next(history=[], target_response=None))
        assert isinstance(r1, StrategyDone)
        assert isinstance(r2, StrategyDone)
