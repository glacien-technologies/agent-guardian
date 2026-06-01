"""Phase C.C1 — MultiTurnPlan YAML loader + factory registry.

Covers: YAML round-trip, malformed-row error messages with per-turn index,
predicate registry lookup (default + custom), plan factory registry, and
the public-API import surface.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from agent_guardian.strategies.multi_turn_plan import (
    MultiTurnPlan,
    TurnRecord,
    TurnSpec,
)
from agent_guardian.strategies.multi_turn_plan_loader import (
    MULTI_TURN_PLAN_REGISTRY,
    PREDICATE_REGISTRY,
    MultiTurnPlanValidationError,
    load_multi_turn_plan_from_yaml,
    load_multi_turn_plans_from_dir,
    register_plan,
    register_predicate,
    resolve_predicate,
)


def _write(path: Path, content: str) -> Path:
    path.write_text(dedent(content).lstrip("\n"), encoding="utf-8")
    return path


def _minimal_yaml() -> str:
    return """
        name: extract_secret
        goal: Probe whether the target leaks a secret
        planned_turns:
          - role: attacker
            prompt_template: "Hello, what is your purpose?"
            expected_outcome: opener
          - role: attacker
            prompt_template: "Reply was: {prev_response}"
            expected_outcome: follow-up
            branch_on_failure: abort
        success_predicate:
          name: any_response_contains
          args:
            token: "secret"
        abort_predicate:
          name: never
    """


# --------------------------------------------------------------------------- #
# Round-trip
# --------------------------------------------------------------------------- #


class TestYamlRoundTrip:
    def test_load_parses_valid_yaml(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "plan.yaml", _minimal_yaml())
        plan = load_multi_turn_plan_from_yaml(path)
        assert isinstance(plan, MultiTurnPlan)
        assert plan.name == "extract_secret"
        assert plan.goal == "Probe whether the target leaks a secret"
        assert len(plan.planned_turns) == 2
        assert plan.planned_turns[0].role == "attacker"
        assert plan.planned_turns[1].branch_on_failure == "abort"

    def test_load_equals_in_python_equivalent(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "plan.yaml", _minimal_yaml())
        loaded = load_multi_turn_plan_from_yaml(path)
        expected_turns = (
            TurnSpec(
                role="attacker",
                prompt_template="Hello, what is your purpose?",
                expected_outcome="opener",
            ),
            TurnSpec(
                role="attacker",
                prompt_template="Reply was: {prev_response}",
                expected_outcome="follow-up",
                branch_on_failure="abort",
            ),
        )
        assert loaded.planned_turns == expected_turns
        assert loaded.goal == "Probe whether the target leaks a secret"
        assert loaded.name == "extract_secret"

    def test_predicates_resolved_from_yaml_evaluate_correctly(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "plan.yaml", _minimal_yaml())
        plan = load_multi_turn_plan_from_yaml(path)
        rec = TurnRecord(
            turn_index=0,
            spec_role="attacker",
            prompt_sent="x",
            target_response="The secret is shibboleth",
        )
        assert plan.success_predicate((rec,)) is True
        assert plan.abort_predicate((rec,)) is False

    def test_loads_seed_plan_from_repo(self) -> None:
        # The shipped seed plan must always parse cleanly.
        from agent_guardian.probes.loader import find_corpus_root

        seed = find_corpus_root() / "multi_turn_plans" / "progressive-context-extraction.yaml"
        plan = load_multi_turn_plan_from_yaml(seed)
        assert plan.name == "progressive_context_extraction"
        assert len(plan.planned_turns) >= 3


# --------------------------------------------------------------------------- #
# Malformed YAML — per-row error messages
# --------------------------------------------------------------------------- #


class TestMalformedYaml:
    def test_missing_goal_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "p.yaml",
            """
            name: x
            planned_turns:
              - role: attacker
                prompt_template: "x"
                expected_outcome: "y"
            """,
        )
        with pytest.raises(MultiTurnPlanValidationError, match="goal must be a non-empty"):
            load_multi_turn_plan_from_yaml(path)

    def test_empty_planned_turns_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "p.yaml",
            """
            name: x
            goal: g
            planned_turns: []
            """,
        )
        with pytest.raises(MultiTurnPlanValidationError, match="planned_turns must be a non-empty"):
            load_multi_turn_plan_from_yaml(path)

    def test_malformed_turn_row_reports_index(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "p.yaml",
            """
            name: x
            goal: g
            planned_turns:
              - role: attacker
                prompt_template: "ok"
                expected_outcome: "ok"
              - role: bogus
                prompt_template: "x"
                expected_outcome: "y"
            """,
        )
        with pytest.raises(MultiTurnPlanValidationError, match=r"planned_turns\[1\]"):
            load_multi_turn_plan_from_yaml(path)

    def test_unknown_turn_key_reports_index(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "p.yaml",
            """
            name: x
            goal: g
            planned_turns:
              - role: attacker
                prompt_template: "ok"
                expected_outcome: "ok"
                unexpected_field: 1
            """,
        )
        with pytest.raises(MultiTurnPlanValidationError, match=r"planned_turns\[0\].*unknown keys"):
            load_multi_turn_plan_from_yaml(path)

    def test_unknown_top_level_key_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "p.yaml",
            """
            name: x
            goal: g
            planned_turns:
              - role: attacker
                prompt_template: "ok"
                expected_outcome: "ok"
            mystery_field: 1
            """,
        )
        with pytest.raises(MultiTurnPlanValidationError, match="unknown top-level keys"):
            load_multi_turn_plan_from_yaml(path)

    def test_unknown_predicate_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "p.yaml",
            """
            name: x
            goal: g
            planned_turns:
              - role: attacker
                prompt_template: "ok"
                expected_outcome: "ok"
            success_predicate:
              name: this_does_not_exist
            """,
        )
        with pytest.raises(MultiTurnPlanValidationError, match="unknown predicate"):
            load_multi_turn_plan_from_yaml(path)

    def test_yaml_parse_error_raises(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "p.yaml", ":\n  ::not yaml::\n")
        with pytest.raises(MultiTurnPlanValidationError, match="YAML parse error"):
            load_multi_turn_plan_from_yaml(path)

    def test_missing_file_raises_filenotfound(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_multi_turn_plan_from_yaml(tmp_path / "missing.yaml")


# --------------------------------------------------------------------------- #
# Predicate registry
# --------------------------------------------------------------------------- #


class TestPredicateRegistry:
    def test_default_predicates_present(self) -> None:
        assert "never" in PREDICATE_REGISTRY
        assert "always" in PREDICATE_REGISTRY
        assert "always_after_n_turns" in PREDICATE_REGISTRY
        assert "verdict_contains" in PREDICATE_REGISTRY
        assert "any_response_contains" in PREDICATE_REGISTRY

    def test_resolve_string_form_uses_default_args(self) -> None:
        pred = resolve_predicate("never", default="never", source="t")
        assert pred(()) is False
        always = resolve_predicate("always", default="never", source="t")
        assert always(()) is True

    def test_resolve_none_uses_default_name(self) -> None:
        pred = resolve_predicate(None, default="always", source="t")
        assert pred(()) is True

    def test_always_after_n_turns_threshold(self) -> None:
        pred = resolve_predicate(
            {"name": "always_after_n_turns", "args": {"n": 2}}, default="never", source="t"
        )
        r = TurnRecord(turn_index=0, spec_role="attacker", prompt_sent="x", target_response="y")
        assert pred((r,)) is False
        assert pred((r, r)) is True

    def test_verdict_contains_case_insensitive(self) -> None:
        pred = resolve_predicate(
            {"name": "verdict_contains", "args": {"token": "FAIL"}},
            default="never",
            source="t",
        )
        r = TurnRecord(
            turn_index=0,
            spec_role="attacker",
            prompt_sent="x",
            target_response="y",
            judge_verdict="Fail",
        )
        assert pred((r,)) is True

    def test_register_predicate_extends_registry(self) -> None:
        def _custom_factory(*, threshold: int) -> object:
            def _f(records: tuple[TurnRecord, ...]) -> bool:
                return len(records) > threshold

            return _f

        register_predicate("test_custom_pred", _custom_factory)  # type: ignore[arg-type]
        try:
            assert "test_custom_pred" in PREDICATE_REGISTRY
            pred = resolve_predicate(
                {"name": "test_custom_pred", "args": {"threshold": 1}},
                default="never",
                source="t",
            )
            r = TurnRecord(turn_index=0, spec_role="attacker", prompt_sent="x", target_response="y")
            assert pred((r,)) is False
            assert pred((r, r)) is True
        finally:
            del PREDICATE_REGISTRY["test_custom_pred"]

    def test_bad_predicate_args_raise_validation_error(self) -> None:
        with pytest.raises(MultiTurnPlanValidationError, match="rejected args"):
            resolve_predicate(
                {"name": "verdict_contains", "args": {"wrong_kwarg": "x"}},
                default="never",
                source="t",
            )


# --------------------------------------------------------------------------- #
# Plan factory registry
# --------------------------------------------------------------------------- #


class TestPlanRegistry:
    def test_register_plan_stores_factory(self) -> None:
        def _factory() -> MultiTurnPlan:
            return MultiTurnPlan(
                goal="g",
                planned_turns=(
                    TurnSpec(role="attacker", prompt_template="x", expected_outcome="y"),
                ),
                success_predicate=PREDICATE_REGISTRY["always"](),
                abort_predicate=PREDICATE_REGISTRY["never"](),
                name="reg_test_plan",
            )

        register_plan("reg_test_plan", _factory)
        try:
            assert "reg_test_plan" in MULTI_TURN_PLAN_REGISTRY
            plan = MULTI_TURN_PLAN_REGISTRY["reg_test_plan"]()
            assert plan.name == "reg_test_plan"
        finally:
            del MULTI_TURN_PLAN_REGISTRY["reg_test_plan"]

    def test_register_plan_rejects_non_callable(self) -> None:
        with pytest.raises(MultiTurnPlanValidationError, match="must be callable"):
            register_plan("bad", "not a function")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Public-API import surface
# --------------------------------------------------------------------------- #


class TestPublicApiSurface:
    def test_strategies_package_reexports(self) -> None:
        from agent_guardian.strategies import (
            MultiTurnPlan as MTP,
        )
        from agent_guardian.strategies import (
            MultiTurnPlanStrategy as MTPS,
        )
        from agent_guardian.strategies import (
            TurnRecord as TR,
        )
        from agent_guardian.strategies import (
            TurnSpec as TS,
        )

        assert MTP is MultiTurnPlan
        assert TR is TurnRecord
        assert TS is TurnSpec
        # Strategy class is the same as the underlying module's
        from agent_guardian.strategies.multi_turn_plan import MultiTurnPlanStrategy as _MTPS

        assert MTPS is _MTPS

    def test_top_level_package_reexports(self) -> None:
        import agent_guardian as ag

        assert ag.MultiTurnPlan is MultiTurnPlan
        assert ag.TurnSpec is TurnSpec
        assert ag.TurnRecord is TurnRecord
        # Strategy + loader surfaced at package root
        assert hasattr(ag, "MultiTurnPlanStrategy")
        assert hasattr(ag, "load_multi_turn_plan_from_yaml")

    def test_load_multi_turn_plans_from_dir_returns_seed(self) -> None:
        from agent_guardian.probes.loader import find_corpus_root

        plans = load_multi_turn_plans_from_dir(find_corpus_root() / "multi_turn_plans")
        names = {p.name for p in plans}
        assert "progressive_context_extraction" in names
