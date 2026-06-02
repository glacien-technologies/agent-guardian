"""Phase C.C6 — ScanScope + ScanBudget primitives.

Tests cover: default-None semantics (no caps), immutability (frozen),
fail-fast validation, round-trip dict↔dataclass, and the per-axis gate
helpers (``tool_is_allowed``, ``domain_is_allowed``, ``strategy_cap``).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from agent_guardian.core.scope import ScanBudget, ScanScope

# --------------------------------------------------------------------------- #
# ScanScope
# --------------------------------------------------------------------------- #


class TestScanScopeDefaults:
    def test_bare_scope_imposes_no_caps(self) -> None:
        s = ScanScope()
        assert s.allowed_tools is None
        assert s.allowed_domains is None
        assert s.max_cost_usd is None
        assert s.hard_abort_predicates == ()

    def test_tool_gate_allows_everything_by_default(self) -> None:
        assert ScanScope().tool_is_allowed("drop_table") is True
        assert ScanScope().tool_is_allowed("any-tool-name") is True

    def test_domain_gate_allows_everything_by_default(self) -> None:
        assert ScanScope().domain_is_allowed("evil.example.com") is True


class TestScanScopeRestrictions:
    def test_allowed_tools_subset_enforcement(self) -> None:
        s = ScanScope(allowed_tools=frozenset({"read_file", "list_dir"}))
        assert s.tool_is_allowed("read_file") is True
        assert s.tool_is_allowed("drop_table") is False

    def test_allowed_domains_subset_enforcement(self) -> None:
        s = ScanScope(allowed_domains=frozenset({"api.customer.com"}))
        assert s.domain_is_allowed("api.customer.com") is True
        assert s.domain_is_allowed("api.attacker.com") is False

    def test_hard_abort_predicates_stored_as_tuple(self) -> None:
        s = ScanScope(hard_abort_predicates=("budget_exceeded", "tier_mismatch"))
        assert s.hard_abort_predicates == ("budget_exceeded", "tier_mismatch")


class TestScanScopeValidation:
    def test_negative_max_cost_usd_raises(self) -> None:
        with pytest.raises(ValueError, match="max_cost_usd must be > 0"):
            ScanScope(max_cost_usd=-1.0)

    def test_zero_max_cost_usd_raises(self) -> None:
        with pytest.raises(ValueError, match="max_cost_usd must be > 0"):
            ScanScope(max_cost_usd=0.0)

    def test_empty_string_tool_name_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty strings"):
            ScanScope(allowed_tools=frozenset({"", "read_file"}))


class TestScanScopeImmutability:
    def test_cannot_reassign_field(self) -> None:
        s = ScanScope()
        with pytest.raises(FrozenInstanceError):
            s.max_cost_usd = 0.50  # type: ignore[misc]


class TestScanScopeRoundTrip:
    def test_round_trip_empty(self) -> None:
        s = ScanScope()
        s2 = ScanScope.from_dict(s.to_dict())
        assert s == s2

    def test_round_trip_populated(self) -> None:
        s = ScanScope(
            allowed_tools=frozenset({"read_file", "list_dir"}),
            allowed_domains=frozenset({"api.customer.com"}),
            max_cost_usd=2.50,
            hard_abort_predicates=("budget_exceeded",),
        )
        s2 = ScanScope.from_dict(s.to_dict())
        assert s == s2

    def test_to_dict_lists_are_sorted(self) -> None:
        # Deterministic output for YAML diffs.
        s = ScanScope(allowed_tools=frozenset({"zebra", "alpha", "mango"}))
        d = s.to_dict()
        assert d["allowed_tools"] == ["alpha", "mango", "zebra"]


# --------------------------------------------------------------------------- #
# ScanBudget
# --------------------------------------------------------------------------- #


class TestScanBudgetDefaults:
    def test_bare_budget_imposes_no_caps(self) -> None:
        b = ScanBudget()
        assert b.max_tokens is None
        assert b.max_usd is None
        assert b.per_strategy_caps is None

    def test_strategy_cap_returns_none_when_no_map(self) -> None:
        assert ScanBudget().strategy_cap("crescendo") is None


class TestScanBudgetRestrictions:
    def test_max_tokens_stored(self) -> None:
        assert ScanBudget(max_tokens=100_000).max_tokens == 100_000

    def test_max_usd_stored(self) -> None:
        assert ScanBudget(max_usd=2.5).max_usd == 2.5

    def test_per_strategy_caps_lookup(self) -> None:
        b = ScanBudget(per_strategy_caps={"crescendo": 5, "pair": 10})
        assert b.strategy_cap("crescendo") == 5
        assert b.strategy_cap("pair") == 10
        assert b.strategy_cap("unknown") is None


class TestScanBudgetValidation:
    def test_negative_max_tokens_raises(self) -> None:
        with pytest.raises(ValueError, match="max_tokens must be > 0"):
            ScanBudget(max_tokens=-1)

    def test_zero_max_tokens_raises(self) -> None:
        with pytest.raises(ValueError, match="max_tokens must be > 0"):
            ScanBudget(max_tokens=0)

    def test_negative_max_usd_raises(self) -> None:
        with pytest.raises(ValueError, match="max_usd must be > 0"):
            ScanBudget(max_usd=-0.01)

    def test_empty_strategy_name_in_caps_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty strings"):
            ScanBudget(per_strategy_caps={"": 5})

    def test_negative_strategy_cap_raises(self) -> None:
        with pytest.raises(ValueError, match="positive int"):
            ScanBudget(per_strategy_caps={"crescendo": -1})


class TestScanBudgetImmutability:
    def test_cannot_reassign_field(self) -> None:
        b = ScanBudget()
        with pytest.raises(FrozenInstanceError):
            b.max_tokens = 1000  # type: ignore[misc]

    def test_per_strategy_caps_defensively_copied(self) -> None:
        # Mutating the input dict after construction must not leak through.
        src = {"crescendo": 5}
        b = ScanBudget(per_strategy_caps=src)
        src["crescendo"] = 999
        assert b.strategy_cap("crescendo") == 5


class TestScanBudgetRoundTrip:
    def test_round_trip_empty(self) -> None:
        b = ScanBudget()
        b2 = ScanBudget.from_dict(b.to_dict())
        assert b == b2

    def test_round_trip_populated(self) -> None:
        b = ScanBudget(
            max_tokens=100_000,
            max_usd=2.5,
            per_strategy_caps={"crescendo": 5, "pair": 10},
        )
        b2 = ScanBudget.from_dict(b.to_dict())
        assert b == b2
