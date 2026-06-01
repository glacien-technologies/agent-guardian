"""ScanScope + ScanBudget — Phase C.C6 primitives.

These are *declarative* limits an operator can attach to a SwarmConfig at
T3+ tier. Both classes are immutable and default to "no limit" — operator
opt-in only, per the no-arbitrary-hardcoded-caps rule. The CLI surfaces
each field as an optional flag; when the flag is omitted the corresponding
field is ``None`` and the swarm runs uncapped on that axis.

``ScanScope`` answers *what* the swarm is allowed to touch (tools, domains,
hard-abort predicates, cost ceiling).

``ScanBudget`` answers *how much* the swarm may spend on tokens/USD,
optionally with per-strategy sub-caps so a noisy strategy can be reined in
without truncating the whole scan.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ScanScope:
    """Declarative scope envelope for a scan.

    Every field defaults to ``None`` / empty so an operator who attaches a
    bare ``ScanScope()`` opts into the primitive without imposing any caps.
    Only fields they explicitly set restrict the swarm.

    Fields:
      allowed_tools: when set, the swarm may only invoke target tools whose
        name is in this set. ``None`` = no restriction. Use a small set for
        tight-scope production audits.
      allowed_domains: HTTP egress allowlist (host names). ``None`` = no
        restriction. The adapter checks this before each request.
      max_cost_usd: hard ceiling. Swarm watchdog trips at this value and the
        ``stopped_reason`` records ``"scope_max_cost_usd_tripped"``. ``None``
        = uncapped (operator did not opt in).
      hard_abort_predicates: tuple of predicate *names* registered with the
        :class:`SwarmCommander`. Each is evaluated after every checkpoint;
        any True result aborts the scan with ``stopped_reason`` set to the
        predicate name. Empty tuple = no abort predicates.
    """

    allowed_tools: frozenset[str] | None = None
    allowed_domains: frozenset[str] | None = None
    max_cost_usd: float | None = None
    hard_abort_predicates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Fail fast on obvious operator errors so the panel surfaces at scan
        # start, not 10 minutes in.
        if self.max_cost_usd is not None and self.max_cost_usd <= 0:
            raise ValueError(
                f"ScanScope.max_cost_usd must be > 0 when set; got {self.max_cost_usd!r}"
            )
        if self.allowed_tools is not None and not all(
            isinstance(t, str) and t for t in self.allowed_tools
        ):
            raise ValueError("ScanScope.allowed_tools entries must be non-empty strings")

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> ScanScope:
        """Build a ScanScope from a YAML/JSON-shaped dict.

        Lists are coerced to frozensets / tuples as appropriate so the
        result is immutable regardless of how the operator authored the
        config.
        """
        return cls(
            allowed_tools=frozenset(d["allowed_tools"])
            if d.get("allowed_tools") is not None
            else None,
            allowed_domains=frozenset(d["allowed_domains"])
            if d.get("allowed_domains") is not None
            else None,
            max_cost_usd=d.get("max_cost_usd"),
            hard_abort_predicates=tuple(d.get("hard_abort_predicates") or ()),
        )

    def to_dict(self) -> dict[str, Any]:
        """Round-trip-safe dict form (sorted lists for deterministic output)."""
        return {
            "allowed_tools": sorted(self.allowed_tools) if self.allowed_tools is not None else None,
            "allowed_domains": sorted(self.allowed_domains)
            if self.allowed_domains is not None
            else None,
            "max_cost_usd": self.max_cost_usd,
            "hard_abort_predicates": list(self.hard_abort_predicates),
        }

    def tool_is_allowed(self, tool_name: str) -> bool:
        """Single-tool gate. Returns True when no restriction is in effect."""
        return self.allowed_tools is None or tool_name in self.allowed_tools

    def domain_is_allowed(self, domain: str) -> bool:
        """Single-domain gate. Returns True when no restriction is in effect."""
        return self.allowed_domains is None or domain in self.allowed_domains


@dataclass(frozen=True, slots=True)
class ScanBudget:
    """Declarative spend envelope for a scan.

    Two axes: total tokens and total USD. Plus a per-strategy mapping for
    fine-grained throttling of noisy strategies without truncating the
    whole scan. All fields default to ``None`` (uncapped) per the
    no-arbitrary-hardcoded-caps rule.

    The per-strategy mapping is a frozen view; assigning to it raises (the
    dataclass is frozen) but the underlying dict is defensively copied at
    ``__post_init__`` so callers can't mutate it after construction.
    """

    max_tokens: int | None = None
    max_usd: float | None = None
    per_strategy_caps: Mapping[str, int] | None = field(default=None)

    def __post_init__(self) -> None:
        if self.max_tokens is not None and self.max_tokens <= 0:
            raise ValueError(f"ScanBudget.max_tokens must be > 0 when set; got {self.max_tokens!r}")
        if self.max_usd is not None and self.max_usd <= 0:
            raise ValueError(f"ScanBudget.max_usd must be > 0 when set; got {self.max_usd!r}")
        if self.per_strategy_caps is not None:
            # Validate before defensive freeze so we surface bad input early.
            for name, cap in self.per_strategy_caps.items():
                if not isinstance(name, str) or not name:
                    raise ValueError("ScanBudget.per_strategy_caps keys must be non-empty strings")
                if not isinstance(cap, int) or cap <= 0:
                    raise ValueError(
                        f"ScanBudget.per_strategy_caps[{name!r}] must be a positive int; got {cap!r}"
                    )
            # Defensive copy — frozen dataclass can't reassign self.per_strategy_caps
            # via simple `self.per_strategy_caps = ...`, so use object.__setattr__.
            object.__setattr__(self, "per_strategy_caps", dict(self.per_strategy_caps))

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> ScanBudget:
        return cls(
            max_tokens=d.get("max_tokens"),
            max_usd=d.get("max_usd"),
            per_strategy_caps=d.get("per_strategy_caps"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_tokens": self.max_tokens,
            "max_usd": self.max_usd,
            "per_strategy_caps": dict(self.per_strategy_caps)
            if self.per_strategy_caps is not None
            else None,
        }

    def strategy_cap(self, strategy_name: str) -> int | None:
        """Return the cap for one strategy, or None if no per-strategy entry."""
        if self.per_strategy_caps is None:
            return None
        return self.per_strategy_caps.get(strategy_name)


__all__ = ["ScanBudget", "ScanScope"]
