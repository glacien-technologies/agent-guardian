"""Phase B.B2 — Sibling map: ASI category -> recommended mutation operators.

The sibling map drives :class:`ReflectiveStrategy` pivots. Each ASI
category maps to an ordered list of operator names (drawn from the
:class:`MutatorRegistry`). When a primary strategy stalls (two consecutive
DEFENDED verdicts) the reflective wrapper pivots to a sibling whose
seeds have been pre-transformed by the chosen operator.

The map is the *source of truth* for "which operators are relevant to
which attack surface" and is consumed by every ASI agent's
``strategy_stack()``.

A sibling is NOT a new strategy class. It is an existing strategy
(:class:`TAPStrategy`, :class:`CrescendoStrategy`, :class:`PAIRStrategy`)
seeded with operator-mutated seeds:

    operator.apply(seed_text, rng) -> mutated_seed
    -> ProbeSeed(probe_id=original + '-mutant-<op>', text=mutated_seed)

The mutated probe_id preserves provenance: the parent probe_id can be
recovered by stripping the ``-mutant-<op>`` suffix (the AsiAgent finding
builder does this lookup in the winning-seed retention paths).
"""

from __future__ import annotations

import functools
import logging
import random
from typing import TYPE_CHECKING

from agent_guardian.models.asi import AsiCategory
from agent_guardian.strategies.mutator import MutatorRegistry

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agent_guardian.strategies.base import ProbeSeed, Strategy, StrategyContext

__all__ = ["SIBLING_MAP", "build_sibling_strategy", "mutate_seeds"]


def _coerce_probe_seeds(seeds: Sequence[ProbeSeed | str]) -> list[ProbeSeed]:
    """Return a list of ProbeSeed objects, wrapping bare strings as needed."""
    from agent_guardian.strategies.base import ProbeSeed

    out: list[ProbeSeed] = []
    for s in seeds:
        if isinstance(s, str):
            out.append(ProbeSeed(probe_id="ad-hoc", text=s))
        else:
            out.append(s)
    return out


_LOG = logging.getLogger("agent_guardian.strategies.sibling_map")


# Source of truth: operators most relevant to each ASI attack surface.
# Drawn directly from the Phase B plan's design_notes — do not reorder
# without updating the docstring above.
SIBLING_MAP: dict[AsiCategory, list[str]] = {
    AsiCategory.ASI01: ["cipher", "low_resource", "flip_attack", "skeleton_key"],
    AsiCategory.ASI02: ["cipher", "many_shot", "pap", "art_prompt"],
    AsiCategory.ASI03: ["skeleton_key", "pap", "low_resource", "deceptive_delight"],
    AsiCategory.ASI04: ["art_prompt", "cipher", "flip_attack"],
    AsiCategory.ASI05: ["h_cot", "cipher", "flip_attack"],
    AsiCategory.ASI06: ["many_shot", "pap", "deceptive_delight"],
    AsiCategory.ASI07: ["skeleton_key", "pap", "cipher"],
    AsiCategory.ASI08: ["many_shot", "bon", "cipher"],
    AsiCategory.ASI09: ["pap", "deceptive_delight", "skeleton_key", "low_resource"],
    AsiCategory.ASI10: ["h_cot", "pap", "flip_attack"],
}


# Validate at import time so a corrupted map fails fast at startup
# instead of mid-scan. All 10 ASI categories must be present; every
# operator name must resolve through the registry; no empty lists.
def _validate_map() -> None:
    known = set(MutatorRegistry.names())
    missing_categories = set(AsiCategory) - set(SIBLING_MAP.keys())
    if missing_categories:
        raise RuntimeError(
            f"sibling map missing categories: {sorted(c.value for c in missing_categories)}"
        )
    for cat, ops in SIBLING_MAP.items():
        if not ops:
            raise RuntimeError(f"sibling map for {cat.value} is empty")
        unknown = [op for op in ops if op not in known]
        if unknown:
            raise RuntimeError(
                f"sibling map for {cat.value} references unknown operators: {unknown}"
            )


_validate_map()


@functools.lru_cache(maxsize=1)
def _log_map_once() -> None:
    """Emit the SIBLING_MAP load line at most once per process.

    Implemented via ``functools.lru_cache(maxsize=1)`` so the idempotent
    behaviour is enforced by the cache (a module-level boolean flag was
    flagged by CodeQL as ``py/unused-global-variable`` because the read
    + write both happen inside the same function under ``global``).
    """
    _LOG.debug(
        "SIBLING_MAP loaded: %d categories mapped",
        len(SIBLING_MAP),
    )


# --------------------------------------------------------------------------- #
# Seed mutation
# --------------------------------------------------------------------------- #


def mutate_seeds(
    seeds: list[ProbeSeed],
    operator_name: str,
    rng: random.Random,
) -> list[ProbeSeed]:
    """Run every seed through ``operator_name`` and return new ProbeSeeds.

    The returned ProbeSeeds carry:

    * ``probe_id = original_probe_id + '-mutant-' + operator_name``
    * ``text     = operator.apply(original.text, rng)``

    The mutant probe_id preserves provenance: stripping the
    ``-mutant-<op>`` suffix recovers the parent.
    """
    from agent_guardian.strategies.base import ProbeSeed

    op = MutatorRegistry.get(operator_name)
    out: list[ProbeSeed] = []
    for seed in seeds:
        # Accept legacy plain-string seeds for back-compat (older test
        # fixtures inject raw strings via StrategyContext.seeds).
        if isinstance(seed, str):
            text = seed
            mutated_text = op.apply(text, rng)
            out.append(
                ProbeSeed(
                    probe_id=f"raw-mutant-{operator_name}",
                    text=mutated_text,
                    asi=None,
                    severity=None,
                )
            )
        else:
            mutated_text = op.apply(seed.text, rng)
            out.append(
                ProbeSeed(
                    probe_id=f"{seed.probe_id}-mutant-{operator_name}",
                    text=mutated_text,
                    asi=seed.asi,
                    severity=seed.severity,
                    mitre_atlas=seed.mitre_atlas,
                    csa_category=seed.csa_category,
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Sibling strategy builder
# --------------------------------------------------------------------------- #


def build_sibling_strategy(
    asi: AsiCategory,
    ctx: StrategyContext,
    primary_strategy: Strategy,
    *,
    max_siblings: int = 2,
) -> list[Strategy]:
    """Construct sibling :class:`Strategy` instances for an ASI category.

    Each sibling is a fresh instance of one of the existing strategy
    classes (currently :class:`CrescendoStrategy` or :class:`TAPStrategy`),
    given a :class:`StrategyContext` whose ``seeds`` have been
    pre-mutated by an operator from ``SIBLING_MAP[asi]``.

    ``primary_strategy`` is provided so the builder can pick a sibling
    class that is structurally different (avoid TAP-as-sibling-of-TAP).
    The cap ``max_siblings`` keeps the strategy pool bounded so a slow
    target does not blow past ``budget.max_turns`` before any sibling
    is exercised.
    """
    from agent_guardian.strategies.base import StrategyContext
    from agent_guardian.strategies.crescendo import CrescendoStrategy
    from agent_guardian.strategies.tap import TAPStrategy

    _log_map_once()

    operators = SIBLING_MAP.get(asi, [])
    _LOG.debug(
        "build_sibling_strategy: asi=%s operators=%s n_siblings=%d",
        asi.value,
        operators,
        min(len(operators), max_siblings),
    )

    siblings: list[Strategy] = []
    primary_class = type(primary_strategy).__name__
    for op_name in operators[:max_siblings]:
        # Pick a sibling class that is structurally different from primary.
        sibling_cls: type[Strategy] = CrescendoStrategy if "TAP" in primary_class else TAPStrategy

        mutated = mutate_seeds(_coerce_probe_seeds(ctx.seeds), op_name, ctx.rng)
        new_ctx = StrategyContext(
            attacker_llm=ctx.attacker_llm,
            attacker_model=ctx.attacker_model,
            goal=ctx.goal,
            seeds=mutated,
            memory=ctx.memory,
            rng=ctx.rng,
            max_turns=ctx.max_turns,
            attack_specialization=ctx.attack_specialization,
            declared_tools=list(ctx.declared_tools),
            declared_memory_keys=list(ctx.declared_memory_keys),
            surface_notes=ctx.surface_notes,
            enable_pretext=ctx.enable_pretext,
            enable_indirect=ctx.enable_indirect,
        )
        sib = sibling_cls(new_ctx)
        siblings.append(sib)
        _LOG.debug(
            "sibling_created: asi=%s operator=%s sibling_strategy_class=%s",
            asi.value,
            op_name,
            sibling_cls.__name__,
        )
    return siblings
