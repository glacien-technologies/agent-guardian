"""Attack strategies (PRD §3.1, M6)."""

from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
)
from agent_guardian.strategies.crescendo import CrescendoStrategy
from agent_guardian.strategies.fuzz import FuzzStrategy
from agent_guardian.strategies.mad_max import MadMaxStrategy
from agent_guardian.strategies.multi_turn_plan import (
    MultiTurnPlan,
    MultiTurnPlanStrategy,
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
)
from agent_guardian.strategies.mutator import (
    ArtPrompt,
    BoN,
    CipherMutator,
    DeceptiveDelightMutator,
    FlipAttack,
    HCoTMutator,
    LowResourceMutator,
    ManyShotMutator,
    MutatorRegistry,
    PAPMutator,
    PAPScheme,
    SkeletonKeyMutator,
    apply_mutation,
)
from agent_guardian.strategies.pair import PAIRStrategy
from agent_guardian.strategies.reflective import ReflectiveStrategy
from agent_guardian.strategies.tap import TAPStrategy
from agent_guardian.strategies.tool_exfil import ToolExfilStrategy

__all__ = [
    "MULTI_TURN_PLAN_REGISTRY",
    "PREDICATE_REGISTRY",
    "ArtPrompt",
    "BoN",
    "CipherMutator",
    "CrescendoStrategy",
    "DeceptiveDelightMutator",
    "FlipAttack",
    "FuzzStrategy",
    "HCoTMutator",
    "LowResourceMutator",
    "MadMaxStrategy",
    "ManyShotMutator",
    "MultiTurnPlan",
    "MultiTurnPlanStrategy",
    "MultiTurnPlanValidationError",
    "MutatorRegistry",
    "NextPrompt",
    "PAIRStrategy",
    "PAPMutator",
    "PAPScheme",
    "ReflectiveStrategy",
    "SkeletonKeyMutator",
    "Strategy",
    "StrategyContext",
    "StrategyDone",
    "StrategyResult",
    "TAPStrategy",
    "ToolExfilStrategy",
    "Turn",
    "TurnRecord",
    "TurnSpec",
    "apply_mutation",
    "load_multi_turn_plan_from_yaml",
    "load_multi_turn_plans_from_dir",
    "register_plan",
    "register_predicate",
]
