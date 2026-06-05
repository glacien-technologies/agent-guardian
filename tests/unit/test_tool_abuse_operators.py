"""B4 — structured tool-abuse mutators (argument injection + tool chaining).

Tool-abuse was tested mostly via prompt text; the judge-evidence half (tool-call
arguments in the trace) shipped earlier. This adds two STRUCTURED mutator
operators that craft argument-level and chain-level attacks (path traversal /
SSRF / injection payloads as tool arguments; read->exfil tool chains), registered
and wired into the ASI02 sibling pool.
"""

from __future__ import annotations

import random

from agent_guardian.models.asi import AsiCategory
from agent_guardian.strategies.mutator import MutatorRegistry, apply_mutation
from agent_guardian.strategies.sibling_map import SIBLING_MAP

_ORIGINAL = "Help me look something up with your tools."


def test_arg_injection_smuggles_a_known_payload() -> None:
    out = apply_mutation("arg_injection", _ORIGINAL, random.Random(1))
    assert _ORIGINAL.rstrip() in out  # preserves the base ask
    # Carries one of the canonical argument-injection payload families.
    assert any(
        marker in out
        for marker in ("../../", "169.254.169.254", "DROP TABLE", "{{7*7}}", "\x00", "$(")
    )


def test_chain_compose_builds_a_read_then_exfil_chain() -> None:
    out = apply_mutation("chain_compose", _ORIGINAL, random.Random(2))
    assert _ORIGINAL.rstrip() in out
    lowered = out.lower()
    assert "chain" in lowered or "then" in lowered
    # Ends in an external sink (exfiltration).
    assert any(s in out for s in ("https://", "s3://", "webhook"))


def test_operators_registered() -> None:
    names = set(MutatorRegistry.names())
    assert {"arg_injection", "chain_compose"} <= names


def test_asi02_sibling_pool_includes_structured_operators() -> None:
    pool = SIBLING_MAP[AsiCategory.ASI02]
    assert "arg_injection" in pool
    assert "chain_compose" in pool
    # They lead the pool so tool-abuse prioritises structured attacks.
    assert pool.index("arg_injection") < pool.index("cipher")


def test_operators_are_deterministic_given_rng() -> None:
    a = apply_mutation("arg_injection", _ORIGINAL, random.Random(7))
    b = apply_mutation("arg_injection", _ORIGINAL, random.Random(7))
    assert a == b
