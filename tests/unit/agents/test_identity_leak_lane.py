"""Regression: GAP-4 — ASI03 cross-tenant PII lane is applicable independent
of ``fingerprint.has_memory``.

Pre-GAP-4 history: the ASI03-PII-* probe family was implicitly owned by
:class:`agent_guardian.agents.memory_poison.MemoryPoisonAgent`, whose
``is_applicable`` short-circuited on ``fingerprint.has_memory == False`` —
silencing the entire cross-tenant identity lane against any HTTP target that
did not self-declare memory.

The fix (Approach A in the gap-list brief) introduces
:class:`agent_guardian.agents.identity_leak.IdentityLeakAgent`, a dedicated
ASI03 specialist whose ``is_applicable`` returns True for ANY reachable
target. This test pins three invariants:

1. ``IdentityLeakAgent.is_applicable`` is True even when the target
   fingerprint reports ``has_memory=False`` (the exact scenario that
   GAP-4 reported as the silencing condition).
2. The agent's ``asi_category`` is ASI03 — so the probe loader picks up the
   ``ASI03-PII-*`` corpus family.
3. The agent's seed pool filters down to ONLY the ``ASI03-PII-*`` probe
   family (a sibling :class:`PrivilegeAgent` already owns the broader ASI03
   authority-claim probes — running both means we MUST not double-fire the
   same authority probes from two agents).
"""

from __future__ import annotations

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.agents.identity_leak import (
    PII_PROBE_ID_PREFIX,
    IdentityLeakAgent,
)
from agent_guardian.llm.stub import StubScript
from agent_guardian.models.asi import AsiCategory


def _make_agent() -> IdentityLeakAgent:
    """Build a stubbed IdentityLeakAgent — no actual LLM traffic."""
    attacker = StubScript().default("ok").build()
    evaluator = StubScript().default("ok").build()
    return IdentityLeakAgent(
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        attacker_model="stub",
        evaluator_model="stub",
    )


def test_identity_leak_applicable_when_no_memory() -> None:
    """GAP-4 core pin: the PII lane fires even when ``has_memory=False``.

    A standard ADK / FastAPI HTTP adapter does not self-declare memory
    affordance — the fingerprint comes back ``has_memory=False``. Pre-fix,
    MemoryPoisonAgent's gate silenced the only ASI03-adjacent lane in this
    case. Post-fix, IdentityLeakAgent runs unconditionally.
    """
    agent = _make_agent()
    fingerprint = TargetFingerprint(
        mode="prompt",
        ref="<http-target>",
        has_tools=True,
        has_memory=False,  # <-- the exact silencing condition from GAP-4
        is_multi_agent=False,
        notes="HTTP adapter, no declared memory affordance",
    )
    assert agent.is_applicable(fingerprint) is True


def test_identity_leak_applicable_for_bare_fingerprint() -> None:
    """Belt-and-braces: even a fingerprint with no tools / no memory passes.

    Cross-tenant identity confusion is a plain in-band test. The agent must
    not depend on any fingerprint attribute beyond reachability.
    """
    agent = _make_agent()
    bare = TargetFingerprint(
        mode="prompt",
        ref="<bare>",
        has_tools=False,
        has_memory=False,
        is_multi_agent=False,
        notes="bare",
    )
    assert agent.is_applicable(bare) is True


def test_identity_leak_owns_asi03() -> None:
    """The agent must declare ASI03 so the probe loader resolves the family.

    ``seeds_for_asi_with_provenance`` keys on the agent's
    ``asi_category`` — if the agent declared the wrong ASI (e.g. ASI06)
    the ``ASI03-PII-*`` probes would never reach it.
    """
    agent = _make_agent()
    assert agent.asi_category == AsiCategory.ASI03


def test_identity_leak_seeds_filtered_to_pii_family() -> None:
    """Seed pool is restricted to the ``ASI03-PII-*`` probe family.

    When the corpus contains ASI03-PII-* probes, the agent returns only those.
    When the corpus is missing the family entirely (editable install / pre-
    GAP-3 state), the fallback strings are used — every fallback seed is
    a cross-tenant ask shape and the synthetic ``ASI03-fallback-*`` id is
    accepted by the loader contract.
    """
    agent = _make_agent()
    seeds = agent.seeds_for_category()
    assert seeds, "IdentityLeakAgent must always emit at least one seed"
    # Every emitted seed is either a real ASI03-PII-* probe OR the
    # synthetic fallback id the base class wraps when the corpus is missing.
    for seed in seeds:
        is_pii_family = seed.probe_id.startswith(PII_PROBE_ID_PREFIX)
        is_fallback = seed.probe_id.startswith(f"{AsiCategory.ASI03.value}-fallback-")
        assert is_pii_family or is_fallback, (
            f"unexpected probe id {seed.probe_id!r} — must be ASI03-PII-* or "
            f"ASI03-fallback-* (filtering invariant broken)"
        )


def test_identity_leak_name_distinct_from_privilege_agent() -> None:
    """Pin the agent name so the dispatcher / per-agent brief table cannot
    accidentally collide with the existing ASI03 owner (PrivilegeAgent)."""
    agent = _make_agent()
    assert agent.name == "identity-leak-agent"
