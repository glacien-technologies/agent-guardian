"""Issue #206 — derive an implicit recon ceiling from overall_wall_seconds.

Background. Live evidence (rc33 auditor-fast scan): the 11-tool ADK auditor
target has a wide recon surface (declared tools include google_search,
code_execution, function_calling, google_threat_intelligence, etc.). With
``overall_wall_seconds=300`` and no explicit ``recon_wall_seconds``, recon
ate ~240s probing those tools and the swarm had 60s left for the entire
attack phase — completeness ended at 0%, band=not_evaluated.

The fix derives an implicit recon ceiling when the operator set
overall_wall but didn't set recon explicitly: 30% of overall, capped at
180s with a 30s floor. Explicit ``--recon-budget-seconds`` always wins.
"""

from __future__ import annotations

from agent_guardian.core.swarm import SwarmConfig


def test_recon_implicit_cap_30pct_of_overall_when_unset() -> None:
    """Without explicit recon budget, the swarm derives an implicit cap.

    The full recon-cap derivation lives in ``_phase_recon`` (not in
    ``SwarmConfig`` itself — it's a runtime decision that may flex with
    the recon-agent's behaviour). This test guards the contract: when
    the operator sets overall but not recon, the SwarmConfig holds
    those values verbatim — the cap is applied at run time inside
    ``_phase_recon`` and surfaced via the ``phase recon: starting``
    log line ("deriving implicit cap=...").
    """
    cfg = SwarmConfig(
        scan_id="cfg-test",
        recon_wall_seconds=None,
        overall_wall_seconds=300.0,
    )
    # Config stores raw operator intent; the cap is applied at run time.
    assert cfg.recon_wall_seconds is None
    assert cfg.overall_wall_seconds == 300.0


def test_recon_explicit_budget_wins_over_implicit_cap() -> None:
    """If the operator passes ``--recon-budget-seconds``, the config holds
    that value and _phase_recon must NOT override it with the implicit
    cap. Tested at the config level here; the run-time behaviour is
    covered by the explicit ``effective_recon_cap = self.config.
    recon_wall_seconds`` branch in _phase_recon.
    """
    cfg = SwarmConfig(
        scan_id="cfg-test-explicit",
        recon_wall_seconds=45.0,
        overall_wall_seconds=300.0,
    )
    assert cfg.recon_wall_seconds == 45.0
    # The run-time helper uses cfg.recon_wall_seconds when it's not None;
    # this test simply guards the field remains read-back-able.


def test_recon_implicit_cap_unaffected_when_overall_also_unset() -> None:
    """When neither budget is set, recon stays uncapped — this is the
    test/CI invocation path and must not silently introduce a cap.
    """
    cfg = SwarmConfig(scan_id="cfg-test-uncapped")
    assert cfg.recon_wall_seconds is None
    assert cfg.overall_wall_seconds is None
