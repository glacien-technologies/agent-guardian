"""Issue #206 follow-up — rc35 deep-review C1.

Background. PR #208 added an implicit recon ceiling
``min(180s, 0.30 * overall_wall_seconds)`` floored at 30s. On the FULL
preset (overall=1200) that gives 180s — fine, recon's natural P50 is well
below that on the finbot testbench. On the FAST preset (overall=300) the
formula collapses to 90s — which is BELOW rc32's natural recon P50 of
109s (and below the P95 of 138.6s). Result on the rc35 deep-review
matrix: 31 of 33 fast scans logged ``recon timed out after 90.0s -- using
minimal fingerprint``, ended with ``baseline_tools=[]``, and silently
dropped four ASI lanes (``never_launched=[ASI02,ASI04,ASI07,ASI10]``) on
every default fast scan.

The fix: lift the multiplier 0.30 -> 0.40 and install a 120s floor so the
fast preset clears rc32's natural P50 + a small headroom, while keeping
the 180s ceiling for the full preset (where 0.40*1200=480 is already over
the ceiling). Explicit ``--recon-budget-seconds`` still wins; no change.

The cap derivation is extracted from ``_phase_recon`` into a pure module
function (``_derive_implicit_recon_cap``) so the policy is unit-testable
without spinning up a Swarm.
"""

from __future__ import annotations

import pytest

from agent_guardian.core.swarm import _derive_implicit_recon_cap


def test_fast_preset_clears_rc32_natural_p50() -> None:
    """rc35 deep-review C1 — fast preset (overall=300s) must give recon
    at least 120s so the 8-tool finbot fingerprint actually completes.

    Before the fix: ``min(180, 0.30 * 300) = 90s`` -> 31/33 fast scans
    hit ``recon timed out after 90.0s``. After the fix: 120s.
    """
    cap = _derive_implicit_recon_cap(overall_wall_seconds=300.0)
    assert cap >= 120.0, (
        f"fast preset cap={cap}s is below the 120s floor required to clear "
        f"rc32's natural recon P50 of 109s on the finbot testbench"
    )


def test_smart_preset_lands_at_ceiling() -> None:
    """Smart preset (overall=600s). 0.40 * 600 = 240, clamped to the 180s
    ceiling. No regression vs prior 0.30 * 600 = 180s.
    """
    cap = _derive_implicit_recon_cap(overall_wall_seconds=600.0)
    assert cap == 180.0


def test_full_preset_lands_at_ceiling() -> None:
    """Full preset (overall=1200s). 0.40 * 1200 = 480, clamped to the
    180s ceiling. No regression vs prior 0.30 * 1200 = 360 clamped to 180.
    """
    cap = _derive_implicit_recon_cap(overall_wall_seconds=1200.0)
    assert cap == 180.0


def test_tiny_overall_budget_hits_floor() -> None:
    """A 60s overall budget would derive 0.40 * 60 = 24s, below the 30s
    floor. The floor prevents the recon agent from doing zero useful work
    on micro-budget invocations.
    """
    cap = _derive_implicit_recon_cap(overall_wall_seconds=60.0)
    assert cap == 30.0


def test_floor_kicks_in_above_smart_preset_boundary() -> None:
    """Boundary: at overall=300s, 0.40 * 300 = 120 == floor. At overall=
    280s, 0.40 * 280 = 112 < 120 -> the 120s floor kicks in. Below
    overall=75s, 0.40 * 75 = 30 == 30s absolute floor (the lower of the
    two floors).
    """
    # At fast-mode boundary the multiplier hits the 120s floor exactly.
    assert _derive_implicit_recon_cap(overall_wall_seconds=300.0) == 120.0
    # Just below the boundary the 120s floor saves us from undershoot.
    assert _derive_implicit_recon_cap(overall_wall_seconds=280.0) == 120.0
    # Way below, the absolute 30s floor still holds.
    assert _derive_implicit_recon_cap(overall_wall_seconds=50.0) == 30.0


@pytest.mark.parametrize(
    "overall_wall,expected_min",
    [
        (300.0, 120.0),  # fast preset must clear 120s (rc32 P50 + headroom)
        (600.0, 180.0),  # smart preset hits ceiling
        (1200.0, 180.0),  # full preset hits ceiling
    ],
)
def test_no_preset_undershoots_natural_recon_p50(overall_wall: float, expected_min: float) -> None:
    """Across all three named presets (fast/smart/full) the cap must
    meet or exceed the natural recon P50 observed on the finbot testbench
    in the rc32 baseline. The 120s floor handles fast; the 180s ceiling
    handles smart and full.
    """
    cap = _derive_implicit_recon_cap(overall_wall_seconds=overall_wall)
    assert cap >= expected_min, (
        f"overall={overall_wall}s preset got cap={cap}s, below the natural "
        f"recon P50 floor of {expected_min}s -> rc35 deep-review C1 regression"
    )
