"""Golden-fixture regression tests for the AIVSS formula.

Each ``tests/golden/aivss_regression/*.json`` file locks one input → output
pair. Any formula change that alters the result will fail one of these tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_guardian.core.scoring import compute_aivss
from agent_guardian.models.finding import Finding
from agent_guardian.models.probe import Probe
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier

FIXTURES_DIR = Path(__file__).parent / "aivss_regression"


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES_DIR.glob("*.json"))


def _load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture_path", _fixture_files(), ids=lambda p: p.stem)
def test_golden_fixture_matches_expected_score(fixture_path: Path) -> None:
    data = _load_fixture(fixture_path)
    probes = [Probe.model_validate(p) for p in data["probes"]]
    findings = [Finding.model_validate(f) for f in data["findings"]]
    tier = Tier(data["tier"])

    result = compute_aivss(findings, probes, tier)
    expected_score = data["expected_aivss"]
    expected_band = SeverityBand(data["expected_band"])

    assert result.score == expected_score, (
        f"{fixture_path.name}: expected AIVSS {expected_score}, got {result.score}"
    )
    assert result.band is expected_band, (
        f"{fixture_path.name}: expected band {expected_band}, got {result.band}"
    )


@pytest.mark.parametrize("fixture_path", _fixture_files(), ids=lambda p: p.stem)
def test_golden_fixture_is_byte_deterministic(fixture_path: Path) -> None:
    """Re-running the same fixture twice yields byte-equal results."""
    data = _load_fixture(fixture_path)
    probes = [Probe.model_validate(p) for p in data["probes"]]
    findings = [Finding.model_validate(f) for f in data["findings"]]
    tier = Tier(data["tier"])

    first = compute_aivss(findings, probes, tier)
    second = compute_aivss(findings, probes, tier)
    assert first == second
