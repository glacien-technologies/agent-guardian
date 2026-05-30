"""Guard the AIVSS-formula worked example against drift.

``docs/concepts/aivss.md`` (formerly ``docs/aivss-formula.md`` — moved in the
Diátaxis restructure) walks through the ``tests/golden/aivss_regression/
good_t1.json`` fixture end-to-end. This test re-runs the scorer on the same
fixture and asserts the documented numbers — formula version, per-step result,
final score — still match. Whenever the formula changes, the docs page must be
updated *and* this test re-pinned in the same commit.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

import pytest

from agent_guardian.core.scoring import AIVSS_FORMULA_VERSION, compute_aivss
from agent_guardian.models.finding import Finding
from agent_guardian.models.probe import Probe
from agent_guardian.models.tier import Tier

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "golden" / "aivss_regression" / "good_t1.json"
DOC = REPO_ROOT / "docs" / "concepts" / "aivss.md"

_TIER_MAP = {
    "T1": Tier.T1_CRITICAL,
    "T2": Tier.T2_HIGH,
    "T3": Tier.T3_STANDARD,
    "T4": Tier.T4_LOW,
}


@pytest.fixture(scope="module")
def fixture_data() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(FIXTURE.read_text(encoding="utf-8")))


def test_fixture_matches_documented_score(fixture_data: dict[str, Any]) -> None:
    """The worked example in docs/aivss-formula.md must equal the scorer output."""

    probes = [Probe.model_validate(p) for p in fixture_data["probes"]]
    findings = [Finding.model_validate(f) for f in fixture_data["findings"]]
    tier = _TIER_MAP[str(fixture_data["tier"])]

    result = compute_aivss(findings, probes, tier)

    assert result.score == fixture_data["expected_aivss"]
    assert result.formula_version == AIVSS_FORMULA_VERSION


def test_doc_references_real_fixture_and_score() -> None:
    """The doc page must cite the actual fixture filename and its expected score."""

    body = DOC.read_text(encoding="utf-8")
    assert "good_t1.json" in body, "aivss-formula.md must reference the fixture by name"
    expected_score = int(json.loads(FIXTURE.read_text(encoding="utf-8"))["expected_aivss"])
    # The doc should anchor a number that matches the fixture's expected_aivss.
    assert re.search(rf"\b{expected_score}\b", body), (
        f"aivss-formula.md must reference the expected score {expected_score} from {FIXTURE.name}"
    )


def test_doc_references_real_source_paths() -> None:
    """The doc must point at the real scorer + fixture paths, not the fictional ones."""

    body = DOC.read_text(encoding="utf-8")
    # The old draft pointed at tests/golden/scoring/good_t1.json — that path
    # never existed. The real fixtures live under tests/golden/aivss_regression/.
    assert "tests/golden/scoring/good_t1.json" not in body, (
        "aivss-formula.md still references a fictional fixture path"
    )
    assert "src/agent_guardian/core/scoring.py" in body
    assert "tests/golden/aivss_regression" in body


def test_doc_does_not_use_old_fictional_formula() -> None:
    """The old `100 - sum(weight * count)` formula does not match the real pipeline."""

    body = DOC.read_text(encoding="utf-8")
    # Phrase from the fictional formula — must not appear.
    assert "weight(tier, asi)" not in body, (
        "aivss-formula.md still describes the fictional 100 - sum(weight*count) formula"
    )


def test_doc_uses_real_verify_flag() -> None:
    """`agent-guardian verify` takes --pubkey / --pubkey-file, not --public-key."""

    body = DOC.read_text(encoding="utf-8")
    assert "--public-key" not in body, "aivss-formula.md still uses the non-existent --public-key"
    assert "--pubkey" in body
