"""Issue #115: NOT_EVALUATED must carry a neutral label, not assert 'stub mode'.

The band is set for several causes (stub evaluator, coverage below the mode
threshold, high attacker-rejection), so the human label must not assert any one
of them — the reason banner names the true cause. A real-model scan withheld
for thin coverage was previously mislabeled "Not Evaluated (stub mode)".
"""

from __future__ import annotations

from agent_guardian.models.severity import SeverityBand, humanise_band


def test_not_evaluated_label_is_neutral() -> None:
    label = humanise_band(SeverityBand.NOT_EVALUATED)
    assert label == "Not Evaluated"
    assert "stub" not in label.lower()
