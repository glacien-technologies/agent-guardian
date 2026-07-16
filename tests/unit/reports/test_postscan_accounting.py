from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.core.budget import tokens_to_usd
from agent_guardian.llm.usage_tracking import UsageCounter
from agent_guardian.models.scan import BudgetReport
from agent_guardian.reports.postscan import can_run_probe_summaries, fold_postscan_usage
from agent_guardian.server import probe_summary
from agent_guardian.server.probe_summary import build_summary_prompt, summary_reservation_usd
from tests.unit._report_fixtures import make_scan


def test_fold_postscan_usage_updates_scan_and_budget() -> None:
    scan = make_scan().model_copy(
        update={
            "cost_usd": 0.010,
            "tokens_total": 100,
            "budget": BudgetReport(cap_usd=0.02, spent_usd=0.010, pct_of_cap=0.5),
        }
    )
    counter = UsageCounter(
        prompt_tokens=1_000,
        completion_tokens=2_000,
        total_tokens=3_000,
        calls=2,
    )

    updated = fold_postscan_usage(scan, counter, "vertex:gemini-2.5-flash")

    expected_extra = tokens_to_usd("vertex:gemini-2.5-flash", 1_000, 2_000)
    assert updated is not scan
    assert updated.tokens_total == 3_100
    assert updated.cost_usd == pytest.approx(0.010 + expected_extra)
    assert updated.budget is not None
    assert updated.budget.spent_usd == pytest.approx(0.010 + expected_extra)
    assert updated.budget.pct_of_cap == pytest.approx((0.010 + expected_extra) / 0.02)


def test_summary_reservation_prices_every_graded_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exports = {
        "graded": {"verdict": "defended", "turns": []},
        "recon": {"verdict": "", "turns": []},
    }
    monkeypatch.setattr(probe_summary, "build_probe_exports", lambda _path: exports)
    expected_input = len(probe_summary._SYSTEM) + len(build_summary_prompt(exports["graded"]))
    expected = tokens_to_usd("vertex:gemini-2.5-flash", expected_input, 2_048)

    assert summary_reservation_usd(tmp_path, "vertex:gemini-2.5-flash") == pytest.approx(expected)


@pytest.mark.parametrize(
    ("cap", "spent", "reservation", "expected"),
    [
        (None, 1.0, 100.0, True),
        (0.02, 0.019, 0.002, False),
        (0.02, 0.010, 0.002, True),
    ],
)
def test_can_run_probe_summaries(
    cap: float | None,
    spent: float,
    reservation: float,
    expected: bool,
) -> None:
    assert can_run_probe_summaries(cap, spent, reservation) is expected
