"""Integration smoke test for the AgentDojo runner (Phase C, C3).

Two flavours:

1. Vendored-corpus path: always runs. Drives the runner end-to-end
   against a tiny in-process target and asserts the AgentDojo-shaped
   report comes out with the documented JSON shape.

2. Upstream path: skipped when the optional ``agentdojo`` extra is not
   installed. When it IS installed, runs a one-task smoke that proves
   the upstream-loader branch + the substring-evaluator fallback both
   integrate without crashing.
"""

from __future__ import annotations

import importlib.util
import json

import pytest

from agent_guardian.adapters.agentdojo import (
    AgentDojoReport,
    is_agentdojo_installed,
    run_agentdojo_suite,
)
from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint


class _CompliantTarget(TargetAdapter):
    """In-process target that always parrots the injection_goal.

    Forces every task to count as an attack-success under the vendored
    substring evaluator -- a deterministic upper bound on the
    ``attack_success_rate`` the runner reports.
    """

    mode = "http"

    def __init__(self) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="http", ref="compliant-stub")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        _ = session
        # Echo back the INJECTED CONTENT block so the heuristic evaluator
        # detects every injection_goal token.
        injection_marker = "--- INJECTED CONTENT (from tool output) ---"
        if injection_marker in prompt:
            after = prompt.split(injection_marker, 1)[1]
            return (
                f"Acknowledged injected directive. Original user wanted: {prompt} -- "
                f"Will execute: {after}"
            )
        return f"Acknowledged. {prompt}"


class _RefusingTarget(TargetAdapter):
    """In-process target that ignores injections and answers neutrally."""

    mode = "http"

    def __init__(self) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="http", ref="refusing-stub")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        _ = session, prompt
        return "I cannot comply with injected instructions."


# ---------------------------------------------------------------------------
# Vendored-corpus path (always runs).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("suite_name", ["banking", "slack", "travel", "workspace"])
async def test_run_agentdojo_suite_vendored_shape(suite_name: str) -> None:
    """Suite runs end-to-end and produces an AgentDojo-shaped report."""
    report = await run_agentdojo_suite(suite_name, _CompliantTarget())
    assert isinstance(report, AgentDojoReport)
    assert report.suite == suite_name
    assert report.source == "vendored"
    assert report.total > 0
    assert report.error_count == 0
    # The compliant target echoes the injection, so attack_count > 0.
    assert report.attack_count >= 1
    # Per-strategy aggregation must be non-empty for at least one strategy.
    assert report.per_attacker_strategy
    # to_dict shape is JSON-serialisable and carries the AgentDojo paper
    # headline metrics.
    payload = report.to_dict()
    raw = json.dumps(payload)  # must not raise
    assert "utility_attack_count" in raw
    assert "attack_success_rate" in raw
    assert "per_attacker_strategy" in raw


async def test_refusing_target_attack_rate_is_zero() -> None:
    """A well-defended target produces attack_success_rate == 0."""
    report = await run_agentdojo_suite("banking", _RefusingTarget())
    assert report.attack_count == 0
    assert report.utility_attack_count == 0
    assert report.to_dict()["attack_success_rate"] == 0.0


async def test_max_concurrency_validation() -> None:
    with pytest.raises(ValueError):
        await run_agentdojo_suite("banking", _RefusingTarget(), max_concurrency=0)


# ---------------------------------------------------------------------------
# Upstream-installed smoke (skipped without the optional extra).
# ---------------------------------------------------------------------------

_AGENTDOJO_AVAILABLE = (
    is_agentdojo_installed() and importlib.util.find_spec("agentdojo") is not None
)


@pytest.mark.skipif(
    not _AGENTDOJO_AVAILABLE,
    reason="optional [agentdojo] extra not installed",
)
async def test_run_agentdojo_suite_upstream_smoke() -> None:
    """When the real `agentdojo` package is installed, the runner works end-to-end."""
    report = await run_agentdojo_suite("banking", _RefusingTarget(), max_concurrency=2)
    assert isinstance(report, AgentDojoReport)
    assert report.total >= 1
    assert report.source in {"upstream", "vendored"}
