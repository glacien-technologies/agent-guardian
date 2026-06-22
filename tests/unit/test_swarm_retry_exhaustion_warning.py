"""rc38 P0-#5 (#263) — scan-finalise aggregate retry-exhaustion WARNING.

The retry layer already logs ONE WARNING per call whose retries are exhausted,
but there was no scan-WIDE signal: an operator could not tell "one unlucky 429"
from "30% of every LLM call gave up". ``SwarmCommander._maybe_warn_retry_exhaustion``
reads the scan-scoped :class:`RetryTally` and emits exactly ONE CLI WARNING when
``exhausted / total`` crosses the 5% threshold, and stays silent otherwise.

These are structural tests over the finalise helper — they don't spin up a full
swarm run. The commander is built with ``__new__`` and only the two attributes
the helper reads (``_retry_tally`` + ``config.scan_id``) are populated.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from agent_guardian.core.swarm import SwarmCommander
from agent_guardian.llm.retry import RetryTally

_SWARM_LOGGER = "agent_guardian.core.swarm"


def _commander_with_tally(tally: RetryTally) -> SwarmCommander:
    """Build a bare commander carrying just the attributes the helper reads."""
    cmd = SwarmCommander.__new__(SwarmCommander)
    cmd._retry_tally = tally
    cmd.config = SimpleNamespace(scan_id="scan-263")  # type: ignore[assignment]
    return cmd


def test_warns_once_when_exhaustion_over_five_percent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """10/100 exhausted (10% > 5%) emits exactly one WARNING."""
    cmd = _commander_with_tally(RetryTally(total=100, exhausted=10))
    with caplog.at_level(logging.WARNING, logger=_SWARM_LOGGER):
        cmd._maybe_warn_retry_exhaustion()
    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "retries exhausted" in r.message
    ]
    assert len(warnings) == 1
    assert "10/100" in warnings[0].message
    assert "scan-263" in warnings[0].message


def test_no_warn_at_or_under_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """5/100 exhausted (exactly 5%, not strictly over) emits nothing."""
    cmd = _commander_with_tally(RetryTally(total=100, exhausted=5))
    with caplog.at_level(logging.WARNING, logger=_SWARM_LOGGER):
        cmd._maybe_warn_retry_exhaustion()
    assert not [r for r in caplog.records if "retries exhausted" in r.message], (
        "5% must NOT trip the >5% warning"
    )


def test_no_warn_well_under_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """1/100 exhausted (1%) emits nothing."""
    cmd = _commander_with_tally(RetryTally(total=100, exhausted=1))
    with caplog.at_level(logging.WARNING, logger=_SWARM_LOGGER):
        cmd._maybe_warn_retry_exhaustion()
    assert not [r for r in caplog.records if "retries exhausted" in r.message]


def test_no_warn_when_no_calls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An empty tally (no LLM calls) emits nothing — no div-by-zero, no noise."""
    cmd = _commander_with_tally(RetryTally(total=0, exhausted=0))
    with caplog.at_level(logging.WARNING, logger=_SWARM_LOGGER):
        cmd._maybe_warn_retry_exhaustion()
    assert not [r for r in caplog.records if "retries exhausted" in r.message]
