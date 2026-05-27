"""Server-side telemetry aggregator.

This is the code that runs on Glacien's collector backend at
``telemetry.agentguardian.ai``. It's shipped in the OSS package so
anyone can audit what would happen with the data they send (Standard
§9.4 -- telemetry transparency).

The reference backend is SQLite -- good enough for the first few
months of data volume. The query layer is intentionally agnostic
about the storage: every aggregator method takes a connection-like
object and runs the same SQL against ClickHouse / TimescaleDB /
SQLite. Production deployment swaps SQLite for ClickHouse without
touching the aggregator code.

The PRD requires k>=50 protection on every public aggregate. The
:class:`Aggregator` class enforces this at the query layer -- every
public method returns ``None`` or a redacted sentinel when the
underlying bucket has fewer than 50 distinct ``install_id`` values.
"""

from __future__ import annotations

from agent_guardian.server.analytics.aggregator import (
    K_ANONYMITY_THRESHOLD,
    AdapterUsageRow,
    Aggregator,
    AsiBreakdownRow,
    HeroNumbers,
    HistogramBucket,
    ProbeRank,
)
from agent_guardian.server.analytics.store import EventStore, init_schema

__all__ = [
    "K_ANONYMITY_THRESHOLD",
    "AdapterUsageRow",
    "Aggregator",
    "AsiBreakdownRow",
    "EventStore",
    "HeroNumbers",
    "HistogramBucket",
    "ProbeRank",
    "init_schema",
]
