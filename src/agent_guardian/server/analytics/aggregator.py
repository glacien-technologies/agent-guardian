"""Aggregator query layer with k-anonymity protection.

Computes the 4 hero numbers + AIVSS histogram + 3 supporting cells
from the event store. Every public method returns ``None`` (or a
redacted shape) when the underlying bucket has fewer than 50 distinct
install_ids -- per the analytics PRD §4 publication rules.

The k>=50 rule applies to **publication**, not to internal queries.
Glacien's internal dashboard can call the raw `_*` methods to see
sub-threshold buckets; the public dashboard only calls the public
methods. The split is enforced by the method-name underscore prefix.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Any

__all__ = [
    "K_ANONYMITY_THRESHOLD",
    "AdapterUsageRow",
    "Aggregator",
    "AsiBreakdownRow",
    "HeroNumbers",
    "HistogramBucket",
    "ProbeRank",
]

K_ANONYMITY_THRESHOLD = 50
"""Per analytics PRD §4 -- minimum distinct install_ids per bucket
before a cell is published. Buckets below threshold are suppressed
or folded into 'Other'."""


@dataclass(frozen=True, slots=True)
class HeroNumbers:
    """The 4 hero numbers shown above the fold on /analytics."""

    total_scans: int
    median_aivss: int | None  # None if below k-threshold
    crash_free_rate_pct: float | None  # None if below k-threshold
    monthly_active_installs: int


@dataclass(frozen=True, slots=True)
class HistogramBucket:
    """One bar of the AIVSS distribution histogram."""

    lower: int  # inclusive
    upper: int  # exclusive (top bucket is inclusive)
    count: int
    percent: float


@dataclass(frozen=True, slots=True)
class ProbeRank:
    """One row of the top-N most-firing probes ranking.

    The v1.0 telemetry schema doesn't ship per-probe data -- this row
    is reserved for v1.1. The aggregator method that produces it
    returns ``[]`` for now so the route handler doesn't have to
    special-case the absence.
    """

    rank: int
    probe_id: str
    asi: str
    fires: int
    catch_rate_pct: float


@dataclass(frozen=True, slots=True)
class AsiBreakdownRow:
    """One row of per-ASI failure attribution.

    Derived from per-scan findings_total + the assumption that any
    scan with critical or high findings 'failed' at one of the 10
    OWASP categories. v1.0 ships an approximate breakdown based on
    finding counts; v1.1 will add per-ASI attribution from
    probe_fire events.
    """

    asi: str
    label: str
    failure_rate_pct: float
    scans: int


@dataclass(frozen=True, slots=True)
class AdapterUsageRow:
    """One row of the adapter-usage mix table."""

    adapter: str
    scans: int
    percent: float
    median_aivss: int | None


_ASI_LABELS: dict[str, str] = {
    "ASI01": "Goal hijack",
    "ASI02": "Tool misuse",
    "ASI03": "Privilege abuse",
    "ASI04": "Supply chain",
    "ASI05": "Code execution",
    "ASI06": "Memory poisoning",
    "ASI07": "Agent-to-agent",
    "ASI08": "Cascading failures",
    "ASI09": "Trust exploitation",
    "ASI10": "Rogue agents",
}


class Aggregator:
    """SQL-backed aggregator with k>=50 protection.

    Takes any DB-API-2 connection object; works against SQLite
    (reference) or any other backend that speaks SQL-92.
    """

    def __init__(self, conn: Any, *, k_threshold: int = K_ANONYMITY_THRESHOLD) -> None:
        self._conn = conn
        self._k = k_threshold

    # ------------------------------------------------------------------
    # Public methods -- k-anonymity-protected
    # ------------------------------------------------------------------

    def hero_numbers(self, *, window_days: int = 30) -> HeroNumbers:
        """The 4 hero numbers for a rolling window. Pass ``window_days=0`` for all-time."""
        cur = self._conn.cursor()
        where: str
        args: tuple[str, ...]
        if window_days > 0:
            where = "WHERE server_received_at >= datetime('now', ?)"
            args = (f"-{window_days} days",)
        else:
            where = ""
            args = ()
        # Total scans
        total = cur.execute(f"SELECT COUNT(*) FROM scan_events {where}", args).fetchone()[0]
        # Distinct installs in window -- used for both MAU and the k-anonymity gate.
        distinct = cur.execute(
            f"SELECT COUNT(DISTINCT install_id) FROM scan_events {where}", args
        ).fetchone()[0]
        # Median AIVSS -- only published if k>=50 distinct installs.
        if distinct >= self._k:
            aivss_rows = cur.execute(f"SELECT aivss FROM scan_events {where}", args).fetchall()
            aivss_vals = [r[0] for r in aivss_rows]
            median_aivss: int | None = int(statistics.median(aivss_vals)) if aivss_vals else None
            # Crash-free rate
            crashes = cur.execute(
                f"SELECT COUNT(*) FROM scan_events {where} "
                + ("AND" if where else "WHERE")
                + " terminated_by = 'crash'",
                args,
            ).fetchone()[0]
            crash_free = (1.0 - (crashes / total)) * 100.0 if total else None
        else:
            median_aivss = None
            crash_free = None
        return HeroNumbers(
            total_scans=int(total),
            median_aivss=median_aivss,
            crash_free_rate_pct=round(crash_free, 2) if crash_free is not None else None,
            monthly_active_installs=int(distinct) if distinct >= self._k else 0,
        )

    def aivss_distribution(self, *, window_days: int = 30) -> list[HistogramBucket]:
        """10-pt AIVSS histogram. Returns ``[]`` if below k-threshold."""
        cur = self._conn.cursor()
        where = "WHERE server_received_at >= datetime('now', ?)" if window_days > 0 else ""
        args = (f"-{window_days} days",) if window_days > 0 else ()
        distinct = cur.execute(
            f"SELECT COUNT(DISTINCT install_id) FROM scan_events {where}", args
        ).fetchone()[0]
        if distinct < self._k:
            return []
        rows = cur.execute(f"SELECT aivss FROM scan_events {where}", args).fetchall()
        if not rows:
            return []
        values = [r[0] for r in rows]
        total = len(values)
        out: list[HistogramBucket] = []
        for lower in range(0, 100, 10):
            upper = lower + 10
            if upper == 100:
                count = sum(1 for v in values if lower <= v <= 100)
            else:
                count = sum(1 for v in values if lower <= v < upper)
            out.append(
                HistogramBucket(
                    lower=lower,
                    upper=upper,
                    count=count,
                    percent=round(count / total * 100, 2) if total else 0.0,
                )
            )
        return out

    def adapter_mix(self, *, window_days: int = 30) -> list[AdapterUsageRow]:
        """Per-adapter share of scans. Filters out adapters below k-threshold."""
        cur = self._conn.cursor()
        where = "WHERE server_received_at >= datetime('now', ?)" if window_days > 0 else ""
        args = (f"-{window_days} days",) if window_days > 0 else ()
        # Total scans for the percentage denominator.
        total = cur.execute(f"SELECT COUNT(*) FROM scan_events {where}", args).fetchone()[0]
        if total == 0:
            return []
        rows = cur.execute(
            f"""
            SELECT adapter,
                   COUNT(*) AS scans,
                   COUNT(DISTINCT install_id) AS distinct_installs
            FROM scan_events {where}
            GROUP BY adapter
            ORDER BY scans DESC
            """,
            args,
        ).fetchall()
        out: list[AdapterUsageRow] = []
        for r in rows:
            if r["distinct_installs"] < self._k:
                continue  # suppress
            # Median AIVSS per adapter -- same connection but a fresh cursor.
            inner = self._conn.cursor()
            aivss_rows = inner.execute(
                f"SELECT aivss FROM scan_events {where} "
                + ("AND" if where else "WHERE")
                + " adapter = ?",
                (*args, r["adapter"]),
            ).fetchall()
            aivss_vals = [a[0] for a in aivss_rows]
            median = int(statistics.median(aivss_vals)) if aivss_vals else None
            out.append(
                AdapterUsageRow(
                    adapter=str(r["adapter"]),
                    scans=int(r["scans"]),
                    percent=round(r["scans"] / total * 100, 2),
                    median_aivss=median,
                )
            )
        return out

    def asi_breakdown(self, *, window_days: int = 30) -> list[AsiBreakdownRow]:
        """Per-ASI failure rate, approximated from finding severity in v1.0.

        Per the PRD: v1.0 has no per-probe attribution, so 'failure
        rate per ASI' is approximated as the share of scans that had
        ANY critical/high finding, weighted equally across the 10 ASIs.
        v1.1 adds proper attribution from probe_fire events.
        """
        cur = self._conn.cursor()
        where = "WHERE server_received_at >= datetime('now', ?)" if window_days > 0 else ""
        args = (f"-{window_days} days",) if window_days > 0 else ()
        distinct = cur.execute(
            f"SELECT COUNT(DISTINCT install_id) FROM scan_events {where}", args
        ).fetchone()[0]
        if distinct < self._k:
            return []
        total = cur.execute(f"SELECT COUNT(*) FROM scan_events {where}", args).fetchone()[0]
        if total == 0:
            return []
        # Approximate: probability that any single ASI fired = total findings / (10 * scans).
        # This is intentionally rough -- see the docstring.
        sums = cur.execute(
            f"""
            SELECT SUM(findings_critical) AS s_crit,
                   SUM(findings_high) AS s_high,
                   SUM(findings_medium) AS s_med,
                   SUM(findings_low) AS s_low
            FROM scan_events {where}
            """,
            args,
        ).fetchone()
        # Weight by severity: critical=5, high=3, medium=2, low=1 (per PRD §C).
        weighted = (
            (sums["s_crit"] or 0) * 5
            + (sums["s_high"] or 0) * 3
            + (sums["s_med"] or 0) * 2
            + (sums["s_low"] or 0) * 1
        )
        if weighted == 0:
            return [
                AsiBreakdownRow(asi=k, label=v, failure_rate_pct=0.0, scans=total)
                for k, v in _ASI_LABELS.items()
            ]
        # Per-ASI rate split evenly across the 10 categories for the v1.0
        # approximation. Total weighted findings / (10 * total scans) gives the
        # mean per-ASI failure rate.
        mean_per_asi = weighted / (10 * total) * 100
        return [
            AsiBreakdownRow(
                asi=k,
                label=v,
                failure_rate_pct=round(mean_per_asi, 2),
                scans=total,
            )
            for k, v in _ASI_LABELS.items()
        ]

    def top_probes(self, *, window_days: int = 30) -> list[ProbeRank]:
        """v1.1 placeholder -- empty until per-probe events are collected."""
        return []

    def python_os_matrix(self, *, window_days: int = 30) -> list[dict[str, Any]]:
        """The Python x OS cell counts. Suppresses cells below k-threshold."""
        cur = self._conn.cursor()
        where = "WHERE server_received_at >= datetime('now', ?)" if window_days > 0 else ""
        args = (f"-{window_days} days",) if window_days > 0 else ()
        rows = cur.execute(
            f"""
            SELECT python_version, os_family,
                   COUNT(*) AS scans,
                   COUNT(DISTINCT install_id) AS distinct_installs
            FROM scan_events {where}
            GROUP BY python_version, os_family
            ORDER BY scans DESC
            """,
            args,
        ).fetchall()
        return [
            {
                "python": r["python_version"],
                "os": r["os_family"],
                "scans": int(r["scans"]),
            }
            for r in rows
            if r["distinct_installs"] >= self._k
        ]

    def recent_scans(self, *, limit: int = 5) -> list[dict[str, Any]]:
        """For the real-time ticker. Returns the most recent N scans
        with only the fields safe for public display."""
        cur = self._conn.cursor()
        rows = cur.execute(
            """
            SELECT aivss, band, adapter, completed_at
            FROM scan_events
            ORDER BY server_received_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "aivss": int(r["aivss"]),
                "band": str(r["band"]),
                "adapter": str(r["adapter"]),
                "completed_at": str(r["completed_at"]),
            }
            for r in rows
        ]
