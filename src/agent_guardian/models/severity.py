"""Severity enumeration, AIVSS band classification, and band-to-colour mapping.

``Severity`` annotates each probe/finding with its raw severity weight.
``SeverityBand`` maps a final AIVSS 0-100 score to one of five named bands
with a stable hex colour for UI rendering.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Final

__all__ = [
    "Severity",
    "SeverityBand",
    "band_for_score",
    "colour_for_band",
    "humanise_band",
]


class Severity(str, Enum):
    """Per-probe severity weight (PRD §6 Step 2)."""

    CRITICAL = "critical"  # weight 1.0
    HIGH = "high"  # weight 0.7
    MEDIUM = "medium"  # weight 0.4
    LOW = "low"  # weight 0.2


class SeverityBand(str, Enum):
    """AIVSS 0-100 band with stable colour for rendering.

    ``NOT_EVALUATED`` is a non-numeric band: it represents a scan whose
    evaluator was not a real LLM (or was otherwise not authoritative), so no
    AIVSS number may be claimed. The scoring phase sets ``band=NOT_EVALUATED``
    whenever ``Scan.scoring_valid`` is ``False`` — it is never returned by
    :func:`band_for_score`, which only maps genuine [0, 100] scores.
    """

    EXCELLENT = "EXCELLENT"  # 90-100, #16a34a
    GOOD = "GOOD"  # 80-89,  #22c55e
    WARNING = "WARNING"  # 60-79,  #f59e0b
    POOR = "POOR"  # 40-59,  #ef4444
    CRITICAL = "CRITICAL"  # 0-39,   #991b1b
    NOT_EVALUATED = "not_evaluated"  # no real assessment, neutral slate #64748b


_BAND_COLOURS: dict[SeverityBand, str] = {
    SeverityBand.EXCELLENT: "#16a34a",
    SeverityBand.GOOD: "#22c55e",
    SeverityBand.WARNING: "#f59e0b",
    SeverityBand.POOR: "#ef4444",
    SeverityBand.CRITICAL: "#991b1b",
    SeverityBand.NOT_EVALUATED: "#64748b",  # neutral slate-500
}


def band_for_score(score: int) -> SeverityBand:
    """Map an AIVSS integer score in [0, 100] to its band.

    Raises:
        ValueError: if ``score`` is outside [0, 100].
    """
    if not 0 <= score <= 100:
        raise ValueError(f"AIVSS score must be in [0, 100]; got {score}")
    if score >= 90:
        return SeverityBand.EXCELLENT
    if score >= 80:
        return SeverityBand.GOOD
    if score >= 60:
        return SeverityBand.WARNING
    if score >= 40:
        return SeverityBand.POOR
    return SeverityBand.CRITICAL


def colour_for_band(band: SeverityBand) -> str:
    """Return the canonical hex colour string for an AIVSS band."""
    return _BAND_COLOURS[band]


# QA-G6 (2026-06-03) — single source of truth for human-facing band labels.
# The dashboard view-model (``server/dashboard_view._humanise_band``) and the
# CLI scan-complete summary (``cli._humanise_band_for_summary``) both delegate
# here so the two surfaces cannot diverge again. The mapping intentionally
# pairs ``NOT_EVALUATED`` with explanatory prose ("Not Evaluated (stub mode)")
# instead of leaking the underscore-bearing enum value verbatim — feedback
# memory ``no_raw_enum_in_ui`` requires it. The dashboard tile uses the
# shorter ``NA`` short-code for layout reasons; the CLI summary uses the
# verbose form because horizontal space is plentiful in a terminal line.
_HUMAN_BAND_LABELS: Final[Mapping[SeverityBand, str]] = {
    SeverityBand.EXCELLENT: "Excellent",
    SeverityBand.GOOD: "Good",
    SeverityBand.WARNING: "Warning",
    SeverityBand.POOR: "Poor",
    SeverityBand.CRITICAL: "Critical",
    SeverityBand.NOT_EVALUATED: "Not Evaluated (stub mode)",
}


def humanise_band(band: SeverityBand | None) -> str:
    """Return an operator-facing label for an AIVSS band.

    Falls back to a title-cased best-effort rendering if a future band slips
    past the mapping — never returns the raw underscore-bearing enum value
    (see ``feedback_no_raw_enum_in_ui``).
    """
    if band is None:
        return "Pending"
    label = _HUMAN_BAND_LABELS.get(band)
    if label is not None:
        return label
    return band.value.replace("_", " ").title()
