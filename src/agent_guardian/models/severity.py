"""Severity enumeration, AIVSS band classification, and band-to-colour mapping.

``Severity`` annotates each probe/finding with its raw severity weight.
``SeverityBand`` maps a final AIVSS 0-100 score to one of five named bands
with a stable hex colour for UI rendering.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "Severity",
    "SeverityBand",
    "band_for_score",
    "colour_for_band",
]


class Severity(str, Enum):
    """Per-probe severity weight (PRD §6 Step 2)."""

    CRITICAL = "critical"  # weight 1.0
    HIGH = "high"  # weight 0.7
    MEDIUM = "medium"  # weight 0.4
    LOW = "low"  # weight 0.2


class SeverityBand(str, Enum):
    """AIVSS 0-100 band with stable colour for rendering."""

    EXCELLENT = "EXCELLENT"  # 90-100, #16a34a
    GOOD = "GOOD"  # 80-89,  #22c55e
    WARNING = "WARNING"  # 60-79,  #f59e0b
    POOR = "POOR"  # 40-59,  #ef4444
    CRITICAL = "CRITICAL"  # 0-39,   #991b1b


_BAND_COLOURS: dict[SeverityBand, str] = {
    SeverityBand.EXCELLENT: "#16a34a",
    SeverityBand.GOOD: "#22c55e",
    SeverityBand.WARNING: "#f59e0b",
    SeverityBand.POOR: "#ef4444",
    SeverityBand.CRITICAL: "#991b1b",
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
