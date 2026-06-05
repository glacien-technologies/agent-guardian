"""Detector-replay + monitoring-coverage aggregation (M2 — DetectionEvasionAgent).

Reframed per the M2 design: we do NOT produce evasion-tuned payloads. For each
already-validated PoV, we replay the request/response pair through the
customer's declared monitoring stack (Lakera Guard, Llama Guard 3, NeMo
Guardrails, Prompt Shield, Rebuff, custom rules) and record each detector's
verdict, then aggregate per OWASP/ASI category. The deliverable is a coverage
report telling the customer which attack categories their monitoring misses.

Detectors are pluggable via the :class:`Detector` protocol so real
integrations (HTTP calls to the customer's declared endpoints) and test stubs
share one interface. A detector is considered "covered" for a category when it
flags at least ``coverage_threshold`` (default 0.8) of that category's PoVs.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

__all__ = [
    "CoverageReport",
    "Detector",
    "DetectorReplay",
    "ReplayItem",
    "function_detector",
]

_LOG = logging.getLogger(__name__)


class Detector(Protocol):
    """A monitoring detector that flags (or misses) an attack request/response."""

    name: str

    async def flags(self, request: str, response: str) -> bool:
        """Return True iff this detector caught the request/response pair."""


@dataclass(frozen=True)
class ReplayItem:
    """One validated PoV to replay through the detector stack."""

    finding_id: str
    category: str  # OWASP/ASI category bucket
    request: str
    response: str


def function_detector(name: str, fn: Callable[[str, str], Awaitable[bool] | bool]) -> Detector:
    """Adapt a plain (request, response)->bool function into a :class:`Detector`."""

    class _FnDetector:
        def __init__(self) -> None:
            self.name = name

        async def flags(self, request: str, response: str) -> bool:
            verdict = fn(request, response)
            if isinstance(verdict, bool):
                return verdict
            return await verdict

    return _FnDetector()


@dataclass(frozen=True)
class CoverageReport:
    """Per-category, per-detector monitoring-coverage breakdown."""

    # category -> detector_name -> flag_rate in [0, 1]
    per_category: dict[str, dict[str, float]] = field(default_factory=dict)
    # categories where NO detector reached the coverage threshold.
    gap_categories: list[str] = field(default_factory=list)
    # detector_name -> verdict per (finding_id) for the audit trail.
    verdicts: dict[str, dict[str, bool]] = field(default_factory=dict)


class DetectorReplay:
    """Replays validated PoVs through a detector stack and aggregates coverage."""

    def __init__(self, detectors: list[Detector], *, coverage_threshold: float = 0.8) -> None:
        if not detectors:
            raise ValueError("DetectorReplay needs at least one detector")
        self._detectors = detectors
        self._threshold = coverage_threshold

    @property
    def detectors(self) -> list[Detector]:
        """The detector stack (read-only) — used by the active-evasion pass."""
        return list(self._detectors)

    async def run(self, items: list[ReplayItem]) -> CoverageReport:
        # Tally flags per (category, detector) and record per-finding verdicts.
        counts: dict[str, dict[str, list[bool]]] = {}
        verdicts: dict[str, dict[str, bool]] = {d.name: {} for d in self._detectors}
        for item in items:
            cat = counts.setdefault(item.category, {d.name: [] for d in self._detectors})
            for det in self._detectors:
                flagged = await det.flags(item.request, item.response)
                cat[det.name].append(flagged)
                verdicts[det.name][item.finding_id] = flagged

        per_category: dict[str, dict[str, float]] = {}
        gap_categories: list[str] = []
        for category, by_detector in counts.items():
            rates = {
                name: (sum(flags) / len(flags) if flags else 0.0)
                for name, flags in by_detector.items()
            }
            per_category[category] = rates
            # A category is a gap if NO detector clears the coverage threshold.
            if not any(rate >= self._threshold for rate in rates.values()):
                gap_categories.append(category)
                _LOG.info(
                    "detector-replay: coverage GAP for category %s (max rate %.2f)",
                    category,
                    max(rates.values(), default=0.0),
                )

        return CoverageReport(
            per_category=per_category,
            gap_categories=sorted(gap_categories),
            verdicts=verdicts,
        )
