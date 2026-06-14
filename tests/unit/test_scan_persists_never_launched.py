"""Issue #207 — Scan model must persist never_launched ASI categories.

Background. Live evidence (rc33 finbot-fast scan): a2a-agent was correctly
skipped as "not applicable for fingerprint" (finbot has no multi-agent
surface), so the AIVSS aggregate excluded ASI07 via
``_tier_weighted_aggregate_excluding`` — headline AIVSS=43 is correct.
But the per-ASI heatmap, markdown table, PDF, JUnit and signed JSON all
showed ASI07 = 0.0 (a deep-red zero next to "Agent Discovery / A2A").

Root cause: ``compute_aivss`` emits ``result.never_launched`` as a
frozenset on ``AivssResult``, but ``Scan(...)`` only persisted
``undertested`` and ``coverage_grade``. With no ``never_launched`` field
on the persisted Scan, every renderer read ``scan.asi_scores.get(ASI07)``
and saw a literal 0.0 it could not distinguish from "launched but
produced 0 findings".

These tests lock the post-fix contract:

* ``Scan`` has a ``never_launched: list[str]`` field, defaulted to empty
  for back-compat with older Scan JSON.
* ``compute_aivss``'s ``never_launched`` set round-trips through Scan as
  a sorted list of raw ASI value strings.
* The field appears as a distinct signal from ``undertested`` so
  renderers can branch on it.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier

_TS = datetime(2026, 6, 14, 12, 0, tzinfo=UTC)


def _baseline_scan_kwargs() -> dict:
    """Minimum kwargs to construct a valid Scan for round-trip tests."""
    return {
        "id": "scan-na-test",
        "package_version": "1.0.0rc34",
        "aivss_formula_version": "aivss-v1",
        "probe_library_version": "probes-v1",
        "target_mode": "http",
        "target_ref": "https://example.test/chat",
        "tier": Tier.T2_HIGH,
        "aivss": 43,
        "band": SeverityBand.POOR,
        "sub_scores": {
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 70.0,
            "pii_containment": 70.0,
            "memory_poisoning_resistance": 70.0,
            "excessive_agency_containment": 70.0,
            "hallucination_resistance": 70.0,
        },
        "findings": [],
        "asi_scores": {cat: 100.0 for cat in AsiCategory},
        "duration_seconds": 250.0,
        "cost_usd": 0.05,
        "tokens_total": 50_000,
        "mode": "fast",
        "engine": {"commander": "real", "attacker": "real", "evaluator": "real"},
        "created_at": _TS,
    }


def test_scan_has_never_launched_field_defaulting_empty() -> None:
    """``Scan`` exposes a ``never_launched`` field. Defaults to empty so
    older Scan JSON on disk deserialises unchanged.
    """
    scan = Scan(**_baseline_scan_kwargs())
    assert hasattr(scan, "never_launched"), (
        "Scan model is missing the ``never_launched`` field. Renderers "
        "cannot distinguish 'agent class was inapplicable to this target' "
        "(N/A) from 'agent ran and produced 0 findings' (a real 0 score) "
        "without this signal. See issue #207 for the rc33 finbot-fast "
        "ASI07-as-0 manifestation."
    )
    assert scan.never_launched == []


def test_scan_never_launched_round_trips_through_json() -> None:
    """The ``never_launched`` field must JSON-round-trip as a sorted list
    of raw ASI value strings (matches the ``undertested`` pattern). This
    is what renderers reading scan.json off disk will see.
    """
    kwargs = _baseline_scan_kwargs()
    kwargs["never_launched"] = ["ASI04", "ASI07"]
    scan = Scan(**kwargs)
    payload = scan.model_dump_json()
    roundtripped = Scan.model_validate_json(payload)
    assert roundtripped.never_launched == ["ASI04", "ASI07"]


def test_scan_never_launched_is_distinct_from_undertested() -> None:
    """``never_launched`` and ``undertested`` are independent signals.

    ``undertested`` = launched-but-thin (some turns, no findings).
    ``never_launched`` = the agent class itself was inapplicable.

    Renderers branch on these differently — undertested is amber
    "thinly tested" framing, never_launched is grey "N/A".
    """
    kwargs = _baseline_scan_kwargs()
    kwargs["undertested"] = ["ASI03"]
    kwargs["never_launched"] = ["ASI07"]
    scan = Scan(**kwargs)
    assert scan.undertested == ["ASI03"]
    assert scan.never_launched == ["ASI07"]
    # The two sets must be allowed to be disjoint (the common case for
    # a fingerprint-driven skip on an otherwise-well-covered scan).
    assert not (set(scan.undertested) & set(scan.never_launched))
