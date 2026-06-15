"""PR-4 — emitter-completeness fixes (rc35 deep-review L1, L6, R31, H3).

Four small additive fixes bundled because they all live in the
emitters/CLI surface and share zero ordering:

* L1 (#218) — ``ScanCompleteness.terminated_by_counts`` exposes the
  per-reason agent-termination breakdown so dashboards / SARIF
  coverage badges can render "12 success / 3 cancelled" instead of
  just the ``agents_cut_short`` aggregate.
* L6 (#221) — ``events.jsonl`` now writes a ``{"kind": "_meta",
  "schema_version": "events-v1", ...}`` header line as the first
  event so downstream parsers can branch on the schema explicitly.
* R31 (#230) — JUnit XML carries ``never_launched`` / ``recon_truncated``
  / ``recon_completion_pct`` on the ``<testsuites><properties>`` block
  and the PDF emitter's ASI table renders never-launched rows as
  "N/A" instead of the 0.0 sentinel, closing the PR #210 multi-emitter
  contract.
* H3 (#213) — ``agent-guardian verify`` recurses into a directory
  argument and discovers the bundle's ``manifest.json``, fixing the
  round-trip with ``agent-guardian scan --bundle X.zip``.
"""

from __future__ import annotations

from agent_guardian.models.scan import ScanCompleteness


def test_scan_completeness_terminated_by_counts_default_empty() -> None:
    """Back-compat: older Scan JSON on disk that predates the field still
    deserialises with an empty dict (no migration needed)."""
    c = ScanCompleteness()
    assert c.terminated_by_counts == {}


def test_scan_completeness_terminated_by_counts_holds_breakdown() -> None:
    """The new field accepts a {reason -> count} dict so the JSON envelope
    can render '13 success / 3 cancelled / 1 error' on a partial scan."""
    c = ScanCompleteness(
        agents_planned=16,
        agents_completed=13,
        agents_cut_short=3,
        turns_used=180,
        turns_planned=320,
        pct=81.3,
        terminated_by_counts={"success": 13, "cancelled": 3},
    )
    assert c.terminated_by_counts == {"success": 13, "cancelled": 3}


def test_events_jsonl_schema_version_constant_pinned() -> None:
    """Lock the schema-version constant so a bump can't ship silently —
    a downstream events.jsonl parser keys off this value."""
    from agent_guardian.server.scan_store import EVENTS_JSONL_SCHEMA_VERSION

    assert EVENTS_JSONL_SCHEMA_VERSION == "events-v1"


def test_junit_emit_carries_never_launched() -> None:
    """JUnit XML <testsuites><properties> must include never_launched +
    the recon-truncation pair so CI consumers that parse JUnit (not the
    SARIF / signed JSON) have the same signal as everyone else."""
    from datetime import UTC, datetime

    from agent_guardian.models.asi import AsiCategory
    from agent_guardian.models.scan import Scan
    from agent_guardian.models.severity import SeverityBand
    from agent_guardian.models.tier import Tier
    from agent_guardian.reports.junit import emit_junit

    scan = Scan(
        id="scan-junit-na",
        package_version="1.0.0rc36",
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="http",
        target_ref="https://example.test/chat",
        tier=Tier.T2_HIGH,
        aivss=43,
        band=SeverityBand.POOR,
        sub_scores={
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 70.0,
            "pii_containment": 70.0,
            "memory_poisoning_resistance": 70.0,
            "excessive_agency_containment": 70.0,
            "hallucination_resistance": 70.0,
        },
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=250.0,
        cost_usd=0.05,
        tokens_total=50_000,
        mode="fast",
        engine={"commander": "real", "attacker": "real", "evaluator": "real"},
        created_at=datetime(2026, 6, 15, tzinfo=UTC),
        never_launched=["ASI04", "ASI07"],
        recon_truncated=True,
        recon_completion_pct=100.0,
    )
    root = emit_junit(scan)
    # Find the <testsuites><properties> block.
    props = root.find("properties")
    assert props is not None, "JUnit <testsuites> must carry a <properties> block"
    keys = {p.get("name"): p.get("value") for p in props.findall("property")}
    assert "never_launched" in keys, (
        f"JUnit emit missing never_launched property. Found keys: "
        f"{sorted(str(k) for k in keys)}. "
        "CI consumers parsing JUnit XML have no other way to read N/A signal (#230)."
    )
    assert "ASI04" in (keys.get("never_launched") or "")
    assert "ASI07" in (keys.get("never_launched") or "")
    # Recon-truncation pair from the same PR-1 follow-up.
    assert "recon_truncated" in keys
    assert "recon_completion_pct" in keys


def test_pdf_asi_rows_carry_is_not_applicable_flag() -> None:
    """The PDF emitter's ``_build_asi_rows`` must mark never-launched
    rows with ``is_not_applicable=True`` so the template can render
    them as "N/A" instead of the 0.0 sentinel (mirrors markdown + SARIF
    + JSON, closing the PR #210 multi-emitter contract)."""
    from datetime import UTC, datetime

    from agent_guardian.models.asi import AsiCategory
    from agent_guardian.models.scan import Scan
    from agent_guardian.models.severity import SeverityBand
    from agent_guardian.models.tier import Tier
    from agent_guardian.reports.pdf import _build_asi_rows

    scan = Scan(
        id="scan-pdf-na",
        package_version="1.0.0rc36",
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="http",
        target_ref="https://example.test/chat",
        tier=Tier.T2_HIGH,
        aivss=43,
        band=SeverityBand.POOR,
        sub_scores={
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 70.0,
            "pii_containment": 70.0,
            "memory_poisoning_resistance": 70.0,
            "excessive_agency_containment": 70.0,
            "hallucination_resistance": 70.0,
        },
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=250.0,
        cost_usd=0.05,
        tokens_total=50_000,
        mode="fast",
        engine={"commander": "real", "attacker": "real", "evaluator": "real"},
        created_at=datetime(2026, 6, 15, tzinfo=UTC),
        never_launched=["ASI04", "ASI07"],
    )
    rows = _build_asi_rows([], scan)
    by_id = {r["id"]: r for r in rows}
    assert by_id["ASI04"]["is_not_applicable"] is True
    assert by_id["ASI07"]["is_not_applicable"] is True
    # An ASI not in never_launched stays flagged False.
    assert by_id["ASI01"]["is_not_applicable"] is False
