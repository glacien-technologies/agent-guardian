"""QA-023 — unit tests for the Executive view-model additions.

Targets the new ``probes_list`` / ``logs_tail`` payload fields produced by
:func:`build_dashboard_context` and the helper functions that back them
(``_assemble_probes_list``, ``_parse_reflection_line``, ``_assemble_logs_tail``,
``_parse_event_line``, ``_derive_log_level``, ``_derive_log_summary``,
``_timestamp_label``). These tests run without a TestClient so the pure
view-model layer is covered in isolation.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.server import ScanStore, create_app
from agent_guardian.server import dashboard_view as dv
from agent_guardian.server.dashboard_view import (
    _assemble_logs_tail,
    _assemble_probes_list,
    _derive_log_level,
    _derive_log_summary,
    _humanise_band,
    _parse_event_line,
    _parse_reflection_line,
    _timestamp_label,
    build_dashboard_context,
    live_snapshot,
)


def _write_probe_record(fh: object, agent: str, asi: str) -> None:
    """Append one ``record_type=reflection`` probe turn to an open memory.jsonl."""
    turn = {
        "agent": agent,
        "asi_category": asi,
        "turn": 1,
        "prompt": "p",
        "target_response": "r",
        "verdict": "robust",
    }
    rec = {
        "timestamp": "2026-05-27T12:30:15+00:00",
        "record_type": "reflection",
        "payload": {"agent": agent, "content": json.dumps(turn)},
    }
    fh.write(json.dumps(rec) + "\n")  # type: ignore[attr-defined]


def test_coverage_counts_distinct_exercised_categories(tmp_path: Path) -> None:
    """QA-070 (2026-06-04) — COVERAGE counts distinct ASI categories that
    received a probe, NOT categories with findings.

    Clean (no-finding) categories still count; duplicate-category probes don't
    double-count; recon / blank-category rows are ignored.
    """
    mem = tmp_path / "memory.jsonl"
    with mem.open("w", encoding="utf-8") as fh:
        _write_probe_record(fh, "asi01-goal", "ASI01")
        _write_probe_record(fh, "asi01-goal", "ASI01")  # duplicate -> still 1
        _write_probe_record(fh, "asi02-tool", "ASI02")
        _write_probe_record(fh, "asi03-pii", "ASI03")  # clean category, counts
        _write_probe_record(fh, "recon", "")  # recon / blank -> ignored
    ctx = build_dashboard_context(
        scan_id="cli-cov",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8080",
        version_label="t",
        scan_dir=tmp_path,
    )
    assert ctx.payload["asi_covered"] == 3
    # The live snapshot carries the same exercised count, "N / 10" shaped.
    assert live_snapshot(ctx)["asi-covered"] == "3 / 10"


def test_live_snapshot_carries_full_10_axis_radar(tmp_path: Path) -> None:
    """QA-069 (2026-06-04) — the radar's live values array always has all 10
    axes (pending categories at 0), so the client updates a stable frame."""
    ctx = build_dashboard_context(
        scan_id="cli-radar",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8080",
        version_label="t",
        scan_dir=tmp_path,
    )
    radar = live_snapshot(ctx)["asi_radar"]
    assert isinstance(radar, list)
    assert len(radar) == 10
    # No scan yet -> every category pending -> plots at 0.
    assert all(v == 0 for v in radar)


def _scan_with_partial_scores() -> Scan:
    """A scan where only ONE ASI category has a score; the other nine are
    absent (pending) — the mid-scan shape that used to collapse the radar."""
    return Scan(
        id="cli-partial-radar",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=50,
        band=SeverityBand.WARNING,
        sub_scores={},
        findings=[],
        asi_scores={AsiCategory.ASI01: 80.0},  # only one category scored
        duration_seconds=1.0,
        cost_usd=0.0,
        tokens_total=0,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )


def test_radar_renders_all_ten_axes_when_most_categories_pending(tmp_path: Path) -> None:
    """QA-069 (2026-06-04) — even when only one category is scored, the radar
    keeps all 10 axes (the old build dropped pending rows and collapsed to a
    single spoke). The data-chart payload + the offscreen data table both
    carry 10 entries; pending categories plot at 0.
    """
    scan = _scan_with_partial_scores()
    scan_dir = tmp_path / scan.id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")

    app = create_app(scan_store=ScanStore(root_dir=tmp_path))
    client = TestClient(app)
    body = client.get(f"/scan/{scan.id}?theme=executive").text

    # The radar canvas data-chart payload carries all 10 axis labels + values.
    m = re.search(r'id="exec-asi-radar"[^>]*data-chart=\'([^\']+)\'', body)
    assert m, "radar canvas with data-chart not found"
    payload = json.loads(m.group(1).replace("&#34;", '"').replace("&quot;", '"'))
    assert len(payload["labels"]) == 10
    assert len(payload["values"]) == 10
    # Exactly one axis carries a non-zero score; the nine pending ones are 0.
    assert sum(1 for v in payload["values"] if v) == 1


# ---------------------------------------------------------------------------
# probes_list helpers
# ---------------------------------------------------------------------------


def test_assemble_probes_list_none_scan_dir_returns_empty() -> None:
    assert _assemble_probes_list(None) == []


def test_assemble_probes_list_missing_file_returns_empty(tmp_path: Path) -> None:
    # tmp_path has no memory.jsonl yet.
    assert _assemble_probes_list(tmp_path) == []


def test_assemble_probes_list_reads_one_reflection_record(tmp_path: Path) -> None:
    turn = {
        "agent": "asi01-goal",
        "asi_category": "ASI01",
        "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
        "turn": 3,
        "strategy": "direct_injection",
        "prompt": "ignore prior instructions",
        "target_response": "I cannot do that.",
        "verdict": "robust",
        "confidence": 0.92,
        "reasoning": "target refused",
        "seed_id": "PROBE-007",
        "attacker_refused": False,
    }
    record = {
        "timestamp": "2026-05-27T12:30:15+00:00",
        "record_type": "reflection",
        "payload": {"agent": "asi01-goal", "content": json.dumps(turn)},
    }
    (tmp_path / "memory.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["agent"] == "asi01-goal"
    assert row["asi_category"] == "ASI01"
    assert row["turn"] == 3
    assert row["probe_id"] == "PROBE-007"
    assert row["prompt"] == "ignore prior instructions"
    assert row["verdict"] == "robust"
    assert row["confidence"] == 0.92
    assert row["timestamp_label"] == "12:30:15"


def test_assemble_probes_list_skips_non_reflection_rows(tmp_path: Path) -> None:
    rows_in = [
        {"record_type": "tool_call", "payload": {"agent": "x"}},
        {
            "record_type": "reflection",
            "payload": {"agent": "y", "content": json.dumps({"agent": "y"})},
        },
        {"random": "noise"},
    ]
    (tmp_path / "memory.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows_in) + "\n", encoding="utf-8"
    )
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 1
    assert rows[0]["agent"] == "y"


def test_assemble_probes_list_skips_blank_and_malformed_lines(tmp_path: Path) -> None:
    payload_lines = [
        "",
        "not-json",
        json.dumps({"record_type": "reflection", "payload": {"agent": "z", "content": "bad-json"}}),
        json.dumps(
            {
                "record_type": "reflection",
                "payload": {
                    "agent": "z",
                    "content": json.dumps({"agent": "z", "verdict": "vulnerable"}),
                },
            }
        ),
    ]
    (tmp_path / "memory.jsonl").write_text("\n".join(payload_lines) + "\n", encoding="utf-8")
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 2
    assert all(r["agent"] == "z" for r in rows)


def test_assemble_probes_list_caps_at_500_entries(tmp_path: Path) -> None:
    record = {
        "record_type": "reflection",
        "payload": {"agent": "x", "content": json.dumps({"agent": "x"})},
    }
    lines = [json.dumps(record)] * 750
    (tmp_path / "memory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 500


def test_parse_reflection_line_returns_none_for_malformed_json() -> None:
    assert _parse_reflection_line("not-json") is None


def test_parse_reflection_line_returns_none_for_non_dict_root() -> None:
    assert _parse_reflection_line(json.dumps([1, 2, 3])) is None


def test_parse_reflection_line_returns_none_for_wrong_record_type() -> None:
    raw = json.dumps({"record_type": "tool_call"})
    assert _parse_reflection_line(raw) is None


def test_parse_reflection_line_returns_none_when_payload_not_dict() -> None:
    raw = json.dumps({"record_type": "reflection", "payload": "string"})
    assert _parse_reflection_line(raw) is None


def test_parse_reflection_line_handles_missing_content() -> None:
    raw = json.dumps({"record_type": "reflection", "payload": {"agent": "x"}})
    parsed = _parse_reflection_line(raw)
    assert parsed is not None
    assert parsed["agent"] == "x"
    assert parsed["prompt"] == ""


def test_parse_reflection_line_handles_unparseable_content_string() -> None:
    raw = json.dumps(
        {"record_type": "reflection", "payload": {"agent": "x", "content": "not-json"}}
    )
    parsed = _parse_reflection_line(raw)
    assert parsed is not None
    assert parsed["agent"] == "x"


@pytest.mark.parametrize("event", ["attacker_refused", "egress_refused"])
def test_parse_reflection_line_drops_not_tested_markers(event: str) -> None:
    """Not-tested lifecycle markers must not surface as dashboard probe rows.

    ``attacker_refused`` / ``egress_refused`` reflections carry no verdict and
    never reached the target; including them would show a junk turn-0 row in the
    Probes tab (same exclusion as coverage + the per-agent probe export).
    """
    turn = {
        "agent": "trust-exploit-agent",
        "asi_category": "ASI09",
        "event": event,
        "outcome": "not_tested",
        "prompt": "Sorry, I cannot fulfill your request to generate adversarial inputs.",
    }
    raw = json.dumps(
        {
            "record_type": "reflection",
            "payload": {"agent": turn["agent"], "content": json.dumps(turn)},
        }
    )
    assert _parse_reflection_line(raw) is None


# ---------------------------------------------------------------------------
# logs_tail helpers
# ---------------------------------------------------------------------------


def test_assemble_logs_tail_none_scan_dir_returns_empty() -> None:
    assert _assemble_logs_tail(None) == []


def test_assemble_logs_tail_missing_file_returns_empty(tmp_path: Path) -> None:
    assert _assemble_logs_tail(tmp_path) == []


def test_assemble_logs_tail_reads_locked_shape(tmp_path: Path) -> None:
    events = [
        {
            "kind": "agent_skipped",
            "agent": "asi02-tool",
            "asi": "ASI02",
            "decision": None,
            "payload": {"reason": "budget exhausted"},
            "timestamp": "2026-05-27T12:01:00+00:00",
        },
        {
            "kind": "finding_emitted",
            "agent": "asi01-goal",
            "asi": "ASI01",
            "payload": {"severity": "critical"},
            "timestamp": "2026-05-27T12:02:00+00:00",
        },
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    rows = _assemble_logs_tail(tmp_path)
    assert len(rows) == 2
    assert rows[0]["level"] == "warn"
    assert "budget exhausted" in rows[0]["summary"]
    assert rows[1]["level"] == "info"
    assert "severity=critical" in rows[1]["summary"]
    assert rows[1]["agent"] == "asi01-goal"
    assert rows[0]["timestamp_label"] == "12:01:00"


def test_assemble_logs_tail_returns_every_line_after_cap_removal(tmp_path: Path) -> None:
    """Cap removed 2026-06-01 per operator request — ``_assemble_logs_tail``
    now returns every event from ``events.jsonl``. A 1200-line file produces
    a 1200-row list; the Logs tab's client-side filter is the operator's
    primary tool for navigating long runs."""
    events = [
        {
            "kind": "tick",
            "agent": None,
            "asi": None,
            "payload": {"seq": i},
            "timestamp": "2026-05-27T12:00:00+00:00",
        }
        for i in range(1200)
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    rows = _assemble_logs_tail(tmp_path)
    assert len(rows) == 1200
    # All rows kept, in original chronological order.
    assert rows[0]["payload_keys"] == ["seq"]
    assert rows[-1]["payload_keys"] == ["seq"]


def test_assemble_logs_tail_skips_malformed_lines(tmp_path: Path) -> None:
    lines = [
        "",
        "{not json",
        json.dumps([1, 2, 3]),  # non-dict
        json.dumps({"kind": "scan_started", "payload": {"message": "boot"}}),
    ]
    (tmp_path / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = _assemble_logs_tail(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "scan_started"


def test_parse_event_line_returns_none_for_malformed_json() -> None:
    assert _parse_event_line("not-json") is None


def test_parse_event_line_returns_none_for_non_dict_root() -> None:
    assert _parse_event_line(json.dumps(42)) is None


def test_parse_event_line_coerces_missing_payload_to_empty_dict() -> None:
    raw = json.dumps({"kind": "tick"})
    parsed = _parse_event_line(raw)
    assert parsed is not None
    assert parsed["payload_keys"] == []
    assert parsed["kind"] == "tick"
    assert parsed["level"] == "info"


# ---------------------------------------------------------------------------
# log level + summary derivation
# ---------------------------------------------------------------------------


def test_derive_log_level_agent_skipped_warns() -> None:
    assert _derive_log_level("agent_skipped", {}) == "warn"


def test_derive_log_level_explicit_error_kind() -> None:
    assert _derive_log_level("error", {}) == "error"


def test_derive_log_level_payload_error_truthy_errors() -> None:
    assert _derive_log_level("any_kind", {"error": "boom"}) == "error"


def test_derive_log_level_default_is_info() -> None:
    assert _derive_log_level("scan_started", {}) == "info"


def test_derive_log_summary_priority_order() -> None:
    # severity wins over reason + message
    assert (
        _derive_log_summary("k", {"severity": "high", "reason": "r", "message": "m"})
        == "k :: severity=high"
    )
    # reason wins over message
    assert _derive_log_summary("k", {"reason": "r", "message": "m"}) == "k :: r"
    # message is the last resort
    assert _derive_log_summary("k", {"message": "m"}) == "k :: m"
    # fallback to the bare kind
    assert _derive_log_summary("k", {}) == "k"


# ---------------------------------------------------------------------------
# kind="log" wire-format extension (Python logging -> events.jsonl bridge)
# ---------------------------------------------------------------------------


def test_derive_log_level_log_kind_reads_payload_level_info() -> None:
    assert _derive_log_level("log", {"level": "INFO"}) == "info"


def test_derive_log_level_log_kind_maps_debug_to_debug() -> None:
    # DEBUG used to collapse into the ``info`` bucket, hiding operator-opted-in
    # debug events behind the INFO chip. Splitting it into its own bucket lets
    # the Logs tab surface them behind a dedicated DEBUG filter chip.
    assert _derive_log_level("log", {"level": "DEBUG"}) == "debug"


def test_derive_log_level_log_kind_maps_warning_to_warn() -> None:
    assert _derive_log_level("log", {"level": "WARNING"}) == "warn"
    assert _derive_log_level("log", {"level": "WARN"}) == "warn"


def test_derive_log_level_log_kind_maps_error_and_critical_to_error() -> None:
    assert _derive_log_level("log", {"level": "ERROR"}) == "error"
    assert _derive_log_level("log", {"level": "CRITICAL"}) == "error"


def test_derive_log_level_log_kind_unknown_level_falls_back_to_info() -> None:
    assert _derive_log_level("log", {"level": "NOTALEVEL"}) == "info"
    assert _derive_log_level("log", {}) == "info"


def test_derive_log_summary_log_kind_prepends_logger_name() -> None:
    out = _derive_log_summary(
        "log", {"logger": "httpx", "message": "HTTP Request: POST https://api"}
    )
    assert out == "httpx — HTTP Request: POST https://api"


def test_derive_log_summary_log_kind_drops_kind_prefix() -> None:
    # Critically: no "log :: " prefix.
    out = _derive_log_summary(
        "log",
        {"logger": "agent_guardian.core.swarm", "message": "phase complete"},
    )
    assert not out.startswith("log :: ")
    assert "phase complete" in out


def test_derive_log_summary_log_kind_message_only_when_no_logger() -> None:
    assert _derive_log_summary("log", {"message": "bare text"}) == "bare text"


def test_derive_log_summary_log_kind_bare_kind_fallback() -> None:
    assert _derive_log_summary("log", {}) == "log"


# ---------------------------------------------------------------------------
# timestamp helper
# ---------------------------------------------------------------------------


def test_timestamp_label_handles_iso_with_z() -> None:
    assert _timestamp_label("2026-05-27T12:30:15Z") == "12:30:15"


def test_timestamp_label_handles_iso_with_offset() -> None:
    assert _timestamp_label("2026-05-27T12:30:15+00:00") == "12:30:15"


def test_timestamp_label_returns_empty_for_non_string() -> None:
    assert _timestamp_label(None) == ""
    assert _timestamp_label(123) == ""


def test_timestamp_label_returns_empty_for_unparseable() -> None:
    assert _timestamp_label("not-a-date") == ""


# ---------------------------------------------------------------------------
# build_dashboard_context — additive payload contract
# ---------------------------------------------------------------------------


def test_build_dashboard_context_additive_keys_with_no_scan_dir() -> None:
    ctx = build_dashboard_context(
        scan_id="sid",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8000",
        version_label="0.0.0",
    )
    p = ctx.payload
    assert "probes_list" in p
    assert "logs_tail" in p
    assert p["probes_list"] == []
    assert p["logs_tail"] == []


def test_build_dashboard_context_with_scan_dir_reads_memory_jsonl(tmp_path: Path) -> None:
    turn = {
        "agent": "x",
        "asi_category": "ASI01",
        "verdict": "vulnerable",
        "seed_id": "P-1",
    }
    record = {
        "record_type": "reflection",
        "payload": {"agent": "x", "content": json.dumps(turn)},
        "timestamp": "2026-05-27T12:01:02+00:00",
    }
    (tmp_path / "memory.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    ctx = build_dashboard_context(
        scan_id="sid",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8000",
        version_label="0.0.0",
        scan_dir=tmp_path,
    )
    assert ctx.payload["probes_list"][0]["agent"] == "x"


def test_dashboard_view_module_caps_are_locked() -> None:
    """Locked constants — ``_PROBES_LIST_CAP`` stays at 500. ``_LOGS_TAIL_CAP``
    was lifted to ``None`` on 2026-06-01 per operator request; the Logs tab
    now renders every event from ``events.jsonl`` and the client-side filter
    toolbar is the primary navigation tool for large logs."""
    assert dv._PROBES_LIST_CAP == 500
    assert dv._LOGS_TAIL_CAP is None


# ---------------------------------------------------------------------------
# band_label humanisation (feedback-no-raw-enum-in-ui)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("band", "expected"),
    [
        (SeverityBand.EXCELLENT, "Excellent"),
        (SeverityBand.GOOD, "Good"),
        (SeverityBand.WARNING, "Warning"),
        (SeverityBand.POOR, "Poor"),
        (SeverityBand.CRITICAL, "Critical"),
        (SeverityBand.NOT_EVALUATED, "NA"),
    ],
)
def test_humanise_band_maps_every_member(band: SeverityBand, expected: str) -> None:
    """Every :class:`SeverityBand` member must humanise — no raw enum text."""
    label = _humanise_band(band)
    assert label == expected
    # And, crucially, never leak the underscore-bearing internal token.
    assert "_" not in label


def test_humanise_band_handles_none_with_pending_label() -> None:
    """When no scan is loaded yet the helper returns a soft placeholder."""
    assert _humanise_band(None) == "Pending"


def _make_scan_with_band(band: SeverityBand, *, scan_id: str = "band-fixture") -> Scan:
    """Build a minimal Scan with the requested band (no findings, stub engine)."""
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=0 if band is SeverityBand.NOT_EVALUATED else 84,
        band=band,
        sub_scores={},
        findings=[],
        asi_scores={cat: 0.0 for cat in AsiCategory},
        duration_seconds=1.0,
        cost_usd=0.0,
        tokens_total=0,
        mode="full",
        scoring_valid=band is not SeverityBand.NOT_EVALUATED,
        evaluation_mode="real" if band is not SeverityBand.NOT_EVALUATED else "stub",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )


def test_build_dashboard_context_band_label_never_raw_enum_for_not_evaluated() -> None:
    """The view-model field must humanise NOT_EVALUATED before it reaches Jinja."""
    scan = _make_scan_with_band(SeverityBand.NOT_EVALUATED)
    ctx = build_dashboard_context(
        scan_id=scan.id,
        scan=scan,
        is_running=False,
        base_url="http://127.0.0.1:8000",
        version_label="0.0.0",
    )
    assert ctx.payload["band_label"] == "NA"
    assert "not_evaluated" not in ctx.payload["band_label"].lower()


def test_build_dashboard_context_band_label_pending_when_scan_absent() -> None:
    """No scan = soft 'Pending' placeholder; never the literal string PENDING."""
    ctx = build_dashboard_context(
        scan_id="sid",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8000",
        version_label="0.0.0",
    )
    assert ctx.payload["band_label"] == "Pending"
    assert "_" not in ctx.payload["band_label"]


def test_rendered_executive_dashboard_never_leaks_not_evaluated_token(
    tmp_path: Path,
) -> None:
    """End-to-end: an Executive render of a NOT_EVALUATED scan must NOT contain
    the raw ``not_evaluated`` token in any user-facing text node.

    The literal token may still legitimately appear as a CSS modifier class
    (``exec-kpi__value--not_evaluated``) — we check for the *visible* string
    instead. QA-065 (2026-06-04) — the band now renders on the AIVSS tile's
    sub-caption (``data-live="band-sub"``) rather than a standalone BAND tile.
    """
    store = ScanStore(root_dir=tmp_path)
    scan = _make_scan_with_band(SeverityBand.NOT_EVALUATED, scan_id="exec-band-not-eval")
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")

    app = create_app(scan_store=store)
    client = TestClient(app)
    resp = client.get(f"/scans/{scan.id}?theme=executive")
    assert resp.status_code == 200
    html = resp.text

    # The humanised label is present, the raw enum token is not (as visible text).
    assert "NA" in html
    # The KPI tile must carry the humanised label, not the underscore token.
    # We allow ``not_evaluated`` only as a CSS class modifier (``--not_evaluated``)
    # — anywhere else (inside a ``>…<`` text node) is a regression.
    assert ">not_evaluated<" not in html
    assert ">NOT_EVALUATED<" not in html
    # And the old verbose label must not linger anywhere in the rendered HTML —
    # if it survived a partial regression we'd see it here.
    assert "Not graded yet" not in html
