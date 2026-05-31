"""QA-007 — ``--debug-format json`` must keep stdout pure NDJSON.

Pre-fix bug: ``agent-guardian scan ... --debug --debug-format json`` emitted
the budget banner + two URL-emission lines (3 non-JSON lines) before the
NDJSON stream began. ``jq -c '.'`` raised ``parse error: Invalid numeric
literal`` on lines 1-3 of every JSON-mode scan.

These tests pin the fix:

* :func:`print_scan_urls` with ``debug_format="json"`` emits exactly one
  ``record_type=banner`` NDJSON line containing ``scan_url`` +
  ``report_url`` as fields.
* The budget banner is replaced by a JSON banner in JSON mode (both the
  capped and uncapped paths).
* The plan-summary JSON banner emitted in JSON mode contains the same
  data the Rich plan panel would have shown in text mode.
* All three sources combined produce only ``json.loads``-parseable lines.

The tests target the pure helpers (no Typer / no subprocess) by injecting
an in-memory buffer and the helper's optional ``write`` parameter.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from agent_guardian.cli import (
    _emit_json_banner,
    print_scan_urls,
)

# ---------------------------------------------------------------------------
# Helper: drain a buffer of NDJSON and assert every line round-trips through
# ``json.loads`` — the QA-007 acceptance criterion in code form.
# ---------------------------------------------------------------------------


def _assert_every_line_is_json(buf_text: str) -> list[dict[str, Any]]:
    lines = [ln for ln in buf_text.splitlines() if ln.strip()]
    assert lines, "expected at least one NDJSON line, got empty output"
    parsed: list[dict[str, Any]] = []
    for idx, ln in enumerate(lines):
        try:
            parsed.append(json.loads(ln))
        except json.JSONDecodeError as exc:  # pragma: no cover - failing path is the assertion
            pytest.fail(
                f"line {idx + 1} is NOT parseable JSON (QA-007 regression): {ln!r} :: {exc}"
            )
    return parsed


# ---------------------------------------------------------------------------
# print_scan_urls — JSON mode
# ---------------------------------------------------------------------------


def test_print_scan_urls_json_mode_emits_single_ndjson_line() -> None:
    """In JSON mode the two-line ▸-prefixed banner collapses to one NDJSON
    record. ``jq -c '.'`` over the output sees exactly one record.
    """
    buf = io.StringIO()
    print_scan_urls(
        "cli-3a4c1d9c2840",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        debug_format="json",
    )
    records = _assert_every_line_is_json(buf.getvalue())
    assert len(records) == 1
    rec = records[0]
    assert rec["record_type"] == "banner"
    assert rec["scan_id"] == "cli-3a4c1d9c2840"
    assert rec["payload"]["kind"] == "scan_url"
    assert rec["payload"]["scan_url"] == "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840"
    assert rec["payload"]["report_url"] == "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840/report"
    assert rec["payload"]["dashboard_base_url"] == "http://127.0.0.1:7474"


def test_print_scan_urls_json_mode_has_no_editorial_marker() -> None:
    """No ``▸`` glyph (the editorial prefix) leaks into JSON-mode output."""
    buf = io.StringIO()
    print_scan_urls(
        "cli-3a4c1d9c2840",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        debug_format="json",
    )
    assert "▸" not in buf.getvalue()
    assert "track live at" not in buf.getvalue()
    assert "Report when complete" not in buf.getvalue()


def test_print_scan_urls_json_mode_has_no_osc8_escape() -> None:
    """OSC 8 hyperlinks are a TTY affordance — JSON consumers must not
    see ESC ] 8 sequences mid-record."""
    buf = io.StringIO()
    print_scan_urls(
        "cli-3a4c1d9c2840",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        debug_format="json",
    )
    assert "\x1b]8;;" not in buf.getvalue()


def test_print_scan_urls_text_mode_unchanged() -> None:
    """Default ``debug_format="text"`` preserves the legacy two-line shape
    so QA-003 (URL within first 2 lines) and the existing
    ``test_scan_url_emission.py`` suite stay green.
    """
    buf = io.StringIO()
    print_scan_urls(
        "cli-3a4c1d9c2840",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        # debug_format defaults to "text"
    )
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    assert "▸ Scan" in lines[0]
    assert "▸ Report when complete" in lines[1]


def test_print_scan_urls_json_mode_suppress_still_no_op() -> None:
    """``suppress=True`` (``--no-publish``) wins over JSON mode."""
    buf = io.StringIO()
    print_scan_urls(
        "cli-3a4c1d9c2840",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        suppress=True,
        debug_format="json",
    )
    assert buf.getvalue() == ""


def test_print_scan_urls_json_mode_case_insensitive() -> None:
    """``debug_format`` matches the ``should_auto_serve`` precedent —
    ``"JSON"`` / ``"Json"`` / ``" json "`` all trigger the JSON branch.
    """
    for variant in ("JSON", "Json", " json "):
        buf = io.StringIO()
        print_scan_urls(
            "cli-3a4c1d9c2840",
            base_url="http://127.0.0.1:7474",
            write=buf.write,
            debug_format=variant,
        )
        records = _assert_every_line_is_json(buf.getvalue())
        assert len(records) == 1
        assert records[0]["payload"]["kind"] == "scan_url"


# ---------------------------------------------------------------------------
# _emit_json_banner — the shared helper
# ---------------------------------------------------------------------------


def test_emit_json_banner_basic_shape() -> None:
    buf = io.StringIO()
    _emit_json_banner(
        scan_id="cli-abc123",
        kind="budget_cap",
        payload={"usd_cap": 5.0, "soft_stop_pct": 80, "message": "x"},
        write=buf.write,
    )
    records = _assert_every_line_is_json(buf.getvalue())
    assert len(records) == 1
    rec = records[0]
    assert rec["record_type"] == "banner"
    assert rec["scan_id"] == "cli-abc123"
    assert rec["payload"]["kind"] == "budget_cap"
    assert rec["payload"]["usd_cap"] == 5.0
    # timestamp is ISO 8601, round-trips through fromisoformat
    from datetime import datetime

    datetime.fromisoformat(rec["timestamp"])


def test_emit_json_banner_single_line_no_embedded_newline() -> None:
    """``jq -c '.'`` requires exactly one record per line — embedded
    newlines in the payload must be JSON-escaped, not raw.
    """
    buf = io.StringIO()
    _emit_json_banner(
        scan_id="",
        kind="budget_cap",
        payload={"message": "line1\nline2"},
        write=buf.write,
    )
    text = buf.getvalue()
    # Exactly one trailing newline — no internal raw newlines.
    assert text.count("\n") == 1
    assert text.endswith("\n")


def test_emit_json_banner_payload_merges_kind() -> None:
    """The ``kind`` arg is injected into ``payload.kind`` so consumers can
    ``jq 'select(.payload.kind=="scan_url")'``.
    """
    buf = io.StringIO()
    _emit_json_banner(
        scan_id="x",
        kind="scan_url",
        payload={"scan_url": "http://x/scans/x"},
        write=buf.write,
    )
    records = _assert_every_line_is_json(buf.getvalue())
    assert records[0]["payload"]["kind"] == "scan_url"
    assert records[0]["payload"]["scan_url"] == "http://x/scans/x"


def test_emit_json_banner_deterministic_key_order() -> None:
    """``sort_keys=True`` so diff-based snapshot tests are deterministic
    (mirrors the ``attack_feed._emit_json`` convention).
    """
    buf = io.StringIO()
    _emit_json_banner(
        scan_id="x",
        kind="k",
        payload={"z": 1, "a": 2},
        write=buf.write,
    )
    line = buf.getvalue().strip()
    # Keys must appear alphabetically at every level — assert by parse +
    # re-dump with sort_keys + compare.
    obj = json.loads(line)
    assert json.dumps(obj, separators=(",", ":"), sort_keys=True) == line


# ---------------------------------------------------------------------------
# QA-007 end-to-end stdout-purity invariant — simulates the full pre-scan
# emission sequence (budget banner + plan summary + scan URLs) in JSON
# mode and asserts ``json.loads`` over every line.
# ---------------------------------------------------------------------------


def test_qa007_end_to_end_pre_swarm_stdout_is_pure_ndjson() -> None:
    """The QA-007 acceptance: ``agent-guardian scan ... --debug-format json
    | jq -c '.'`` produces zero parse errors across the entire output.

    We can't exec the full Typer scan in a unit test (it needs a target +
    LLM), so we replay the exact emission sequence the fix introduces:

      1. budget banner (capped variant)
      2. plan-summary banner
      3. scan-URL banner

    Every line in the combined buffer must round-trip through
    ``json.loads``.
    """
    buf = io.StringIO()
    # 1. budget cap (matches Edit 3's capped branch)
    _emit_json_banner(
        scan_id="",
        kind="budget_cap",
        payload={
            "usd_cap": 2.5,
            "soft_stop_pct": 80,
            "message": "budget cap: $2.5000 (...)",
        },
        write=buf.write,
    )
    # 2. plan summary (matches Edit 4's JSON-mode branch)
    _emit_json_banner(
        scan_id="cli-3a4c1d9c2840",
        kind="plan_summary",
        payload={
            "target": "https://api.example.com/v1/chat",
            "target_mode": "endpoint",
            "reachable": True,
            "reachable_latency_ms": 42,
            "multi_agent": False,
            "models": [{"role": "attacker", "spec": "gemini:gemini-2.5-flash", "valid": True}],
            "budget_mode": "smart",
            "wall_seconds_cap": 1800,
            "usd_cap": 2.5,
            "requested_output": "json",
            "auto_serve_spawned": False,
            "auto_serve_reused": False,
            "auto_serve_suppression": "--debug-format json",
            "dashboard_url": "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840",
        },
        write=buf.write,
    )
    # 3. scan URLs (matches Edit 2's JSON branch)
    print_scan_urls(
        "cli-3a4c1d9c2840",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        debug_format="json",
    )
    records = _assert_every_line_is_json(buf.getvalue())
    assert len(records) == 3
    kinds = [r["payload"]["kind"] for r in records]
    assert kinds == ["budget_cap", "plan_summary", "scan_url"]
    # Every record is a banner type — never confused with a "reflection"
    # record from the downstream AttackFeedRenderer.
    assert all(r["record_type"] == "banner" for r in records)


def test_qa007_end_to_end_uncapped_budget_branch_is_pure_ndjson() -> None:
    """Same as above but for the uncapped budget path (the more common
    no-flag case). Regression guard against branch-coverage drift.
    """
    buf = io.StringIO()
    _emit_json_banner(
        scan_id="",
        kind="budget_cap",
        payload={
            "usd_cap": None,
            "soft_stop_pct": None,
            "message": "no budget cap (running to completion)",
        },
        write=buf.write,
    )
    print_scan_urls(
        "cli-deadbeef0001",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        debug_format="json",
    )
    records = _assert_every_line_is_json(buf.getvalue())
    assert len(records) == 2
    assert records[0]["payload"]["usd_cap"] is None
    assert records[1]["payload"]["kind"] == "scan_url"


def test_qa007_jq_filter_extracts_scan_url_as_field() -> None:
    """The whole point of option (a): a ``jq`` consumer reads
    ``.payload.scan_url`` as a structured field instead of regex-scraping
    the ``▸`` editorial prefix.
    """
    buf = io.StringIO()
    print_scan_urls(
        "cli-3a4c1d9c2840",
        base_url="http://127.0.0.1:7474",
        write=buf.write,
        debug_format="json",
    )
    records = _assert_every_line_is_json(buf.getvalue())
    # Simulate `jq -c 'select(.payload.kind=="scan_url") | .payload.scan_url'`
    extracted = [
        r["payload"]["scan_url"] for r in records if r["payload"].get("kind") == "scan_url"
    ]
    assert extracted == ["http://127.0.0.1:7474/scans/cli-3a4c1d9c2840"]
