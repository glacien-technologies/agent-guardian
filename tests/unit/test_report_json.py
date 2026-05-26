"""JSON report emitter + signing tests (M13)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_guardian.reports.canonical import to_canonical_json
from agent_guardian.reports.json_report import (
    SCHEMA_VERSION,
    emit_json,
    verify_signatures,
    write_json,
)
from tests.unit._report_fixtures import make_scan


@pytest.fixture(autouse=True)
def _isolate_keys_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Redirect HOME so Ed25519 key persistence doesn't touch the user's real keys."""
    monkeypatch.setenv("HOME", str(tmp_path))


def test_emit_json_has_expected_top_level_keys() -> None:
    scan = make_scan()
    payload = emit_json(scan)
    assert payload["schema"] == SCHEMA_VERSION
    for key in (
        "scan_id",
        "package_version",
        "probe_library_version",
        "aivss_formula_version",
        "target",
        "tier",
        "aivss",
        "band",
        "sub_scores",
        "asi_scores",
        "findings_summary",
        "findings",
        "duration_seconds",
        "cost_usd",
        "created_at",
        "signatures",
    ):
        assert key in payload, f"missing key {key}"


def test_emit_json_target_subobject_shape() -> None:
    payload = emit_json(make_scan())
    assert payload["target"] == {"mode": "prompt", "ref": "prompt.txt"}


def test_emit_json_findings_summary_matches_scan() -> None:
    scan = make_scan()
    payload = emit_json(scan)
    assert payload["findings_summary"] == scan.findings_summary()


def test_emit_json_asi_scores_use_string_keys() -> None:
    payload = emit_json(make_scan())
    assert "ASI01" in payload["asi_scores"]
    assert isinstance(payload["asi_scores"]["ASI01"], float)


def test_emit_json_can_disable_signatures() -> None:
    payload = emit_json(make_scan(), sign=False)
    assert "signatures" not in payload


def test_emit_json_includes_both_signature_algorithms() -> None:
    payload = emit_json(make_scan())
    sigs = payload["signatures"]
    assert "hmac_sha256" in sigs
    assert "ed25519" in sigs


def test_write_json_roundtrips(tmp_path: Path) -> None:
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == SCHEMA_VERSION
    assert data["scan_id"] == scan.id
    assert data["aivss"] == scan.aivss


def test_verify_signatures_passes_on_fresh_report(tmp_path: Path) -> None:
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path)
    result = verify_signatures(path)
    assert result.schema_ok
    assert result.hmac_valid
    assert result.ed25519_valid
    assert result.ok
    assert result.error is None


def test_verify_signatures_fails_on_tampered_payload(tmp_path: Path) -> None:
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aivss"] = 0  # tamper
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    result = verify_signatures(path)
    assert not result.hmac_valid
    assert not result.ed25519_valid
    assert not result.ok


def test_verify_signatures_handles_missing_block(tmp_path: Path) -> None:
    scan = make_scan()
    payload = emit_json(scan, sign=False)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = verify_signatures(path)
    assert not result.ok
    assert result.error is not None


def test_verify_signatures_handles_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text("this is not json", encoding="utf-8")
    result = verify_signatures(path)
    assert not result.ok
    assert result.error is not None


def test_canonical_json_is_stable_across_runs() -> None:
    payload = emit_json(make_scan(), sign=False)
    a = to_canonical_json(payload)
    b = to_canonical_json(payload)
    assert a == b


def test_verify_signatures_accepts_in_memory_dict(tmp_path: Path) -> None:
    payload = emit_json(make_scan())
    result = verify_signatures(payload)
    assert result.ok
