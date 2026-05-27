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
        "coverage",
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


# ----------------------------------------------------------------------
# Coverage block (M13 follow-up) — populated from memory.jsonl
# ----------------------------------------------------------------------


def _write_memory_jsonl(memory_root: Path, scan_id: str, records: list[dict]) -> Path:
    """Helper: write JSONL records to the canonical scan-memory path."""
    scan_dir = memory_root / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    path = scan_dir / "memory.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    return path


def _make_reflection_record(
    scan_id: str,
    *,
    agent: str,
    asi_category: str,
    mitre: list[str],
    csa: str,
    turn: int = 1,
) -> dict:
    content = json.dumps(
        {
            "agent": agent,
            "asi_category": asi_category,
            "mitre_techniques": mitre,
            "csa_category": csa,
            "turn": turn,
            "strategy": "pair",
            "prompt": "test prompt",
            "rationale": "",
            "target_response": "test response",
            "verdict": "pass",
            "confidence": 0.5,
            "reasoning": "ok",
            "strategy_metadata": {},
            "seed_id": None,
        }
    )
    return {
        "record_type": "reflection",
        "scan_id": scan_id,
        "timestamp": "2026-05-27T00:00:00+00:00",
        "payload": {"agent": agent, "content": content},
    }


def test_emit_json_includes_coverage_block_empty_when_no_memory(tmp_path: Path) -> None:
    scan = make_scan()
    payload = emit_json(scan, memory_root=tmp_path)
    cov = payload["coverage"]
    assert cov == {
        "attempts_total": 0,
        "asi_categories": [],
        "mitre_techniques": [],
        "csa_categories": [],
        "agents": {},
        "probes_attempted": [],
        "attacker_refused_turns": 0,
        "attacker_refusal_rate": 0.0,
    }


def test_coverage_attempts_total_matches_reflection_count(tmp_path: Path) -> None:
    scan = make_scan()
    _write_memory_jsonl(
        tmp_path,
        scan.id,
        [
            _make_reflection_record(
                scan.id,
                agent="goal-hijack-agent",
                asi_category="ASI01",
                mitre=["AML.T0054"],
                csa="goal_instruction_manipulation",
                turn=1,
            ),
            _make_reflection_record(
                scan.id,
                agent="goal-hijack-agent",
                asi_category="ASI01",
                mitre=["AML.T0054"],
                csa="goal_instruction_manipulation",
                turn=2,
            ),
            _make_reflection_record(
                scan.id,
                agent="tool-abuse-agent",
                asi_category="ASI02",
                mitre=["AML.T0040"],
                csa="authorization_control_hijacking",
                turn=1,
            ),
        ],
    )
    payload = emit_json(scan, memory_root=tmp_path)
    cov = payload["coverage"]
    assert cov["attempts_total"] == 3
    assert cov["asi_categories"] == ["ASI01", "ASI02"]
    assert cov["mitre_techniques"] == ["AML.T0040", "AML.T0054"]
    assert cov["csa_categories"] == [
        "authorization_control_hijacking",
        "goal_instruction_manipulation",
    ]
    assert cov["agents"] == {"goal-hijack-agent": 2, "tool-abuse-agent": 1}


def test_coverage_skips_non_reflection_records(tmp_path: Path) -> None:
    """Findings, fingerprints, attempted_seeds must not inflate attempts."""
    scan = make_scan()
    _write_memory_jsonl(
        tmp_path,
        scan.id,
        [
            {
                "record_type": "fingerprint",
                "scan_id": scan.id,
                "timestamp": "2026-05-27T00:00:00+00:00",
                "payload": {"mode": "prompt", "ref": "x"},
            },
            {
                "record_type": "attempted_seed",
                "scan_id": scan.id,
                "timestamp": "2026-05-27T00:00:00+00:00",
                "payload": {"asi": "ASI01", "seed_id": "seed-1"},
            },
            _make_reflection_record(
                scan.id,
                agent="goal-hijack-agent",
                asi_category="ASI01",
                mitre=["AML.T0054"],
                csa="goal_instruction_manipulation",
            ),
        ],
    )
    payload = emit_json(scan, memory_root=tmp_path)
    assert payload["coverage"]["attempts_total"] == 1


def test_coverage_tolerates_malformed_lines(tmp_path: Path) -> None:
    """A garbled line in memory.jsonl must not bring down report emission."""
    scan = make_scan()
    path = tmp_path / scan.id / "memory.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    good = _make_reflection_record(
        scan.id,
        agent="cascade-agent",
        asi_category="ASI03",
        mitre=["AML.T0042"],
        csa="cascading_trust_failure_in_inter_agent_systems",
    )
    path.write_text(
        "not-json\n" + json.dumps(good) + "\n{partial: broken\n",
        encoding="utf-8",
    )
    payload = emit_json(scan, memory_root=tmp_path)
    assert payload["coverage"]["attempts_total"] == 1
    assert payload["coverage"]["asi_categories"] == ["ASI03"]


def test_emit_json_with_coverage_still_signs_and_verifies(tmp_path: Path) -> None:
    """Adding coverage must not break the signature flow."""
    scan = make_scan()
    _write_memory_jsonl(
        tmp_path,
        scan.id,
        [
            _make_reflection_record(
                scan.id,
                agent="drift-agent",
                asi_category="ASI10",
                mitre=["AML.T0051"],
                csa="hallucination_exploitation",
            ),
        ],
    )
    path = tmp_path / "report.json"
    write_json(scan, path, memory_root=tmp_path)
    result = verify_signatures(path)
    assert result.ok
