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
        "tokens_total",
        "engine",
        "evaluation_mode",
        "scoring_valid",
        "created_at",
        "signatures",
    ):
        assert key in payload, f"missing key {key}"


def test_emit_json_target_subobject_shape() -> None:
    payload = emit_json(make_scan())
    assert payload["target"] == {
        "mode": "prompt",
        "ref": "prompt.txt",
        "inferred_goal": None,
        "profile_source": None,
    }


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


def _embedded_pubkey(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    pubkey: str = data["signatures"]["ed25519"]["public_key_b32"]
    return pubkey


def test_verify_signatures_passes_on_fresh_report_with_anchor(tmp_path: Path) -> None:
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path, secret="real-signing-secret")
    # Trust-bearing verify needs a pinned pubkey + the real HMAC secret.
    result = verify_signatures(
        path,
        expected_ed25519_pubkey=_embedded_pubkey(path),
        expected_hmac_secret="real-signing-secret",
    )
    assert result.schema_ok
    assert result.hmac_valid
    assert result.ed25519_valid
    assert result.anchored
    assert result.ok
    assert result.error is None


def test_verify_signatures_unanchored_is_integrity_only(tmp_path: Path) -> None:
    # No anchor supplied: integrity may verify, but the result is NOT trusted.
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path, secret="real-signing-secret")
    result = verify_signatures(path, expected_hmac_secret="real-signing-secret")
    # HMAC anchored via real secret -> ed25519 still unpinned, but HMAC anchor
    # is enough for `ok` per the OR semantics; assert the ed25519-only path is
    # unanchored instead.
    ed_only = verify_signatures(path)  # no secret, no pubkey -> fully unanchored
    assert ed_only.ed25519_valid  # integrity of ed25519 holds
    assert not ed_only.hmac_valid  # HMAC fails closed (no secret)
    assert not ed_only.anchored
    assert not ed_only.ok
    assert ed_only.error is not None and "UNANCHORED" in ed_only.error
    # And the HMAC-anchored verify above IS trusted.
    assert result.anchored and result.ok


def test_verify_signatures_rejects_forged_ed25519_key(tmp_path: Path) -> None:
    # Forge: re-sign tampered content with a DIFFERENT keypair. Integrity holds
    # for the forged bytes, but pinning the original key must reject it.
    scan = make_scan()
    good = tmp_path / "good.json"
    write_json(scan, good, secret="real-signing-secret")
    pinned = _embedded_pubkey(good)

    forged = tmp_path / "forged.json"
    write_json(
        scan.model_copy(update={"aivss": 100}),
        forged,
        secret="real-signing-secret",
        keys_dir=tmp_path / "attacker-keys",  # fresh keypair
    )
    result = verify_signatures(
        forged,
        expected_ed25519_pubkey=pinned,
        expected_hmac_secret="real-signing-secret",
    )
    # ed25519 pin mismatch -> ed25519 invalid; not trusted.
    assert not result.ed25519_valid
    assert not result.ok


def test_verify_signatures_default_hmac_secret_is_not_trusted(tmp_path: Path) -> None:
    # A report signed with the public DEFAULT secret must NOT verify when no
    # real secret is supplied (fail closed).
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path)  # signed with default secret
    result = verify_signatures(path, expected_ed25519_pubkey=_embedded_pubkey(path))
    # ed25519 is pinned + valid -> anchored via ed25519; HMAC fails closed (the
    # public default secret is never trusted on verify).
    assert not result.hmac_valid
    assert result.ed25519_valid
    assert result.anchored  # ed25519 pin is the anchor
    # The HMAC channel was NOT anchored (no real secret supplied), so its
    # closed-fail must not veto a pinned-and-valid Ed25519: a genuine report
    # accepts when its Ed25519 key is pinned. (#6 — the common trust scenario.)
    assert not result.hmac_anchor_failed
    assert result.ok


def test_verify_signatures_fails_on_tampered_payload(tmp_path: Path) -> None:
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path, secret="real-signing-secret")
    pinned = _embedded_pubkey(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aivss"] = 0  # tamper
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    result = verify_signatures(
        path,
        expected_ed25519_pubkey=pinned,
        expected_hmac_secret="real-signing-secret",
    )
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
    payload = emit_json(make_scan(), secret="real-signing-secret")
    pinned = payload["signatures"]["ed25519"]["public_key_b32"]
    result = verify_signatures(
        payload,
        expected_ed25519_pubkey=pinned,
        expected_hmac_secret="real-signing-secret",
    )
    assert result.ok


# ----------------------------------------------------------------------
# Finding #8 — audit + engine folded into the SIGNED payload
# ----------------------------------------------------------------------


def test_emit_json_includes_audit_and_engine_before_signing(tmp_path: Path) -> None:
    scan = make_scan().model_copy(
        update={
            "audit": {
                "contract_sha256": "d" * 64,
                "authorization_ref": "JIRA-77",
                "suppressed_tool_attempts": 47,
            },
            "engine": {
                "commander": "openai:gpt-4o",
                "attacker": "openai:gpt-4o",
                "evaluator": "openai:gpt-4o",
            },
        }
    )
    payload = emit_json(scan, secret="real-signing-secret")
    # audit + engine present in payload...
    assert payload["audit"]["suppressed_tool_attempts"] == 47
    assert payload["audit"]["contract_sha256"] == "d" * 64
    assert payload["engine"]["evaluator"] == "openai:gpt-4o"
    # ...and covered by the signature (verify trusts the whole payload).
    pinned = payload["signatures"]["ed25519"]["public_key_b32"]
    result = verify_signatures(
        payload,
        expected_ed25519_pubkey=pinned,
        expected_hmac_secret="real-signing-secret",
    )
    assert result.ok
    # Tampering with the embedded audit must break the signature.
    import copy

    tampered = copy.deepcopy(payload)
    tampered["audit"]["suppressed_tool_attempts"] = 0
    bad = verify_signatures(
        tampered,
        expected_ed25519_pubkey=pinned,
        expected_hmac_secret="real-signing-secret",
    )
    assert not bad.ok


def test_emit_json_engine_none_when_unset() -> None:
    payload = emit_json(make_scan(), sign=False)
    assert payload["engine"] is None
    assert payload["evaluation_mode"] == "real"
    assert payload["scoring_valid"] is True
    assert "audit" not in payload  # omitted when scan.audit is None


def _leaky_scan():
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    leaky = make_finding(
        id="f_leak",
        probe_id="ASI02-TM-009",
        severity=Severity.HIGH,
        summary="target returned ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        trigger_prompt="leaked bearer abc123def456ghi789 token",
    )
    return make_scan(findings=[leaky])


def test_emit_json_redacts_secrets_in_findings_when_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Redaction is opt-in (off by default) — set AGENT_GUARDIAN_REDACT_PII like
    # the memory-redaction tests do to exercise the scrubbing path.
    monkeypatch.setenv("AGENT_GUARDIAN_REDACT_PII", "1")
    payload = emit_json(_leaky_scan(), sign=False)
    blob = json.dumps(payload)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in blob
    assert "[REDACTED:GITHUB_TOKEN]" in blob
    # trigger_prompt is redacted too.
    assert "abc123def456ghi789" not in blob
    assert "[REDACTED:BEARER_TOKEN]" in blob


def test_emit_json_leaves_secrets_raw_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off by default: without the opt-in env var (and no explicit flag) the
    verbatim target output is preserved — parity with memory.jsonl."""
    monkeypatch.delenv("AGENT_GUARDIAN_REDACT_PII", raising=False)
    payload = emit_json(_leaky_scan(), sign=False)
    blob = json.dumps(payload)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in blob
    assert "[REDACTED:GITHUB_TOKEN]" not in blob


def test_emit_json_explicit_redact_pii_overrides_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit ``redact_pii=`` bool wins over the env var either way."""
    # Env says on, explicit False wins -> raw.
    monkeypatch.setenv("AGENT_GUARDIAN_REDACT_PII", "1")
    raw = json.dumps(emit_json(_leaky_scan(), sign=False, redact_pii=False))
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in raw
    # Env unset, explicit True wins -> scrubbed.
    monkeypatch.delenv("AGENT_GUARDIAN_REDACT_PII", raising=False)
    scrubbed = json.dumps(emit_json(_leaky_scan(), sign=False, redact_pii=True))
    assert "[REDACTED:GITHUB_TOKEN]" in scrubbed


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
        "noop_attacker_turns": 0,
        "attacker_active": True,
        "skipped_agents": [],
        "strategies_used": {},
        "strategies_flattened": {},
        "unseeded_llm_calls": 0,
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
    write_json(scan, path, memory_root=tmp_path, secret="real-signing-secret")
    pinned = _embedded_pubkey(path)
    result = verify_signatures(
        path,
        expected_ed25519_pubkey=pinned,
        expected_hmac_secret="real-signing-secret",
    )
    assert result.ok


# ----------------------------------------------------------------------
# P2 — verify_signatures must always populate `error` on anchor failure
# ----------------------------------------------------------------------
#
# Previous logic: the two anchored-failure error messages were gated behind
# additional conditions (``anchored or ed25519_anchor_failed``,
# ``anchored``). If only one anchor was supplied and it alone failed —
# the most common operator mistake — neither branch fired and
# ``error`` was ``None``. The CLI prints ``error:`` only when truthy, so
# an operator pinning the wrong pubkey saw a bare red ``ok=False`` with
# no human-readable explanation.


def test_verify_signatures_wrong_ed25519_pin_alone_reports_error(tmp_path: Path) -> None:
    """Supply ONLY a wrong ed25519 pin on a clean report. Old code: error=None.
    New code: error mentions 'pinned' / 'Ed25519'."""
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path, secret="real-signing-secret")
    # A different report under a fresh keys_dir produces a different pubkey.
    decoy = tmp_path / "decoy.json"
    write_json(scan, decoy, keys_dir=tmp_path / "decoy-keys")
    wrong_pubkey = _embedded_pubkey(decoy)
    assert wrong_pubkey != _embedded_pubkey(path)

    result = verify_signatures(path, expected_ed25519_pubkey=wrong_pubkey)
    assert result.ed25519_anchor_failed
    assert not result.ok
    assert result.error is not None, (
        "verify_signatures must populate `error` when an anchor fails — the "
        "CLI only prints `error:` on a truthy message."
    )
    assert "pinned" in result.error.lower() or "ed25519" in result.error.lower()


def test_verify_signatures_wrong_hmac_secret_alone_reports_error(tmp_path: Path) -> None:
    """Supply ONLY a wrong HMAC secret. Old code: error=None when ed25519 was
    not anchored. New code: error mentions tamper / wrong secret."""
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path, secret="real-signing-secret")
    # Tamper the report so HMAC fails even if the right secret were used —
    # this exercises the "HMAC verification FAILED" branch end-to-end.
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aivss"] = 0
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    result = verify_signatures(path, expected_hmac_secret="real-signing-secret")
    assert result.hmac_anchor_failed
    assert not result.ok
    assert result.error is not None
    lowered = result.error.lower()
    assert "tamper" in lowered or "wrong secret" in lowered or "hmac" in lowered


def test_verify_signatures_both_anchors_fail_combined_message(tmp_path: Path) -> None:
    """Both anchors wrong: a combined message names both failed channels so
    the operator doesn't have to re-run with one at a time to diagnose."""
    scan = make_scan()
    path = tmp_path / "report.json"
    write_json(scan, path, secret="real-signing-secret")
    decoy = tmp_path / "decoy.json"
    write_json(scan, decoy, keys_dir=tmp_path / "decoy-keys")
    wrong_pubkey = _embedded_pubkey(decoy)

    result = verify_signatures(
        path,
        expected_ed25519_pubkey=wrong_pubkey,
        expected_hmac_secret="WRONG-secret",
    )
    assert result.hmac_anchor_failed
    assert result.ed25519_anchor_failed
    assert not result.ok
    assert result.error is not None
    assert "BOTH" in result.error or ("HMAC" in result.error and "Ed25519" in result.error)
