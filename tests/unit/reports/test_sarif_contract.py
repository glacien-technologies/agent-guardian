"""SARIF contract-provenance + invocation block tests (Stage 1B).

These cover the ``scan.audit`` branch of :func:`emit_sarif`:

* when ``audit`` is present, contract provenance is merged onto
  ``runs[0].properties`` and a ``runs[0].invocations`` array (SARIF 2.1.0
  defines ``run.invocations`` as an array) carrying the RoE budget envelope
  appears;
* when ``audit`` is ``None`` (the default), the SARIF omits the invocations
  block and leaves ``properties`` untouched.

The shared :func:`make_scan` fixture is reused; because :class:`Scan` is
frozen we attach ``audit`` via ``model_copy(update=...)``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_guardian.models.scan import Scan
from agent_guardian.reports.sarif import emit_sarif
from tests.unit._report_fixtures import make_scan

_SARIF_SCHEMA_PATH = Path(__file__).parent / "_fixtures" / "sarif-2.1.0.schema.json"


def _audit_record() -> dict[str, Any]:
    """A representative ``AuditRecord.to_dict()`` payload (Stage 1B shape)."""
    return {
        "contract_sha256": "a" * 64,
        "contract_version": "1.0",
        "authorization_ref": "JIRA-1234",
        "environment": "staging",
        "budgets_granted": {
            "max_tokens": 2_000_000,
            "max_requests": 500,
            "max_wallclock_minutes": 15,
        },
        "budgets_consumed": {
            "tokens": 12_345,
            "requests": 87,
            "wallclock_seconds": 42.5,
        },
        "suppressed_tool_attempts": 3,
        "started_at": "2026-05-29T12:00:00+00:00",
    }


def _scan_with_audit(audit: dict[str, Any] | None = None) -> Scan:
    """``make_scan()`` with an ``audit`` payload attached (frozen-safe)."""
    return make_scan().model_copy(update={"audit": audit or _audit_record()})


# --------------------------------------------------------------------------- #
# audit present
# --------------------------------------------------------------------------- #


def test_properties_carry_contract_provenance() -> None:
    log = emit_sarif(_scan_with_audit())
    props = log["runs"][0]["properties"]
    assert props["contract_sha256"] == "a" * 64
    assert props["contract_version"] == "1.0"
    assert props["authorization_ref"] == "JIRA-1234"
    assert props["environment"] == "staging"


def test_properties_still_carry_baseline_aivss() -> None:
    scan = _scan_with_audit()
    props = emit_sarif(scan)["runs"][0]["properties"]
    # Provenance is additive — the baseline keys are untouched.
    assert props["aivss"] == scan.aivss
    assert props["band"] == scan.band.value
    assert props["tier"] == scan.tier.value


def test_invocations_block_present_and_successful() -> None:
    log = emit_sarif(_scan_with_audit())
    invocations = log["runs"][0]["invocations"]
    # SARIF 2.1.0 — run.invocations is an ARRAY.
    assert isinstance(invocations, list)
    assert len(invocations) == 1
    assert invocations[0]["executionSuccessful"] is True


def test_invocation_properties_carry_budget_envelope() -> None:
    audit = _audit_record()
    log = emit_sarif(_scan_with_audit(audit))
    inv_props = log["runs"][0]["invocations"][0]["properties"]
    assert inv_props["budgets_granted"] == audit["budgets_granted"]
    assert inv_props["budgets_consumed"] == audit["budgets_consumed"]
    assert inv_props["suppressed_tool_attempts"] == 3
    assert inv_props["started_at"] == "2026-05-29T12:00:00+00:00"


def test_absent_audit_keys_are_omitted() -> None:
    # Sparse audit: only a hash + started_at. Missing keys must NOT appear.
    sparse = {
        "contract_sha256": "b" * 64,
        "started_at": "2026-05-29T12:00:00+00:00",
    }
    log = emit_sarif(_scan_with_audit(sparse))
    props = log["runs"][0]["properties"]
    inv_props = log["runs"][0]["invocations"][0]["properties"]
    assert props["contract_sha256"] == "b" * 64
    assert "contract_version" not in props
    assert "authorization_ref" not in props
    assert "environment" not in props
    assert inv_props == {"started_at": "2026-05-29T12:00:00+00:00"}


def test_none_valued_audit_keys_are_omitted() -> None:
    audit = _audit_record()
    audit["authorization_ref"] = None
    audit["budgets_consumed"] = None
    log = emit_sarif(_scan_with_audit(audit))
    props = log["runs"][0]["properties"]
    inv_props = log["runs"][0]["invocations"][0]["properties"]
    assert "authorization_ref" not in props
    assert "budgets_consumed" not in inv_props


# --------------------------------------------------------------------------- #
# audit absent — pre-Stage-1B output must be unchanged
# --------------------------------------------------------------------------- #


def test_no_audit_means_no_invocations() -> None:
    scan = make_scan()
    assert scan.audit is None
    log = emit_sarif(scan)
    assert "invocations" not in log["runs"][0]
    assert "invocation" not in log["runs"][0]


def test_no_audit_leaves_properties_unchanged() -> None:
    log = emit_sarif(make_scan())
    props = log["runs"][0]["properties"]
    # Posture + run config + honesty signals + version pins are always present.
    assert {
        "aivss",
        "band",
        "tier",
        "asi_scores",
        "target_ref",
        "mode",
        "evaluation_mode",
        "mode_authoritative",
        "aivss_formula_version",
        "probe_library_version",
    } <= set(props)
    # But with no scan.audit, the contract-provenance keys must NOT leak in.
    assert "contract_sha256" not in props
    assert "authorization_ref" not in props


def test_audit_none_is_byte_for_byte_identical_to_baseline() -> None:
    # Same Scan, one with audit explicitly None — output must be identical to
    # a Scan that never set audit at all.
    baseline = emit_sarif(make_scan())
    explicit_none = emit_sarif(make_scan().model_copy(update={"audit": None}))
    assert baseline == explicit_none


# --------------------------------------------------------------------------- #
# real SARIF 2.1.0 schema validation (finding #7) — invocations as an array
# --------------------------------------------------------------------------- #


def _validate_against_sarif_schema(log: dict[str, Any]) -> list[str]:
    """Return a list of schema-violation messages (empty == valid)."""
    jsonschema = pytest.importorskip("jsonschema")
    if not _SARIF_SCHEMA_PATH.is_file():  # pragma: no cover — fixture missing
        pytest.skip(f"SARIF 2.1.0 schema fixture missing at {_SARIF_SCHEMA_PATH}")
    schema = json.loads(_SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    return [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(log)]


def test_emitted_sarif_with_audit_validates_against_2_1_0_schema() -> None:
    # The whole point of finding #7: a singular ``invocation`` key tripped
    # ``run.additionalProperties=false``. With ``invocations`` (array) the
    # audit-bearing SARIF must validate with ZERO errors.
    log = emit_sarif(_scan_with_audit())
    errors = _validate_against_sarif_schema(log)
    assert errors == [], f"SARIF (with audit) failed 2.1.0 validation: {errors}"


def test_emitted_sarif_without_audit_validates_against_2_1_0_schema() -> None:
    log = emit_sarif(make_scan())
    errors = _validate_against_sarif_schema(log)
    assert errors == [], f"SARIF (no audit) failed 2.1.0 validation: {errors}"
