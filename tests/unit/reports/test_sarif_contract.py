"""SARIF contract-provenance + invocation block tests (Stage 1B).

These cover the ``scan.audit`` branch of :func:`emit_sarif`:

* when ``audit`` is present, contract provenance is merged onto
  ``runs[0].properties`` and a ``runs[0].invocation`` block carrying the RoE
  budget envelope appears;
* when ``audit`` is ``None`` (the default), the SARIF is byte-for-byte
  identical to the pre-Stage-1B emitter — no ``invocation``, untouched
  ``properties``.

The shared :func:`make_scan` fixture is reused; because :class:`Scan` is
frozen we attach ``audit`` via ``model_copy(update=...)``.
"""

from __future__ import annotations

from typing import Any

from agent_guardian.models.scan import Scan
from agent_guardian.reports.sarif import emit_sarif
from tests.unit._report_fixtures import make_scan


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


def test_invocation_block_present_and_successful() -> None:
    log = emit_sarif(_scan_with_audit())
    invocation = log["runs"][0]["invocation"]
    assert invocation["executionSuccessful"] is True


def test_invocation_properties_carry_budget_envelope() -> None:
    audit = _audit_record()
    log = emit_sarif(_scan_with_audit(audit))
    inv_props = log["runs"][0]["invocation"]["properties"]
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
    inv_props = log["runs"][0]["invocation"]["properties"]
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
    inv_props = log["runs"][0]["invocation"]["properties"]
    assert "authorization_ref" not in props
    assert "budgets_consumed" not in inv_props


# --------------------------------------------------------------------------- #
# audit absent — pre-Stage-1B output must be unchanged
# --------------------------------------------------------------------------- #


def test_no_audit_means_no_invocation() -> None:
    scan = make_scan()
    assert scan.audit is None
    log = emit_sarif(scan)
    assert "invocation" not in log["runs"][0]


def test_no_audit_leaves_properties_unchanged() -> None:
    log = emit_sarif(make_scan())
    props = log["runs"][0]["properties"]
    assert set(props) == {
        "aivss",
        "band",
        "tier",
        "asi_scores",
        "aivss_formula_version",
        "probe_library_version",
    }


def test_audit_none_is_byte_for_byte_identical_to_baseline() -> None:
    # Same Scan, one with audit explicitly None — output must be identical to
    # a Scan that never set audit at all.
    baseline = emit_sarif(make_scan())
    explicit_none = emit_sarif(make_scan().model_copy(update={"audit": None}))
    assert baseline == explicit_none
