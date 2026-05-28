"""JSON report emitter — primary machine-readable format (PRD §10.1, M13).

Schema is ``agentguardian-scan-v1``. Reports are sorted-key and may include
both HMAC-SHA256 and Ed25519 signature blocks under the ``signatures`` key.
The signing input is the canonical JSON of the payload *without* the
``signatures`` field so verifiers can reconstruct the signed bytes.

PII redaction is on by default. With ``redact_pii=True`` the ``summary``
and ``transcript_ref`` strings of each finding are passed through
:class:`PiiRedactor` (best-effort, presidio-backed when available).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from agent_guardian.core.coverage import compute_coverage_from_memory
from agent_guardian.core.redact import PiiRedactor
from agent_guardian.crypto.ed25519_sig import (
    Ed25519SignatureBlock,
    sign_ed25519,
    verify_ed25519,
)
from agent_guardian.crypto.hmac_sig import (
    HmacSignatureBlock,
    sign_hmac,
    verify_hmac,
)
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.reports.canonical import to_canonical_json

__all__ = [
    "SCHEMA_VERSION",
    "VerifyResult",
    "emit_json",
    "sign_payload",
    "verify_signatures",
    "write_json",
]

SCHEMA_VERSION = "agentguardian-scan-v1"

_LOG = logging.getLogger(__name__)

_REDACTOR = PiiRedactor()


def _redact(text: str | None) -> str | None:
    if text is None or not text:
        return text
    return _REDACTOR.redact(text)


def _finding_to_dict(finding: Finding, redact: bool) -> dict[str, Any]:
    data = finding.model_dump(mode="json")
    if redact:
        data["summary"] = _redact(finding.summary)
        data["transcript_ref"] = _redact(finding.transcript_ref)
    return data


def _strip_signatures(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "signatures"}


def sign_payload(
    payload: dict[str, Any],
    *,
    secret: str | None = None,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    """Sign a JSON-serialisable payload with both HMAC and Ed25519.

    The signing input is canonical JSON of the payload minus the existing
    ``signatures`` key (idempotent: signing an already-signed payload twice
    yields the same payload bytes).
    """
    canonical = to_canonical_json(_strip_signatures(payload))
    hmac_block: HmacSignatureBlock = sign_hmac(canonical, secret=secret)
    ed_block: Ed25519SignatureBlock = sign_ed25519(canonical, keys_dir=keys_dir)
    return {"hmac_sha256": hmac_block, "ed25519": ed_block}


def emit_json(
    scan: Scan,
    *,
    redact_pii: bool = True,
    sign: bool = True,
    secret: str | None = None,
    keys_dir: Path | None = None,
    memory_root: Path | None = None,
) -> dict[str, Any]:
    """Build the ``agentguardian-scan-v1`` payload for a :class:`Scan`.

    The ``coverage`` block is reconstructed from the scan's on-disk
    ``memory.jsonl`` (under ``~/.agentguardian/scans/<scan_id>/`` by
    default). When no memory file exists (e.g. a hand-constructed Scan
    in a unit test) the coverage block has the canonical empty shape so
    the schema is stable.
    """
    coverage = compute_coverage_from_memory(scan, root_dir=memory_root)
    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "scan_id": scan.id,
        "package_version": scan.package_version,
        "probe_library_version": scan.probe_library_version,
        "aivss_formula_version": scan.aivss_formula_version,
        "target": {"mode": scan.target_mode, "ref": scan.target_ref},
        "tier": scan.tier.value,
        "aivss": scan.aivss,
        "band": scan.band.value,
        "sub_scores": dict(scan.sub_scores),
        "asi_scores": {cat.value: score for cat, score in scan.asi_scores.items()},
        "findings_summary": scan.findings_summary(),
        "coverage": coverage,
        "findings": [_finding_to_dict(f, redact_pii) for f in scan.findings],
        "duration_seconds": scan.duration_seconds,
        "cost_usd": scan.cost_usd,
        "tokens_total": scan.tokens_total,
        # v1.1 -- mode is the user-facing dial that controls early-stop
        # and probe-subsetting. Surfacing it in the report lets the
        # public dashboard segment coverage stats by mode (you can't
        # fairly compare a 45-second FAST scan against a 5-minute FULL
        # scan in the same aggregate bucket).
        "mode": scan.mode,
        "created_at": scan.created_at.astimezone().isoformat()
        if scan.created_at.tzinfo
        else scan.created_at.isoformat(),
    }
    if sign:
        payload["signatures"] = sign_payload(payload, secret=secret, keys_dir=keys_dir)
    return payload


def write_json(
    scan: Scan,
    path: Path,
    *,
    redact_pii: bool = True,
    sign: bool = True,
    indent: int = 2,
    secret: str | None = None,
    keys_dir: Path | None = None,
    memory_root: Path | None = None,
) -> None:
    """Render :func:`emit_json` to ``path`` (UTF-8, sorted keys)."""
    payload = emit_json(
        scan,
        redact_pii=redact_pii,
        sign=sign,
        secret=secret,
        keys_dir=keys_dir,
        memory_root=memory_root,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=indent, sort_keys=True)
    path.write_text(rendered, encoding="utf-8")
    _LOG.info(
        "report written: format=json path=%s bytes=%d signed=%s redacted=%s",
        path,
        len(rendered),
        sign,
        redact_pii,
    )


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of verifying a signed JSON report."""

    hmac_valid: bool
    ed25519_valid: bool
    schema_ok: bool
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.hmac_valid and self.ed25519_valid and self.schema_ok


def verify_signatures(
    source: Path | dict[str, Any],
    *,
    secret: str | None = None,
) -> VerifyResult:
    """Verify HMAC + Ed25519 signatures on a JSON report path or in-memory dict."""
    if isinstance(source, Path):
        try:
            data: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return VerifyResult(
                hmac_valid=False,
                ed25519_valid=False,
                schema_ok=False,
                error=f"could not read JSON: {exc}",
            )
    else:
        data = source

    if not isinstance(data, dict):
        return VerifyResult(
            hmac_valid=False,
            ed25519_valid=False,
            schema_ok=False,
            error="payload is not a JSON object",
        )

    schema_ok = data.get("schema") == SCHEMA_VERSION
    signatures = data.get("signatures")
    if not isinstance(signatures, dict):
        return VerifyResult(
            hmac_valid=False,
            ed25519_valid=False,
            schema_ok=schema_ok,
            error="missing 'signatures' block",
        )

    canonical = to_canonical_json(_strip_signatures(data))
    hmac_block = signatures.get("hmac_sha256")
    ed_block = signatures.get("ed25519")

    hmac_ok = isinstance(hmac_block, dict) and verify_hmac(
        canonical, cast(dict[str, object], hmac_block), secret=secret
    )
    ed_ok = isinstance(ed_block, dict) and verify_ed25519(
        canonical, cast(dict[str, object], ed_block)
    )
    return VerifyResult(
        hmac_valid=hmac_ok,
        ed25519_valid=ed_ok,
        schema_ok=schema_ok,
    )
