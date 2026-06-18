"""JSON report emitter — primary machine-readable format (PRD §10.1, M13).

Schema is ``agentguardian-scan-v1``. Reports are sorted-key and may include
both HMAC-SHA256 and Ed25519 signature blocks under the ``signatures`` key.
The signing input is the canonical JSON of the payload *without* the
``signatures`` field so verifiers can reconstruct the signed bytes.

PII / secret redaction is **opt-in** (off by default; set
``AGENT_GUARDIAN_REDACT_PII=1`` or pass ``redact_pii=True``). This mirrors the
``memory.jsonl`` durable-storage default — operators asked to see the verbatim
target output (account ids, transaction ids, dollar amounts were being mangled
into ``[REDACTED:PHONE_NUMBER]``). When redaction is enabled every finding is
routed through the shared :func:`agent_guardian.core.redact.redact_finding`
helper, which scrubs ``summary``, ``description``, ``trigger_prompt``,
``transcript_ref`` and ``evidence`` of PII *and* credential shapes (OpenAI /
AWS / GitHub / Google keys, JWTs, bearer tokens, ``password=`` assignments)
using the regex fallback, with presidio layered on for richer PII when the
``[full]`` extra is installed. The same helper is used by the SARIF, JUnit,
Markdown and PDF emitters so every output surface scrubs identically — a
security scanner must never re-emit a captured secret.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from agent_guardian.core.coverage import compute_coverage_from_memory
from agent_guardian.core.redact import redact_finding
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

# Opt-IN PII redaction of report findings — off by default, mirroring the
# ``memory.jsonl`` durable-storage default (see ``core.memory``). Set
# ``AGENT_GUARDIAN_REDACT_PII=1`` to re-enable scrubbing for shareable
# artifacts. Callers may still force it on/off by passing ``redact_pii=`` an
# explicit bool; the env var only resolves the unset (``None``) default.
_REDACT_ENV = "AGENT_GUARDIAN_REDACT_PII"
_TRUTHY = {"1", "true", "yes", "on"}


def _resolve_redact(redact_pii: bool | None) -> bool:
    """Resolve the effective redaction flag.

    An explicit ``True``/``False`` wins; ``None`` (the default) reads
    ``AGENT_GUARDIAN_REDACT_PII`` and is off unless opted in.
    """
    if redact_pii is not None:
        return redact_pii
    return os.environ.get(_REDACT_ENV, "").strip().lower() in _TRUTHY


def _finding_to_dict(finding: Finding, redact: bool) -> dict[str, Any]:
    # Redact at the Finding source-of-truth via the shared helper so summary,
    # description, trigger_prompt, transcript_ref and evidence are all scrubbed
    # of PII + credential shapes before serialisation.
    scrubbed: Finding = redact_finding(finding, enabled=redact)
    return scrubbed.model_dump(mode="json")


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
    redact_pii: bool | None = None,
    sign: bool = True,
    secret: str | None = None,
    keys_dir: Path | None = None,
    memory_root: Path | None = None,
) -> dict[str, Any]:
    """Build the ``agentguardian-scan-v1`` payload for a :class:`Scan`.

    PII / secret redaction of findings is **opt-in**: ``redact_pii`` defaults
    to ``None``, which resolves from ``AGENT_GUARDIAN_REDACT_PII`` (off unless
    set), mirroring the ``memory.jsonl`` default. Pass ``redact_pii=True`` /
    ``False`` to force it regardless of the env var.

    The ``coverage`` block is reconstructed from the scan's on-disk
    ``memory.jsonl`` (under ``~/.agentguardian/scans/<scan_id>/`` by
    default). When no memory file exists (e.g. a hand-constructed Scan
    in a unit test) the coverage block has the canonical empty shape so
    the schema is stable.
    """
    redact = _resolve_redact(redact_pii)
    coverage = compute_coverage_from_memory(scan, root_dir=memory_root)
    # Issue #261 — when ``scoring_valid=False`` the numeric AIVSS is NOT
    # authoritative and the per-ASI scores default to 100.0 for never-tested
    # boundaries. The rc38 matrix surfaced 35 scans with
    # ``aivss=88, band=not_evaluated`` simultaneously — two contradictory
    # truths in one signed report. Suppress the numeric AIVSS and the
    # per-ASI score dict in the rendered payload so dashboards that read
    # ``headline.aivss`` without joining ``scoring_valid`` cannot
    # mis-classify quota-failed scans as healthy 88s. The in-memory Scan
    # keeps the numeric for forensic trend-tracking (back-compat with the
    # documented contract); only the rendered payload is nulled.
    rendered_aivss: int | None = scan.aivss if scan.scoring_valid else None
    rendered_asi_scores: dict[str, float] = (
        {cat.value: score for cat, score in scan.asi_scores.items()} if scan.scoring_valid else {}
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "scan_id": scan.id,
        "package_version": scan.package_version,
        "probe_library_version": scan.probe_library_version,
        "aivss_formula_version": scan.aivss_formula_version,
        "target": {
            "mode": scan.target_mode,
            "ref": scan.target_ref,
            "inferred_goal": scan.target_inferred_goal,
            "profile_source": scan.target_profile_source,
        },
        "tier": scan.tier.value,
        "aivss": rendered_aivss,
        "band": scan.band.value,
        "sub_scores": dict(scan.sub_scores),
        "asi_scores": rendered_asi_scores,
        "findings_summary": scan.findings_summary(),
        # #134 — ``findings_summary`` counts only confirmed (``success=True``)
        # findings; this is the complement so a reader can see how many
        # unconfirmed/informational records sit in ``findings[]`` without
        # re-deriving it.
        "findings_informational": scan.informational_count(),
        "coverage": coverage,
        "findings": [_finding_to_dict(f, redact) for f in scan.findings],
        "duration_seconds": scan.duration_seconds,
        "cost_usd": scan.cost_usd,
        "tokens_total": scan.tokens_total,
        # v1.1 -- mode is the user-facing dial that controls early-stop
        # and probe-subsetting. Surfacing it in the report lets the
        # public dashboard segment coverage stats by mode (you can't
        # fairly compare a 45-second FAST scan against a 5-minute FULL
        # scan in the same aggregate bucket).
        "mode": scan.mode,
        # Why the scan ended + the USD budget outcome + how much of the planned
        # attack work actually ran. ``stopped_reason="budget"`` plus a sub-100%
        # ``completeness.pct`` lets a reader trust a partial (budget-capped) scan.
        "stopped_reason": scan.stopped_reason,
        "budget": scan.budget.model_dump(mode="json") if scan.budget is not None else None,
        "completeness": (
            scan.completeness.model_dump(mode="json") if scan.completeness is not None else None
        ),
        # Provenance: which LLM specs drove the scan (commander/attacker/evaluator
        # → model id, e.g. "openai:gpt-4o" or "stub"). Folded in BEFORE signing so
        # the signature covers it and an auditor/leaderboard can tell a real
        # assessment from a vacuous stub run.
        "engine": dict(scan.engine) if scan.engine is not None else None,
        # Whether the verdicts came from a real evaluator + whether the numeric
        # AIVSS is authoritative + whether the scan mode itself was exhaustive
        # (full) rather than a smart/fast early-stop. All three travel inside
        # the signature so a downstream consumer can tell a real assessment
        # apart from a partial-coverage one.
        "evaluation_mode": scan.evaluation_mode,
        "scoring_valid": scan.scoring_valid,
        "mode_authoritative": scan.mode_authoritative,
        # #46 / coverage signal — the list of "thinly tested" categories and
        # the overall coverage grade (A..F). Travel inside the signature so a
        # downstream consumer can refuse a "100 / EXCELLENT" verdict on a scan
        # whose coverage_grade is D or worse without re-deriving it.
        "undertested": list(scan.undertested),
        # Issue #207 — categories the swarm declared inapplicable for this
        # target (fingerprint-driven skip, e.g. a2a-agent on a non-a2a
        # target). Renderers / dashboards / SARIF consumers branch on
        # this to show N/A instead of the misleading deep-red 0 sitting
        # in asi_scores[cat] for these categories.
        "never_launched": list(scan.never_launched),
        # Issue #206 follow-up (rc35 deep-review M2) — recon-truncation
        # signal. Lets consumers distinguish "agent classes correctly out
        # of scope" from "scanner-side budget loss" when never_launched
        # is non-empty.
        "recon_truncated": scan.recon_truncated,
        "recon_completion_pct": scan.recon_completion_pct,
        # Issue #215 — commander planner outcome ("adaptive" / "uniform" /
        # None). CI gates + dashboards can branch on adaptive-vs-uniform
        # without grep-ing run.log.
        "planner_fallback": scan.planner_fallback,
        "coverage_grade": scan.coverage_grade,
        "created_at": scan.created_at.astimezone().isoformat()
        if scan.created_at.tzinfo
        else scan.created_at.isoformat(),
    }
    # RoE / contract audit envelope (contract_sha256, authorization_ref,
    # suppressed_tool_attempts, egress_refused_turns, …). Folded into the signed
    # payload so the canonical artifact can prove which contract authorized the
    # scan and how many turns were suppressed / refused.
    if scan.audit is not None:
        payload["audit"] = dict(scan.audit)
    # C7 — judge calibration (Brier + accuracy). Folded into the signed payload
    # so a downstream consumer can refuse a verdict whose judge is uncalibrated.
    if scan.calibration is not None:
        payload["calibration"] = scan.calibration.model_dump(mode="json")
    if sign:
        payload["signatures"] = sign_payload(payload, secret=secret, keys_dir=keys_dir)
    return payload


def write_json(
    scan: Scan,
    path: Path,
    *,
    redact_pii: bool | None = None,
    sign: bool = True,
    indent: int = 2,
    secret: str | None = None,
    keys_dir: Path | None = None,
    memory_root: Path | None = None,
) -> None:
    """Render :func:`emit_json` to ``path`` (UTF-8, sorted keys).

    Redaction is opt-in; see :func:`emit_json` for how ``redact_pii`` resolves.
    """
    redact = _resolve_redact(redact_pii)
    payload = emit_json(
        scan,
        redact_pii=redact,
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
        redact,
    )


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of verifying a signed JSON report.

    Two distinct notions are kept separate:

    * **integrity** (``integrity_ok``) — at least one signature channel
      recomputes, so the signed bytes were not tampered. This says *nothing*
      about who signed.
    * **trust** (``anchored``) — the Ed25519 key was pinned against a caller-
      supplied expected key (and verified), and/or HMAC verified with a real,
      non-default secret. Without an anchor the report is integrity-checked but
      ``UNANCHORED`` — its provenance cannot be trusted.

    :attr:`ok` is the conservative, trust-bearing result: it requires a valid,
    *anchored* signature channel. A forged report re-signed with a fresh key (or
    the public default HMAC secret) never anchors, so it never reports ``ok``.
    A genuine report whose HMAC was signed with the public default secret can
    still report ``ok`` when its Ed25519 key is pinned and verifies — the HMAC
    channel (worthless without a real secret) does not veto a pinned Ed25519.

    ``hmac_anchor_failed`` / ``ed25519_anchor_failed`` record that an anchor was
    explicitly supplied for that channel but it did *not* validate — a hard
    tamper / wrong-anchor signal. Either vetoes ``ok``: when the operator
    supplies both anchors, both must pass; when they supply one, that one must
    pass. A worthless channel the operator did *not* anchor (e.g. HMAC with the
    public default secret) cannot veto a pinned-and-valid Ed25519.
    """

    hmac_valid: bool
    ed25519_valid: bool
    schema_ok: bool
    anchored: bool = False
    hmac_anchor_failed: bool = False
    ed25519_anchor_failed: bool = False
    error: str | None = None

    @property
    def integrity_ok(self) -> bool:
        """Bytes-not-tampered: schema valid and at least one channel recomputes."""
        return self.schema_ok and (self.hmac_valid or self.ed25519_valid)

    @property
    def ok(self) -> bool:
        """Trust-bearing result — requires a valid, anchored signature channel.

        Fails closed if *any* explicitly-supplied anchor did not validate
        (``hmac_anchor_failed`` / ``ed25519_anchor_failed``): an anchored channel
        must never be silently ignored, so providing both anchors requires both
        to pass and providing one requires that one to pass.
        """
        return (
            self.schema_ok
            and self.anchored
            and not self.hmac_anchor_failed
            and not self.ed25519_anchor_failed
        )


def verify_signatures(
    source: Path | dict[str, Any],
    *,
    secret: str | None = None,
    expected_ed25519_pubkey: str | None = None,
    expected_hmac_secret: str | None = None,
) -> VerifyResult:
    """Verify HMAC + Ed25519 signatures on a JSON report path or in-memory dict.

    **Trust anchoring (fail closed).** A signature alone does not prove
    authenticity — Ed25519 carries its own verifying key and the HMAC default
    secret is public — so a forger can re-sign arbitrary content. To report a
    *trusted* result (``VerifyResult.ok``) the caller must supply a trust
    anchor:

    * ``expected_ed25519_pubkey`` — the pinned signer public key (base32); the
      embedded key must match it (constant-time) before Ed25519 is trusted.
    * ``expected_hmac_secret`` (or ``secret`` / ``AGENT_GUARDIAN_SIGNING_SECRET``)
      — the real signing secret; the public default is never accepted on verify.

    Without an anchor the result is integrity-checked but ``anchored=False``
    (``UNANCHORED``): ``integrity_ok`` may be true while ``ok`` is false.
    """
    # ``secret`` is the legacy/back-compat name; ``expected_hmac_secret`` takes
    # precedence when both are given.
    hmac_secret = expected_hmac_secret if expected_hmac_secret is not None else secret

    if isinstance(source, Path):
        try:
            data: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return VerifyResult(
                hmac_valid=False,
                ed25519_valid=False,
                schema_ok=False,
                anchored=False,
                error=f"could not read JSON: {exc}",
            )
    else:
        data = source

    if not isinstance(data, dict):
        return VerifyResult(
            hmac_valid=False,
            ed25519_valid=False,
            schema_ok=False,
            anchored=False,
            error="payload is not a JSON object",
        )

    schema_ok = data.get("schema") == SCHEMA_VERSION
    signatures = data.get("signatures")
    if not isinstance(signatures, dict):
        return VerifyResult(
            hmac_valid=False,
            ed25519_valid=False,
            schema_ok=schema_ok,
            anchored=False,
            error="missing 'signatures' block",
        )

    canonical = to_canonical_json(_strip_signatures(data))
    hmac_block = signatures.get("hmac_sha256")
    ed_block = signatures.get("ed25519")

    # verify_hmac fails closed when no real secret is available (it never trusts
    # the public DEFAULT_SIGNING_SECRET).
    hmac_ok = isinstance(hmac_block, dict) and verify_hmac(
        canonical, cast(dict[str, object], hmac_block), secret=hmac_secret
    )
    ed_ok = isinstance(ed_block, dict) and verify_ed25519(
        canonical,
        cast(dict[str, object], ed_block),
        expected_pubkey_b32=expected_ed25519_pubkey,
    )

    # Anchored == a real trust anchor was supplied. An Ed25519 result is only a
    # trust anchor when pinned; an HMAC result is a trust anchor when a real
    # secret (explicit or env) was used (verify_hmac already failed closed on
    # the default).
    anchored = (expected_ed25519_pubkey is not None and ed_ok) or (
        hmac_secret is not None and hmac_ok
    )
    # An anchor was explicitly supplied for a channel but it did not validate —
    # a tamper / wrong-anchor signal that must veto a green result even if the
    # other channel anchored. (Supplying both anchors thus requires both.)
    hmac_anchor_failed = hmac_secret is not None and not hmac_ok
    ed25519_anchor_failed = expected_ed25519_pubkey is not None and not ed_ok
    # Build an operator-facing error message for every failure mode. The
    # earlier (gated) version only emitted a message when ``anchored`` was
    # True — so a wrong pubkey pin on a clean report (the most common
    # operator mistake) silently produced ``error=None`` even though
    # ``ok`` was False. Every anchored-but-failed branch now produces an
    # explicit message so the CLI ``error:`` line surfaces the problem.
    error: str | None = None
    if hmac_anchor_failed and ed25519_anchor_failed:
        error = (
            "BOTH anchors FAILED: HMAC did not match the supplied secret AND "
            "Ed25519 did not match the pinned public key — tamper, wrong "
            "secret, wrong pin, or forgery; refusing to trust"
        )
    elif hmac_anchor_failed:
        error = (
            "HMAC verification FAILED with the supplied secret — the report "
            "does not match this signing secret (tamper or wrong secret); "
            "refusing to trust"
        )
    elif ed25519_anchor_failed:
        error = (
            "Ed25519 verification FAILED against the pinned public key — the "
            "report was signed by a different key (forgery or wrong pin); "
            "refusing to trust"
        )
    elif not anchored and (hmac_ok or ed_ok):
        error = (
            "UNANCHORED: signature integrity verified but no trust anchor supplied "
            "(pass expected_ed25519_pubkey and/or a real HMAC secret to establish "
            "provenance) — provenance untrusted"
        )
    return VerifyResult(
        hmac_valid=hmac_ok,
        ed25519_valid=ed_ok,
        schema_ok=schema_ok,
        anchored=anchored,
        hmac_anchor_failed=hmac_anchor_failed,
        ed25519_anchor_failed=ed25519_anchor_failed,
        error=error,
    )
