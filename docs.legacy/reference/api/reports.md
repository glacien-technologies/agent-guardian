# Reports

**TL;DR** — Five emitters (JSON, SARIF, JUnit, Markdown, PDF) plus the canonical-JSON helper and the HMAC + Ed25519 signing entry points. PII / secret redaction is on by default on every emitter — a security scanner must never re-emit a captured secret. For user-facing output format selection, see [Output formats](../output-formats.md).

## JSON (`agentguardian-scan-v1`)

The canonical machine-readable format. Schema is keyed `agentguardian-scan-v1` ([`SCHEMA_VERSION`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/json_report.py#L52)). Output is sorted-key and may include both HMAC-SHA256 and Ed25519 signature blocks under the top-level `signatures` field. The signing input is the canonical JSON of the payload *without* the `signatures` field so verifiers can reconstruct the signed bytes.

::: agent_guardian.reports.json_report
    options:
      show_root_heading: false
      members:
        - emit_json
        - write_json
        - SCHEMA_VERSION

## Signing and verification

`sign_payload` produces both signature blocks over the canonical JSON of the payload minus any existing `signatures` field — signing an already-signed payload twice is idempotent. `verify_signatures` is the only function the operator and the CLI's `verify` sub-command should call.

**Trust anchoring (fail closed).** A signature alone does not prove authenticity — Ed25519 carries its own verifying key, and the HMAC default secret is public — so a forger can re-sign arbitrary content. To return a *trusted* result (`VerifyResult.ok`) you must supply a trust anchor: an `expected_ed25519_pubkey` (base32) and/or an `expected_hmac_secret`. Without one, the result is integrity-checked but `anchored=False` (`integrity_ok` may be true while `ok` is false). For the narrative discussion of the trust model see [Signing & verification](../../security/signing.md).

::: agent_guardian.reports.json_report
    options:
      show_root_heading: false
      members:
        - sign_payload
        - verify_signatures
        - VerifyResult

```python
from agent_guardian import sign_payload, verify_signatures, SCHEMA_VERSION

payload = {"schema": SCHEMA_VERSION, "scan_id": "demo", "findings": []}
sigs = sign_payload(payload, secret="dev-secret")
payload["signatures"] = sigs

result = verify_signatures(payload, expected_hmac_secret="dev-secret")
assert result.ok               # anchored and verified
assert result.integrity_ok     # bytes not tampered

unanchored = verify_signatures(payload)  # no expected_* args
assert unanchored.integrity_ok           # still True
assert not unanchored.ok                 # but not trust-bearing
```

The HMAC channel and the Ed25519 channel are independent: an output can be `ok` via Ed25519 (pinned key) even when HMAC is unverifiable (signed with the public default and no `AGENT_GUARDIAN_SIGNING_SECRET`). See the `VerifyResult` docstring above for the precedence rules.

## Canonical JSON

Stable serialiser used by every signer and verifier: sorted keys, deterministic float formatting, byte-equal output for byte-equal input.

::: agent_guardian.reports.canonical
    options:
      show_root_heading: false
      members:
        - to_canonical_json
        - from_canonical_json

## SARIF 2.1.0

GitHub code-scanning / Azure DevOps / generic security-dashboard format. The output is validated against the bundled `sarif-2.1.0.schema.json` before return (set `validate=False` to skip — only safe when the caller validates upstream). Contract provenance from `scan.audit` is merged onto `runs[0].properties` and a `runs[0].invocations` *array* (SARIF 2.1.0 forbids singular `invocation`) carries the RoE budget envelope. Conformance is enforced by [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py).

::: agent_guardian.reports.sarif
    options:
      show_root_heading: false
      members:
        - emit_sarif
        - write_sarif

## JUnit XML

CI test-reporter format — Jenkins, GitLab, CircleCI, etc. One `testsuite` per ASI category; one `testcase` per finding.

::: agent_guardian.reports.junit
    options:
      show_root_heading: false
      members:
        - emit_junit
        - write_junit

## Markdown

Human-readable summary — drop into a PR description or wiki. Includes the AIVSS roll-up, per-ASI table, top-N findings (default 10), and the audit block.

::: agent_guardian.reports.markdown
    options:
      show_root_heading: false
      members:
        - emit_markdown
        - write_markdown
        - TOP_FINDINGS_DEFAULT

## PDF

Signed forensic bundle. Engine auto-selected from what's importable: WeasyPrint (rich layout, install `agent-guardian[full]`) or ReportLab (smaller fallback, `agent-guardian[pdf-fallback]`). The WeasyPrint *wheel* imports without its native deps (`cairo`, `pango`, `libgobject`) — `write_pdf` probes a minimal render once and transparently falls back to ReportLab when only the wheel is present, so operators get a clear `PdfFeatureUnavailable` (with install hint) instead of an opaque CFFI `OSError`. Override the engine choice with `AGENT_GUARDIAN_PDF_ENGINE=weasyprint|reportlab`.

::: agent_guardian.reports.pdf
    options:
      show_root_heading: false
      members:
        - write_pdf
        - available_pdf_engines
        - PdfFeatureUnavailable
        - PDF_ENV_VAR

```python
from pathlib import Path
from agent_guardian import available_pdf_engines, write_pdf, PdfFeatureUnavailable

engines = available_pdf_engines()
if not engines:
    raise PdfFeatureUnavailable(
        "Install 'agent-guardian[full]' for WeasyPrint or "
        "'agent-guardian[pdf-fallback]' for ReportLab."
    )
# `scan` is an agent_guardian.Scan instance
write_pdf(scan, Path("report.pdf"))  # auto-selects best engine
```
