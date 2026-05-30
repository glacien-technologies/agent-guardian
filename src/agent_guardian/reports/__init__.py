"""Report emitters and signing (PRD §10, M13).

The five emitters share a tiny public surface — each module exposes an
``emit_*`` (returns an in-memory representation) and a ``write_*`` (writes
to a path). Signing is layered on top in :mod:`json_report` so consumers
of the JSON path get HMAC-SHA256 + Ed25519 by default.
"""

from __future__ import annotations

from agent_guardian.reports.canonical import (
    from_canonical_json,
    to_canonical_json,
)
from agent_guardian.reports.json_report import (
    SCHEMA_VERSION,
    VerifyResult,
    emit_json,
    sign_payload,
    verify_signatures,
    write_json,
)
from agent_guardian.reports.junit import emit_junit, write_junit
from agent_guardian.reports.markdown import emit_markdown, write_markdown
from agent_guardian.reports.pdf import (
    PDF_ENV_VAR,
    PdfFeatureUnavailable,
    available_pdf_engines,
    write_pdf,
)
from agent_guardian.reports.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    ReportError,
    emit_sarif,
    write_sarif,
)

__all__ = [
    "PDF_ENV_VAR",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SCHEMA_VERSION",
    "PdfFeatureUnavailable",
    "ReportError",
    "VerifyResult",
    "available_pdf_engines",
    "emit_json",
    "emit_junit",
    "emit_markdown",
    "emit_sarif",
    "from_canonical_json",
    "sign_payload",
    "to_canonical_json",
    "verify_signatures",
    "write_json",
    "write_junit",
    "write_markdown",
    "write_pdf",
    "write_sarif",
]
