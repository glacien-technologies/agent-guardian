"""GitLab Code Quality (CodeClimate) emitter (CI/CD feature).

GitLab's merge-request "Code Quality" widget consumes a CodeClimate-format
JSON report: a flat array of issue objects exposed as an
``artifacts:reports:codequality`` artifact. We emit one entry per
:class:`Finding` so an AgentGuardian scan surfaces its findings inline in the
MR diff — alongside (and complementing) the sticky MR note posted by
:class:`agent_guardian.ci.posters.gitlab.GitlabPoster`.

GitLab only requires a subset of the full CodeClimate spec; we emit exactly the
keys it reads (`description`, `check_name`, `fingerprint`, `severity`,
`location.path`, `location.lines.begin`). AgentGuardian findings have no real
source line, so each entry points at a synthetic per-ASI path
(``agentguardian/<ASI>.md``) with ``begin = 1`` — enough for GitLab to group and
de-duplicate by fingerprint without pretending the finding lives at a code line.

Finding text is scrubbed of PII + credential shapes via the shared
:func:`agent_guardian.core.redact.redact_finding` helper (on by default) so a
captured secret is never re-published into the MR widget.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from agent_guardian.core.redact import redact_finding
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity

__all__ = ["emit_codeclimate", "write_codeclimate"]

# AgentGuardian severity -> GitLab Code Quality severity. GitLab's allowed
# values are info | minor | major | critical | blocker. We reserve ``blocker``
# for critical findings that actually succeeded (the agent was compromised) and
# ``critical`` for critical findings that were merely reachable, so the most
# severe live exploit sorts to the top of the widget.
_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "major",
    Severity.MEDIUM: "minor",
    Severity.LOW: "info",
}


def _cq_severity(finding: Finding) -> str:
    """Map an AgentGuardian finding to a GitLab Code Quality severity."""
    if finding.severity is Severity.CRITICAL and finding.success:
        return "blocker"
    return _SEVERITY_MAP.get(finding.severity, "minor")


def _fingerprint(finding: Finding) -> str:
    """Stable sha256 fingerprint keyed on probe_id + ASI + severity.

    GitLab de-duplicates Code Quality issues across pipelines by fingerprint, so
    it must be stable for "the same finding" and independent of run-specific
    fields (finding id, confidence, attempt count). Keying on
    ``probe_id``/``ASI``/``severity`` keeps a recurring finding collapsed to a
    single widget row across merge-request updates.
    """
    key = f"{finding.probe_id}|{finding.asi.value}|{finding.severity.value}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _location(finding: Finding) -> dict[str, Any]:
    """Synthetic per-ASI location — AgentGuardian findings have no source line."""
    return {
        "path": f"agentguardian/{finding.asi.value}.md",
        "lines": {"begin": 1},
    }


def _entry(finding: Finding) -> dict[str, Any]:
    return {
        "description": finding.summary,
        "check_name": finding.probe_id,
        "fingerprint": _fingerprint(finding),
        "severity": _cq_severity(finding),
        "location": _location(finding),
    }


def emit_codeclimate(scan: Scan, *, redact: bool = True) -> list[dict[str, Any]]:
    """Return a GitLab Code Quality (CodeClimate) report for ``scan``.

    One entry per :class:`Finding`. Finding text is scrubbed of PII + credential
    shapes when ``redact`` is true (the default — a scanner must not re-emit
    captured secrets into the MR widget). The entries are sorted by fingerprint
    so the output is deterministic across runs.
    """
    findings = [redact_finding(f, enabled=redact) for f in scan.findings]
    entries = [_entry(f) for f in findings]
    entries.sort(key=lambda e: e["fingerprint"])
    return entries


def write_codeclimate(scan: Scan, path: Path, *, redact: bool = True, indent: int = 2) -> None:
    """Write the GitLab Code Quality report for ``scan`` to ``path`` (UTF-8)."""
    payload = emit_codeclimate(scan, redact=redact)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=indent, sort_keys=True),
        encoding="utf-8",
    )
