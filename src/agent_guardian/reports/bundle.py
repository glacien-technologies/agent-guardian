"""Finding bundle writer (M2 Pattern 10).

Assembles a self-contained, checksummed bundle directory per scan so downstream
scoring + evidence-pack tooling consumes one standard artifact:

    bundle_<scan_id>/
    ├── findings.sarif       # SARIF 2.1.0 (reports/sarif.py, PoV-ref extended)
    ├── pov/<finding_id>.py  # reproducer scripts (when supplied)
    ├── evidence/<finding_id>/<name>   # transcripts / raw responses
    └── manifest.json        # sha256 of every file + scan envelope

Reuses :func:`reports.sarif.write_sarif` for the SARIF run and
:func:`reports.canonical.to_canonical_json` for stable manifest bytes.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from agent_guardian.models.scan import Scan
from agent_guardian.reports.canonical import to_canonical_json
from agent_guardian.reports.sarif import write_sarif

__all__ = ["write_bundle"]

_LOG = logging.getLogger(__name__)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def write_bundle(
    scan: Scan,
    out_dir: Path,
    *,
    pov_scripts: dict[str, str] | None = None,
    evidence: dict[str, dict[str, str]] | None = None,
) -> Path:
    """Write a ``bundle_<scan_id>/`` directory under ``out_dir``; return its path.

    ``pov_scripts`` maps finding_id -> reproducer source; ``evidence`` maps
    finding_id -> {filename: content}. Both optional — an empty bundle still
    emits ``findings.sarif`` + ``manifest.json`` so the schema is stable.
    """
    pov_scripts = pov_scripts or {}
    evidence = evidence or {}
    bundle_dir = out_dir / f"bundle_{scan.id}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []

    sarif_path = bundle_dir / "findings.sarif"
    write_sarif(scan, sarif_path)
    written.append(sarif_path)

    if pov_scripts:
        pov_dir = bundle_dir / "pov"
        pov_dir.mkdir(parents=True, exist_ok=True)
        for finding_id, source in pov_scripts.items():
            p = pov_dir / f"{_safe(finding_id)}.py"
            p.write_text(source, encoding="utf-8")
            written.append(p)

    for finding_id, files in evidence.items():
        ev_dir = bundle_dir / "evidence" / _safe(finding_id)
        ev_dir.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            p = ev_dir / _safe(name)
            p.write_text(content, encoding="utf-8")
            written.append(p)

    manifest = {
        "scan": {
            "id": scan.id,
            "aivss": scan.aivss,
            "band": scan.band.value,
            "tier": scan.tier.value,
            "mode": scan.mode,
            "package_version": scan.package_version,
            "created_at": scan.created_at.isoformat(),
            "findings_total": len(scan.findings),
        },
        "files": {
            str(p.relative_to(bundle_dir)): {"sha256": _sha256(p), "bytes": p.stat().st_size}
            for p in sorted(written)
        },
    }
    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_bytes(to_canonical_json(manifest))
    _LOG.info("bundle written: %s (%d files)", bundle_dir, len(written) + 1)
    return bundle_dir


def _safe(name: str) -> str:
    """Sanitize a path component — no separators / traversal.

    Output is bounded to 120 characters so the bundle survives the most
    aggressive filesystem limits (eCryptfs caps single-component names at
    143 bytes; we leave headroom). For names that would be truncated, a
    12-char sha256 disambiguator is appended (107 + ``_`` + 12 = 120) so two
    long finding IDs that happen to share their first 120 chars still map to
    distinct files — the alternative is a silent overwrite.
    """
    cleaned = name.replace("/", "_").replace("\\", "_").replace("..", "_")
    if not cleaned:
        return "unnamed"
    if len(cleaned) <= 120:
        return cleaned
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    return cleaned[:107] + "_" + digest
