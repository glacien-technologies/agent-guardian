"""D2 (issue #76) — tamper-evident forensic manifest over a scan's artifacts.

The signed ``scan.json`` / ``report.json`` covers the *summary*. OWASP red-team
guidance calls for immutable logging of the full evidence trail — the raw
``run.log``, the per-turn ``memory.jsonl``, the per-agent ``probe/*.json``, and
the ``events.jsonl`` SSE stream. This module seals those by writing a
``forensic_manifest.json`` that records a SHA-256 digest of each artifact and
signs the manifest with the same Ed25519 + HMAC machinery as the report, so any
post-hoc edit to a forensic file is detectable.

Note: ``run.log`` is written live; the manifest captures it as-of-finalize, so
log lines emitted *after* the manifest is sealed (there are a few) are not
covered — the scan-body evidence is.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from agent_guardian.reports.json_report import sign_payload

__all__ = [
    "FORENSIC_MANIFEST_SCHEMA",
    "build_forensic_manifest",
    "write_forensic_manifest",
]

FORENSIC_MANIFEST_SCHEMA = "agentguardian-forensic-manifest-v1"

# Top-level artifacts sealed by the manifest (each optional — only hashed when
# present so a partial/early-stopped scan still produces a valid manifest).
_FORENSIC_FILES = ("run.log", "memory.jsonl", "events.jsonl", "report.json", "scan.json")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_forensic_manifest(scan_dir: Path, scan_id: str, created_at: str) -> dict[str, Any]:
    """Return the (unsigned) manifest: a SHA-256 digest of each forensic file."""
    files: dict[str, dict[str, Any]] = {}
    for rel in _FORENSIC_FILES:
        p = scan_dir / rel
        if p.is_file():
            files[rel] = {"sha256": _sha256_file(p), "bytes": p.stat().st_size}
    probe_dir = scan_dir / "probe"
    if probe_dir.is_dir():
        for pf in sorted(probe_dir.glob("*.json")):
            files[f"probe/{pf.name}"] = {"sha256": _sha256_file(pf), "bytes": pf.stat().st_size}
    return {
        "schema": FORENSIC_MANIFEST_SCHEMA,
        "scan_id": scan_id,
        "created_at": created_at,
        "algorithm": "sha256",
        "files": files,
    }


def write_forensic_manifest(
    scan_dir: Path,
    scan_id: str,
    created_at: str,
    *,
    secret: str | None = None,
    keys_dir: Path | None = None,
    sign: bool = True,
) -> Path:
    """Build, sign, and write ``forensic_manifest.json`` into ``scan_dir``.

    The signature covers the canonical JSON of the manifest *without* the
    ``signatures`` field (mirroring ``json_report``), so a verifier reconstructs
    the signed bytes the same way. Returns the manifest path.
    """
    manifest = build_forensic_manifest(scan_dir, scan_id, created_at)
    if sign:
        manifest["signatures"] = sign_payload(manifest, secret=secret, keys_dir=keys_dir)
    path = scan_dir / "forensic_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return path
