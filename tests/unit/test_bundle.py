"""Tests for the M2 bundle writer + SARIF PoV-property extension (Pattern 10)."""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.reports.bundle import write_bundle
from agent_guardian.reports.sarif import emit_sarif
from tests.unit._report_fixtures import make_finding, make_scan


def test_sarif_result_carries_pov_properties_when_present() -> None:
    finding = make_finding(id="f_pov", pov_reference="pov/f_pov.py", pov_reliability=0.92)
    scan = make_scan(findings=[finding])
    sarif = emit_sarif(scan)
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["pov_reference"] == "pov/f_pov.py"
    assert result["properties"]["pov_reliability"] == 0.92


def test_sarif_omits_pov_properties_for_v1_findings() -> None:
    scan = make_scan(findings=[make_finding(id="f_legacy")])
    result = emit_sarif(scan)["runs"][0]["results"][0]
    assert "pov_reference" not in result["properties"]
    assert "pov_reliability" not in result["properties"]


def test_write_bundle_layout_and_manifest(tmp_path: Path) -> None:
    finding = make_finding(id="f_001", pov_reference="pov/f_001.py", pov_reliability=0.9)
    scan = make_scan(findings=[finding])
    bundle = write_bundle(
        scan,
        tmp_path,
        pov_scripts={"f_001": "# reproducer\nprint('repro')\n"},
        evidence={"f_001": {"transcript.txt": "attacker: ...\ntarget: leaked"}},
    )
    assert bundle.name == f"bundle_{scan.id}"
    assert (bundle / "findings.sarif").is_file()
    assert (bundle / "pov" / "f_001.py").is_file()
    assert (bundle / "evidence" / "f_001" / "transcript.txt").is_file()
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["scan"]["id"] == scan.id
    assert manifest["scan"]["findings_total"] == 1
    # Every written file is checksummed.
    assert "findings.sarif" in manifest["files"]
    assert "pov/f_001.py" in manifest["files"]
    for meta in manifest["files"].values():
        assert len(meta["sha256"]) == 64
        assert meta["bytes"] > 0


def test_write_bundle_empty_still_emits_sarif_and_manifest(tmp_path: Path) -> None:
    scan = make_scan(findings=[make_finding()])
    bundle = write_bundle(scan, tmp_path)
    assert (bundle / "findings.sarif").is_file()
    assert (bundle / "manifest.json").is_file()
    assert not (bundle / "pov").exists()


def test_write_bundle_sanitizes_path_components(tmp_path: Path) -> None:
    scan = make_scan(findings=[make_finding()])
    bundle = write_bundle(
        scan,
        tmp_path,
        pov_scripts={"../../etc/passwd": "x"},
    )
    # Traversal neutralized — no file escapes the bundle dir.
    pov_files = list((bundle / "pov").iterdir())
    assert len(pov_files) == 1
    assert ".." not in pov_files[0].name
    assert pov_files[0].parent == bundle / "pov"


# --- finding #33: long-name disambiguation in bundle._safe ---------------


def test_safe_short_name_is_unchanged() -> None:
    """A name that fits inside the 120-char budget must round-trip verbatim
    so the existing manifest entries don't churn after the fix lands."""
    from agent_guardian.reports.bundle import _safe

    assert _safe("f_001") == "f_001"
    assert _safe("a" * 120) == "a" * 120


def test_safe_long_name_gets_disambiguator() -> None:
    """A name longer than 120 chars must be truncated to 107 chars + ``_`` +
    12-char sha256 prefix — total length 120."""
    from agent_guardian.reports.bundle import _safe

    long_name = "z" * 200
    result = _safe(long_name)
    assert len(result) == 120
    assert result.startswith("z" * 107)
    assert result[107] == "_"
    # The disambiguator must be the sha256 prefix of the ORIGINAL name.
    import hashlib

    expected_digest = hashlib.sha256(long_name.encode("utf-8")).hexdigest()[:12]
    assert result.endswith(expected_digest)


def test_safe_disambiguates_two_ids_sharing_first_120_chars() -> None:
    """The whole point of the fix: two finding IDs whose first 120 chars are
    identical must map to DISTINCT filenames so the bundle never silently
    overwrites one with the other."""
    from agent_guardian.reports.bundle import _safe

    prefix = "a" * 200
    id_one = prefix + "_alpha"
    id_two = prefix + "_beta"
    assert id_one[:120] == id_two[:120]
    safe_one = _safe(id_one)
    safe_two = _safe(id_two)
    assert safe_one != safe_two
    assert len(safe_one) == 120
    assert len(safe_two) == 120


def test_write_bundle_two_long_finding_ids_dont_collide(tmp_path: Path) -> None:
    """End-to-end: two long, first-120-chars-identical PoV keys produce two
    DISTINCT files inside ``bundle/pov/`` (no silent overwrite)."""
    scan = make_scan(findings=[make_finding()])
    prefix = "x" * 200
    bundle = write_bundle(
        scan,
        tmp_path,
        pov_scripts={
            prefix + "_alpha": "# alpha\n",
            prefix + "_beta": "# beta\n",
        },
    )
    pov_files = list((bundle / "pov").iterdir())
    assert len(pov_files) == 2
    contents = {p.read_text() for p in pov_files}
    assert contents == {"# alpha\n", "# beta\n"}
