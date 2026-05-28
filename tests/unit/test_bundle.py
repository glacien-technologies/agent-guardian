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
