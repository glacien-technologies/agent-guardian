"""Suite runner — isolation, registration, report collection, failure handling.

Uses a FAKE `scan`/`report` CLI so the test exercises the real subprocess +
HOME-isolation + move + collect machinery without a live LLM scan.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_guardian.suite.runner import run_suite_sync
from agent_guardian.suite.schema import SuiteFile

# A stand-in for `agent-guardian`. Honors HOME exactly like the real scan/report
# write/read paths (Path.home()). `scan` writes a scan dir + report.json under
# $HOME and records which HOME it saw; `report` writes the requested output file.
_FAKE_CLI = r"""
import json, os, secrets, sys
from pathlib import Path

argv = sys.argv[1:]
sub = argv[0] if argv else ""
home = Path(os.environ["HOME"])

if sub == "scan":
    scans = home / ".agentguardian" / "scans"
    scans.mkdir(parents=True, exist_ok=True)
    scan_id = "cli-" + secrets.token_hex(6)
    d = scans / scan_id
    d.mkdir()
    # record the HOME this child saw (isolation proof) + the endpoint arg
    endpoint = ""
    if "--endpoint" in argv:
        endpoint = argv[argv.index("--endpoint") + 1]
    report = {
        "scan_id": scan_id,
        "aivss": 41,
        "band": "POOR",
        "tier": "T2",
        "findings": [{}, {}, {}],
        "findings_summary": {"critical": 0, "high": 1, "medium": 1, "low": 1},
        "coverage": {"attacker_refusal_rate": 0.0},
        "evaluation_mode": "real",
        "scoring_valid": True,
        "mode_authoritative": True,
        "coverage_grade": "A",
        "undertested": [],
        "_seen_home": str(home),
        "_endpoint": endpoint,
    }
    (d / "report.json").write_text(json.dumps(report))
    (d / "scan.raw.json").write_text(json.dumps({"scan_id": scan_id}))
    (d / "run.log").write_text("fake run log\n")
    print(f"scan {scan_id} done: AIVSS=41")
    sys.exit(int(os.environ.get("AG_FAKE_EXIT", "0")))

if sub == "report":
    scan_id = argv[1]
    out_path = Path(argv[argv.index("--output-path") + 1])
    fmt = argv[argv.index("--output") + 1]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(f"<fake {fmt} for {scan_id}>")
    sys.exit(0)

sys.exit(99)
"""


@pytest.fixture()
def fake_cli(tmp_path: Path) -> list[str]:
    script = tmp_path / "fake_ag.py"
    script.write_text(_FAKE_CLI, encoding="utf-8")
    return [sys.executable, str(script)]


def _suite(**suite_over: object) -> SuiteFile:
    suite = {"name": "demo", "formats": ["json", "sarif"]}
    suite.update(suite_over)
    return SuiteFile.model_validate(
        {
            "version": 1,
            "suite": suite,
            "defaults": {"model": "gemini:gemini-2.5-flash", "mode": "fast"},
            "workloads": [
                {"name": "alpha", "endpoint": "https://alpha.test/agent"},
                {"name": "bravo", "endpoint": "https://bravo.test/agent"},
            ],
        }
    )


def test_each_workload_runs_in_its_own_home(fake_cli: list[str], tmp_path: Path) -> None:
    out = tmp_path / "out"
    real_home = tmp_path / "realhome"
    result = run_suite_sync(_suite(), out_dir=out, command_prefix=fake_cli, real_home=real_home)

    assert len(result.rows) == 2
    # Each child ran under a DISTINCT, isolated HOME under out/homes/<name>.
    assert (out / "homes" / "alpha").is_dir()
    assert (out / "homes" / "bravo").is_dir()


def test_scans_registered_into_real_home_by_id(fake_cli: list[str], tmp_path: Path) -> None:
    out = tmp_path / "out"
    real_home = tmp_path / "realhome"
    result = run_suite_sync(_suite(), out_dir=out, command_prefix=fake_cli, real_home=real_home)
    registered = list((real_home / ".agentguardian" / "scans").iterdir())
    assert len(registered) == 2  # both scans now browsable by their own id
    for r in result.rows:
        assert r["scan_id"] is not None
        assert (real_home / ".agentguardian" / "scans" / r["scan_id"]).is_dir()
        # log_folder points at the registered (canonical) location
        assert str(real_home) in r["log_folder"]


def test_reports_collected_flat_per_workload(fake_cli: list[str], tmp_path: Path) -> None:
    out = tmp_path / "out"
    run_suite_sync(_suite(), out_dir=out, command_prefix=fake_cli, real_home=tmp_path / "rh")
    reports = out / "reports"
    for name in ("alpha", "bravo"):
        assert (reports / f"{name}.json").is_file()
        assert (reports / f"{name}.sarif").is_file()


def test_summary_json_written(fake_cli: list[str], tmp_path: Path) -> None:
    out = tmp_path / "out"
    run_suite_sync(_suite(), out_dir=out, command_prefix=fake_cli, real_home=tmp_path / "rh")
    summary = json.loads((out / "summary.json").read_text())
    assert len(summary["workloads"]) == 2
    assert all(w["aivss"] == 41 for w in summary["workloads"])
    assert all(w["authoritative"] for w in summary["workloads"])


def test_register_disabled_keeps_scan_in_home(fake_cli: list[str], tmp_path: Path) -> None:
    out = tmp_path / "out"
    real_home = tmp_path / "realhome"
    run_suite_sync(
        _suite(register_scans=False),
        out_dir=out,
        command_prefix=fake_cli,
        real_home=real_home,
    )
    assert not (real_home / ".agentguardian" / "scans").exists()
    # scan stays under the isolated home
    assert list((out / "homes" / "alpha" / ".agentguardian" / "scans").iterdir())


def test_no_isolation_uses_real_home(fake_cli: list[str], tmp_path: Path) -> None:
    out = tmp_path / "out"
    real_home = tmp_path / "realhome"
    run_suite_sync(
        _suite(isolate_home=False),
        out_dir=out,
        command_prefix=fake_cli,
        real_home=real_home,
    )
    # both scans wrote directly into the shared real home (unique ids => no clash)
    assert len(list((real_home / ".agentguardian" / "scans").iterdir())) == 2


def test_failed_workload_does_not_abort_siblings(
    fake_cli: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AG_FAKE_EXIT=2 -> every child "errors". Suite still completes all rows.
    monkeypatch.setenv("AG_FAKE_EXIT", "2")
    out = tmp_path / "out"
    result = run_suite_sync(
        _suite(), out_dir=out, command_prefix=fake_cli, real_home=tmp_path / "rh"
    )
    assert len(result.rows) == 2
    assert all(r["status"] == "error" for r in result.rows)
    assert result.exit_code == 1  # any-gate-fail


def test_gate_failure_sets_suite_exit_1(
    fake_cli: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AG_FAKE_EXIT=1 -> a gate tripped; scan still completed (status ok) but the
    # suite exit reflects the gate breach under the default policy.
    monkeypatch.setenv("AG_FAKE_EXIT", "1")
    out = tmp_path / "out"
    result = run_suite_sync(
        _suite(), out_dir=out, command_prefix=fake_cli, real_home=tmp_path / "rh"
    )
    assert all(r["status"] == "ok" for r in result.rows)
    assert result.exit_code == 1
