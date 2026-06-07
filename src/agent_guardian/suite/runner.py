"""Parallel suite runner — one isolated ``agent-guardian scan`` subprocess per
workload, then register + collect deliverables and aggregate a summary.

Isolation is the whole point: each workload runs in its own OS process under its
own ``HOME`` (so its ``~/.agentguardian`` tree — scan dir AND winning_seeds.db —
is private), bounded by an ``asyncio.Semaphore``. The runner never imports the
swarm engine, so a suite run of one workload is byte-identical to typing that one
``scan`` command. ``register_scans`` then moves each finished scan into the
operator's real scans root so the dashboard can browse it by its own scan id.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_guardian.suite.aggregate import (
    format_summary_lines,
    read_report,
    summary_row,
    write_summary_json,
)
from agent_guardian.suite.argv import build_scan_argv
from agent_guardian.suite.resolve import resolve_workloads
from agent_guardian.suite.schema import SuiteFile, WorkloadFields

_LOG = logging.getLogger(__name__)

# Scan exit codes that still mean "the scan ran and finalized a report". 0 = OK,
# 1 = a gate (--fail-under/--max-*) tripped — both produce a real scan dir.
_EXIT_OK = 0
_EXIT_FAIL_UNDER = 1
_COMPLETED_EXITS = frozenset({_EXIT_OK, _EXIT_FAIL_UNDER})

_FORMAT_EXT = {
    "json": "json",
    "sarif": "sarif",
    "junit": "xml",
    "md": "md",
    "gitlab": "json",
    "pdf": "pdf",
}


@dataclass
class SuiteRunResult:
    rows: list[dict[str, Any]] = field(default_factory=list)
    exit_code: int = 0

    def summary_text(self) -> str:
        return "\n".join(format_summary_lines(self.rows))


def _default_command_prefix() -> list[str]:
    return [sys.executable, "-m", "agent_guardian"]


def _scans_root(home: Path) -> Path:
    return home / ".agentguardian" / "scans"


def _discover_scan_dir(home: Path) -> Path | None:
    """The single (or newest) scan dir under an isolated HOME's scans root."""
    root = _scans_root(home)
    if not root.is_dir():
        return None
    dirs = [d for d in root.iterdir() if d.is_dir()]
    if not dirs:
        return None
    return max(dirs, key=lambda d: d.stat().st_mtime)


async def _spawn(cmd: list[str], *, env: dict[str, str], cwd: str | None, log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as logf:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=logf, stderr=asyncio.subprocess.STDOUT, env=env, cwd=cwd
        )
        await proc.wait()
    return proc.returncode if proc.returncode is not None else -1


async def _spawn_with_timeout(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: str | None,
    log_path: Path,
    timeout: float | None,
) -> tuple[int, bool]:
    """Run a child; return (exit_code, timed_out). On timeout the child is killed."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logf = log_path.open("wb")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=logf, stderr=asyncio.subprocess.STDOUT, env=env, cwd=cwd
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except TimeoutError:
            _LOG.warning(
                "suite: workload exceeded timeout_seconds=%s — killed (log: %s)",
                timeout,
                log_path,
            )
            proc.kill()
            await proc.wait()
            return (-1, True)
        return (proc.returncode if proc.returncode is not None else -1, False)
    finally:
        logf.close()


def _child_env(child_home: Path, extra: dict[str, str] | None) -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(child_home)
    # Keep any AGENT_GUARDIAN_HOME in lockstep so read-side commands the child
    # might invoke also resolve under the isolated tree.
    env["AGENT_GUARDIAN_HOME"] = str(child_home / ".agentguardian")
    if extra:
        env.update(extra)
    return env


async def _render_extra_format(
    *,
    command_prefix: list[str],
    scan_id: str,
    fmt: str,
    out_file: Path,
    home: Path,
    env_extra: dict[str, str] | None,
    log_path: Path,
) -> bool:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        *command_prefix,
        "report",
        scan_id,
        "--output",
        fmt,
        "--output-path",
        str(out_file),
    ]
    code = await _spawn(cmd, env=_child_env(home, env_extra), cwd=None, log_path=log_path)
    return code == _EXIT_OK and out_file.exists()


async def _collect_reports(
    *,
    command_prefix: list[str],
    workload: WorkloadFields,
    scan_id: str,
    scan_dir: Path,
    reports_dir: Path,
    home: Path,
    env_extra: dict[str, str] | None,
) -> dict[str, str]:
    """Place each requested format flat at reports_dir/<name>.<ext>."""
    reports: dict[str, str] = {}
    reports_dir.mkdir(parents=True, exist_ok=True)
    name = workload.name or scan_id
    for fmt in workload.formats or ["json"]:
        ext = _FORMAT_EXT.get(fmt, fmt)
        out_file = reports_dir / f"{name}.{ext}"
        if fmt == "json":
            native = scan_dir / "report.json"
            if native.is_file():
                shutil.copyfile(native, out_file)
                reports[fmt] = str(out_file)
            continue
        render_log = reports_dir / f"{name}.{fmt}.render.log"
        ok = await _render_extra_format(
            command_prefix=command_prefix,
            scan_id=scan_id,
            fmt=fmt,
            out_file=out_file,
            home=home,
            env_extra=env_extra,
            log_path=render_log,
        )
        if ok:
            reports[fmt] = str(out_file)
            # Keep reports_dir clean: the render log only matters when a format
            # FAILED to render — drop it on success.
            render_log.unlink(missing_ok=True)
    return reports


async def _run_one(
    workload: WorkloadFields,
    *,
    suite_file: SuiteFile,
    out_dir: Path,
    reports_dir: Path,
    homes_dir: Path,
    real_home: Path,
    command_prefix: list[str],
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    name = workload.name or "workload"
    suite = suite_file.suite
    child_home = (homes_dir / name) if suite.isolate_home else real_home
    child_home.mkdir(parents=True, exist_ok=True)
    console_log = out_dir / f"{name}.console.log"

    async with semaphore:
        cmd = [*command_prefix, *build_scan_argv(workload)]
        exit_code, timed_out = await _spawn_with_timeout(
            cmd,
            env=_child_env(child_home, workload.env),
            cwd=workload.workdir,
            log_path=console_log,
            timeout=workload.timeout_seconds,
        )

    if timed_out:
        return summary_row(
            name=name,
            scan_id=None,
            scan_dir=None,
            report=None,
            status="timeout",
            exit_code=exit_code,
            reports={},
            console_log=str(console_log),
        )

    scan_dir = _discover_scan_dir(child_home)
    if exit_code not in _COMPLETED_EXITS or scan_dir is None:
        return summary_row(
            name=name,
            scan_id=None,
            scan_dir=str(scan_dir) if scan_dir else None,
            report=None,
            status="error",
            exit_code=exit_code,
            reports={},
            console_log=str(console_log),
        )

    scan_id = scan_dir.name
    final_dir = scan_dir
    render_home = child_home

    # Register: move the finished scan into the operator's real scans root so the
    # dashboard / `report <id>` find it by its own (unique) scan id.
    if suite.register_scans and suite.isolate_home:
        dest = _scans_root(real_home) / scan_id
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            shutil.move(str(scan_dir), str(dest))
            final_dir = dest
            render_home = real_home

    reports = await _collect_reports(
        command_prefix=command_prefix,
        workload=workload,
        scan_id=scan_id,
        scan_dir=final_dir,
        reports_dir=reports_dir,
        home=render_home,
        env_extra=workload.env,
    )
    report = read_report(final_dir)
    return summary_row(
        name=name,
        scan_id=scan_id,
        scan_dir=str(final_dir),
        report=report,
        status="ok",
        exit_code=exit_code,
        reports=reports,
        console_log=str(console_log),
    )


def _compute_exit_code(rows: list[dict[str, Any]], policy: str) -> int:
    if policy == "always-zero":
        return 0
    any_fail = any(r["status"] != "ok" or r.get("exit_code") == _EXIT_FAIL_UNDER for r in rows)
    if policy == "all-pass":
        all_clean = all(
            r["status"] == "ok" and r.get("exit_code") == _EXIT_OK and r["authoritative"]
            for r in rows
        )
        return 0 if all_clean else 1
    # default: any-gate-fail
    return 1 if any_fail else 0


async def run_suite(
    suite_file: SuiteFile,
    *,
    out_dir: str | Path | None = None,
    command_prefix: list[str] | None = None,
    real_home: str | Path | None = None,
) -> SuiteRunResult:
    """Run every workload in parallel and return the aggregated result."""
    suite = suite_file.suite
    resolved = resolve_workloads(suite_file)
    out = Path(out_dir or suite.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reports_dir = Path(suite.reports_dir) if suite.reports_dir else out / "reports"
    homes_dir = out / "homes"
    real = Path(real_home) if real_home is not None else Path.home()
    prefix = command_prefix or _default_command_prefix()

    cap = suite.concurrency or min(len(resolved), os.cpu_count() or 4)
    semaphore = asyncio.Semaphore(max(1, cap))

    tasks = [
        _run_one(
            wl,
            suite_file=suite_file,
            out_dir=out,
            reports_dir=reports_dir,
            homes_dir=homes_dir,
            real_home=real,
            command_prefix=prefix,
            semaphore=semaphore,
        )
        for wl in resolved
    ]
    rows = await asyncio.gather(*tasks)

    write_summary_json(rows, out / "summary.json")
    return SuiteRunResult(rows=list(rows), exit_code=_compute_exit_code(rows, suite.exit_code))


def run_suite_sync(
    suite_file: SuiteFile,
    *,
    out_dir: str | Path | None = None,
    command_prefix: list[str] | None = None,
    real_home: str | Path | None = None,
) -> SuiteRunResult:
    return asyncio.run(
        run_suite(
            suite_file,
            out_dir=out_dir,
            command_prefix=command_prefix,
            real_home=real_home,
        )
    )
