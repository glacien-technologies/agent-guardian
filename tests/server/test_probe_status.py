"""Probe-row run status — completed / running / skipped per agent.

The Probes table needs a column showing whether each agent has finished or is
still running. The authoritative per-agent signal is the terminal SSE event the
swarm appends to ``events.jsonl`` (``agent_done`` / ``agent_skipped``) — NOT
``has_run_result`` (which is true for any agent with a graded turn, including an
in-flight one).
"""

from __future__ import annotations

from pathlib import Path

from agent_guardian.server.dashboard_view import (
    _agent_lifecycle_states,
    _probe_status,
)


def _write_events(tmp_path: Path, lines: list[dict]) -> Path:
    import json

    d = tmp_path / "scan"
    d.mkdir()
    (d / "events.jsonl").write_text(
        "\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8"
    )
    return d


def test_lifecycle_collects_done_and_skipped(tmp_path: Path) -> None:
    d = _write_events(
        tmp_path,
        [
            {"kind": "agent_start", "agent": "tool-abuse-agent"},
            {"kind": "agent_done", "agent": "tool-abuse-agent"},
            {"kind": "agent_start", "agent": "memory-poison-agent"},
            {"kind": "agent_skipped", "agent": "a2a-agent"},
        ],
    )
    states = _agent_lifecycle_states(d)
    assert states["tool-abuse-agent"] == "completed"
    assert states["a2a-agent"] == "skipped"
    # started-but-not-finished agent is absent → still running
    assert "memory-poison-agent" not in states


def test_lifecycle_handles_missing_dir_and_file(tmp_path: Path) -> None:
    assert _agent_lifecycle_states(None) == {}
    assert _agent_lifecycle_states(tmp_path / "nope") == {}


def test_lifecycle_tolerates_corrupt_lines(tmp_path: Path) -> None:
    d = tmp_path / "scan"
    d.mkdir()
    (d / "events.jsonl").write_text(
        '{"kind":"agent_done","agent":"x"}\nNOT JSON\n\n{"kind":"agent_done","agent":"y"}\n',
        encoding="utf-8",
    )
    states = _agent_lifecycle_states(d)
    assert states == {"x": "completed", "y": "completed"}


def test_probe_status_running_when_live_and_unfinished() -> None:
    assert _probe_status("tool-abuse-agent", {}, scan_finalized=False) == ("Running", "running")


def test_probe_status_done_when_agent_emitted_done() -> None:
    states = {"tool-abuse-agent": "completed"}
    assert _probe_status("tool-abuse-agent", states, scan_finalized=False) == ("Done", "done")


def test_probe_status_done_when_scan_finalized() -> None:
    # A finalized scan: everything is done even without a per-agent event.
    assert _probe_status("recon-agent", {}, scan_finalized=True) == ("Done", "done")


def test_probe_status_skipped() -> None:
    states = {"a2a-agent": "skipped"}
    assert _probe_status("a2a-agent", states, scan_finalized=True) == ("Skipped", "skipped")
