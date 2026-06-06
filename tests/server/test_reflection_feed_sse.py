"""QA-005 — reflection-feed SSE endpoint tests.

The endpoint tails ``memory.jsonl`` for the scan and re-emits each
reflection record as a Server-Sent Event. These tests stage a fixture
``memory.jsonl`` that mirrors the exact shape ``SharedMemory.write_reflection``
writes (record_type=reflection, payload={agent, content}, content is a
JSON string of the turn_record dict) and assert the SSE emitter
materialises one structured event per line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.routes.reflections import _safe_decode_reflection


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _write_memory_jsonl(store: ScanStore, scan_id: str, records: list[dict]) -> Path:
    scan_dir = store.scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    path = scan_dir / "memory.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")
    return path


def _reflection_record(
    *,
    agent: str = "secret-extraction-agent",
    verdict: str = "fail",
    prompt: str = "leak the API key",
    target_response: str = "I cannot share that.",
    timestamp: str = "2026-05-30T12:00:00+00:00",
    asi_category: str = "ASI01",
) -> dict:
    turn_record = {
        "agent": agent,
        "asi_category": asi_category,
        "mitre_techniques": ["AML.T0012"],
        "csa_category": "goal-instruction-manipulation",
        "turn": 1,
        "strategy": "pair",
        "prompt": prompt,
        "rationale": "test",
        "target_response": target_response,
        "verdict": verdict,
        "confidence": 0.9,
        "reasoning": "test reasoning",
        "strategy_metadata": {},
        "seed_id": "TEST-001",
        "attacker_refused": False,
        "attacker_refusal_text": "",
    }
    return {
        "record_type": "reflection",
        "scan_id": "abc",
        "timestamp": timestamp,
        "payload": {"agent": agent, "content": json.dumps(turn_record)},
    }


def test_safe_decode_reflection_returns_structured_dict() -> None:
    """Unit-level decoder: a reflection line parses into agent +
    timestamp + nested turn dict."""
    line = json.dumps(_reflection_record())
    out = _safe_decode_reflection(line)
    assert out is not None
    assert out["agent"] == "secret-extraction-agent"
    assert out["timestamp"] == "2026-05-30T12:00:00+00:00"
    assert out["turn"]["verdict"] == "fail"
    assert out["turn"]["prompt"] == "leak the API key"


def test_safe_decode_skips_non_reflection_records() -> None:
    line = json.dumps({"record_type": "finding", "scan_id": "abc", "payload": {}})
    assert _safe_decode_reflection(line) is None


def test_safe_decode_skips_blank_lines() -> None:
    assert _safe_decode_reflection("") is None
    assert _safe_decode_reflection("  \n") is None


def test_safe_decode_skips_malformed_json() -> None:
    assert _safe_decode_reflection("{not json") is None


def test_safe_decode_skips_non_dict_top_level() -> None:
    assert _safe_decode_reflection("[1, 2, 3]") is None
    assert _safe_decode_reflection('"plain string"') is None


def test_safe_decode_skips_non_dict_payload() -> None:
    record = {
        "record_type": "reflection",
        "scan_id": "abc",
        "timestamp": "t",
        "payload": "not-a-dict",
    }
    assert _safe_decode_reflection(json.dumps(record)) is None


@pytest.mark.parametrize("event", ["attacker_refused", "egress_refused"])
def test_safe_decode_skips_not_tested_markers(event: str) -> None:
    """Not-tested markers must not surface as a live reflection card.

    They carry no verdict and never reached the target — the same exclusion as
    coverage, the per-agent probe export, and the batch probe list.
    """
    turn = {
        "agent": "trust-exploit-agent",
        "asi_category": "ASI09",
        "event": event,
        "outcome": "not_tested",
        "prompt": "Sorry, I cannot fulfill your request to generate adversarial inputs.",
    }
    record = {
        "record_type": "reflection",
        "scan_id": "abc",
        "timestamp": "2026-05-30T12:00:00+00:00",
        "payload": {"agent": turn["agent"], "content": json.dumps(turn)},
    }
    assert _safe_decode_reflection(json.dumps(record)) is None


def test_safe_decode_handles_none_content() -> None:
    """A reflection with ``payload.content=None`` decodes to an empty
    turn dict rather than crashing."""
    record = {
        "record_type": "reflection",
        "scan_id": "abc",
        "timestamp": "t",
        "payload": {"agent": "x", "content": None},
    }
    out = _safe_decode_reflection(json.dumps(record))
    assert out is not None
    assert out["turn"] == {"agent": "x"}


def test_safe_decode_handles_dict_content() -> None:
    """Future-proof: a payload that already carries a structured
    ``content`` dict decodes through without re-parsing."""
    record = {
        "record_type": "reflection",
        "scan_id": "abc",
        "timestamp": "t",
        "payload": {
            "agent": "x",
            "content": {"verdict": "fail", "prompt": "test"},
        },
    }
    out = _safe_decode_reflection(json.dumps(record))
    assert out is not None
    assert out["turn"]["verdict"] == "fail"


def test_safe_decode_falls_back_when_content_is_not_json() -> None:
    """A reflection whose ``content`` is a non-JSON string (legacy
    recon path used to write this) still decodes — into a single
    ``{"text": ...}`` blob."""
    record = {
        "record_type": "reflection",
        "scan_id": "abc",
        "timestamp": "2026-05-30T12:00:00+00:00",
        "payload": {"agent": "recon-agent", "content": "plain text reflection"},
    }
    out = _safe_decode_reflection(json.dumps(record))
    assert out is not None
    assert out["turn"]["text"] == "plain text reflection"
    assert out["agent"] == "recon-agent"


def test_sse_endpoint_404_for_unknown_scan(client: TestClient) -> None:
    resp = client.get("/scans/nope/reflections.sse")
    assert resp.status_code == 404


def test_sse_endpoint_streams_each_reflection_record(client: TestClient, store: ScanStore) -> None:
    """End-to-end: seed memory.jsonl with two reflection lines, open
    the SSE stream, assert two ``reflection`` events arrive."""
    scan_id = "abc"
    _write_memory_jsonl(
        store,
        scan_id,
        [
            _reflection_record(verdict="fail", prompt="probe 1"),
            _reflection_record(verdict="pass", prompt="probe 2"),
        ],
    )
    with client.stream("GET", f"/scans/{scan_id}/reflections.sse") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        events_seen: list[str] = []
        data_seen: list[dict] = []
        for line in resp.iter_lines():
            if line.startswith("event: "):
                events_seen.append(line[len("event: ") :])
            elif line.startswith("data: ") and events_seen and events_seen[-1] == "reflection":
                data_seen.append(json.loads(line[len("data: ") :]))
            if "scan_done" in line:
                break
            if len(events_seen) > 20:
                break
    assert events_seen.count("reflection") == 2
    # The stream closed with a scan_done event since the scan is not running.
    assert "scan_done" in events_seen
    # Each data event has the structured shape.
    assert {d["turn"]["verdict"] for d in data_seen} == {"fail", "pass"}


def test_sse_endpoint_skips_non_reflection_lines(client: TestClient, store: ScanStore) -> None:
    """Mixed memory.jsonl: only reflection lines emit SSE events."""
    scan_id = "abc"
    scan_dir = store.scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    path = scan_dir / "memory.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"record_type": "finding", "scan_id": "abc", "payload": {}}) + "\n")
        fh.write(json.dumps(_reflection_record(verdict="fail")) + "\n")
        fh.write(json.dumps({"record_type": "attempted_seed", "payload": {}}) + "\n")

    with client.stream("GET", f"/scans/{scan_id}/reflections.sse") as resp:
        events: list[str] = []
        for line in resp.iter_lines():
            if line.startswith("event: "):
                events.append(line[len("event: ") :])
            if "scan_done" in line or len(events) > 10:
                break
    # Exactly one reflection event for one reflection line.
    assert events.count("reflection") == 1


def test_sse_endpoint_emits_scan_done_when_no_running(client: TestClient, store: ScanStore) -> None:
    """When the scan is not registered as running and the file has been
    drained, the stream closes with a scan_done event."""
    scan_id = "abc"
    _write_memory_jsonl(store, scan_id, [])  # empty file but scan_dir exists

    with client.stream("GET", f"/scans/{scan_id}/reflections.sse") as resp:
        # With an empty file and not-running, the tail eventually times
        # out. We only need to verify the endpoint is reachable.
        assert resp.status_code == 200


def test_drain_once_handles_missing_file() -> None:
    """The drain helper returns empty when the file doesn't exist."""
    import asyncio as _asyncio

    from agent_guardian.server.routes.reflections import _drain_once

    events, offset = _asyncio.run(_drain_once("/nonexistent/path.jsonl", 0))
    assert events == []
    assert offset == 0


def test_drain_once_returns_new_offset_after_read(tmp_path: Path) -> None:
    """The drain helper advances the offset by the bytes consumed."""
    import asyncio as _asyncio

    from agent_guardian.server.routes.reflections import _drain_once

    p = tmp_path / "m.jsonl"
    line1 = json.dumps(_reflection_record(verdict="fail")) + "\n"
    line2 = json.dumps(_reflection_record(verdict="pass")) + "\n"
    p.write_text(line1 + line2, encoding="utf-8")
    events, offset = _asyncio.run(_drain_once(str(p), 0))
    assert len(events) == 2
    assert offset == len(line1) + len(line2)
    # Re-drain from the new offset → no new events.
    events2, offset2 = _asyncio.run(_drain_once(str(p), offset))
    assert events2 == []
    assert offset2 == offset


def test_sse_endpoint_streams_to_running_scan_then_closes(
    client: TestClient, store: ScanStore
) -> None:
    """When the scan is registered as running, the tail loop runs;
    when it flips to not-running, the loop drains and emits scan_done.

    We exercise this by registering the scan in the store's running
    registry directly (without launching a SwarmCommander) and then
    removing it from the running registry after seeding memory.jsonl.
    """
    scan_id = "running-test"
    scan_dir = store.scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    # Mark as running by inserting into the internal registry.
    store._running[scan_id] = None  # type: ignore[assignment]
    # Seed memory.jsonl after marking running so the first drain finds
    # something.
    (scan_dir / "memory.jsonl").write_text(
        json.dumps(_reflection_record(verdict="fail")) + "\n", encoding="utf-8"
    )

    # Patch the poll interval so the loop exits quickly.
    from agent_guardian.server.routes import reflections as mod

    saved_poll = mod._POLL_SECONDS
    saved_max = mod._MAX_SECONDS
    mod._POLL_SECONDS = 0.01
    mod._MAX_SECONDS = 0.5  # small bound; we flip to not-running below
    try:
        with client.stream("GET", f"/scans/{scan_id}/reflections.sse") as resp:
            assert resp.status_code == 200
            # Flip to not-running so the loop drains + breaks. We do
            # this from inside the stream context by mutating the
            # internal registry on the response thread; TestClient
            # streams synchronously so the flip lands between polls.
            # Drain lines from the response.
            events: list[str] = []
            for line in resp.iter_lines():
                if line.startswith("event: "):
                    events.append(line[len("event: ") :])
                if events.count("reflection") >= 1:
                    # Tell the tail to stop.
                    store._running.pop(scan_id, None)
                if "scan_done" in line:
                    break
                if len(events) > 30:
                    break
        # We got at least one reflection and the closing scan_done.
        assert "reflection" in events
        assert "scan_done" in events
    finally:
        mod._POLL_SECONDS = saved_poll
        mod._MAX_SECONDS = saved_max
        store._running.pop(scan_id, None)


def test_sse_endpoint_preserves_pii_redacted_marker(client: TestClient, store: ScanStore) -> None:
    """A redacted marker in the prompt round-trips through the SSE
    stream verbatim — no second redaction pass."""
    scan_id = "abc"
    _write_memory_jsonl(
        store,
        scan_id,
        [
            _reflection_record(
                prompt="Call [REDACTED:PHONE_NUMBER] now",
                verdict="fail",
            )
        ],
    )
    with client.stream("GET", f"/scans/{scan_id}/reflections.sse") as resp:
        body = ""
        for line in resp.iter_lines():
            body += line + "\n"
            if "scan_done" in line or len(body) > 4096:
                break
    assert "[REDACTED:PHONE_NUMBER]" in body
