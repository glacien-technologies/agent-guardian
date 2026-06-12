"""Test-only HTTP endpoints for Playwright UI tests.

This router MUST NOT be mounted in production. It is gated behind the
``AGENT_GUARDIAN_TEST_HOOKS`` env var (must equal ``"1"``); import of
this module raises ``RuntimeError`` otherwise, so accidentally including
it from ``create_app`` in a non-test deployment is a hard crash, not a
silent capability leak.

Endpoints:

- ``POST /test/fixtures/load`` — atomically loads a frozen scan fixture
  from ``tests/e2e/fixtures/{name}/`` into the in-memory scan store so
  subsequent dashboard requests render against a known-good state.
- ``GET /scan/{scan_id}/events.replay`` — re-emits a persisted SSE log
  from the fixture as a Server-Sent Events stream so Playwright can
  drive during-scan tests deterministically without a live LLM call.
- ``POST /test/scan/{scan_id}/crash`` — flips a fixture's stored status
  to ``failed`` so failure-path tests can assert the dashboard renders
  a "Failed" pill on a crashed scan.

All endpoints are exempt from the regular dashboard auth — they only
exist when the env gate is on, and the gate itself is the auth.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

_ENV_FLAG = "AGENT_GUARDIAN_TEST_HOOKS"

if os.environ.get(_ENV_FLAG) != "1":
    raise RuntimeError(
        f"server.routes.test_hooks imported without {_ENV_FLAG}=1. "
        "This module is a Playwright-test-only surface and must never be "
        "loaded in a production server."
    )


router = APIRouter(prefix="/test", tags=["test-hooks"])


# Fixture root: tests/e2e/fixtures/ at the repo root. Resolved lazily so
# tests can override via env (rare; default is correct for the in-repo
# fixture corpus).
def _fixtures_root() -> Path:
    env = os.environ.get("AGENT_GUARDIAN_E2E_FIXTURES")
    if env:
        return Path(env).resolve()
    # Up from src/agent_guardian/server/routes/test_hooks.py to repo root.
    return Path(__file__).resolve().parents[4] / "tests" / "e2e" / "fixtures"


class LoadFixtureBody(BaseModel):
    """Body for ``POST /test/fixtures/load``."""

    name: str


@router.post("/fixtures/load")
async def load_fixture(body: LoadFixtureBody, request: Request) -> dict[str, str]:
    """Load a frozen scan fixture into the in-memory scan store.

    The fixture directory must contain ``report.json`` (the canonical
    scan record) and optionally ``events.jsonl`` (for replay) and
    ``run.log``. The scan_id is taken from ``report.json["id"]``.
    """
    fixture_dir = _fixtures_root() / body.name
    if not fixture_dir.is_dir():
        raise HTTPException(404, f"fixture {body.name!r} not found at {fixture_dir}")

    report_path = fixture_dir / "report.json"
    if not report_path.is_file():
        raise HTTPException(400, f"fixture {body.name!r} missing report.json")

    try:
        report = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"fixture {body.name!r} has invalid report.json: {exc}") from exc

    scan_id = report.get("id")
    if not isinstance(scan_id, str) or not scan_id:
        raise HTTPException(400, f"fixture {body.name!r} report.json missing 'id'")

    store = request.app.state.scan_store
    target_dir = store.scan_dir(scan_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    # Copy the report to where ``load_completed`` reads it from.
    (target_dir / "scan.json").write_text(json.dumps(report))

    # Copy any optional artefacts.
    for artifact in ("events.jsonl", "run.log"):
        src = fixture_dir / artifact
        if src.is_file():
            (target_dir / artifact).write_text(src.read_text())

    # Refresh the on-disk index so /home pagination sees the row.
    store._index_upsert(scan_id, is_running=False)

    return {"scan_id": scan_id, "fixture": body.name, "loaded_from": str(fixture_dir)}


@router.get("/scan/{scan_id}/events.replay")
async def replay_events(
    scan_id: str,
    request: Request,
    speed: float = 0.0,
) -> StreamingResponse:
    """Re-emit a persisted SSE log as a Server-Sent Events stream.

    Reads ``events.jsonl`` from the scan's dir and replays each line as
    a single SSE message. ``speed=0`` means as-fast-as-the-consumer
    (default for unit-test speed); ``speed > 0`` paces at that
    multiplier of the per-event "delta_ms" field if present.
    """
    store = request.app.state.scan_store
    scan_dir = store.scan_dir(scan_id)
    events_path = scan_dir / "events.jsonl"
    if not events_path.is_file():
        raise HTTPException(404, f"no events.jsonl for scan {scan_id!r}")

    lines = [line for line in events_path.read_text().splitlines() if line.strip()]

    from collections.abc import AsyncIterator

    async def gen() -> AsyncIterator[str]:
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = event.get("kind", "message")
            yield f"event: {kind}\ndata: {json.dumps(event)}\n\n"
            if speed > 0:
                delta_ms = float(event.get("delta_ms") or 0.0)
                if delta_ms:
                    await asyncio.sleep((delta_ms / 1000.0) / speed)

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/scan/{scan_id}/crash")
async def crash_scan(scan_id: str, request: Request) -> dict[str, str]:
    """Flip a loaded fixture's stored status to ``failed``.

    Used by failure-path Playwright tests to assert the dashboard
    renders a "Failed" pill and blanks numeric columns. The scan must
    already be in the store (load it via ``/test/fixtures/load`` first).
    """
    store = request.app.state.scan_store
    scan = store.load_completed(scan_id)
    if scan is None:
        raise HTTPException(404, f"scan {scan_id!r} not in store")

    # Force the row to "is_running=False" + clear completeness so the
    # status derives to "failed" via the issue #112 gate.
    index = store._index_read()
    if scan_id in index:
        row = index[scan_id]
        row["is_running"] = False
        row["completeness_pct"] = 20.0  # < 100 → status="failed"
        store._index_write(index)

    return {"scan_id": scan_id, "new_status": "failed"}
