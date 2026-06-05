"""GET /scan/{id}/events — SSE event stream + /events/view rendered JSONL."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_scan_store, get_templates
from agent_guardian.server.sse import stream_scan_events

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])

# Cap the rendered-view page so a long, noisy scan can't build a multi-MB
# HTML document. The SSE stream (above) remains the unbounded source of truth.
_MAX_VIEW_RECORDS = 500


@router.get("/scan/{scan_id}/events")
async def events_stream(request: Request, scan_id: str) -> StreamingResponse:
    """Stream :class:`SwarmEvent` records as Server-Sent Events.

    The response stays open until the scan emits ``scan_done`` or the
    client disconnects. For completed scans that have an on-disk
    ``events.jsonl`` we replay every event then emit a synthetic
    ``scan_done`` terminator so the client knows to close.
    """
    store = get_scan_store(request)
    if not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")

    headers = {
        # SSE-friendly headers — disable any intermediary buffering.
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    # Phase 2 Step 2.1 — W3C EventSource resume protocol. The browser
    # sends the last ``id:`` it saw via the ``Last-Event-ID`` header on
    # reconnect; we filter out any event with ``seq <= last_event_id`` in
    # ``stream_scan_events`` so the client never sees a duplicate.
    last_event_id = request.headers.get("last-event-id")
    return StreamingResponse(
        stream_scan_events(scan_id, store, last_event_id=last_event_id),
        media_type="text/event-stream",
        headers=headers,
    )


@router.get("/scan/{scan_id}/events/view", response_class=HTMLResponse)
async def events_view(
    request: Request,
    scan_id: str,
    probe: str | None = Query(default=None),
) -> HTMLResponse:
    """Render the scan's JSONL records as pretty-printed, highlighted JSON.

    This is what the slideover's "View JSONL events for this probe" link opens.
    The bare ``/events`` endpoint above is a ``text/event-stream`` SSE source —
    opening it in a browser tab dumps the raw replay, which is unreadable. This
    route instead reads the on-disk JSONL (``events.jsonl`` and, when present,
    the recon probe log ``recon_probes.jsonl``), optionally filters to a single
    ``probe`` id, and renders each record formatted in ``events_view.html``.
    """
    store = get_scan_store(request)
    templates = get_templates(request)
    scan_dir = store.scan_dir(scan_id)
    if not store.is_running(scan_id) and not scan_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    records = _collect_jsonl_records(scan_dir, probe)
    return templates.TemplateResponse(
        request,
        "events_view.html",
        {"scan_id": scan_id, "probe": probe, "records": records},
    )


def _collect_jsonl_records(scan_dir: Path, probe: str | None) -> list[dict[str, Any]]:
    """Read the scan's JSONL files and pretty-print each record for the view.

    Reads ``events.jsonl``, ``recon_probes.jsonl`` (the latter only exists when
    the opt-in recon probe log was enabled), then ``memory.jsonl``. When
    ``probe`` is set, only records whose raw line references that id are kept —
    a substring match is robust across the id's several nested positions
    (``probe_id`` / ``seed_id`` / payload fields).

    ``memory.jsonl`` reflection rows are DECODED (the per-turn ``turn_record``
    is JSON-encoded inside ``payload.content``) and surfaced as ``turn`` records
    so the page shows the AUTHORITATIVE, untruncated prompt / target response /
    judge reasoning — the ``events.jsonl`` ``log`` lines only carry an elided
    ``…`` preview. The complete, uncapped record is also persisted on disk by
    :func:`agent_guardian.server.probe_export.write_probe_exports`.

    Defensive: a missing or corrupt file yields no rows and never raises;
    output is capped at :data:`_MAX_VIEW_RECORDS` (a render-size guard for the
    HTML page only — the on-disk ``probe/`` export is uncapped).
    """
    out: list[dict[str, Any]] = []
    for fname in ("events.jsonl", "recon_probes.jsonl", "memory.jsonl"):
        try:
            raw = (scan_dir / fname).read_text(encoding="utf-8")
        except OSError as exc:
            _LOG.debug("events_view: %s not readable (%s) -- skipping", fname, exc)
            continue
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or (probe and probe not in stripped):
                continue
            try:
                rec = json.loads(stripped)
            except (json.JSONDecodeError, ValueError) as exc:
                _LOG.debug("events_view: skipping corrupt %s line (%s)", fname, exc)
                continue
            kind = "event"
            seq: Any = None
            if isinstance(rec, dict):
                kind = str(rec.get("kind") or rec.get("intent") or "event")
                seq = rec.get("seq")
            # memory.jsonl reflection rows carry the full turn record as a
            # JSON string in ``payload.content`` — decode it so the page shows
            # the verbatim prompt / response / reasoning, not an escaped blob.
            if fname == "memory.jsonl" and isinstance(rec, dict):
                if rec.get("record_type") != "reflection":
                    continue
                content = (rec.get("payload") or {}).get("content")
                turn = None
                if isinstance(content, str):
                    try:
                        turn = json.loads(content)
                    except (json.JSONDecodeError, ValueError):
                        turn = None
                if isinstance(turn, dict):
                    rec = turn
                    kind = f"turn · {turn.get('verdict') or 'turn'}"
                    seq = turn.get("turn")
            out.append(
                {
                    "source": fname,
                    "kind": kind,
                    "seq": seq,
                    "pretty": json.dumps(rec, indent=2, ensure_ascii=False, default=str),
                }
            )
            if len(out) >= _MAX_VIEW_RECORDS:
                return out
    return out
