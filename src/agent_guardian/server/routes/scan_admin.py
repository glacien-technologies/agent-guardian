"""DELETE /scan/{scan_id} — remove a stored scan from the dashboard (issue #111).

The dashboard previously had no way to remove a scan: every route was a GET and
the server exposed no delete endpoint, so old/test/failed scans piled up with no
in-product cleanup. This route reuses the same path-contained removal the CLI
``scans delete`` uses (:meth:`ScanStore.delete_scan`) and clears the scan's
directory + on-disk index row so it disappears from history, not just the disk.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_scan_store

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

# Same auth posture as every other dashboard route (loopback / token / cookie).
router = APIRouter(dependencies=[Depends(require_dashboard_auth)])


@router.delete("/scan/{scan_id}")
async def delete_scan(request: Request, scan_id: str) -> JSONResponse:
    """Delete a stored scan (directory + index row).

    * ``200 {"deleted": "<id>"}`` — removed.
    * ``404`` — nothing to delete (already gone / unknown id).
    * ``400`` — unsafe / traversing scan id (rejected before any filesystem op).
    """
    store = get_scan_store(request)
    try:
        removed = await asyncio.to_thread(store.delete_scan, scan_id)
    except ValueError as exc:
        _LOG.warning("rejected delete for unsafe scan_id %r: %s", scan_id, exc)
        return JSONResponse({"error": str(exc)}, status_code=400)
    if not removed:
        return JSONResponse({"error": "scan not found"}, status_code=404)
    return JSONResponse({"deleted": scan_id})
