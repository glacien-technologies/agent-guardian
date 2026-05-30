"""GET / — dashboard landing page with paginated scan history."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["DEFAULT_PAGE_SIZE", "MAX_PAGE_SIZE", "router"]

router = APIRouter()


# Sensible defaults: 50 rows is one viewport on the dashboard at a typical
# 1080p resolution. 500 is the absolute upper bound; anything higher would
# stall the renderer for users with thousands of scans on record.
DEFAULT_PAGE_SIZE: int = 50
MAX_PAGE_SIZE: int = 500


@router.get("/", response_class=HTMLResponse, dependencies=[Depends(require_dashboard_auth)])
async def home(
    request: Request,
    page: int = Query(1, ge=1, description="1-based page index."),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Rows per page (1..{MAX_PAGE_SIZE}).",
    ),
) -> HTMLResponse:
    """Render the scan-history landing page (paginated, newest-first).

    Pagination uses ``?page=&page_size=``. The store's
    :meth:`ScanStore.list_scans_page_async` does the heavy lifting on a
    worker thread so a slow disk doesn't block the event loop.
    """
    store = get_scan_store(request)
    templates = get_templates(request)
    offset = (page - 1) * page_size
    summaries, total = await store.list_scans_page_async(offset=offset, limit=page_size)
    # Defensive: a `page` past the end shouldn't 200 with an empty list — it
    # is almost always a typo or a stale bookmark. Permit page=1 even when
    # there are zero rows (the empty-state copy is rendered).
    if page > 1 and offset >= total:
        raise HTTPException(status_code=404, detail="page out of range")
    total_pages = max(1, (total + page_size - 1) // page_size)
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "scans": summaries,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "page_title": "Scan history",
        },
    )
