"""Tiny helpers route modules share.

Centralising the ``app.state`` accessors here keeps each route file
small and gives mypy a single place to type-check the un-typed
:class:`starlette.datastructures.State` reads.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.templating import Jinja2Templates

from agent_guardian.server.scan_store import ScanStore

__all__ = ["get_scan_store", "get_templates"]


def get_scan_store(request: Request) -> ScanStore:
    store = request.app.state.scan_store
    if not isinstance(store, ScanStore):
        raise RuntimeError("app.state.scan_store is not a ScanStore instance")
    return store


def get_templates(request: Request) -> Jinja2Templates:
    templates = request.app.state.templates
    if not isinstance(templates, Jinja2Templates):
        raise RuntimeError("app.state.templates is not a Jinja2Templates instance")
    return templates
