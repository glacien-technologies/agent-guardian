"""Live web dashboard for AgentGuardian (M12).

The dashboard is a small FastAPI app served at ``localhost:7474`` that
shows live scan progress over Server-Sent Events. See
:func:`agent_guardian.server.app.create_app` for the public entry
point and :class:`agent_guardian.server.scan_store.ScanStore` for the
in-memory + on-disk registry of scans.
"""

from __future__ import annotations

from agent_guardian.server.app import create_app
from agent_guardian.server.scan_store import ScanStore, ScanSummary

__all__ = ["ScanStore", "ScanSummary", "create_app"]
