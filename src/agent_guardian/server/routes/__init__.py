"""Route modules for the M12 dashboard.

Each submodule exposes a single :data:`router` :class:`fastapi.APIRouter`
that :func:`agent_guardian.server.app.create_app` mounts in turn. The
split-by-page layout keeps each route's handler small, testable, and
trivially reorderable.
"""

from __future__ import annotations
