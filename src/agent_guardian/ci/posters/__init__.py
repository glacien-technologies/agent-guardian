"""Per-platform CI comment posters (package marker).

Concrete posters live in sibling modules (``github`` today; ``gitlab`` /
``bitbucket`` are added later by other agents). Resolve one via
:func:`agent_guardian.ci.posters.base.get_poster`, which imports the platform
module lazily so a new platform can be dropped in without editing this file.
"""

from __future__ import annotations
