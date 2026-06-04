"""CI/CD integration surface for AgentGuardian.

This package holds the platform-agnostic glue between a finished
:class:`~agent_guardian.models.scan.Scan` and a code-host CI integration:

* :mod:`agent_guardian.ci.comment` renders the shared PR/MR comment body.
* :mod:`agent_guardian.ci.posters` holds the per-platform "upsert this comment"
  posters (GitHub today; GitLab / Bitbucket added later by other agents).

The CLI (``agent-guardian comment`` / ``agent-guardian code-insights``) is the
primary entry point; everything here is also importable for SDK callers.
"""

from __future__ import annotations
