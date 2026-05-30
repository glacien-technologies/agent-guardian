"""UI rendering helpers for the AgentGuardian CLI (QA-002 + QA-005).

Holds the Rich Live-region renderables (``dashboard``) and the
reflection-feed sink (``attack_feed``). All renderables share the
single per-process ``Console`` defined in
:mod:`agent_guardian.logging_setup`, so log lines, the Live frame, and
reflection panels never compete for stdout ownership.
"""

from __future__ import annotations

from agent_guardian.ui.attack_feed import (
    AttackFeedRenderer,
    DebugFormat,
    DebugLevel,
    build_curl_one_liner,
    render_reflection_block,
)

__all__: list[str] = [
    "AttackFeedRenderer",
    "DebugFormat",
    "DebugLevel",
    "build_curl_one_liner",
    "render_reflection_block",
]
