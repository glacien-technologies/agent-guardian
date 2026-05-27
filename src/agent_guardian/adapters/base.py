"""Target adapter base classes (PRD §7).

Every target mode AgentGuardian can scan — system prompt, Python callable,
hosted HTTP API, or framework-native object — implements
:class:`TargetAdapter`. The common shape is "send one prompt, get back one
text reply", with an opaque ``session`` token threading conversation state
for agents that need it.

The :class:`TargetFingerprint` captures the *static* attack surface known at
adapter-construction time. The recon-agent (M5) refines it during phase 1
of the swarm; the swarm's tiering logic (PRD §6.3) reads it via
:meth:`TargetFingerprint.to_observed_surface`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from agent_guardian.models.tier import ObservedSurface

__all__ = ["TargetAdapter", "TargetFingerprint", "TargetMode"]

TargetMode = Literal["prompt", "code", "http", "framework"]


class TargetFingerprint(BaseModel):
    """Static description of a target's attack surface.

    Populated as much as possible at adapter-construction time; the
    recon-agent refines it during phase 1 of the swarm.
    """

    mode: TargetMode
    ref: str
    has_tools: bool = False
    has_memory: bool = False
    touches_pii: bool = False
    is_multi_agent: bool = False
    # OWASP-2026-relevant evidence-backed signals (set by recon agent based on
    # observed target responses). Distinct from ``has_tools`` / ``has_memory``
    # / ``is_multi_agent`` which are heuristic / adapter-declared — these
    # three are populated only when recon probes elicit positive evidence.
    external_systems_detected: bool = False
    multi_agent_detected: bool = False
    cross_session_data_detected: bool = False
    framework: str | None = None
    declared_tools: list[str] = Field(default_factory=list)
    declared_memory_keys: list[str] = Field(default_factory=list)
    notes: str = ""

    model_config = ConfigDict(frozen=True, extra="forbid")

    def to_observed_surface(self) -> ObservedSurface:
        """Project this fingerprint onto the four-signal tiering input."""
        from agent_guardian.models.tier import ObservedSurface

        return ObservedSurface(
            has_tools=self.has_tools,
            has_memory=self.has_memory,
            touches_pii=self.touches_pii,
            is_multi_agent=self.is_multi_agent,
        )


class TargetAdapter(ABC):
    """Common interface for every target mode.

    :meth:`call` sends a single user-turn to the target and returns its text
    response. ``session`` is an opaque string the adapter can use to thread
    conversation state; agents pass distinct session IDs for parallel
    attacks so per-session histories never cross-contaminate.

    Subclasses MUST set ``self._fingerprint`` inside ``__init__`` —
    :meth:`fingerprint` raises if it is still ``None``.
    """

    mode: TargetMode = "prompt"

    def __init__(self) -> None:
        self._fingerprint: TargetFingerprint | None = None

    @abstractmethod
    async def call(self, prompt: str, *, session: str | None = None) -> str:
        """Send one user-turn; return the assistant text reply."""

    def fingerprint(self) -> TargetFingerprint:
        if self._fingerprint is None:
            raise RuntimeError(f"{type(self).__name__} did not set _fingerprint in __init__")
        return self._fingerprint

    async def aclose(self) -> None:
        """Release any resources (HTTP clients, etc.). Subclasses override."""
        return None
