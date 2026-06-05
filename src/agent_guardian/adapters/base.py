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

import ast
import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from agent_guardian.models.tier import ObservedSurface

__all__ = ["ProfileEvidence", "TargetAdapter", "TargetFingerprint", "TargetMode"]

_LOG = logging.getLogger(__name__)

# Cap on source text handed to the profiler in one shot. Generous because modern
# models swallow it easily; a single agent + its tools is almost always well
# under this. Sprawling multi-file agents that still exceed it get entry-point
# scoping below (and, as a future follow-up, an agentic grep/read loop).
_MAX_SOURCE_CHARS = 80_000


def _scope_source(entry_src: str, module_src: str, cap: int) -> str:
    """Scope a too-large module to the transitive closure from the entry point.

    Instead of dumping (and truncating) a huge module, keep the entry-point
    source plus the module-level functions / classes / constants it references
    by name — the agent + its tools — and drop unrelated code. Falls back to a
    capped slice of the module if parsing fails.
    """
    try:
        referenced = {
            node.id for node in ast.walk(ast.parse(entry_src)) if isinstance(node, ast.Name)
        } | {
            node.attr for node in ast.walk(ast.parse(entry_src)) if isinstance(node, ast.Attribute)
        }
        tree = ast.parse(module_src)
    except SyntaxError:
        return (entry_src or module_src)[:cap]

    chunks: list[str] = [entry_src] if entry_src else []
    seen: set[str] = set(chunks)
    for node in tree.body:
        name: str | None = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            name = next((t for t in targets if t in referenced), None)
        if name and name in referenced:
            segment = ast.get_source_segment(module_src, node)
            if segment and segment not in seen:
                chunks.append(segment)
                seen.add(segment)
    scoped = "\n\n".join(chunks).strip()
    return (scoped or module_src)[:cap]


def safe_source_and_root(obj: object) -> tuple[str | None, Path | None]:
    """Best-effort `(source_text, source_root)` for a callable / class / instance.

    Returns the defining module's source (it usually carries the agent + its
    tool definitions); for a small module that's the whole thing, for a module
    larger than ``_MAX_SOURCE_CHARS`` it's the entry-point-scoped slice (see
    :func:`_scope_source`). Also returns the package dir so a future agentic
    pass can read deeper. ``(None, None)`` when source is unavailable
    (C-extension, REPL, lambda) — caller falls back to black-box.
    """
    target = obj if (inspect.isfunction(obj) or inspect.isclass(obj)) else type(obj)
    module = inspect.getmodule(target)
    module_src: str | None = None
    try:
        if module is not None:
            module_src = inspect.getsource(module)
    except (OSError, TypeError):
        module_src = None
    try:
        entry_src: str | None = inspect.getsource(target)
    except (OSError, TypeError):
        entry_src = None

    if module_src is not None and len(module_src) <= _MAX_SOURCE_CHARS:
        text: str | None = module_src
    elif module_src is not None:
        # Large module: scope to the entry point's closure instead of truncating.
        text = _scope_source(entry_src or "", module_src, _MAX_SOURCE_CHARS)
    elif entry_src is not None:
        text = entry_src[:_MAX_SOURCE_CHARS]
    else:
        _LOG.debug("source unavailable for %r -- black-box fallback", target)
        text = None

    root: Path | None = None
    module_file = getattr(module, "__file__", None)
    if module_file:
        try:
            root = Path(module_file).resolve().parent
        except (OSError, ValueError):  # pragma: no cover -- defensive
            root = None
    return text, root


@dataclass(frozen=True)
class ProfileEvidence:
    """The richest material the profiler can read for a target.

    ``box="white"`` means we can *read* the target (system prompt text,
    in-process source, framework introspection); ``box="black"`` means we can
    only *call* it (HTTP endpoint) and must audit it behaviourally.
    """

    box: Literal["white", "black"]
    text: str | None = None
    structured: dict[str, Any] = field(default_factory=dict)
    source_root: Path | None = None


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
    # Intent profile (recon redesign). The target's *purpose* and the shape of
    # what's worth attacking, derived from the richest available evidence
    # (source / prompt / framework introspection / behavioural audit). These
    # drive goal-relevant attack scenarios; surface flags above stay as
    # ammunition + tiering. ``profile_source`` records HOW the profile was
    # derived so the report is honest; ``"heuristic"`` is the static default
    # before recon refines it.
    inferred_goal: str | None = None
    domain: str | None = None
    sensitive_actions: list[str] = Field(default_factory=list)
    declared_guardrails: list[str] = Field(default_factory=list)
    profile_source: Literal["code", "prompt", "framework", "endpoint", "heuristic"] = "heuristic"
    profile_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    # Deeper evidence-grounded recon signals (additive). Defaults make older
    # persisted fingerprint records (which lack these keys) parse unchanged.
    # ``recon_coverage`` / ``recon_probe_count`` carry the capability-audit
    # ledger so the dashboard can render coverage state + probe volume.
    guardrail_posture: str | None = None
    requires_confirmation: bool | None = None
    data_exposure: list[str] = Field(default_factory=list)
    behavioral_flags: list[str] = Field(default_factory=list)
    tool_descriptions: dict[str, str] = Field(default_factory=dict)
    recon_coverage: dict[str, str] = Field(default_factory=dict)
    recon_probe_count: int = 0
    # Coarse inference-family class from the time-channel recon probe
    # (RECON-TC-001): "tight-cluster" (small hosted model), "wide-variance"
    # (large reasoning model / multi-step pipeline), or "" (not measured).
    # Used to route reasoning-targeted probes (H-CoT / ReAct) to capable targets.
    inference_class: str = ""

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

    def profile_evidence(self) -> ProfileEvidence:
        """Best readable evidence for profiling. Default: black-box (call-only).

        White-box adapters (prompt / code / framework) override this to expose
        the system prompt, source, or framework introspection so the profiler
        can read the target instead of interrogating it.
        """
        return ProfileEvidence(box="black")

    async def aclose(self) -> None:
        """Release any resources (HTTP clients, etc.). Subclasses override."""
        return None
