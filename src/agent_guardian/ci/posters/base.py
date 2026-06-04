"""Poster abstraction + lazy per-platform resolver (CI/CD feature).

A :class:`Poster` knows how to *upsert* a comment on a code host's
pull/merge request: it finds an existing AgentGuardian comment by its hidden
marker and edits it in place, or creates a new one if none is present. This
keeps a noisy PR to a single, always-current AgentGuardian comment.

:func:`get_poster` resolves a platform name (``"github"`` / ``"gitlab"`` /
``"bitbucket"``) to its concrete poster by importing
``agent_guardian.ci.posters.<platform>`` lazily. New platforms are added simply
by dropping a ``<platform>.py`` module exposing a ``get_poster()`` factory — no
edit to this file is required.
"""

from __future__ import annotations

import importlib
import logging
from abc import ABC, abstractmethod

from agent_guardian.ci.comment import MARKER

__all__ = ["MARKER", "Poster", "PosterError", "get_poster"]

_LOG = logging.getLogger(__name__)


class PosterError(RuntimeError):
    """A poster could not run — missing platform module, env, or API failure."""


class Poster(ABC):
    """Upsert an AgentGuardian comment onto a code-host pull/merge request."""

    #: Hidden marker the implementation searches for to find its own comment.
    marker: str = MARKER

    @abstractmethod
    def upsert(self, body: str) -> None:
        """Create the comment, or update the existing marker-bearing one.

        Implementations: list the PR/MR comments, find the first whose body
        contains :attr:`marker`, and PATCH/PUT it with ``body``; if none is
        found, create a new comment with ``body``.
        """
        raise NotImplementedError


# Platforms that ship today vs. modules added later by other agents. We do not
# hard-code the full set here so a new poster module is pickable the moment it
# lands on disk; this set only powers a friendlier "did you mean" error.
_KNOWN_PLATFORMS = ("github", "gitlab", "bitbucket")


def get_poster(platform: str) -> Poster:
    """Resolve and instantiate the poster for ``platform``.

    Lazily imports ``agent_guardian.ci.posters.<platform>`` and calls its
    module-level ``get_poster()`` factory.

    Raises:
        PosterError: if no module exists for ``platform`` or it does not expose
            a ``get_poster`` factory.
    """
    name = (platform or "").strip().lower()
    if not name:
        raise PosterError("no platform given -- choose one of: " + ", ".join(_KNOWN_PLATFORMS))
    try:
        module = importlib.import_module(f"agent_guardian.ci.posters.{name}")
    except ModuleNotFoundError as exc:
        # Only swallow a missing *platform* module; re-raise if the platform
        # module itself failed to import one of its own dependencies.
        if exc.name and exc.name.endswith(f"posters.{name}"):
            _LOG.debug("no poster module for platform %r: %s", name, exc)
            raise PosterError(
                f"no poster for platform '{platform}' -- available: {', '.join(_KNOWN_PLATFORMS)}"
            ) from exc
        raise
    factory = getattr(module, "get_poster", None)
    if factory is None:
        raise PosterError(f"poster module for '{platform}' does not expose a get_poster() factory")
    poster = factory()
    if not isinstance(poster, Poster):
        raise PosterError(f"poster module for '{platform}' did not return a Poster instance")
    return poster
