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

from abc import ABC, abstractmethod

from agent_guardian.ci.comment import MARKER

__all__ = ["MARKER", "Poster", "PosterError", "get_poster"]


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
# Per-platform loaders. Each does a LITERAL import of exactly one poster module
# (so semgrep's non-literal-import audit stays clean and no arbitrary module can
# be loaded) and stays lazy (only the chosen loader runs). Distinct functions
# avoid mypy's no-redef on a shared import alias.
def _load_github() -> Poster:
    from agent_guardian.ci.posters.github import get_poster

    return get_poster()


def _load_gitlab() -> Poster:
    from agent_guardian.ci.posters.gitlab import get_poster

    return get_poster()


def _load_bitbucket() -> Poster:
    from agent_guardian.ci.posters.bitbucket import get_poster

    return get_poster()


_POSTER_LOADERS = {
    "github": _load_github,
    "gitlab": _load_gitlab,
    "bitbucket": _load_bitbucket,
}
_KNOWN_PLATFORMS = tuple(_POSTER_LOADERS)


def get_poster(platform: str) -> Poster:
    """Resolve and instantiate the poster for ``platform``.

    Dispatches to a per-platform loader that lazily imports exactly one poster
    module and calls its ``get_poster()`` factory.

    Raises:
        PosterError: if no loader exists for ``platform`` or the module did not
            return a :class:`Poster` instance.
    """
    name = (platform or "").strip().lower()
    loader = _POSTER_LOADERS.get(name)
    if loader is None:
        raise PosterError(
            f"no poster for platform '{platform}' -- choose one of: " + ", ".join(_KNOWN_PLATFORMS)
        )
    poster = loader()
    if not isinstance(poster, Poster):
        raise PosterError(f"poster module for '{platform}' did not return a Poster instance")
    return poster
