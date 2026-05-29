"""Auth provider ABC and the per-request signing context (Stage 1A).

An :class:`AuthProvider` decorates an outgoing request. It is handed an
:class:`AuthContext` describing the request being sent (method, URL, headers,
body bytes) and may mutate ``headers`` (and, for transport-level auth like
mTLS, ``client_kwargs``) in place. Providers must be cheap and side-effect-free
beyond the mutation they declare; any network work (e.g. an OAuth2 token fetch)
happens inside :meth:`apply` and is expected to be cached.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

__all__ = ["AuthContext", "AuthProvider", "NoAuth"]


@dataclass(slots=True)
class AuthContext:
    """Mutable description of the request an :class:`AuthProvider` is signing."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    client_kwargs: dict[str, Any] = field(default_factory=dict)


class AuthProvider(ABC):
    """Decorates an outgoing request with credentials."""

    @abstractmethod
    async def apply(self, ctx: AuthContext) -> None:
        """Mutate ``ctx`` (headers / client_kwargs) to authenticate the request."""

    async def on_unauthorized(self, ctx: AuthContext) -> bool:
        """React to a 401. Return ``True`` to signal the caller to retry once.

        Default: do nothing and do not retry. Token-based providers override
        this to refresh and retry exactly once.
        """
        return False


class NoAuth(AuthProvider):
    """No-op provider for unauthenticated targets."""

    async def apply(self, ctx: AuthContext) -> None:
        return None
