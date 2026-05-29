"""Bearer-token auth (Stage 1A).

Sets ``Authorization: Bearer <token>`` from a pre-resolved token. The scheme
word is configurable for targets that use a non-standard prefix.
"""

from __future__ import annotations

from agent_guardian.transports.auth.base import AuthContext, AuthProvider

__all__ = ["BearerAuth"]


class BearerAuth(AuthProvider):
    """Inject a pre-resolved bearer token into the ``Authorization`` header."""

    def __init__(self, token: str, *, scheme: str = "Bearer") -> None:
        if not token:
            raise ValueError("BearerAuth requires a non-empty token")
        self._token = token
        self._scheme = scheme

    async def apply(self, ctx: AuthContext) -> None:
        ctx.headers["Authorization"] = f"{self._scheme} {self._token}"
