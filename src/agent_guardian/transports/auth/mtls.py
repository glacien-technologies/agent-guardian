"""Mutual-TLS auth (Stage 1A).

mTLS is configured at the transport-client level, not per-request: the client
certificate and verification settings must be passed to the
:class:`httpx.AsyncClient` constructor. This provider therefore writes ``cert``
and ``verify`` into ``ctx.client_kwargs`` so the transport can build (or
rebuild) its client with them. It does not touch per-request headers.

Cert paths are pre-resolved (the caller has already materialised any secret
key material to disk and resolved the path).
"""

from __future__ import annotations

from agent_guardian.transports.auth.base import AuthContext, AuthProvider

__all__ = ["MutualTlsAuth"]

# httpx's ``cert`` accepts a single path, a (cert, key) tuple, or
# (cert, key, password) tuple. ``verify`` accepts a CA bundle path or bool.
CertSpec = str | tuple[str, str] | tuple[str, str, str]


class MutualTlsAuth(AuthProvider):
    """Configure client-certificate mTLS via ``client_kwargs``."""

    def __init__(
        self,
        *,
        cert: CertSpec,
        verify: str | bool = True,
    ) -> None:
        if not cert:
            raise ValueError("MutualTlsAuth requires a client cert")
        self._cert = cert
        self._verify = verify

    @property
    def cert(self) -> CertSpec:
        return self._cert

    @property
    def verify(self) -> str | bool:
        return self._verify

    async def apply(self, ctx: AuthContext) -> None:
        ctx.client_kwargs["cert"] = self._cert
        ctx.client_kwargs["verify"] = self._verify
