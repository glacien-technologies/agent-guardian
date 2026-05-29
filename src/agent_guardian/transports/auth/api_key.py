"""API-key header auth (Stage 1A).

Sets a configurable header (default ``x-api-key``) to a pre-resolved key, with
an optional value template so schemes like ``ApiKey {key}`` work without a
bespoke provider.
"""

from __future__ import annotations

from agent_guardian.transports.auth.base import AuthContext, AuthProvider

__all__ = ["ApiKeyAuth"]


class ApiKeyAuth(AuthProvider):
    """Inject a pre-resolved API key into a request header."""

    def __init__(
        self,
        api_key: str,
        *,
        header_name: str = "x-api-key",
        value_template: str = "{key}",
    ) -> None:
        if not api_key:
            raise ValueError("ApiKeyAuth requires a non-empty api_key")
        self._api_key = api_key
        self._header_name = header_name
        self._value_template = value_template

    async def apply(self, ctx: AuthContext) -> None:
        ctx.headers[self._header_name] = self._value_template.format(key=self._api_key)
