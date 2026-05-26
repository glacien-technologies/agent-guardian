"""HttpAdapter — Mode C: hosted HTTP API target (STUB).

The M4 cut wires the configuration surface (endpoint, shape, auth headers,
request template, response JSONPath) and validates the chosen shape, but
:meth:`HttpAdapter.call` raises :class:`NotImplementedError` until M9 lands
the real transport (httpx client, retry policy, SigV4 / OAuth2 helpers,
request templating). The pure-function shapes in
:mod:`agent_guardian.adapters.http_shapes` are fully usable today.
"""

from __future__ import annotations

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.adapters.http_shapes.base import HttpShape, get_shape

__all__ = ["HttpAdapter"]


class HttpAdapter(TargetAdapter):
    """Wraps a hosted HTTP/JSON API endpoint (M4 stub; M9 production)."""

    mode = "http"

    def __init__(
        self,
        endpoint: str,
        *,
        shape: str = "generic",
        auth_headers: dict[str, str] | None = None,
        request_template: str | None = None,
        response_jsonpath: str | None = None,
        ref: str | None = None,
    ) -> None:
        super().__init__()
        if not endpoint:
            raise ValueError("HttpAdapter requires a non-empty endpoint")
        self._endpoint = endpoint
        self._shape_name = shape
        self._auth_headers = dict(auth_headers or {})
        self._request_template = request_template
        self._response_jsonpath = response_jsonpath
        self._shape: HttpShape = get_shape(shape)
        self._fingerprint = TargetFingerprint(
            mode="http",
            ref=ref or endpoint,
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            notes=(f"Mode C STUB — production HTTP transport lands in M9. shape={shape}."),
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def shape_name(self) -> str:
        return self._shape_name

    async def call(self, _prompt: str, *, session: str | None = None) -> str:
        raise NotImplementedError(
            "HttpAdapter.call() is a stub in M4. Production HTTP transport with "
            "request templating, response extraction, and provider-specific shapes "
            "lands in M9. Pure-function shapes are testable today via "
            "agent_guardian.adapters.http_shapes."
        )
