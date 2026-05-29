"""HMAC request-signing auth (Stage 1A).

Computes an HMAC signature over a *signing string* assembled from a template,
then writes it into a header. The signing-string template is a Python
``str.format`` template with these fields available:

* ``method`` — upper-cased HTTP method.
* ``url`` — the request URL.
* ``path`` — the URL path (best-effort split on the first ``?``).
* ``body`` — the request body decoded as UTF-8 (lossy).
* ``timestamp`` — the unix timestamp string used for this request.
* ``nonce`` — a per-request random nonce.

The secret key is a pre-resolved string. The digest algorithm is configurable
(default ``sha256``) and the output encoding is hex or base64. A timestamp
header is also emitted by default so the server can verify freshness.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from agent_guardian.transports.auth.base import AuthContext, AuthProvider

__all__ = ["HmacAuth"]


def _split_path(url: str) -> str:
    """Return the URL path component (no scheme/host/query/fragment).

    Falls back to the raw, fragment/query-stripped string when ``url`` has no
    scheme (so a bare ``/api?x=1`` still yields ``/api``).
    """
    parts = urlsplit(url)
    if parts.path:
        return parts.path
    return url.split("#", 1)[0].split("?", 1)[0]


class HmacAuth(AuthProvider):
    """Sign a request with HMAC over a templated signing string."""

    def __init__(
        self,
        secret: str,
        *,
        signing_string_template: str = "{method}\n{path}\n{timestamp}\n{body}",
        signature_header: str = "x-signature",
        timestamp_header: str | None = "x-timestamp",
        nonce_header: str | None = None,
        algorithm: str = "sha256",
        encoding: str = "hex",
        signature_prefix: str = "",
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        if not secret:
            raise ValueError("HmacAuth requires a non-empty secret")
        if algorithm not in hashlib.algorithms_available:
            raise ValueError(f"HmacAuth: unknown digest algorithm {algorithm!r}")
        if encoding not in ("hex", "base64"):
            raise ValueError(f"HmacAuth: encoding must be 'hex' or 'base64', got {encoding!r}")
        self._secret = secret.encode("utf-8")
        self._template = signing_string_template
        self._signature_header = signature_header
        self._timestamp_header = timestamp_header
        self._nonce_header = nonce_header
        self._algorithm = algorithm
        self._encoding = encoding
        self._signature_prefix = signature_prefix
        self._clock = clock
        self._nonce_factory = nonce_factory

    def _encode(self, digest: bytes) -> str:
        if self._encoding == "base64":
            return base64.b64encode(digest).decode("ascii")
        return digest.hex()

    def compute_signature(self, ctx: AuthContext, *, timestamp: str, nonce: str) -> str:
        """Build the signing string and return the encoded HMAC signature."""
        signing_string = self._template.format(
            method=ctx.method.upper(),
            url=ctx.url,
            path=_split_path(ctx.url),
            body=ctx.body.decode("utf-8", errors="replace"),
            timestamp=timestamp,
            nonce=nonce,
        )
        digest = hmac.new(
            self._secret,
            signing_string.encode("utf-8"),
            self._algorithm,
        ).digest()
        return self._signature_prefix + self._encode(digest)

    async def apply(self, ctx: AuthContext) -> None:
        timestamp = str(int(self._clock()))
        nonce = self._nonce_factory()
        ctx.headers[self._signature_header] = self.compute_signature(
            ctx, timestamp=timestamp, nonce=nonce
        )
        if self._timestamp_header is not None:
            ctx.headers[self._timestamp_header] = timestamp
        if self._nonce_header is not None:
            ctx.headers[self._nonce_header] = nonce
