"""AWS Signature Version 4 request signing (Stage 1B — cloud providers).

Signs the outgoing request with SigV4 using ``botocore``. The provider builds a
throwaway :class:`botocore.awsrequest.AWSRequest` from the
:class:`~agent_guardian.transports.auth.base.AuthContext` (method / URL / body),
runs :class:`botocore.auth.SigV4Auth` over it, then copies the resulting
``Authorization`` and ``X-Amz-*`` headers back onto the context.

Credentials come either from explicit constructor arguments or, when those are
``None``, from the default botocore credential chain
(:meth:`botocore.session.Session.get_credentials` — env vars, shared config,
instance/role metadata, etc.).

``botocore`` ships only with the ``[aws]`` extra; it is import-guarded so that a
target which never uses SigV4 does not force the dependency. A clear
:class:`ImportError` with remediation is raised at construction when the import
fails.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agent_guardian.transports.auth.base import AuthContext, AuthProvider

if TYPE_CHECKING:
    from botocore.credentials import Credentials

__all__ = ["AwsSigV4Auth"]

_LOG = logging.getLogger(__name__)

_AWS_EXTRA_HINT = "install agent-guardian[aws] to use AWS SigV4 authentication"


class AwsSigV4Auth(AuthProvider):
    """Sign requests with AWS Signature Version 4 via ``botocore``."""

    def __init__(
        self,
        *,
        region: str,
        service: str,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        session_token: str | None = None,
    ) -> None:
        if not region:
            raise ValueError("AwsSigV4Auth requires a region")
        if not service:
            raise ValueError("AwsSigV4Auth requires a service")
        try:
            import botocore.auth as _botocore_auth
            import botocore.awsrequest as _botocore_awsrequest
            import botocore.credentials as _botocore_credentials
            import botocore.session as _botocore_session
        except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
            _LOG.debug("sigv4: botocore import failed (%s)", exc)
            raise ImportError(f"AwsSigV4Auth requires botocore: {_AWS_EXTRA_HINT}") from exc

        self._region = region
        self._service = service
        self._sigv4_cls = _botocore_auth.SigV4Auth
        self._awsrequest_cls = _botocore_awsrequest.AWSRequest

        if access_key_id and secret_access_key:
            self._credentials: Credentials | None = _botocore_credentials.Credentials(
                access_key=access_key_id,
                secret_key=secret_access_key,
                token=session_token,
            )
        else:
            self._credentials = _botocore_session.Session().get_credentials()

    async def apply(self, ctx: AuthContext) -> None:
        if self._credentials is None:
            raise ValueError(
                "AwsSigV4Auth: no AWS credentials available "
                "(none supplied and the default credential chain is empty)"
            )
        aws_request = self._awsrequest_cls(
            method=ctx.method.upper(),
            url=ctx.url,
            data=ctx.body,
            headers=dict(ctx.headers),
        )
        signer = self._sigv4_cls(self._credentials, self._service, self._region)
        signer.add_auth(aws_request)
        for header in (
            "Authorization",
            "X-Amz-Date",
            "X-Amz-Security-Token",
            "X-Amz-Content-SHA256",
        ):
            value = aws_request.headers.get(header)
            if value is not None:
                ctx.headers[header] = value
