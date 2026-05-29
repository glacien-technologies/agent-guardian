"""Contract → transport wiring (Stage 1B).

This is the *only* module that bridges a :class:`~agent_guardian.contract.schema.Contract`
onto the primitive-driven :mod:`agent_guardian.transports` layer. The transports
package itself deliberately knows nothing about contracts (see its module
docstring); the decoupling rule says the contract→transport translation lives
here, on the contract side of the seam.

Three builders make up the bridge:

* :func:`build_auth_provider` maps the contract's discriminated ``auth`` block
  onto the matching :class:`~agent_guardian.transports.auth.base.AuthProvider`,
  resolving every :class:`~agent_guardian.contract.secrets.SecretRef` to its
  concrete plaintext value via the contract's own resolver. The providers only
  ever receive resolved strings — a :class:`SecretRef` never reaches them.
* :func:`build_transport` constructs an :class:`~agent_guardian.transports.http.HttpTransport`
  from the contract's transport / request / response primitives. Non-HTTP
  transport kinds raise :class:`NotImplementedError` with a Stage-2+ message.
* :func:`build_session_machine` wraps a transport in the
  :class:`~agent_guardian.transports.session.SessionMachine` the contract's
  ``session.mode`` calls for.

Secrets are resolved through :func:`agent_guardian.contract.resolve_secrets`,
which returns a ``{SecretRef: plaintext}`` mapping; the OAuth2 provider, which
needs to perform a token-endpoint round-trip, is handed a dedicated
:class:`httpx.AsyncClient` owned by the resulting transport graph.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from agent_guardian.contract.schema import (
    ApiKeyAuth as ContractApiKeyAuth,
)
from agent_guardian.contract.schema import (
    BearerAuth as ContractBearerAuth,
)
from agent_guardian.contract.schema import (
    HmacAuth as ContractHmacAuth,
)
from agent_guardian.contract.schema import (
    MtlsAuth as ContractMtlsAuth,
)
from agent_guardian.contract.schema import (
    NoAuth as ContractNoAuth,
)
from agent_guardian.contract.schema import (
    OAuth2ClientCredentialsAuth as ContractOAuth2Auth,
)
from agent_guardian.contract.secrets import (
    SecretRef,
    SecretResolver,
    resolve_secrets,
)
from agent_guardian.transports.auth.api_key import ApiKeyAuth
from agent_guardian.transports.auth.base import AuthProvider, NoAuth
from agent_guardian.transports.auth.bearer import BearerAuth
from agent_guardian.transports.auth.hmac import HmacAuth
from agent_guardian.transports.auth.mtls import MutualTlsAuth
from agent_guardian.transports.auth.oauth2 import OAuth2ClientCredentialsAuth
from agent_guardian.transports.http import HttpTransport
from agent_guardian.transports.session import SessionMachine, SessionMode

if TYPE_CHECKING:
    from agent_guardian.contract.schema import Auth, Contract
    from agent_guardian.transports.base import Transport

_LOG = logging.getLogger(__name__)

__all__ = [
    "build_auth_provider",
    "build_session_machine",
    "build_transport",
]


def _resolve(
    refs: dict[SecretRef, str],
    ref: SecretRef,
) -> str:
    """Return the resolved plaintext for ``ref`` from the precomputed mapping.

    ``resolve_secrets`` has already resolved every ref reachable from the
    contract, so a miss here is a programming error (a ref that was not walked)
    rather than a runtime secret failure — we surface it loudly.
    """
    try:
        return refs[ref]
    except KeyError as exc:  # pragma: no cover - defensive: refs are pre-walked
        _LOG.debug("secret ref %r missing from resolved mapping", ref)
        raise KeyError(f"secret ref {ref!r} was not resolved from the contract") from exc


def build_auth_provider(
    contract: Contract,
    *,
    resolver: SecretResolver | None = None,
    oauth2_client: httpx.AsyncClient | None = None,
) -> AuthProvider:
    """Build the :class:`AuthProvider` the contract's ``auth`` block describes.

    Resolves every :class:`SecretRef` up front via
    :func:`agent_guardian.contract.resolve_secrets` (optionally with an injected
    ``resolver`` so tests can drive ``env`` / ``file`` deterministically), then
    dispatches on the discriminated ``auth.kind``:

    * ``none`` → :class:`NoAuth`
    * ``api_key`` → :class:`ApiKeyAuth` (header injection; ``prefix`` folded into
      the value template)
    * ``bearer`` → :class:`BearerAuth`
    * ``oauth2_client_credentials`` → :class:`OAuth2ClientCredentialsAuth`
      (handed ``oauth2_client`` for its token round-trip)
    * ``mtls`` → :class:`MutualTlsAuth` (resolved cert / key / CA material)
    * ``hmac`` → :class:`HmacAuth`

    The providers only ever receive **resolved plaintext strings**; a
    :class:`SecretRef` never crosses this boundary.

    Raises:
        ValueError: an ``oauth2_client_credentials`` auth was declared but no
            ``oauth2_client`` was supplied to perform the token fetch.
    """
    auth: Auth = contract.target.auth
    refs = resolve_secrets(contract, resolver=resolver)

    if isinstance(auth, ContractNoAuth):
        return NoAuth()

    if isinstance(auth, ContractApiKeyAuth):
        key = _resolve(refs, auth.value)
        # ``prefix`` (e.g. ``"Bearer "``) is folded into the value template so a
        # contract that says ``Authorization: Bearer <key>`` works with the
        # primitive ApiKeyAuth provider without a bespoke variant.
        value_template = f"{auth.prefix}{{key}}" if auth.prefix else "{key}"
        return ApiKeyAuth(key, header_name=auth.name, value_template=value_template)

    if isinstance(auth, ContractBearerAuth):
        token = _resolve(refs, auth.token)
        return BearerAuth(token, scheme="Bearer")

    if isinstance(auth, ContractOAuth2Auth):
        if oauth2_client is None:
            raise ValueError(
                "oauth2_client_credentials auth requires an httpx.AsyncClient "
                "for the token endpoint round-trip"
            )
        return OAuth2ClientCredentialsAuth(
            token_url=str(auth.token_url),
            client_id=_resolve(refs, auth.client_id),
            client_secret=_resolve(refs, auth.client_secret),
            scope=auth.scope or "",
            client=oauth2_client,
        )

    if isinstance(auth, ContractMtlsAuth):
        cert: str | tuple[str, str] = (
            _resolve(refs, auth.client_cert),
            _resolve(refs, auth.client_key),
        )
        verify: str | bool = _resolve(refs, auth.ca_bundle) if auth.ca_bundle else True
        return MutualTlsAuth(cert=cert, verify=verify)

    if isinstance(auth, ContractHmacAuth):
        secret = _resolve(refs, auth.secret)
        return HmacAuth(
            secret,
            signing_string_template=auth.signing_string_template,
            signature_header=auth.header,
            algorithm=auth.algorithm,
        )

    # The discriminated union is closed; an unrecognised member is unreachable
    # unless the schema gains a new auth kind without a matching factory arm.
    raise NotImplementedError(  # pragma: no cover - defensive
        f"auth kind {auth.kind!r} has no transport provider mapping"
    )


def build_transport(
    contract: Contract,
    *,
    resolver: SecretResolver | None = None,
) -> Transport:
    """Build the :class:`Transport` the contract's ``target.transport`` describes.

    Only ``kind == "http"`` ships today: it constructs an :class:`HttpTransport`
    from the contract's transport / request / response primitives (endpoint,
    Jinja request body, output / error / tool-call JSONPaths, base headers,
    timeout). The OAuth2 provider — when the contract authenticates that way —
    is given a dedicated :class:`httpx.AsyncClient` for its token round-trip.

    Raises:
        NotImplementedError: the transport kind is anything other than ``http``.
    """
    transport = contract.target.transport
    if transport.kind != "http":
        raise NotImplementedError(
            f"transport kind {transport.kind!r} is not supported yet "
            "(only 'http' ships in Stage 1; other kinds land in Stage 2+)"
        )

    target = contract.target
    response = target.response

    # OAuth2 needs an httpx client for the token endpoint; build one only when
    # the contract authenticates that way, and let the transport own it so it is
    # closed on ``aclose``.
    oauth2_client: httpx.AsyncClient | None = None
    if isinstance(target.auth, ContractOAuth2Auth):
        oauth2_client = httpx.AsyncClient(timeout=httpx.Timeout(transport.timeout_ms / 1000.0))

    auth = build_auth_provider(contract, resolver=resolver, oauth2_client=oauth2_client)

    return HttpTransport(
        endpoint=str(transport.url),
        request_template=target.request.body,
        output_path=response.output_path,
        error_path=response.error.error_path,
        tool_call_path=response.tool_call_path,
        base_headers=transport.headers,
        auth=auth,
        timeout_seconds=transport.timeout_ms / 1000.0,
    )


_SESSION_MODE_MAP: dict[str, SessionMode] = {
    "stateless": SessionMode.STATELESS,
    "server_session": SessionMode.SERVER_SESSION,
    "client_history": SessionMode.CLIENT_HISTORY,
}


def build_session_machine(contract: Contract, transport: Transport) -> SessionMachine:
    """Wrap ``transport`` in the :class:`SessionMachine` the contract calls for.

    Maps ``target.session.mode`` (``stateless`` / ``server_session`` /
    ``client_history``) onto the transport-layer :class:`SessionMode`. The
    machine starts with no seeded session token — the ``server_session`` flow
    captures the token from the first response.
    """
    mode = _SESSION_MODE_MAP[contract.target.session.mode]
    return SessionMachine(transport, mode=mode)
