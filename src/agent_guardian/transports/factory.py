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
    AnthropicMessagesTransport as ContractAnthropicTransport,
)
from agent_guardian.contract.schema import (
    ApiKeyAuth as ContractApiKeyAuth,
)
from agent_guardian.contract.schema import (
    AwsSigV4Auth as ContractAwsSigV4Auth,
)
from agent_guardian.contract.schema import (
    AzureEntraAuth as ContractAzureEntraAuth,
)
from agent_guardian.contract.schema import (
    AzureFoundryAgentTransport as ContractAzureFoundryTransport,
)
from agent_guardian.contract.schema import (
    BearerAuth as ContractBearerAuth,
)
from agent_guardian.contract.schema import (
    BedrockAgentTransport as ContractBedrockTransport,
)
from agent_guardian.contract.schema import (
    BrowserTransport as ContractBrowserTransport,
)
from agent_guardian.contract.schema import (
    GcpAdcAuth as ContractGcpAdcAuth,
)
from agent_guardian.contract.schema import (
    GcpSaJsonAuth as ContractGcpSaJsonAuth,
)
from agent_guardian.contract.schema import (
    GrpcTransport as ContractGrpcTransport,
)
from agent_guardian.contract.schema import (
    HmacAuth as ContractHmacAuth,
)
from agent_guardian.contract.schema import (
    HttpTransport as ContractHttpTransport,
)
from agent_guardian.contract.schema import (
    McpOAuthAuth as ContractMcpOAuthAuth,
)
from agent_guardian.contract.schema import (
    McpTransport as ContractMcpTransport,
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
from agent_guardian.contract.schema import (
    OpenAiResponsesTransport as ContractOpenAiTransport,
)
from agent_guardian.contract.schema import (
    SdkTransport as ContractSdkTransport,
)
from agent_guardian.contract.schema import (
    SubprocessTransport as ContractSubprocessTransport,
)
from agent_guardian.contract.schema import (
    VertexAgentTransport as ContractVertexTransport,
)
from agent_guardian.contract.schema import (
    WebSocketTransport as ContractWebSocketTransport,
)
from agent_guardian.contract.secrets import (
    SecretRef,
    SecretResolver,
    resolve_secrets,
)
from agent_guardian.transports.anthropic_messages import AnthropicMessagesTransport
from agent_guardian.transports.auth.api_key import ApiKeyAuth
from agent_guardian.transports.auth.azure_entra import AzureEntraAuth
from agent_guardian.transports.auth.base import AuthProvider, NoAuth
from agent_guardian.transports.auth.bearer import BearerAuth
from agent_guardian.transports.auth.gcp import GcpAdcAuth, GcpSaJsonAuth
from agent_guardian.transports.auth.hmac import HmacAuth
from agent_guardian.transports.auth.mcp_oauth import McpOAuthProvider
from agent_guardian.transports.auth.mtls import MutualTlsAuth
from agent_guardian.transports.auth.oauth2 import OAuth2ClientCredentialsAuth
from agent_guardian.transports.auth.sigv4 import AwsSigV4Auth
from agent_guardian.transports.azure_foundry import AzureFoundryAgentTransport
from agent_guardian.transports.bedrock_agent import BedrockAgentTransport
from agent_guardian.transports.browser import BrowserTransport
from agent_guardian.transports.grpc_transport import GrpcTransport
from agent_guardian.transports.http import HttpTransport, SessionSendIn
from agent_guardian.transports.mcp import McpTransport
from agent_guardian.transports.openai_responses import OpenAiResponsesTransport
from agent_guardian.transports.sdk import SdkTransport
from agent_guardian.transports.session import SessionMachine, SessionMode
from agent_guardian.transports.subprocess import SubprocessTransport
from agent_guardian.transports.vertex_agent import VertexAgentTransport
from agent_guardian.transports.websocket import SessionMode as WsSessionMode
from agent_guardian.transports.websocket import WebSocketTransport

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
        # NOTE: ``ref`` is a SecretRef pointer of the form ``${backend:key}`` —
        # never the resolved plaintext — but to be defensive we log only the
        # backend name so the diagnostic can't leak even a key name.
        _LOG.debug("secret ref missing from resolved mapping (backend=%s)", ref.backend)
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
    * ``aws_sigv4`` → :class:`AwsSigV4Auth` (resolved AWS credentials, or the
      default botocore credential chain when none are supplied)
    * ``azure_entra`` → :class:`AzureEntraAuth` (handed ``oauth2_client`` for its
      Entra token round-trip, like ``oauth2_client_credentials``)
    * ``gcp_adc`` → :class:`GcpAdcAuth` (ambient Application Default Credentials)
    * ``gcp_sa_json`` → :class:`GcpSaJsonAuth` (resolved service-account JSON)
    * ``mcp_oauth`` → :class:`McpOAuthProvider` (MCP OAuth 2.1 + PKCE S256; handed
      ``oauth2_client`` for its token round-trip + RFC 9728 discovery)

    The providers only ever receive **resolved plaintext strings**; a
    :class:`SecretRef` never crosses this boundary.

    Raises:
        ValueError: an ``oauth2_client_credentials``, ``azure_entra`` or
            ``mcp_oauth`` auth was declared but no ``oauth2_client`` was supplied
            to perform the token fetch.
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

    if isinstance(auth, ContractAwsSigV4Auth):
        # Explicit credentials are optional; when omitted the provider falls back
        # to the default botocore credential chain.
        access_key_id = _resolve(refs, auth.access_key_id) if auth.access_key_id else None
        secret_access_key = (
            _resolve(refs, auth.secret_access_key) if auth.secret_access_key else None
        )
        session_token = _resolve(refs, auth.session_token) if auth.session_token else None
        return AwsSigV4Auth(
            region=auth.region,
            service=auth.service,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
        )

    if isinstance(auth, ContractAzureEntraAuth):
        if oauth2_client is None:
            raise ValueError(
                "azure_entra auth requires an httpx.AsyncClient for the Entra "
                "token endpoint round-trip"
            )
        # ``client_secret`` is optional (federated / managed-identity flows); the
        # provider requires a string, so an absent secret resolves to "".
        client_secret = _resolve(refs, auth.client_secret) if auth.client_secret else ""
        return AzureEntraAuth(
            tenant_id=auth.tenant_id,
            client_id=_resolve(refs, auth.client_id),
            client_secret=client_secret,
            scope=auth.scope,
            client=oauth2_client,
        )

    if isinstance(auth, ContractGcpAdcAuth):
        return GcpAdcAuth()

    if isinstance(auth, ContractGcpSaJsonAuth):
        service_account_json = _resolve(refs, auth.service_account_json)
        if auth.scopes:
            return GcpSaJsonAuth(
                service_account_json=service_account_json,
                scopes=tuple(auth.scopes),
            )
        # No scopes declared: let the provider apply its cloud-platform default.
        return GcpSaJsonAuth(service_account_json=service_account_json)

    if isinstance(auth, ContractMcpOAuthAuth):
        if oauth2_client is None:
            raise ValueError(
                "mcp_oauth auth requires an httpx.AsyncClient for the token "
                "endpoint round-trip (and RFC 9728 discovery)"
            )
        # ``client_secret`` is optional (public clients omit it). ``token_url``
        # (an explicit override that skips RFC 9728 discovery) is the only place a
        # URL crosses; the provider derives discovery endpoints from ``resource``.
        mcp_client_secret: str | None = (
            _resolve(refs, auth.client_secret) if auth.client_secret else None
        )
        return McpOAuthProvider(
            client_id=_resolve(refs, auth.client_id),
            client_secret=mcp_client_secret,
            scopes=list(auth.scopes),
            resource=auth.resource,
            token_url=str(auth.token_url) if auth.token_url else None,
            client=oauth2_client,
        )

    # The discriminated union is closed; an unrecognised member is unreachable
    # unless the schema gains a new auth kind without a matching factory arm.
    raise NotImplementedError(  # pragma: no cover - defensive
        f"auth kind {auth.kind!r} has no transport provider mapping"
    )


# Auth kinds that require a dedicated httpx client for a token-endpoint
# round-trip (OAuth2 client-credentials, Azure Entra, and MCP OAuth — the latter
# also walks RFC 9728 discovery over that client). The factory builds one and
# hands it to ``build_auth_provider``.
_TOKEN_FETCH_AUTH = (ContractOAuth2Auth, ContractAzureEntraAuth, ContractMcpOAuthAuth)

# Default data-plane timeout (seconds) for cloud transports whose contract
# transport block carries no ``timeout_ms`` field.
_DEFAULT_CLOUD_TIMEOUT_SECONDS = 60.0

# The WebSocket transport only models ``stateless`` / ``client_history`` (a
# socket carries no server-issued session id to capture/replay). A contract that
# declares ``server_session`` for a WebSocket target degrades to a per-send
# (stateless) socket — the swarm still inlines prior turns via the template's
# ``conversation`` variable under ``client_history``.
_WS_SESSION_MODE_MAP: dict[str, WsSessionMode] = {
    "stateless": "stateless",
    "client_history": "client_history",
}


def build_transport(
    contract: Contract,
    *,
    resolver: SecretResolver | None = None,
) -> Transport:
    """Build the :class:`Transport` the contract's ``target.transport`` describes.

    Dispatches on the discriminated ``target.transport.kind``:

    * ``http`` → :class:`HttpTransport` from the request / response primitives
      (endpoint, Jinja request body, output / error / tool-call JSONPaths, base
      headers, timeout) plus server-session wiring (``session.id_source`` →
      ``session_path`` for capture, ``session.id_send.{in,name}`` →
      ``session_send_in`` / ``session_send_name`` for outbound replay).
    * ``openai_responses`` → :class:`OpenAiResponsesTransport`
    * ``anthropic_messages`` → :class:`AnthropicMessagesTransport`
    * ``bedrock_agent`` → :class:`BedrockAgentTransport`
    * ``vertex_agent`` → :class:`VertexAgentTransport`
    * ``azure_foundry_agent`` → :class:`AzureFoundryAgentTransport`
    * ``mcp`` → :class:`McpTransport` (JSON-RPC 2.0 over Streamable HTTP; built
      from ``url`` / ``entry_tool`` / ``prompt_argument`` / ``init_timeout_ms``,
      owning its own httpx client)
    * ``websocket`` → :class:`WebSocketTransport` (``ws(s)://`` send-template +
      ``output_path``; auth applied as connection headers)
    * ``grpc`` → :class:`GrpcTransport` (generic unary-unary; auth lowered into
      call metadata; prompt mapped through the request template)
    * ``sdk`` → :class:`SdkTransport` (in-process ``module:callable``; **no auth**)
    * ``subprocess`` → :class:`SubprocessTransport` (spawn-per-turn local
      executable; **no auth**)
    * ``browser`` → :class:`BrowserTransport` (Playwright-driven web UI; **no
      auth** — UI/cookie-driven, not header-driven)

    Each cloud transport is constructed from its contract fields plus the built
    :class:`AuthProvider`; the transport graph owns whatever httpx client it
    creates and closes it on ``aclose``. ``OAuth2`` / ``azure_entra`` auth — when
    the contract authenticates that way — is given a dedicated
    :class:`httpx.AsyncClient` for its token round-trip.

    Raises:
        NotImplementedError: the transport kind has no factory arm.
    """
    target = contract.target
    transport = target.transport

    # OAuth2 / Entra need an httpx client for the token endpoint; build one only
    # when the contract authenticates that way.
    oauth2_client: httpx.AsyncClient | None = None
    if isinstance(target.auth, _TOKEN_FETCH_AUTH):
        oauth2_client = httpx.AsyncClient(timeout=httpx.Timeout(_DEFAULT_CLOUD_TIMEOUT_SECONDS))

    auth = build_auth_provider(contract, resolver=resolver, oauth2_client=oauth2_client)

    if isinstance(transport, ContractHttpTransport):
        return _build_http_transport(contract, transport, auth, resolver=resolver)
    if isinstance(transport, ContractOpenAiTransport):
        return OpenAiResponsesTransport(
            base_url=str(transport.base_url),
            model=transport.model,
            store=transport.store,
            auth=auth,
        )
    if isinstance(transport, ContractAnthropicTransport):
        return AnthropicMessagesTransport(
            base_url=str(transport.base_url),
            model=transport.model,
            max_tokens=transport.max_tokens,
            anthropic_version=transport.anthropic_version,
            auth=auth,
        )
    if isinstance(transport, ContractBedrockTransport):
        return BedrockAgentTransport(
            region=transport.region,
            agent_id=transport.agent_id,
            agent_alias_id=transport.agent_alias_id,
            enable_trace=transport.enable_trace,
            auth=auth,
        )
    if isinstance(transport, ContractVertexTransport):
        return VertexAgentTransport(
            project=transport.project,
            location=transport.location,
            engine_id=transport.reasoning_engine_id,
            auth=auth,
        )
    if isinstance(transport, ContractAzureFoundryTransport):
        return AzureFoundryAgentTransport(
            endpoint=str(transport.endpoint),
            agent_id=transport.agent_id,
            auth=auth,
        )
    if isinstance(transport, ContractMcpTransport):
        # The MCP transport owns its data-plane httpx client and closes it on
        # ``aclose``. The auth provider (mcp_oauth) keeps the separate
        # ``oauth2_client`` for its token / RFC 9728 discovery round-trips, like
        # every other token-fetch transport in this module.
        return McpTransport(
            endpoint=str(transport.url),
            entry_tool=transport.entry_tool,
            prompt_argument=transport.prompt_argument,
            auth=auth,
            timeout_seconds=transport.init_timeout_ms / 1000.0,
        )
    if isinstance(transport, ContractWebSocketTransport):
        # The WebSocket transport accepts an auth provider (applied as connection
        # headers). ``subprotocol`` is not yet plumbed through the transport's
        # constructor; the contract's stream block (delta/done) is a later wiring.
        return WebSocketTransport(
            url=str(transport.url),
            send_template=transport.send_template,
            output_path=transport.output_path,
            session_mode=_WS_SESSION_MODE_MAP.get(contract.target.session.mode, "stateless"),
            auth=auth,
            timeout_seconds=transport.open_timeout_ms / 1000.0,
        )
    if isinstance(transport, ContractGrpcTransport):
        # The gRPC transport accepts an auth provider (lowered into call
        # metadata). It uses the JSON request encoding by default, mapping the
        # prompt through the request template and reading ``output_field``.
        return GrpcTransport(
            target=transport.target,
            service_method=transport.service_method,
            output_field=transport.output_field,
            use_tls=transport.use_tls,
            send_template=contract.target.request.body,
            auth=auth,
        )
    if isinstance(transport, ContractSdkTransport):
        # In-process callable: no auth (the entrypoint lives in this process).
        return SdkTransport(transport.entrypoint)
    if isinstance(transport, ContractSubprocessTransport):
        # Local executable: no auth. ``output_path`` is optional in the contract
        # but the transport wants a JSONPath when parsing JSON; fall back to its
        # default ``$.output`` when the contract leaves it unset.
        return SubprocessTransport(
            transport.command,
            prompt_mode=transport.prompt_mode,
            output_mode=transport.output_mode,
            output_path=transport.output_path or "$.output",
            cwd=transport.cwd,
            timeout_seconds=transport.timeout_ms / 1000.0,
        )
    if isinstance(transport, ContractBrowserTransport):
        # Browser UI: the transport takes no auth provider (a web UI session is
        # cookie/UI-driven, not header-driven). ``submit_with_enter`` is implied
        # when no explicit submit selector is declared.
        return BrowserTransport(
            url=str(transport.url),
            input_selector=transport.input_selector,
            output_selector=transport.output_selector,
            submit_selector=transport.submit_selector,
            submit_with_enter=transport.submit_selector is None,
            nav_timeout_ms=transport.nav_timeout_ms,
            headless=transport.headless,
        )

    # The discriminated union is closed; an unrecognised member is unreachable
    # unless the schema gains a new transport kind without a matching factory arm.
    raise NotImplementedError(f"transport kind {transport.kind!r} has no factory arm")


def _build_http_transport(
    contract: Contract,
    transport: ContractHttpTransport,
    auth: AuthProvider,
    *,
    resolver: SecretResolver | None = None,
) -> HttpTransport:
    """Construct an :class:`HttpTransport` from the contract's HTTP primitives.

    Server-session wiring: ``session.id_source`` becomes the ``session_path``
    used to *capture* a server-issued session id off the response, and
    ``session.id_send.{in,name}`` becomes the ``session_send_in`` /
    ``session_send_name`` used to *replay* it outbound on the next turn. The
    :class:`~agent_guardian.transports.session.SessionMachine` (SERVER_SESSION
    mode) threads the captured id back through ``Request.session``.

    TLS wiring: ``transport.tls`` is lowered onto the transport's ``verify``
    knob — ``tls.insecure`` → ``verify=False`` (no cert verification), else a
    resolved ``tls.ca_bundle`` → ``verify=<path>`` (pin a private CA), else the
    secure default ``verify=True``. ``insecure`` wins if both are set. The
    ``ca_bundle`` :class:`SecretRef` resolves to a CA-bundle *path* string (the
    same convention :func:`build_auth_provider` uses for ``mtls.ca_bundle``);
    reference it via e.g. ``${env:CA_BUNDLE_PATH}``.
    """
    target = contract.target
    response = target.response
    session = target.session

    session_send_in: SessionSendIn | None = None
    session_send_name: str | None = None
    if session.id_send is not None:
        session_send_in = session.id_send.in_
        session_send_name = session.id_send.name

    verify: bool | str = True
    if transport.tls is not None:
        if transport.tls.insecure:
            verify = False
        elif transport.tls.ca_bundle is not None:
            refs = resolve_secrets(contract, resolver=resolver)
            verify = _resolve(refs, transport.tls.ca_bundle)

    return HttpTransport(
        endpoint=str(transport.url),
        request_template=target.request.body,
        output_path=response.output_path,
        error_path=response.error.error_path,
        tool_call_path=response.tool_call_path,
        session_path=session.id_source,
        session_send_in=session_send_in,
        session_send_name=session_send_name,
        base_headers=transport.headers,
        auth=auth,
        timeout_seconds=transport.timeout_ms / 1000.0,
        verify=verify,
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

    The mapping is *transport-kind agnostic*: a cloud transport that manages its
    own server session (``openai_responses`` via ``previous_response_id``,
    ``bedrock_agent`` via the path ``sessionId``, ``vertex_agent`` via
    ``session_id``, ``azure_foundry`` via the thread id) declares
    ``session.mode: server_session`` and gets the SERVER_SESSION machine, which
    captures :attr:`Response.session` and replays it via :attr:`Request.session`
    on the next turn — exactly the contract every server-session transport
    implements. The HTTP transport reaches the same place via the
    ``id_source`` / ``id_send`` wiring done in :func:`_build_http_transport`.

    Reset hooks (``session.reset.create`` / ``session.reset.delete``) are *not*
    invoked here. They describe provider-native endpoints to mint / tear down a
    session out-of-band; a future stage would call them from the transport's
    :meth:`Transport.open_session` / :meth:`Transport.close_session` lifecycle
    (see :func:`_session_reset_hooks` for the wiring sketch). Until then the
    SERVER_SESSION machine's lazy capture-on-first-response is sufficient.
    """
    mode = _SESSION_MODE_MAP[contract.target.session.mode]
    return SessionMachine(transport, mode=mode)


def _session_reset_hooks(contract: Contract) -> tuple[str | None, str | None]:
    """Return the contract's ``(create, delete)`` session-reset hook references.

    These map onto the :class:`Transport` lifecycle: a ``create`` hook would be
    invoked by :meth:`Transport.open_session` to mint a fresh server session
    (e.g. ``POST /threads`` for Azure Foundry, ``POST .../sessions`` for
    Bedrock), and a ``delete`` hook by :meth:`Transport.close_session` to tear it
    down. The base :class:`Transport` ships both as no-op defaults
    (``open_session`` / ``close_session``), so a contract may declare the hooks
    today and a later stage will wire provider-native create / delete calls
    through them.

    TODO(stage-3): drive ``create`` from :meth:`Transport.open_session` and
    ``delete`` from :meth:`Transport.close_session` for transports that expose a
    session-management data plane (Bedrock sessions, Foundry threads). The
    current builders rely on lazy capture-on-first-response, which covers the
    common case without an explicit create round-trip.
    """
    reset = contract.target.session.reset
    if reset is None:
        return (None, None)
    return (reset.create, reset.delete)
