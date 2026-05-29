"""Target contract schema (Stage 1).

A *contract* is the declarative, on-disk description of the system under test:
what it is (an HTTP endpoint, today), how to authenticate to it, how to shape a
request, how to extract the model's reply, how sessions are managed, and the
Rules of Engagement (RoE) that bound any scan. It is the single source of truth
the rest of AgentGuardian compiles a transport from (in a later stage).

Design rules baked into this module:

* **Pydantic v2, ``extra="forbid"``** on every model — typos fail loudly. The
  one escape hatch is ``x-`` prefixed extension keys, accepted on the top-level
  :class:`Contract` for forward-compat metadata.
* **Discriminated unions** for the polymorphic ``transport`` and ``auth``
  fields, keyed on a ``kind`` literal, so adding a kind later is additive.
* **No raw secrets.** Credentials are :class:`SecretRef` pointers (see
  :mod:`agent_guardian.contract.secrets`).
* **Jinja templates are validated, not rendered.** We parse ``request.body``
  and reject any variable outside the allowed set (``prompt``,
  ``conversation``, ``tool_results``, ``session``).
* **JSONPath fields start with ``$``.** Output / error / tool / delta paths are
  ``$.a.b[0]`` style dot-paths walked against the JSON response.
* **Prod requires ``authorization_ref``.** A contract whose target
  ``environment`` is ``prod`` must carry ``roe.authorization_ref`` — proof the
  operator is allowed to test the target.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Literal

from jinja2 import Environment, TemplateSyntaxError, meta
from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agent_guardian.contract.secrets import SecretRef

_LOG = logging.getLogger(__name__)

__all__ = [
    "ALLOWED_TEMPLATE_VARS",
    "CURRENT_CONTRACT_VERSION",
    "MAX_KNOWN_CONTRACT_VERSION",
    "AnthropicMessagesTransport",
    "ApiKeyAuth",
    "Auth",
    "AwsSigV4Auth",
    "AzureEntraAuth",
    "AzureFoundryAgentTransport",
    "BearerAuth",
    "BedrockAgentTransport",
    "Budgets",
    "Contract",
    "DataEgress",
    "Environment_",
    "GcpAdcAuth",
    "GcpSaJsonAuth",
    "HmacAuth",
    "HttpTransport",
    "IdSend",
    "Identity",
    "MtlsAuth",
    "Network",
    "NoAuth",
    "OAuth2ClientCredentialsAuth",
    "Observability",
    "OpenAiResponsesTransport",
    "Rate",
    "Request",
    "Reset",
    "Response",
    "ResponseError",
    "Retry",
    "RoE",
    "RoeTools",
    "Session",
    "Stream",
    "Target",
    "Tls",
    "ToolRef",
    "Tools",
    "Transport",
    "VertexAgentTransport",
]

CURRENT_CONTRACT_VERSION = 1
# The highest schema version this build *recognises* (even if it can't load it
# natively yet). Versions in ``(CURRENT, MAX_KNOWN]`` are migratable; anything
# beyond ``MAX_KNOWN`` is a hard "upgrade your build" stop.
MAX_KNOWN_CONTRACT_VERSION = 2

# The only variables a request body template may reference. Anything else is a
# typo or an attempt to smuggle state we don't expose, and is rejected at load
# time rather than blowing up at render time inside a live scan.
ALLOWED_TEMPLATE_VARS: frozenset[str] = frozenset(
    {"prompt", "conversation", "tool_results", "session"}
)

Environment_ = Literal["prod", "staging", "clone"]


def _validate_jinja_template(template: str) -> str:
    """Parse ``template`` and reject unknown / disallowed variables.

    The template is *validated, never rendered* — we use Jinja's AST analysis
    (:func:`jinja2.meta.find_undeclared_variables`) to enumerate the free
    variables and assert they are a subset of :data:`ALLOWED_TEMPLATE_VARS`.
    """
    env = Environment(autoescape=False)
    try:
        ast = env.parse(template)
    except TemplateSyntaxError as exc:
        _LOG.debug("contract: invalid request body Jinja2 syntax (%s)", exc.message)
        raise ValueError(f"request.body is not valid Jinja2: {exc.message}") from exc
    used = meta.find_undeclared_variables(ast)
    unknown = sorted(used - ALLOWED_TEMPLATE_VARS)
    if unknown:
        allowed = ", ".join(sorted(ALLOWED_TEMPLATE_VARS))
        raise ValueError(
            f"request.body references disallowed variable(s) {unknown}; "
            f"allowed variables are: {allowed}"
        )
    return template


def _validate_jsonpath(value: str | None) -> str | None:
    """Reject a JSONPath that does not begin with ``$`` (``None`` passes through)."""
    if value is None:
        return None
    if not value.startswith("$"):
        raise ValueError(f"json path must start with '$' (got {value!r})")
    return value


# ---------------------------------------------------------------------------
# Auth — discriminated union on ``kind``
# ---------------------------------------------------------------------------


class NoAuth(BaseModel):
    """No authentication — the target is open / unauthenticated."""

    kind: Literal["none"] = "none"

    model_config = ConfigDict(frozen=True, extra="forbid")


class ApiKeyAuth(BaseModel):
    """API-key authentication.

    The key is supplied via header (default) or, when ``in_`` is ``query``, as a
    query parameter named ``name``. The secret is a :class:`SecretRef`.
    """

    kind: Literal["api_key"] = "api_key"
    in_: Literal["header", "query"] = Field(default="header", alias="in")
    name: str = "Authorization"
    value: SecretRef
    prefix: str = ""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class BearerAuth(BaseModel):
    """Bearer-token authentication (``Authorization: Bearer <token>``)."""

    kind: Literal["bearer"] = "bearer"
    token: SecretRef
    header: str = "Authorization"

    model_config = ConfigDict(frozen=True, extra="forbid")


class OAuth2ClientCredentialsAuth(BaseModel):
    """OAuth2 client-credentials grant.

    The transport exchanges ``client_id`` / ``client_secret`` at ``token_url``
    for an access token. Both credentials are :class:`SecretRef` pointers.
    """

    kind: Literal["oauth2_client_credentials"] = "oauth2_client_credentials"
    token_url: AnyUrl
    client_id: SecretRef
    client_secret: SecretRef
    scope: str | None = None
    audience: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class MtlsAuth(BaseModel):
    """Mutual-TLS authentication via a client certificate + key."""

    kind: Literal["mtls"] = "mtls"
    client_cert: SecretRef
    client_key: SecretRef
    ca_bundle: SecretRef | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class HmacAuth(BaseModel):
    """HMAC request signing.

    ``signing_string_template`` is the operator-supplied signing string; the
    digest is computed with ``algorithm`` over the shared ``secret``.
    """

    kind: Literal["hmac"] = "hmac"
    header: str
    algorithm: str = "sha256"
    secret: SecretRef
    signing_string_template: str

    model_config = ConfigDict(frozen=True, extra="forbid")


class AwsSigV4Auth(BaseModel):
    """AWS SigV4 request signing for AWS-hosted targets (Bedrock, etc.).

    Explicit credentials are optional :class:`SecretRef` pointers; when omitted
    the transport falls back to the default AWS credential chain (env vars,
    shared config, instance / container role).
    """

    kind: Literal["aws_sigv4"] = "aws_sigv4"
    region: str
    service: str = "bedrock"
    access_key_id: SecretRef | None = None
    secret_access_key: SecretRef | None = None
    session_token: SecretRef | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class AzureEntraAuth(BaseModel):
    """Azure Entra ID (formerly Azure AD) OAuth2 client-credentials grant.

    Exchanges ``client_id`` / ``client_secret`` against the tenant for an access
    token scoped to ``scope``. ``client_secret`` is optional to allow
    federated / managed-identity flows that need no static secret.
    """

    kind: Literal["azure_entra"] = "azure_entra"
    tenant_id: str
    client_id: SecretRef
    client_secret: SecretRef | None = None
    scope: str = "https://cognitiveservices.azure.com/.default"

    model_config = ConfigDict(frozen=True, extra="forbid")


class GcpAdcAuth(BaseModel):
    """GCP Application Default Credentials — no static secret material.

    Credentials are discovered from the ambient environment (gcloud login,
    workload identity, GCE metadata, ``GOOGLE_APPLICATION_CREDENTIALS``).
    """

    kind: Literal["gcp_adc"] = "gcp_adc"

    model_config = ConfigDict(frozen=True, extra="forbid")


class GcpSaJsonAuth(BaseModel):
    """GCP service-account authentication from a JSON key.

    The service-account JSON is a :class:`SecretRef` pointer; ``scopes`` are the
    OAuth2 scopes to mint the access token against.
    """

    kind: Literal["gcp_sa_json"] = "gcp_sa_json"
    service_account_json: SecretRef
    scopes: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True, extra="forbid")


# Discriminated union keyed on ``kind``. Every variant maps 1:1 to an
# implemented transport auth provider (api_key, bearer, oauth2, mtls, hmac plus
# the cloud-provider kinds), so a later factory can dispatch on ``kind`` without
# a lookup table.
Auth = Annotated[
    NoAuth
    | ApiKeyAuth
    | BearerAuth
    | OAuth2ClientCredentialsAuth
    | MtlsAuth
    | HmacAuth
    | AwsSigV4Auth
    | AzureEntraAuth
    | GcpAdcAuth
    | GcpSaJsonAuth,
    Field(discriminator="kind"),
]


# ---------------------------------------------------------------------------
# Transport — discriminated union on ``kind``
# ---------------------------------------------------------------------------


class Tls(BaseModel):
    """TLS knobs for an HTTP transport."""

    ca_bundle: SecretRef | None = None
    insecure: bool = False

    model_config = ConfigDict(frozen=True, extra="forbid")


class HttpTransport(BaseModel):
    """An HTTP(S) endpoint under test."""

    kind: Literal["http"] = "http"
    url: AnyUrl
    method: Literal["GET", "POST", "PUT", "PATCH"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    openapi: str | None = None
    timeout_ms: int = Field(default=60000, gt=0)
    tls: Tls | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class OpenAiResponsesTransport(BaseModel):
    """OpenAI Responses API target (``/responses``)."""

    kind: Literal["openai_responses"] = "openai_responses"
    base_url: AnyUrl = AnyUrl("https://api.openai.com/v1")
    model: str
    store: bool = True

    model_config = ConfigDict(frozen=True, extra="forbid")


class AnthropicMessagesTransport(BaseModel):
    """Anthropic Messages API target (``/messages``)."""

    kind: Literal["anthropic_messages"] = "anthropic_messages"
    base_url: AnyUrl = AnyUrl("https://api.anthropic.com/v1")
    model: str
    max_tokens: int = Field(default=1024, gt=0)
    anthropic_version: str = "2023-06-01"

    model_config = ConfigDict(frozen=True, extra="forbid")


class BedrockAgentTransport(BaseModel):
    """AWS Bedrock Agent runtime target (InvokeAgent)."""

    kind: Literal["bedrock_agent"] = "bedrock_agent"
    region: str
    agent_id: str
    agent_alias_id: str
    enable_trace: bool = True

    model_config = ConfigDict(frozen=True, extra="forbid")


class VertexAgentTransport(BaseModel):
    """GCP Vertex AI reasoning-engine (agent) target."""

    kind: Literal["vertex_agent"] = "vertex_agent"
    project: str
    location: str
    reasoning_engine_id: str

    model_config = ConfigDict(frozen=True, extra="forbid")


class AzureFoundryAgentTransport(BaseModel):
    """Azure AI Foundry agent target."""

    kind: Literal["azure_foundry_agent"] = "azure_foundry_agent"
    endpoint: AnyUrl
    agent_id: str

    model_config = ConfigDict(frozen=True, extra="forbid")


# A discriminated union keyed on ``kind``. ``http`` is the generic primitive;
# the cloud-provider kinds are first-class so a later factory can dispatch on
# ``kind`` without a lookup table. The discriminator + Annotated shape keeps
# additional transport kinds purely additive.
Transport = Annotated[
    HttpTransport
    | OpenAiResponsesTransport
    | AnthropicMessagesTransport
    | BedrockAgentTransport
    | VertexAgentTransport
    | AzureFoundryAgentTransport,
    Field(discriminator="kind"),
]


# ---------------------------------------------------------------------------
# Request / Response
# ---------------------------------------------------------------------------


class Stream(BaseModel):
    """Streaming-response extraction (SSE / chunked / websocket)."""

    format: Literal["sse", "chunked", "ws"]
    delta_path: str
    done_signal: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("delta_path")
    @classmethod
    def _check_delta_path(cls, value: str) -> str:
        if not value.startswith("$"):
            raise ValueError(f"delta_path must start with '$' (got {value!r})")
        return value


class ResponseError(BaseModel):
    """How to detect an error response."""

    status_success: list[int] = Field(default_factory=lambda: [200, 201])
    error_path: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("error_path")
    @classmethod
    def _check_error_path(cls, value: str | None) -> str | None:
        return _validate_jsonpath(value)


class Response(BaseModel):
    """How to extract the model's reply (and optional tool calls / stream)."""

    output_path: str
    error: ResponseError = Field(default_factory=ResponseError)
    tool_call_path: str | None = None
    stream: Stream | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("output_path")
    @classmethod
    def _check_output_path(cls, value: str) -> str:
        if not value.startswith("$"):
            raise ValueError(f"output_path must start with '$' (got {value!r})")
        return value

    @field_validator("tool_call_path")
    @classmethod
    def _check_tool_call_path(cls, value: str | None) -> str | None:
        return _validate_jsonpath(value)


class Request(BaseModel):
    """How to shape the request body (Jinja, validated-not-rendered)."""

    prompt_location: Literal["body", "query", "path", "header"] = "body"
    body: str = '{"input": "{{ prompt }}"}'
    content_type: str = "application/json"
    multipart: bool = False

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("body")
    @classmethod
    def _check_body(cls, value: str) -> str:
        return _validate_jinja_template(value)


# ---------------------------------------------------------------------------
# Session / Identity / Tools
# ---------------------------------------------------------------------------


class IdSend(BaseModel):
    """Where / how to send a session id back to the target."""

    in_: Literal["header", "query", "body"] = Field(alias="in")
    name: str

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class Reset(BaseModel):
    """Optional create / delete hooks for session lifecycle."""

    create: str | None = None
    delete: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class Session(BaseModel):
    """Session-management policy for the target."""

    mode: Literal["stateless", "server_session", "client_history"] = "stateless"
    id_source: str | None = None
    id_send: IdSend | None = None
    isolate_per_scenario: bool = True
    reset: Reset | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class Identity(BaseModel):
    """Identity / tenancy hints for the target."""

    user_id: str | None = None
    jit_credentials: bool = False
    tenant: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolRef(BaseModel):
    """A named tool the target is expected to expose."""

    name: str

    model_config = ConfigDict(frozen=True, extra="forbid")


class Tools(BaseModel):
    """Tool-discovery + expectations for the target."""

    discovery: Literal["mcp", "openapi", "manual", "none"] = "none"
    record_calls: bool = True
    expected: list[ToolRef] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------


class Observability(BaseModel):
    """Where to emit traces / events during a scan."""

    otel_endpoint: str | None = None
    webhook: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Rules of Engagement (RoE)
# ---------------------------------------------------------------------------


class Budgets(BaseModel):
    """Hard upper bounds on a scan's resource consumption."""

    max_tokens: int | None = Field(default=None, gt=0)
    max_wallclock_minutes: int | None = Field(default=None, gt=0)
    max_requests: int | None = Field(default=None, gt=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class Retry(BaseModel):
    """Retry policy for transient failures."""

    max_attempts: int = Field(default=3, ge=1)
    backoff: Literal["exponential", "linear"] = "exponential"

    model_config = ConfigDict(frozen=True, extra="forbid")


class Rate(BaseModel):
    """Rate / concurrency controls."""

    max_rps: float | None = Field(default=None, gt=0)
    parallel_workers: int | None = Field(default=None, gt=0)
    retry: Retry | None = None
    idempotency_key_header: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class RoeTools(BaseModel):
    """Tool allow / block lists for the scan."""

    allowlist: list[str] | None = None
    blocklist: list[str] | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class DataEgress(BaseModel):
    """Data-egress policy."""

    allow_external: bool = False

    model_config = ConfigDict(frozen=True, extra="forbid")


class Network(BaseModel):
    """Network policy (proxying, etc.)."""

    proxy: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class RoE(BaseModel):
    """Rules of Engagement — the bounds a scan must respect.

    The defaults make a minimal ``roe: {}`` valid, except for the prod gate
    enforced on :class:`Contract`: a ``prod`` target requires a non-empty
    :attr:`authorization_ref`.
    """

    authorization_ref: str | None = None
    budgets: Budgets = Field(default_factory=Budgets)
    rate: Rate = Field(default_factory=Rate)
    tools: RoeTools | None = None
    do_not_test_windows: list[str] = Field(default_factory=list)
    data_egress: DataEgress = Field(default_factory=DataEgress)
    network: Network | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Target — the system under test
# ---------------------------------------------------------------------------


class Target(BaseModel):
    """The system under test: transport, auth, request/response shaping."""

    name: str = Field(min_length=1)
    description: str | None = None
    environment: Environment_ = "staging"
    region: str | None = None
    transport: Transport
    auth: Auth = Field(default_factory=NoAuth)
    request: Request = Field(default_factory=Request)
    response: Response
    session: Session = Field(default_factory=Session)
    identity: Identity | None = None
    tools: Tools | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Contract — the document root
# ---------------------------------------------------------------------------


class Contract(BaseModel):
    """The root contract document.

    ``version`` is the schema version (the loader gates on it *before* building
    this model). ``extra="forbid"`` rejects typos, except ``x-`` prefixed keys
    which are retained verbatim in :attr:`extensions` for forward-compat.
    """

    version: int = CURRENT_CONTRACT_VERSION
    target: Target
    observability: Observability | None = None
    roe: RoE = Field(default_factory=RoE)
    extensions: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _collect_extensions(cls, data: Any) -> Any:
        """Pull ``x-`` prefixed top-level keys into ``extensions``.

        This lets a contract carry forward-compat metadata (``x-team``,
        ``x-ticket``…) without ``extra="forbid"`` rejecting it, while still
        rejecting genuine typos.
        """
        if not isinstance(data, dict):
            return data
        ext = dict(data.get("extensions") or {})
        cleaned: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(key, str) and key.startswith("x-"):
                ext[key] = value
            else:
                cleaned[key] = value
        if ext:
            cleaned["extensions"] = ext
        return cleaned

    @model_validator(mode="after")
    def _prod_requires_authorization(self) -> Contract:
        """A ``prod`` target must carry a non-empty ``roe.authorization_ref``."""
        if self.target.environment == "prod" and not (self.roe.authorization_ref or "").strip():
            raise ValueError(
                "target.environment 'prod' requires a non-empty "
                "'roe.authorization_ref' (proof of authorization to test the target)"
            )
        return self
