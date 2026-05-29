"""Unit tests for the contract schema (Stage 1)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from agent_guardian.contract.schema import (
    ALLOWED_TEMPLATE_VARS,
    AnthropicMessagesTransport,
    ApiKeyAuth,
    AwsSigV4Auth,
    AzureEntraAuth,
    AzureFoundryAgentTransport,
    BearerAuth,
    BedrockAgentTransport,
    Budgets,
    Contract,
    GcpAdcAuth,
    GcpSaJsonAuth,
    HmacAuth,
    HttpTransport,
    IdSend,
    MtlsAuth,
    NoAuth,
    OAuth2ClientCredentialsAuth,
    OpenAiResponsesTransport,
    Rate,
    Request,
    Response,
    Retry,
    Session,
    Stream,
    Target,
    Tls,
    Tools,
    VertexAgentTransport,
)
from agent_guardian.contract.secrets import SecretRef


def _base_data(**target_overrides: Any) -> dict[str, Any]:
    """A minimal-but-valid contract mapping; ``target_overrides`` patch ``target``."""
    target: dict[str, Any] = {
        "name": "demo",
        "environment": "staging",
        "transport": {"kind": "http", "url": "https://api.example.com/chat"},
        "response": {"output_path": "$.output.text"},
    }
    target.update(target_overrides)
    return {"version": 1, "target": target}


# --------------------------------------------------------------------------
# Minimal contract + defaults
# --------------------------------------------------------------------------


def test_minimal_contract_valid() -> None:
    c = Contract.model_validate(_base_data())
    assert isinstance(c.target, Target)
    assert isinstance(c.target.transport, HttpTransport)
    assert c.target.transport.kind == "http"
    assert c.target.transport.method == "POST"
    assert c.target.transport.timeout_ms == 60000
    # roe defaults make a minimal roe valid
    assert c.roe.authorization_ref is None
    assert isinstance(c.roe.budgets, Budgets)
    assert isinstance(c.roe.rate, Rate)
    assert c.roe.data_egress.allow_external is False
    assert c.observability is None
    assert c.version == 1


def test_target_request_session_defaults() -> None:
    c = Contract.model_validate(_base_data())
    assert isinstance(c.target.request, Request)
    assert c.target.request.body == '{"input": "{{ prompt }}"}'
    assert c.target.request.content_type == "application/json"
    assert c.target.request.multipart is False
    assert c.target.request.prompt_location == "body"
    assert isinstance(c.target.session, Session)
    assert c.target.session.mode == "stateless"
    assert c.target.session.isolate_per_scenario is True
    assert isinstance(c.target.auth, NoAuth)
    assert c.target.identity is None
    assert c.target.tools is None


def test_environment_defaults_to_staging() -> None:
    data = _base_data()
    del data["target"]["environment"]
    c = Contract.model_validate(data)
    assert c.target.environment == "staging"


@pytest.mark.parametrize("env", ["prod", "staging", "clone"])
def test_environment_literals_accepted(env: str) -> None:
    ref = "JIRA-1" if env == "prod" else None
    c = Contract.model_validate({**_base_data(environment=env), "roe": {"authorization_ref": ref}})
    assert c.target.environment == env


def test_environment_rejects_legacy_dev() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(environment="dev"))


# --------------------------------------------------------------------------
# Auth discriminated union — every kind, valid + invalid discriminator
# --------------------------------------------------------------------------


def test_auth_none_is_default() -> None:
    c = Contract.model_validate(_base_data())
    assert isinstance(c.target.auth, NoAuth)
    assert c.target.auth.kind == "none"


def test_auth_api_key_valid_and_alias() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "api_key",
                "in": "query",
                "name": "api_key",
                "value": "${env:K}",
            }
        )
    )
    assert isinstance(c.target.auth, ApiKeyAuth)
    assert c.target.auth.in_ == "query"
    assert c.target.auth.name == "api_key"
    assert c.target.auth.value.backend == "env"


def test_auth_bearer_valid() -> None:
    c = Contract.model_validate(_base_data(auth={"kind": "bearer", "token": "${env:K}"}))
    assert isinstance(c.target.auth, BearerAuth)
    assert c.target.auth.token.key == "K"


def test_auth_oauth2_valid() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "oauth2_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id": "${env:CID}",
                "client_secret": "${file:/run/cs}",
                "scope": "a b",
            }
        )
    )
    assert isinstance(c.target.auth, OAuth2ClientCredentialsAuth)
    assert c.target.auth.client_secret.backend == "file"


def test_auth_mtls_valid() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "mtls",
                "client_cert": "${file:/c.crt}",
                "client_key": "${file:/c.key}",
            }
        )
    )
    assert isinstance(c.target.auth, MtlsAuth)
    assert c.target.auth.ca_bundle is None


def test_auth_hmac_valid() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "hmac",
                "header": "X-Sig",
                "secret": "${env:HS}",
                "signing_string_template": "{method}\n{path}",
            }
        )
    )
    assert isinstance(c.target.auth, HmacAuth)
    assert c.target.auth.algorithm == "sha256"


def test_unknown_auth_kind_rejected() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(auth={"kind": "kerberos"}))


def test_missing_auth_discriminator_rejected() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(auth={"token": "${env:K}"}))


def test_unknown_transport_kind_rejected() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(transport={"kind": "grpc", "url": "https://x.example"}))


def test_missing_transport_discriminator_rejected() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(transport={"url": "https://x.example"}))


# --------------------------------------------------------------------------
# Cloud auth kinds — parse from dict, defaults, extra="forbid", SecretRef
# --------------------------------------------------------------------------


def test_auth_aws_sigv4_minimal() -> None:
    c = Contract.model_validate(_base_data(auth={"kind": "aws_sigv4", "region": "us-east-1"}))
    assert isinstance(c.target.auth, AwsSigV4Auth)
    assert c.target.auth.region == "us-east-1"
    # creds optional -> default credential chain
    assert c.target.auth.service == "bedrock"
    assert c.target.auth.access_key_id is None
    assert c.target.auth.secret_access_key is None
    assert c.target.auth.session_token is None


def test_auth_aws_sigv4_with_credentials() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "aws_sigv4",
                "region": "eu-west-1",
                "service": "bedrock-runtime",
                "access_key_id": "${env:AWS_AK}",
                "secret_access_key": "${env:AWS_SK}",
                "session_token": "${env:AWS_ST}",
            }
        )
    )
    assert isinstance(c.target.auth, AwsSigV4Auth)
    assert c.target.auth.service == "bedrock-runtime"
    assert c.target.auth.access_key_id is not None
    assert c.target.auth.access_key_id.backend == "env"
    assert c.target.auth.session_token is not None


def test_auth_azure_entra_minimal_and_default_scope() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "azure_entra",
                "tenant_id": "tid",
                "client_id": "${env:AZ_CID}",
            }
        )
    )
    assert isinstance(c.target.auth, AzureEntraAuth)
    assert c.target.auth.tenant_id == "tid"
    assert c.target.auth.client_secret is None
    assert c.target.auth.scope == "https://cognitiveservices.azure.com/.default"


def test_auth_azure_entra_with_secret_and_scope() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "azure_entra",
                "tenant_id": "tid",
                "client_id": "${env:AZ_CID}",
                "client_secret": "${file:/run/az_cs}",
                "scope": "https://management.azure.com/.default",
            }
        )
    )
    assert isinstance(c.target.auth, AzureEntraAuth)
    assert c.target.auth.client_secret is not None
    assert c.target.auth.client_secret.backend == "file"
    assert c.target.auth.scope == "https://management.azure.com/.default"


def test_auth_gcp_adc_has_no_secrets() -> None:
    c = Contract.model_validate(_base_data(auth={"kind": "gcp_adc"}))
    assert isinstance(c.target.auth, GcpAdcAuth)
    assert c.target.auth.kind == "gcp_adc"


def test_auth_gcp_sa_json_minimal() -> None:
    c = Contract.model_validate(
        _base_data(auth={"kind": "gcp_sa_json", "service_account_json": "${file:/run/sa.json}"})
    )
    assert isinstance(c.target.auth, GcpSaJsonAuth)
    assert c.target.auth.service_account_json.backend == "file"
    assert c.target.auth.scopes == []


def test_auth_gcp_sa_json_with_scopes() -> None:
    c = Contract.model_validate(
        _base_data(
            auth={
                "kind": "gcp_sa_json",
                "service_account_json": "${env:GCP_SA}",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            }
        )
    )
    assert isinstance(c.target.auth, GcpSaJsonAuth)
    assert c.target.auth.scopes == ["https://www.googleapis.com/auth/cloud-platform"]


@pytest.mark.parametrize(
    "auth",
    [
        {"kind": "aws_sigv4", "region": "us-east-1", "regn": "typo"},
        {"kind": "azure_entra", "tenant_id": "t", "client_id": "${env:K}", "tenent": "typo"},
        {"kind": "gcp_adc", "junk": 1},
        {"kind": "gcp_sa_json", "service_account_json": "${env:K}", "scope": "typo"},
    ],
)
def test_cloud_auth_extra_field_forbidden(auth: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(auth=auth))


def test_aws_sigv4_secret_fields_reject_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(auth={"kind": "aws_sigv4", "region": "us-east-1", "access_key_id": _RAW})
        )
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(auth={"kind": "aws_sigv4", "region": "us-east-1", "secret_access_key": _RAW})
        )
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(auth={"kind": "aws_sigv4", "region": "us-east-1", "session_token": _RAW})
        )


def test_azure_entra_secret_fields_reject_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(auth={"kind": "azure_entra", "tenant_id": "t", "client_id": _RAW})
        )
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                auth={
                    "kind": "azure_entra",
                    "tenant_id": "t",
                    "client_id": "${env:CID}",
                    "client_secret": _RAW,
                }
            )
        )


def test_gcp_sa_json_secret_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(auth={"kind": "gcp_sa_json", "service_account_json": _RAW})
        )


# --------------------------------------------------------------------------
# Cloud transport kinds — parse from dict, defaults, extra="forbid"
# --------------------------------------------------------------------------


def test_transport_openai_responses() -> None:
    c = Contract.model_validate(
        _base_data(transport={"kind": "openai_responses", "model": "gpt-4o"})
    )
    assert isinstance(c.target.transport, OpenAiResponsesTransport)
    assert c.target.transport.model == "gpt-4o"
    assert str(c.target.transport.base_url) == "https://api.openai.com/v1"
    assert c.target.transport.store is True


def test_transport_anthropic_messages() -> None:
    c = Contract.model_validate(
        _base_data(
            transport={
                "kind": "anthropic_messages",
                "model": "claude-opus-4",
                "max_tokens": 2048,
            }
        )
    )
    assert isinstance(c.target.transport, AnthropicMessagesTransport)
    assert c.target.transport.max_tokens == 2048
    assert c.target.transport.anthropic_version == "2023-06-01"
    assert str(c.target.transport.base_url) == "https://api.anthropic.com/v1"


def test_transport_anthropic_messages_rejects_non_positive_max_tokens() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(transport={"kind": "anthropic_messages", "model": "claude", "max_tokens": 0})
        )


def test_transport_bedrock_agent() -> None:
    c = Contract.model_validate(
        _base_data(
            transport={
                "kind": "bedrock_agent",
                "region": "us-east-1",
                "agent_id": "AID",
                "agent_alias_id": "ALIAS",
            }
        )
    )
    assert isinstance(c.target.transport, BedrockAgentTransport)
    assert c.target.transport.agent_id == "AID"
    assert c.target.transport.enable_trace is True


def test_transport_vertex_agent() -> None:
    c = Contract.model_validate(
        _base_data(
            transport={
                "kind": "vertex_agent",
                "project": "proj",
                "location": "us-central1",
                "reasoning_engine_id": "RE-1",
            }
        )
    )
    assert isinstance(c.target.transport, VertexAgentTransport)
    assert c.target.transport.reasoning_engine_id == "RE-1"


def test_transport_azure_foundry_agent() -> None:
    c = Contract.model_validate(
        _base_data(
            transport={
                "kind": "azure_foundry_agent",
                "endpoint": "https://foundry.example.com",
                "agent_id": "agt-1",
            }
        )
    )
    assert isinstance(c.target.transport, AzureFoundryAgentTransport)
    assert c.target.transport.agent_id == "agt-1"
    assert str(c.target.transport.endpoint).startswith("https://foundry.example.com")


@pytest.mark.parametrize(
    "transport",
    [
        {"kind": "openai_responses", "model": "gpt-4o", "stor": True},
        {"kind": "anthropic_messages", "model": "claude", "maxtokens": 1},
        {"kind": "bedrock_agent", "region": "r", "agent_id": "a", "agent_alias_id": "x", "j": 1},
        {
            "kind": "vertex_agent",
            "project": "p",
            "location": "l",
            "reasoning_engine_id": "r",
            "z": 1,
        },
        {"kind": "azure_foundry_agent", "endpoint": "https://x.example", "agent_id": "a", "k": 1},
    ],
)
def test_cloud_transport_extra_field_forbidden(transport: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(transport=transport))


def test_cloud_transport_missing_required_field_rejected() -> None:
    # openai_responses requires ``model``
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(transport={"kind": "openai_responses"}))
    # bedrock_agent requires agent_id / agent_alias_id
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(transport={"kind": "bedrock_agent", "region": "r"}))


# --------------------------------------------------------------------------
# SecretRef raw-literal rejection on EACH secret field
# --------------------------------------------------------------------------

_RAW = "sk-ant-rawtoken-do-not-do-this-1234567890"


def test_api_key_value_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(auth={"kind": "api_key", "value": _RAW}))


def test_bearer_token_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(auth={"kind": "bearer", "token": _RAW}))


def test_oauth2_client_id_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                auth={
                    "kind": "oauth2_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id": _RAW,
                    "client_secret": "${env:CS}",
                }
            )
        )


def test_oauth2_client_secret_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                auth={
                    "kind": "oauth2_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id": "${env:CID}",
                    "client_secret": _RAW,
                }
            )
        )


def test_mtls_cert_and_key_reject_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(auth={"kind": "mtls", "client_cert": _RAW, "client_key": "${file:/k}"})
        )
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(auth={"kind": "mtls", "client_cert": "${file:/c}", "client_key": _RAW})
        )


def test_mtls_ca_bundle_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                auth={
                    "kind": "mtls",
                    "client_cert": "${file:/c}",
                    "client_key": "${file:/k}",
                    "ca_bundle": _RAW,
                }
            )
        )


def test_hmac_secret_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                auth={
                    "kind": "hmac",
                    "header": "X-Sig",
                    "secret": _RAW,
                    "signing_string_template": "{method}",
                }
            )
        )


def test_tls_ca_bundle_rejects_raw_literal() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                transport={
                    "kind": "http",
                    "url": "https://x.example",
                    "tls": {"ca_bundle": _RAW},
                }
            )
        )


def test_tls_ca_bundle_accepts_pointer() -> None:
    c = Contract.model_validate(
        _base_data(
            transport={
                "kind": "http",
                "url": "https://x.example",
                "tls": {"ca_bundle": "${file:/ca.pem}", "insecure": True},
            }
        )
    )
    assert isinstance(c.target.transport.tls, Tls)
    assert c.target.transport.tls.insecure is True


# --------------------------------------------------------------------------
# extra="forbid" + x- passthrough
# --------------------------------------------------------------------------


def test_extra_field_forbidden_on_contract() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate({**_base_data(), "bogus_field": 1})


def test_extra_field_forbidden_on_target() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(junk=1))


def test_extra_field_forbidden_on_transport() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(transport={"kind": "http", "url": "https://x.example", "junk": 1})
        )


def test_extra_field_forbidden_on_auth() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(auth={"kind": "bearer", "token": "${env:K}", "junk": 1}))


def test_extra_field_forbidden_on_roe() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate({**_base_data(), "roe": {"junk": 1}})


def test_x_prefixed_keys_pass_through_to_extensions() -> None:
    c = Contract.model_validate({**_base_data(), "x-team": "redteam", "x-ticket": "SEC-9"})
    assert c.extensions == {"x-team": "redteam", "x-ticket": "SEC-9"}


def test_x_prefixed_merges_with_explicit_extensions() -> None:
    c = Contract.model_validate({**_base_data(), "x-team": "a", "extensions": {"x-existing": "b"}})
    assert c.extensions == {"x-existing": "b", "x-team": "a"}


def test_before_collector_passes_non_dict_through() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(["not", "a", "mapping"])


# --------------------------------------------------------------------------
# Jinja request.body — validated, not rendered
# --------------------------------------------------------------------------


@pytest.mark.parametrize("var", sorted(ALLOWED_TEMPLATE_VARS))
def test_allowed_template_vars_accepted(var: str) -> None:
    c = Contract.model_validate(_base_data(request={"body": "{{ " + var + " }}"}))
    assert isinstance(c.target.request, Request)


def test_disallowed_template_var_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        Contract.model_validate(_base_data(request={"body": "{{ secret_env_var }}"}))
    assert "disallowed variable" in str(exc.value)


def test_malformed_template_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        Contract.model_validate(_base_data(request={"body": "{{ prompt "}))
    assert "valid Jinja2" in str(exc.value)


def test_template_with_loop_over_tool_results_ok() -> None:
    tmpl = "{% for r in tool_results %}{{ r }}{% endfor %}{{ conversation }}"
    c = Contract.model_validate(_base_data(request={"body": tmpl}))
    assert isinstance(c.target.request, Request)


def test_request_can_be_omitted() -> None:
    c = Contract.model_validate(_base_data())
    assert c.target.request.body == '{"input": "{{ prompt }}"}'


# --------------------------------------------------------------------------
# JSONPath fields — must start with $
# --------------------------------------------------------------------------


def test_output_path_required() -> None:
    data = _base_data()
    del data["target"]["response"]
    with pytest.raises(ValidationError):
        Contract.model_validate(data)


def test_output_path_must_start_with_dollar() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(response={"output_path": "output.text"}))


def test_tool_call_path_must_start_with_dollar() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(response={"output_path": "$.a", "tool_call_path": "no-dollar"})
        )


def test_response_error_path_must_start_with_dollar() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(response={"output_path": "$.a", "error": {"error_path": "no-dollar"}})
        )


def test_response_error_defaults() -> None:
    c = Contract.model_validate(_base_data())
    assert isinstance(c.target.response, Response)
    assert c.target.response.error.status_success == [200, 201]
    assert c.target.response.error.error_path is None
    assert c.target.response.tool_call_path is None
    assert c.target.response.stream is None


def test_response_optional_paths_accept_explicit_none() -> None:
    # Explicit None must pass through the JSONPath validator unchanged.
    c = Contract.model_validate(
        _base_data(
            response={
                "output_path": "$.a",
                "tool_call_path": None,
                "error": {"error_path": None},
            }
        )
    )
    assert c.target.response.tool_call_path is None
    assert c.target.response.error.error_path is None


def test_response_paths_accept_explicit_values() -> None:
    c = Contract.model_validate(
        _base_data(
            response={
                "output_path": "$.data.reply",
                "tool_call_path": "$.data.tool_calls[0]",
                "error": {"status_success": [200, 202], "error_path": "$.err"},
            }
        )
    )
    assert c.target.response.tool_call_path == "$.data.tool_calls[0]"
    assert c.target.response.error.error_path == "$.err"


def test_stream_valid() -> None:
    c = Contract.model_validate(
        _base_data(
            response={
                "output_path": "$.a",
                "stream": {"format": "sse", "delta_path": "$.delta", "done_signal": "[DONE]"},
            }
        )
    )
    assert isinstance(c.target.response.stream, Stream)
    assert c.target.response.stream.format == "sse"


def test_stream_delta_path_must_start_with_dollar() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                response={
                    "output_path": "$.a",
                    "stream": {"format": "sse", "delta_path": "delta"},
                }
            )
        )


def test_stream_format_literal_enforced() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(
                response={
                    "output_path": "$.a",
                    "stream": {"format": "grpc", "delta_path": "$.delta"},
                }
            )
        )


# --------------------------------------------------------------------------
# Session / Identity / Tools
# --------------------------------------------------------------------------


def test_session_id_send_alias() -> None:
    c = Contract.model_validate(
        _base_data(
            session={
                "mode": "server_session",
                "id_send": {"in": "header", "name": "X-Session"},
            }
        )
    )
    assert isinstance(c.target.session.id_send, IdSend)
    assert c.target.session.id_send.in_ == "header"


def test_session_mode_literal_enforced() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(session={"mode": "magic"}))


def test_identity_block() -> None:
    c = Contract.model_validate(
        _base_data(identity={"user_id": "u1", "jit_credentials": True, "tenant": "t1"})
    )
    assert c.target.identity is not None
    assert c.target.identity.jit_credentials is True


def test_tools_block() -> None:
    c = Contract.model_validate(
        _base_data(
            tools={
                "discovery": "openapi",
                "expected": [{"name": "search"}, {"name": "fetch"}],
            }
        )
    )
    assert isinstance(c.target.tools, Tools)
    assert [t.name for t in c.target.tools.expected] == ["search", "fetch"]


def test_tools_discovery_literal_enforced() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(tools={"discovery": "graphql"}))


# --------------------------------------------------------------------------
# RoE constraints
# --------------------------------------------------------------------------


def test_budgets_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate({**_base_data(), "roe": {"budgets": {"max_tokens": 0}}})


def test_rate_max_rps_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate({**_base_data(), "roe": {"rate": {"max_rps": 0}}})


def test_retry_max_attempts_min_one() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate({**_base_data(), "roe": {"rate": {"retry": {"max_attempts": 0}}}})


def test_roe_full_block() -> None:
    c = Contract.model_validate(
        {
            **_base_data(),
            "roe": {
                "authorization_ref": "JIRA-1",
                "budgets": {"max_tokens": 100, "max_requests": 10},
                "rate": {
                    "max_rps": 2.5,
                    "parallel_workers": 3,
                    "retry": {"max_attempts": 5, "backoff": "linear"},
                    "idempotency_key_header": "X-Idem",
                },
                "tools": {"allowlist": ["a"], "blocklist": ["b"]},
                "do_not_test_windows": ["sat", "sun"],
                "data_egress": {"allow_external": True},
                "network": {"proxy": "http://p:3128"},
            },
        }
    )
    assert c.roe.rate.retry == Retry(max_attempts=5, backoff="linear")
    assert c.roe.tools is not None
    assert c.roe.data_egress.allow_external is True
    assert c.roe.network is not None
    assert c.roe.do_not_test_windows == ["sat", "sun"]


# --------------------------------------------------------------------------
# Observability
# --------------------------------------------------------------------------


def test_observability_block() -> None:
    c = Contract.model_validate(
        {
            **_base_data(),
            "observability": {"otel_endpoint": "http://otel:4317", "webhook": "http://w"},
        }
    )
    assert c.observability is not None
    assert c.observability.otel_endpoint == "http://otel:4317"


# --------------------------------------------------------------------------
# prod-requires roe.authorization_ref
# --------------------------------------------------------------------------


def test_prod_without_authorization_ref_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        Contract.model_validate(_base_data(environment="prod"))
    assert "authorization_ref" in str(exc.value)


def test_prod_with_blank_authorization_ref_rejected() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            {**_base_data(environment="prod"), "roe": {"authorization_ref": "   "}}
        )


def test_prod_with_authorization_ref_ok() -> None:
    c = Contract.model_validate(
        {**_base_data(environment="prod"), "roe": {"authorization_ref": "JIRA-1"}}
    )
    assert c.target.environment == "prod"
    assert c.roe.authorization_ref == "JIRA-1"


def test_staging_without_authorization_ref_ok() -> None:
    c = Contract.model_validate(_base_data(environment="staging"))
    assert c.roe.authorization_ref is None


# --------------------------------------------------------------------------
# misc constraints
# --------------------------------------------------------------------------


def test_empty_name_rejected() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(_base_data(name=""))


def test_non_positive_timeout_rejected() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _base_data(transport={"kind": "http", "url": "https://x.example", "timeout_ms": 0})
        )


def test_secret_ref_string_round_trips() -> None:
    c = Contract.model_validate(_base_data(auth={"kind": "bearer", "token": "${env:K}"}))
    assert isinstance(c.target.auth, BearerAuth)
    assert c.target.auth.token == SecretRef("${env:K}")
    assert str(c.target.auth.token) == "${env:K}"
