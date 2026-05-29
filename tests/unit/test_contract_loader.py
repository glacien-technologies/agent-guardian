"""Unit tests for contract loading + discovery + version gate (Stage 1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from agent_guardian.contract.errors import (
    ContractValidationError,
    MigrationNeeded,
    UnsupportedContractVersion,
)
from agent_guardian.contract.loader import (
    CONTRACT_FILENAME,
    discover_contract_path,
    load_contract,
    load_contract_file,
    parse_contract,
)
from agent_guardian.contract.schema import (
    ApiKeyAuth,
    BearerAuth,
    Contract,
    HmacAuth,
    MtlsAuth,
    OAuth2ClientCredentialsAuth,
)

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "contracts"


def _base_data(**target_overrides: Any) -> dict[str, Any]:
    target: dict[str, Any] = {
        "name": "demo",
        "environment": "staging",
        "transport": {"kind": "http", "url": "https://api.example.com/chat"},
        "response": {"output_path": "$.output.text"},
    }
    target.update(target_overrides)
    return {"version": 1, "target": target}


# --------------------------------------------------------------------------
# Golden fixtures — full round-trip loads
# --------------------------------------------------------------------------


def test_load_golden_valid_http_api_key() -> None:
    c = load_contract_file(GOLDEN / "valid_http_api_key.yaml")
    assert isinstance(c, Contract)
    assert c.target.name == "acme-chat-gateway"
    assert c.target.environment == "staging"
    assert isinstance(c.target.auth, ApiKeyAuth)
    assert c.target.auth.value.backend == "env"
    assert c.target.auth.value.key == "AG_KEY"
    assert c.target.response.output_path == "$.choices[0].message.content"
    assert c.target.session.mode == "server_session"
    assert c.roe.budgets.max_tokens == 100000
    assert c.roe.rate.max_rps == 5.0
    assert c.observability is not None
    assert c.extensions == {"x-team": "redteam", "x-ticket": "SEC-1234"}


def test_load_golden_oauth2() -> None:
    c = load_contract_file(GOLDEN / "valid_http_oauth2.yaml")
    assert isinstance(c.target.auth, OAuth2ClientCredentialsAuth)
    assert c.target.auth.client_id.key == "ACME_CLIENT_ID"
    assert c.target.auth.client_secret.backend == "file"


def test_load_golden_mtls() -> None:
    c = load_contract_file(GOLDEN / "valid_http_mtls.yaml")
    assert isinstance(c.target.auth, MtlsAuth)
    assert c.target.environment == "clone"
    assert c.target.transport.tls is not None
    assert c.target.response.stream is not None
    assert c.target.response.stream.format == "sse"


def test_load_golden_hmac() -> None:
    c = load_contract_file(GOLDEN / "valid_http_hmac.yaml")
    assert isinstance(c.target.auth, HmacAuth)
    assert c.target.auth.header == "X-Signature"
    assert c.target.tools is not None
    assert [t.name for t in c.target.tools.expected] == ["search", "fetch"]
    assert c.roe.authorization_ref == "JIRA-9001"


def test_load_golden_prod_without_authorization_ref_rejected() -> None:
    with pytest.raises(ContractValidationError, match="authorization_ref"):
        load_contract_file(GOLDEN / "prod_without_authorization_ref.yaml")


def test_load_golden_v2_migration_needed() -> None:
    with pytest.raises(MigrationNeeded):
        load_contract_file(GOLDEN / "v2_migration_needed.yaml")


def test_load_golden_wrong_secret_raw_literal_rejected() -> None:
    with pytest.raises(ContractValidationError):
        load_contract_file(GOLDEN / "wrong_secret_raw_literal.yaml")


# --------------------------------------------------------------------------
# Version gate is FIRST (before model validation)
# --------------------------------------------------------------------------


def test_version_gate_runs_before_model_validation() -> None:
    # Document is structurally broken (missing target) but declares v2: the
    # version gate must fire FIRST with MigrationNeeded, not a validation error.
    with pytest.raises(MigrationNeeded):
        parse_contract({"version": 2})


def test_v2_migration_needed() -> None:
    with pytest.raises(MigrationNeeded) as exc:
        parse_contract({**_base_data(), "version": 2})
    assert exc.value.found == 2
    assert exc.value.target == 1


def test_v99_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion) as exc:
        parse_contract({**_base_data(), "version": 99})
    assert exc.value.found == 99


def test_version_zero_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        parse_contract({**_base_data(), "version": 0})


def test_non_int_version_unsupported() -> None:
    with pytest.raises(UnsupportedContractVersion):
        parse_contract({**_base_data(), "version": "1"})


def test_bool_version_unsupported() -> None:
    # bool is an int subclass — must not sneak through as version 1.
    with pytest.raises(UnsupportedContractVersion):
        parse_contract({**_base_data(), "version": True})


def test_default_version_is_current() -> None:
    data = _base_data()
    c = parse_contract(data)
    assert c.version == 1


# --------------------------------------------------------------------------
# parse_contract validation wrapping
# --------------------------------------------------------------------------


def test_parse_invalid_wrapped_as_contract_validation_error() -> None:
    with pytest.raises(ContractValidationError):
        parse_contract(_base_data(name=""))


def test_parse_valid_bearer() -> None:
    c = parse_contract(_base_data(auth={"kind": "bearer", "token": "${env:K}"}))
    assert isinstance(c.target.auth, BearerAuth)


# --------------------------------------------------------------------------
# _read_yaml behaviour (via file)
# --------------------------------------------------------------------------


def test_load_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(ContractValidationError, match="not found"):
        load_contract_file(tmp_path / "missing.yaml")


def test_empty_yaml_file_fails_validation(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text("", encoding="utf-8")
    # Empty doc -> {} -> default version 1 passes the gate, then model
    # validation fails on the missing required fields.
    with pytest.raises(ContractValidationError):
        load_contract_file(p)


def test_non_mapping_yaml_rejected(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ContractValidationError, match="mapping"):
        load_contract_file(p)


def test_comment_only_yaml_is_empty_then_fails_validation(tmp_path: Path) -> None:
    # A document that parses to None (only comments) -> {} -> default version
    # passes the gate, then validation fails on the missing required fields.
    p = tmp_path / CONTRACT_FILENAME
    p.write_text("# just a comment\n", encoding="utf-8")
    with pytest.raises(ContractValidationError):
        load_contract_file(p)


def test_malformed_yaml_rejected(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text("key: : : broken\n  - bad\n", encoding="utf-8")
    with pytest.raises(ContractValidationError, match="could not read"):
        load_contract_file(p)


def test_model_validate_rejects_non_mapping() -> None:
    # The before-collector passes non-dict input straight through; Pydantic then
    # rejects it as not a valid Contract.
    with pytest.raises(ValidationError):
        Contract.model_validate(["not", "a", "mapping"])


# --------------------------------------------------------------------------
# discovery (cwd/agentguardian.yaml ONLY)
# --------------------------------------------------------------------------


def test_discover_explicit_wins(tmp_path: Path) -> None:
    explicit = tmp_path / "somewhere.yaml"
    assert discover_contract_path(explicit) == explicit


def test_discover_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    candidate = tmp_path / CONTRACT_FILENAME
    candidate.write_text("x: 1\n", encoding="utf-8")
    assert discover_contract_path() == candidate


def test_discover_none_when_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert discover_contract_path() is None


def test_discover_ignores_dotfile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The CLI config dotfile must NOT be picked up as a contract.
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".agentguardian.yaml").write_text("x: 1\n", encoding="utf-8")
    assert discover_contract_path() is None


def test_load_contract_no_file_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ContractValidationError, match="no contract found"):
        load_contract()


def test_load_contract_via_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / CONTRACT_FILENAME).write_text(yaml.safe_dump(_base_data()), encoding="utf-8")
    c = load_contract()
    assert c.target.name == "demo"
