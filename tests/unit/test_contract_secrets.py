"""Unit tests for contract secret references + resolution (Stage 1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.contract.errors import SecretResolutionError
from agent_guardian.contract.schema import Contract
from agent_guardian.contract.secrets import (
    SecretRef,
    SecretResolver,
    iter_secret_refs,
    redact,
    resolve_secret,
    resolve_secrets,
)
from agent_guardian.logging_setup import _REDACTED

# --------------------------------------------------------------------------
# SecretRef parsing + raw-literal rejection
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "backend", "key"),
    [
        ("${env:ACME_API_KEY}", "env", "ACME_API_KEY"),
        ("${file:/run/secrets/token}", "file", "/run/secrets/token"),
        ("${vault:secret/data/token}", "vault", "secret/data/token"),
        ("${sops:enc/token}", "sops", "enc/token"),
    ],
)
def test_secret_ref_pointer_accepted(raw: str, backend: str, key: str) -> None:
    ref = SecretRef(raw)
    assert ref.backend == backend
    assert ref.key == key
    assert str(ref) == raw


def test_secret_ref_is_str_subclass() -> None:
    ref = SecretRef("${env:K}")
    assert isinstance(ref, str)
    assert ref == "${env:K}"


def test_secret_ref_idempotent_construction() -> None:
    ref = SecretRef("${env:K}")
    assert SecretRef(ref) is ref


@pytest.mark.parametrize(
    "raw",
    [
        "sk-abcdef0123456789",
        "sk-ant-abcdef0123456789",
        "AIzaSyABCDEF0123456789",
        "ghp_abcdef0123456789",
        "xoxb-1234-5678-token",
        "Bearer abcdef.token",
        "AG_API_KEY",  # bare env-var name, not a pointer
        "env:AG_KEY",  # missing ${...}
        "${aws:AG_KEY}",  # unknown backend
        "${env:}",  # empty key
        "prefix ${env:K}",  # not anchored
        "",
    ],
)
def test_secret_ref_rejects_non_pointer(raw: str) -> None:
    with pytest.raises(ValueError):
        SecretRef(raw)


def test_secret_ref_rejects_whitespace_only_key() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        SecretRef("${env:   }")


def test_secret_ref_rejects_non_string() -> None:
    with pytest.raises(ValueError, match="must be a string"):
        SecretRef(123)  # type: ignore[arg-type]


def test_secret_ref_strips_surrounding_whitespace() -> None:
    ref = SecretRef("  ${env:K}  ")
    assert str(ref) == "${env:K}"
    assert ref.key == "K"


# --------------------------------------------------------------------------
# env backend
# --------------------------------------------------------------------------


def test_resolve_env_via_monkeypatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AG_TEST_SECRET", "s3cr3t")
    assert resolve_secret(SecretRef("${env:AG_TEST_SECRET}")) == "s3cr3t"


def test_resolve_env_injected_dict() -> None:
    resolver = SecretResolver(env={"K": "value"})
    assert resolver.resolve(SecretRef("${env:K}")) == "value"


def test_resolve_env_missing_is_loud() -> None:
    resolver = SecretResolver(env={})
    with pytest.raises(SecretResolutionError, match="is not set"):
        resolver.resolve(SecretRef("${env:DEFINITELY_NOT_SET_AG_XYZ}"))


# --------------------------------------------------------------------------
# file backend
# --------------------------------------------------------------------------


def test_resolve_file_absolute(tmp_path: Path) -> None:
    secret_file = tmp_path / "token.txt"
    secret_file.write_text("file-secret\n", encoding="utf-8")
    assert resolve_secret(SecretRef(f"${{file:{secret_file}}}")) == "file-secret"


def test_resolve_file_relative_to_root(tmp_path: Path) -> None:
    (tmp_path / "creds").mkdir()
    (tmp_path / "creds" / "k").write_text("  relrooted  ", encoding="utf-8")
    resolver = SecretResolver(file_root=tmp_path)
    assert resolver.resolve(SecretRef("${file:creds/k}")) == "relrooted"


def test_resolve_file_missing_is_loud(tmp_path: Path) -> None:
    ref = SecretRef(f"${{file:{tmp_path / 'nope.txt'}}}")
    with pytest.raises(SecretResolutionError, match="does not exist"):
        resolve_secret(ref)


# --------------------------------------------------------------------------
# reserved backends
# --------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["vault", "sops"])
def test_reserved_backend_not_implemented(backend: str) -> None:
    ref = SecretRef(f"${{{backend}:path/to/secret}}")
    with pytest.raises(NotImplementedError):
        resolve_secret(ref)


# --------------------------------------------------------------------------
# iter_secret_refs + resolve_secrets across the nested tree
# --------------------------------------------------------------------------


def _contract_with_secrets() -> Contract:
    return Contract.model_validate(
        {
            "version": 1,
            "target": {
                "name": "demo",
                "environment": "staging",
                "transport": {
                    "kind": "http",
                    "url": "https://x.example",
                    "tls": {"ca_bundle": "${file:/etc/ca.pem}"},
                },
                "auth": {
                    "kind": "oauth2_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id": "${env:CID}",
                    "client_secret": "${env:CSEC}",
                },
                "response": {"output_path": "$.out"},
            },
        }
    )


def test_iter_secret_refs_finds_all_nested() -> None:
    refs = iter_secret_refs(_contract_with_secrets())
    keys = sorted(r.key for r in refs)
    assert keys == ["/etc/ca.pem", "CID", "CSEC"]


def test_resolve_secrets_across_tree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("CA-CONTENT\n", encoding="utf-8")
    monkeypatch.setenv("CID", "client-id-value")
    monkeypatch.setenv("CSEC", "client-secret-value")
    contract = Contract.model_validate(
        {
            "version": 1,
            "target": {
                "name": "demo",
                "environment": "staging",
                "transport": {
                    "kind": "http",
                    "url": "https://x.example",
                    "tls": {"ca_bundle": f"${{file:{ca}}}"},
                },
                "auth": {
                    "kind": "oauth2_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id": "${env:CID}",
                    "client_secret": "${env:CSEC}",
                },
                "response": {"output_path": "$.out"},
            },
        }
    )
    resolved = resolve_secrets(contract)
    by_key = {ref.key: val for ref, val in resolved.items()}
    assert by_key == {
        "CID": "client-id-value",
        "CSEC": "client-secret-value",
        str(ca): "CA-CONTENT",
    }


def test_resolve_secrets_missing_key_is_loud() -> None:
    contract = _contract_with_secrets()
    resolver = SecretResolver(env={})
    with pytest.raises(SecretResolutionError):
        resolve_secrets(contract, resolver=resolver)


def test_iter_secret_refs_empty_when_no_auth() -> None:
    contract = Contract.model_validate(
        {
            "version": 1,
            "target": {
                "name": "demo",
                "environment": "staging",
                "transport": {"kind": "http", "url": "https://x.example"},
                "response": {"output_path": "$.out"},
            },
        }
    )
    assert iter_secret_refs(contract) == []


def test_iter_secret_refs_walks_plain_dict_and_list() -> None:
    payload = {
        "nested": {"ref": SecretRef("${env:A}")},
        "items": [SecretRef("${file:/b}"), "plain", 7],
    }
    keys = sorted(r.key for r in iter_secret_refs(payload))
    assert keys == ["/b", "A"]


# --------------------------------------------------------------------------
# redact()
# --------------------------------------------------------------------------


def test_redact_masks_secret_ref() -> None:
    out = redact(SecretRef("${env:ACME_API_KEY}"))
    assert out == f"${{env:{_REDACTED}}}"
    assert "ACME_API_KEY" not in out


def test_redact_preserves_backend_shape() -> None:
    assert redact(SecretRef("${env:K}")) != redact(SecretRef("${file:/k}"))


def test_redact_scrubs_strings() -> None:
    out = redact("https://x/?key=AIzaSyABCDEFGHIJKLMNOP")
    assert _REDACTED in out
    assert "AIza" not in out


def test_redact_walks_containers() -> None:
    payload = {
        "ref": SecretRef("${env:K}"),
        "items": [SecretRef("${file:/tmp/x}"), "plain"],
        "n": 7,
        "flag": True,
        "nothing": None,
    }
    out = redact(payload)
    assert _REDACTED in out["ref"]
    assert _REDACTED in out["items"][0]
    assert out["items"][1] == "plain"
    assert out["n"] == 7
    assert out["flag"] is True
    assert out["nothing"] is None


def test_redact_walks_models() -> None:
    contract = _contract_with_secrets()
    out = redact(contract)
    # Every secret in the rendered view is masked.
    auth = out["target"]["auth"]
    assert _REDACTED in auth["client_id"]
    assert _REDACTED in auth["client_secret"]
    assert _REDACTED in out["target"]["transport"]["tls"]["ca_bundle"]


def test_redact_normalises_non_json_scalar() -> None:
    from pydantic import AnyUrl

    out = redact(AnyUrl("https://example.com/path"))
    assert isinstance(out, str)
    assert out.startswith("https://example.com")
