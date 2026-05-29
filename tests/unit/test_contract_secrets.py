"""Unit tests for contract secret references + resolution (Stage 1)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import httpx
import pytest
import respx

from agent_guardian.contract.errors import SecretResolutionError
from agent_guardian.contract.schema import Contract
from agent_guardian.contract.secrets import (
    ALL_BACKENDS,
    DEFAULT_BACKENDS,
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
# backend allowlist (vault / sops are opt-in)
# --------------------------------------------------------------------------


def test_default_backends_are_env_and_file() -> None:
    assert DEFAULT_BACKENDS == ("env", "file")
    assert set(ALL_BACKENDS) == {"env", "file", "vault", "sops"}


@pytest.mark.parametrize("backend", ["vault", "sops"])
def test_optin_backend_disabled_by_default_is_loud(backend: str) -> None:
    # The default resolver only enables env + file; a vault/sops ref must fail
    # loudly rather than silently reaching out to infrastructure.
    ref = SecretRef(f"${{{backend}:path/to/secret#field}}")
    with pytest.raises(SecretResolutionError, match="is not enabled"):
        resolve_secret(ref)


def test_disabling_env_backend_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AG_X", "v")
    resolver = SecretResolver(backends=("file",))
    with pytest.raises(SecretResolutionError, match="is not enabled"):
        resolver.resolve(SecretRef("${env:AG_X}"))


# --------------------------------------------------------------------------
# vault backend (KV v2 + KV v1, error shapes)
# --------------------------------------------------------------------------


def _vault_resolver(**kw: object) -> SecretResolver:
    return SecretResolver(
        backends=("env", "file", "vault"),
        vault_addr="https://vault.example:8200",
        vault_token="s.testtoken",
        **kw,  # type: ignore[arg-type]
    )


@respx.mock
def test_vault_kv_v2_shape() -> None:
    # KV v2 nests the secret fields under data.data.
    respx.get("https://vault.example:8200/v1/secret/data/acme").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"data": {"api_key": "kv2-secret"}, "metadata": {"version": 3}}},
        )
    )
    resolver = _vault_resolver()
    assert resolver.resolve(SecretRef("${vault:secret/data/acme#api_key}")) == "kv2-secret"


@respx.mock
def test_vault_kv_v1_fallback_shape() -> None:
    # KV v1 puts fields directly under data.
    respx.get("https://vault.example:8200/v1/kv/acme").mock(
        return_value=httpx.Response(200, json={"data": {"token": "kv1-secret"}})
    )
    resolver = _vault_resolver()
    assert resolver.resolve(SecretRef("${vault:kv/acme#token}")) == "kv1-secret"


@respx.mock
def test_vault_leading_slash_in_path_is_normalised() -> None:
    respx.get("https://vault.example:8200/v1/secret/data/x").mock(
        return_value=httpx.Response(200, json={"data": {"data": {"f": "ok"}}})
    )
    resolver = _vault_resolver()
    assert resolver.resolve(SecretRef("${vault:/secret/data/x#f}")) == "ok"


def test_vault_missing_addr_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    resolver = SecretResolver(backends=("vault",), vault_token="s.tok")
    with pytest.raises(SecretResolutionError, match="VAULT_ADDR"):
        resolver.resolve(SecretRef("${vault:secret/data/x#f}"))


def test_vault_missing_token_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    resolver = SecretResolver(backends=("vault",), vault_addr="https://v.example")
    with pytest.raises(SecretResolutionError, match="VAULT_TOKEN"):
        resolver.resolve(SecretRef("${vault:secret/data/x#f}"))


def test_vault_addr_token_fall_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://env-vault.example")
    monkeypatch.setenv("VAULT_TOKEN", "s.fromenv")
    with respx.mock:
        route = respx.get("https://env-vault.example/v1/secret/data/x").mock(
            return_value=httpx.Response(200, json={"data": {"data": {"f": "v"}}})
        )
        resolver = SecretResolver(backends=("vault",))
        assert resolver.resolve(SecretRef("${vault:secret/data/x#f}")) == "v"
    assert route.calls.last.request.headers["X-Vault-Token"] == "s.fromenv"


@pytest.mark.parametrize("bad", ["secret/data/x", "#f", "secret/data/x#"])
def test_vault_malformed_ref_is_loud(bad: str) -> None:
    resolver = _vault_resolver()
    with pytest.raises(SecretResolutionError, match="secret/path#field"):
        resolver.resolve(SecretRef(f"${{vault:{bad}}}"))


@respx.mock
def test_vault_missing_field_is_loud() -> None:
    respx.get("https://vault.example:8200/v1/secret/data/x").mock(
        return_value=httpx.Response(200, json={"data": {"data": {"other": "v"}}})
    )
    resolver = _vault_resolver()
    with pytest.raises(SecretResolutionError, match="no field 'api_key'"):
        resolver.resolve(SecretRef("${vault:secret/data/x#api_key}"))


@respx.mock
def test_vault_unexpected_shape_is_loud() -> None:
    respx.get("https://vault.example:8200/v1/secret/data/x").mock(
        return_value=httpx.Response(200, json={"not_data": {}})
    )
    resolver = _vault_resolver()
    with pytest.raises(SecretResolutionError, match="unexpected shape"):
        resolver.resolve(SecretRef("${vault:secret/data/x#f}"))


@respx.mock
def test_vault_http_error_is_loud() -> None:
    respx.get("https://vault.example:8200/v1/secret/data/x").mock(
        return_value=httpx.Response(403, json={"errors": ["permission denied"]})
    )
    resolver = _vault_resolver()
    with pytest.raises(SecretResolutionError, match="could not read vault secret"):
        resolver.resolve(SecretRef("${vault:secret/data/x#f}"))


@respx.mock
def test_vault_connect_error_is_loud() -> None:
    respx.get("https://vault.example:8200/v1/secret/data/x").mock(
        side_effect=httpx.ConnectError("refused")
    )
    resolver = _vault_resolver()
    with pytest.raises(SecretResolutionError, match="could not read vault secret"):
        resolver.resolve(SecretRef("${vault:secret/data/x#f}"))


# --------------------------------------------------------------------------
# sops backend (monkeypatched subprocess)
# --------------------------------------------------------------------------

_SOPS_YAML = "creds:\n  api:\n    key: sops-secret\nflat: top-level\n"


def _sops_file(tmp_path: Path) -> Path:
    f = tmp_path / "enc.yaml"
    f.write_text("placeholder-ciphertext\n", encoding="utf-8")
    return f


def _patch_sops(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: str = _SOPS_YAML,
    returncode: int = 0,
    stderr: str = "",
    raise_fnf: bool = False,
) -> None:
    def _fake_run(argv: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
        if raise_fnf:
            raise FileNotFoundError(argv[0])
        if returncode != 0:
            raise subprocess.CalledProcessError(returncode, argv, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=stderr)

    monkeypatch.setattr("agent_guardian.contract.secrets.subprocess.run", _fake_run)


def test_sops_nested_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sops(monkeypatch)
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    assert resolver.resolve(SecretRef(f"${{sops:{f}#creds.api.key}}")) == "sops-secret"


def test_sops_top_level_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sops(monkeypatch)
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    assert resolver.resolve(SecretRef(f"${{sops:{f}#flat}}")) == "top-level"


def test_sops_relative_to_file_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sops(monkeypatch)
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "enc.yaml").write_text("x\n", encoding="utf-8")
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops", file_root=tmp_path)
    assert resolver.resolve(SecretRef("${sops:secrets/enc.yaml#flat}")) == "top-level"


def test_sops_binary_absent_is_loud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No sops_bin injected and none on PATH -> shutil.which returns None.
    monkeypatch.setattr("agent_guardian.contract.secrets.shutil.which", lambda _name: None)
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",))
    with pytest.raises(SecretResolutionError, match="requires the 'sops' CLI"):
        resolver.resolve(SecretRef(f"${{sops:{f}#flat}}"))


def test_sops_binary_not_executable_is_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_sops(monkeypatch, raise_fnf=True)
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",), sops_bin="/nonexistent/sops")
    with pytest.raises(SecretResolutionError, match="could not be executed"):
        resolver.resolve(SecretRef(f"${{sops:{f}#flat}}"))


def test_sops_decrypt_failure_is_loud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sops(monkeypatch, returncode=1, stderr="no key could decrypt the data")
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    with pytest.raises(SecretResolutionError, match="failed to decrypt"):
        resolver.resolve(SecretRef(f"${{sops:{f}#flat}}"))


def test_sops_missing_file_is_loud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sops(monkeypatch)
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    missing = tmp_path / "nope.yaml"
    with pytest.raises(SecretResolutionError, match="does not exist"):
        resolver.resolve(SecretRef(f"${{sops:{missing}#flat}}"))


@pytest.mark.parametrize("bad", ["enc.yaml", "#flat", "enc.yaml#"])
def test_sops_malformed_ref_is_loud(bad: str) -> None:
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    with pytest.raises(SecretResolutionError, match="dotted key to read"):
        resolver.resolve(SecretRef(f"${{sops:{bad}}}"))


def test_sops_missing_key_is_loud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sops(monkeypatch)
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    with pytest.raises(SecretResolutionError, match="stopped at segment 'missing'"):
        resolver.resolve(SecretRef(f"${{sops:{f}#creds.missing}}"))


def test_sops_structured_value_serialised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A dotted key that lands on a mapping is JSON-serialised rather than
    # str(dict)-leaked.
    _patch_sops(monkeypatch)
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    out = resolver.resolve(SecretRef(f"${{sops:{f}#creds.api}}"))
    assert out == '{"key": "sops-secret"}'


def test_sops_invalid_yaml_output_is_loud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sops(monkeypatch, stdout="key: : : not valid yaml\n  - broken")
    f = _sops_file(tmp_path)
    resolver = SecretResolver(backends=("sops",), sops_bin="/usr/bin/sops")
    with pytest.raises(SecretResolutionError, match="not valid YAML/JSON"):
        resolver.resolve(SecretRef(f"${{sops:{f}#flat}}"))


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
