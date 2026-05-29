"""Unit tests for the contract content hash (Stage 1)."""

from __future__ import annotations

from typing import Any

import pytest

from agent_guardian.contract.hashing import contract_hash_input, contract_sha256
from agent_guardian.contract.schema import Contract


def _contract(**target_overrides: Any) -> Contract:
    target: dict[str, Any] = {
        "name": "demo",
        "environment": "staging",
        "transport": {"kind": "http", "url": "https://api.example.com/chat"},
        "auth": {"kind": "api_key", "value": "${env:MY_KEY}"},
        "response": {"output_path": "$.output.text"},
    }
    target.update(target_overrides)
    return Contract.model_validate({"version": 1, "target": target})


def test_hash_is_hex_sha256() -> None:
    h = contract_sha256(_contract())
    assert len(h) == 64
    assert all(ch in "0123456789abcdef" for ch in h)


def test_hash_stable_across_runs() -> None:
    assert contract_sha256(_contract()) == contract_sha256(_contract())


def test_hash_invariant_to_resolved_secret_value(monkeypatch: pytest.MonkeyPatch) -> None:
    # The contract points at env var MY_KEY. Whatever concrete value the env
    # holds must NOT influence the hash (secrets are redacted before hashing).
    c = _contract()
    monkeypatch.setenv("MY_KEY", "value-one")
    h1 = contract_sha256(c)
    monkeypatch.setenv("MY_KEY", "value-two-totally-different")
    h2 = contract_sha256(c)
    assert h1 == h2


def test_hash_invariant_to_secret_key_name() -> None:
    # Two contracts that differ ONLY in the secret-ref key name still hash the
    # same, because the key is redacted in the hash input.
    a = _contract(auth={"kind": "api_key", "value": "${env:KEY_A}"})
    b = _contract(auth={"kind": "api_key", "value": "${env:KEY_B}"})
    assert contract_sha256(a) == contract_sha256(b)


def test_hash_sensitive_to_backend_change() -> None:
    # The reference *shape* (backend) is preserved, so changing it changes hash.
    a = _contract(auth={"kind": "api_key", "value": "${env:K}"})
    b = _contract(auth={"kind": "api_key", "value": "${file:/k}"})
    assert contract_sha256(a) != contract_sha256(b)


def test_hash_changes_on_name_change() -> None:
    assert contract_sha256(_contract(name="a")) != contract_sha256(_contract(name="b"))


def test_hash_changes_on_transport_change() -> None:
    a = _contract()
    b = _contract(transport={"kind": "http", "url": "https://OTHER.example.com/chat"})
    assert contract_sha256(a) != contract_sha256(b)


def test_hash_changes_on_environment_change() -> None:
    a = _contract(environment="staging")
    b = Contract.model_validate(
        {
            "version": 1,
            "target": {
                "name": "demo",
                "environment": "prod",
                "transport": {"kind": "http", "url": "https://api.example.com/chat"},
                "auth": {"kind": "api_key", "value": "${env:MY_KEY}"},
                "response": {"output_path": "$.output.text"},
            },
            "roe": {"authorization_ref": "JIRA-1"},
        }
    )
    assert contract_sha256(a) != contract_sha256(b)


def test_hash_changes_on_roe_change() -> None:
    a = Contract.model_validate(
        {
            "version": 1,
            "target": {
                "name": "demo",
                "environment": "staging",
                "transport": {"kind": "http", "url": "https://api.example.com/chat"},
                "response": {"output_path": "$.output.text"},
            },
            "roe": {"budgets": {"max_tokens": 100}},
        }
    )
    b = Contract.model_validate(
        {
            "version": 1,
            "target": {
                "name": "demo",
                "environment": "staging",
                "transport": {"kind": "http", "url": "https://api.example.com/chat"},
                "response": {"output_path": "$.output.text"},
            },
            "roe": {"budgets": {"max_tokens": 200}},
        }
    )
    assert contract_sha256(a) != contract_sha256(b)


def test_hash_input_is_redacted_bytes() -> None:
    raw = contract_hash_input(_contract())
    assert isinstance(raw, bytes)
    # The env var name must NOT appear in the canonical hash input (redacted).
    assert b"MY_KEY" not in raw
    assert b"REDACTED" in raw
