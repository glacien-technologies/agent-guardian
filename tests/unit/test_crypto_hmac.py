"""HMAC-SHA256 signer / verifier tests (M13)."""

from __future__ import annotations

import base64

import pytest

from agent_guardian.crypto.hmac_sig import (
    DEFAULT_PBKDF2_ITERATIONS,
    HMAC_ALGORITHM,
    SIGNATURE_VERSION,
    derive_key,
    sign_hmac,
    verify_hmac,
)


def test_sign_hmac_returns_well_formed_block() -> None:
    block = sign_hmac(b"hello", secret="topsecret")
    assert block["algorithm"] == HMAC_ALGORITHM
    assert block["version"] == SIGNATURE_VERSION
    assert block["iterations"] == DEFAULT_PBKDF2_ITERATIONS
    assert isinstance(block["salt"], str)
    assert isinstance(block["signature"], str)
    # Both base64-encoded.
    base64.b64decode(block["salt"])
    base64.b64decode(block["signature"])


def test_sign_then_verify_roundtrips() -> None:
    payload = b'{"hello":"world"}'
    block = sign_hmac(payload, secret="abc")
    assert verify_hmac(payload, block, secret="abc") is True


def test_verify_tampered_payload_returns_false() -> None:
    payload = b'{"hello":"world"}'
    block = sign_hmac(payload, secret="abc")
    assert verify_hmac(payload + b"!", block, secret="abc") is False


def test_verify_wrong_secret_returns_false() -> None:
    block = sign_hmac(b"x", secret="abc")
    assert verify_hmac(b"x", block, secret="def") is False


def test_sign_uses_fresh_salt_per_call() -> None:
    b1 = sign_hmac(b"x", secret="abc")
    b2 = sign_hmac(b"x", secret="abc")
    # Salts must differ — randomness sanity check.
    assert b1["salt"] != b2["salt"]
    # But both verify.
    assert verify_hmac(b"x", b1, secret="abc")
    assert verify_hmac(b"x", b2, secret="abc")


def test_verify_rejects_missing_fields() -> None:
    block = sign_hmac(b"x", secret="abc")
    broken = {k: v for k, v in block.items() if k != "signature"}
    assert verify_hmac(b"x", broken, secret="abc") is False


def test_verify_rejects_unknown_algorithm() -> None:
    block = dict(sign_hmac(b"x", secret="abc"))
    block["algorithm"] = "MD5"
    assert verify_hmac(b"x", block, secret="abc") is False


def test_verify_rejects_unknown_version() -> None:
    block = dict(sign_hmac(b"x", secret="abc"))
    block["version"] = "ag-sig-v0"
    assert verify_hmac(b"x", block, secret="abc") is False


def test_verify_rejects_malformed_base64() -> None:
    block = dict(sign_hmac(b"x", secret="abc"))
    block["salt"] = "!!!notbase64!!!"
    assert verify_hmac(b"x", block, secret="abc") is False


def test_derive_key_deterministic_for_same_inputs() -> None:
    key1 = derive_key("secret", b"\x00" * 16, iterations=1000)
    key2 = derive_key("secret", b"\x00" * 16, iterations=1000)
    assert key1 == key2
    assert len(key1) == 32


def test_derive_key_rejects_non_positive_iterations() -> None:
    with pytest.raises(ValueError):
        derive_key("secret", b"\x00" * 16, iterations=0)


def test_sign_honours_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_SIGNING_SECRET", "env-secret")
    block = sign_hmac(b"payload")
    # Verify using same env var.
    assert verify_hmac(b"payload", block)
    # Verify with explicit secret matches env.
    assert verify_hmac(b"payload", block, secret="env-secret")


def test_lower_iterations_speed_up_tests() -> None:
    block = sign_hmac(b"x", secret="s", iterations=1000)
    assert block["iterations"] == 1000
    assert verify_hmac(b"x", block, secret="s")
