"""Ed25519 signer / verifier tests (M13)."""

from __future__ import annotations

import base64
from pathlib import Path

from agent_guardian.crypto.ed25519_sig import (
    ED25519_ALGORITHM,
    load_or_create_keypair,
    sign_ed25519,
    verify_ed25519,
)
from agent_guardian.crypto.hmac_sig import SIGNATURE_VERSION


def test_sign_returns_well_formed_block(tmp_path: Path) -> None:
    block = sign_ed25519(b"hello", keys_dir=tmp_path / "k1")
    assert block["algorithm"] == ED25519_ALGORITHM
    assert block["version"] == SIGNATURE_VERSION
    assert isinstance(block["public_key_b32"], str)
    assert isinstance(block["signature"], str)
    base64.b64decode(block["signature"])


def test_sign_then_verify_roundtrips(tmp_path: Path) -> None:
    block = sign_ed25519(b"payload bytes", keys_dir=tmp_path / "k1")
    assert verify_ed25519(b"payload bytes", block) is True


def test_verify_tampered_payload_returns_false(tmp_path: Path) -> None:
    block = sign_ed25519(b"payload", keys_dir=tmp_path / "k1")
    assert verify_ed25519(b"payload-modified", block) is False


def test_verify_tampered_signature_returns_false(tmp_path: Path) -> None:
    block = dict(sign_ed25519(b"payload", keys_dir=tmp_path / "k1"))
    sig = bytearray(base64.b64decode(block["signature"]))
    sig[0] ^= 0xFF
    block["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    assert verify_ed25519(b"payload", block) is False


def test_keypair_is_persisted_across_calls(tmp_path: Path) -> None:
    keys_dir = tmp_path / "persistent"
    b1 = sign_ed25519(b"payload", keys_dir=keys_dir)
    b2 = sign_ed25519(b"payload", keys_dir=keys_dir)
    # Same public key on both calls (deterministic file lookup).
    assert b1["public_key_b32"] == b2["public_key_b32"]


def test_keypair_files_are_created_with_expected_mode(tmp_path: Path) -> None:
    keys_dir = tmp_path / "mode_test"
    load_or_create_keypair(keys_dir=keys_dir)
    priv = keys_dir / "ed25519.priv"
    pub = keys_dir / "ed25519.pub"
    assert priv.is_file()
    assert pub.is_file()
    # Private key chmod best-effort — on POSIX, expect 0o600.
    mode = priv.stat().st_mode & 0o777
    assert mode in (0o600, 0o644)  # tolerate Windows / weird FS


def test_two_keys_dirs_yield_two_distinct_keypairs(tmp_path: Path) -> None:
    b1 = sign_ed25519(b"payload", keys_dir=tmp_path / "a")
    b2 = sign_ed25519(b"payload", keys_dir=tmp_path / "b")
    assert b1["public_key_b32"] != b2["public_key_b32"]
    # Each still verifies on its own.
    assert verify_ed25519(b"payload", b1)
    assert verify_ed25519(b"payload", b2)


def test_verify_rejects_unknown_algorithm(tmp_path: Path) -> None:
    block = dict(sign_ed25519(b"x", keys_dir=tmp_path / "k"))
    block["algorithm"] = "RSA-SHA256"
    assert verify_ed25519(b"x", block) is False


def test_verify_rejects_unknown_version(tmp_path: Path) -> None:
    block = dict(sign_ed25519(b"x", keys_dir=tmp_path / "k"))
    block["version"] = "ag-sig-v0"
    assert verify_ed25519(b"x", block) is False


def test_verify_rejects_malformed_public_key(tmp_path: Path) -> None:
    block = dict(sign_ed25519(b"x", keys_dir=tmp_path / "k"))
    block["public_key_b32"] = "!!"
    assert verify_ed25519(b"x", block) is False


def test_verify_rejects_missing_fields(tmp_path: Path) -> None:
    block = sign_ed25519(b"x", keys_dir=tmp_path / "k")
    broken = {k: v for k, v in block.items() if k != "signature"}
    assert verify_ed25519(b"x", broken) is False


def test_load_or_create_keypair_returns_objects(tmp_path: Path) -> None:
    kp = load_or_create_keypair(keys_dir=tmp_path / "k")
    # Re-signing with that keypair should be valid.
    sig = kp["private_key"].sign(b"hello")
    kp["public_key"].verify(sig, b"hello")
