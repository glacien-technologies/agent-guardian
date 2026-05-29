"""Ed25519 detached signer with on-disk keypair persistence (PRD §11.2).

The first call to :func:`sign_ed25519` generates a fresh keypair in
``~/.agentguardian/keys/`` (``ed25519.priv`` mode-0600, ``ed25519.pub``
world-readable). Subsequent calls reuse it. The public key is embedded in
every signature block so verifiers don't need access to the filesystem.

Signature block shape::

    {
      "algorithm": "Ed25519",
      "version": "ag-sig-v1",
      "public_key_b32": "<rfc4648 base32, no padding>",
      "signature": "<b64>"
    }

Base32 (no padding) for the public key is the same encoding TOTP, Onion v3
addresses, and DNSSEC use — it round-trips through copy/paste cleanly.
"""

from __future__ import annotations

import base64
import hmac
import logging
from pathlib import Path
from typing import TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_guardian.crypto.hmac_sig import SIGNATURE_VERSION

_LOG = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_KEYS_DIR",
    "ED25519_ALGORITHM",
    "Ed25519Keypair",
    "Ed25519SignatureBlock",
    "load_or_create_keypair",
    "sign_ed25519",
    "verify_ed25519",
]

ED25519_ALGORITHM = "Ed25519"
DEFAULT_KEYS_DIR = Path.home() / ".agentguardian" / "keys"
_PRIV_FILENAME = "ed25519.priv"
_PUB_FILENAME = "ed25519.pub"


class Ed25519SignatureBlock(TypedDict):
    """Shape of an Ed25519 signature block in a report's ``signatures`` field."""

    algorithm: str
    version: str
    public_key_b32: str
    signature: str


class Ed25519Keypair(TypedDict):
    """Bare-bones holder for an Ed25519 keypair (avoids leaking ``cryptography`` types)."""

    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey


def _b32_no_padding(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32_decode_no_padding(value: str) -> bytes:
    # Re-pad to a multiple of 8 before decoding.
    pad = (-len(value)) % 8
    return base64.b32decode(value + ("=" * pad))


def load_or_create_keypair(*, keys_dir: Path | None = None) -> Ed25519Keypair:
    """Load the on-disk Ed25519 keypair, generating one on first use.

    The private key is written with ``0o600`` permissions. We never log or
    return the secret bytes — callers receive opaque ``cryptography`` objects.
    """
    target_dir = keys_dir if keys_dir is not None else DEFAULT_KEYS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    priv_path = target_dir / _PRIV_FILENAME
    pub_path = target_dir / _PUB_FILENAME

    if priv_path.is_file():
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_path.read_bytes())
        _LOG.debug("ed25519: loaded existing keypair from %s", priv_path)
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv_path.write_bytes(priv_bytes)
        _LOG.info("ed25519: generated new keypair at %s", priv_path)
        # Best-effort chmod — Windows / weird FS may reject 0o600.
        try:
            priv_path.chmod(0o600)
        except OSError as exc:
            _LOG.debug(
                "ed25519: chmod 0600 on %s failed (%s) — non-POSIX FS likely, continuing",
                priv_path,
                exc,
            )

    public_key = private_key.public_key()
    if not pub_path.is_file():
        pub_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    return Ed25519Keypair(private_key=private_key, public_key=public_key)


def sign_ed25519(payload: bytes, *, keys_dir: Path | None = None) -> Ed25519SignatureBlock:
    """Produce a detached Ed25519 signature block over ``payload`` bytes."""
    keypair = load_or_create_keypair(keys_dir=keys_dir)
    private_key = keypair["private_key"]
    public_key = keypair["public_key"]
    sig = private_key.sign(payload)
    pub_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Ed25519SignatureBlock(
        algorithm=ED25519_ALGORITHM,
        version=SIGNATURE_VERSION,
        public_key_b32=_b32_no_padding(pub_raw),
        signature=base64.b64encode(sig).decode("ascii"),
    )


def verify_ed25519(
    payload: bytes,
    block: Ed25519SignatureBlock | dict[str, object],
    *,
    expected_pubkey_b32: str | None = None,
) -> bool:
    """Verify a detached Ed25519 signature against an embedded public key.

    Returns ``False`` for any structural defect or signature mismatch.

    **Trust anchoring**: when ``expected_pubkey_b32`` is supplied, the embedded
    public key must match it (constant-time, normalised through the same
    base32 round-trip) before the signature is even checked. Without a pinned
    key the signature only attests *integrity* (the bytes were not tampered),
    NOT *authenticity* (who signed) — because Ed25519 carries its own verifying
    key, anyone can re-sign forged content with a fresh key. Callers that need a
    trust decision (the ``verify`` CLI) must pass an expected key; see
    :func:`agent_guardian.reports.json_report.verify_signatures`.
    """
    try:
        algorithm = block.get("algorithm")
        version = block.get("version")
        pub_b32 = block.get("public_key_b32")
        sig_b64 = block.get("signature")
    except AttributeError as exc:
        _LOG.warning("ed25519 verify: block is not a mapping (%s)", exc)
        return False
    if algorithm != ED25519_ALGORITHM or version != SIGNATURE_VERSION:
        _LOG.warning(
            "ed25519 verify: algorithm/version mismatch (got %r/%r, expect %r/%r)",
            algorithm,
            version,
            ED25519_ALGORITHM,
            SIGNATURE_VERSION,
        )
        return False
    if not isinstance(pub_b32, str) or not isinstance(sig_b64, str):
        _LOG.warning("ed25519 verify: public_key_b32 / signature must be strings")
        return False
    try:
        pub_raw = _b32_decode_no_padding(pub_b32)
        sig = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        _LOG.warning("ed25519 verify: signature/public-key decode failed: %s", exc)
        return False
    # Trust anchor: pin the embedded key against the expected one (constant-time
    # on the raw key bytes, after normalising the expected key through the same
    # decode so base32 padding / casing differences don't matter).
    if expected_pubkey_b32 is not None:
        try:
            expected_raw = _b32_decode_no_padding(expected_pubkey_b32)
        except (ValueError, TypeError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            _LOG.warning("ed25519 verify: expected public key decode failed: %s", exc)
            return False
        if not hmac.compare_digest(pub_raw, expected_raw):
            _LOG.warning(
                "ed25519 verify: embedded public key does not match the pinned "
                "expected key — refusing to trust this signature"
            )
            return False
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
    except ValueError as exc:
        _LOG.warning("ed25519 verify: malformed public key bytes: %s", exc)
        return False
    try:
        public_key.verify(sig, payload)
    except InvalidSignature:
        _LOG.warning("ed25519 verify: signature does not match payload")
        return False
    _LOG.debug("ed25519 verify: signature valid (payload_bytes=%d)", len(payload))
    return True
