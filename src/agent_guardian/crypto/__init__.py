"""Cryptographic primitives for evidence-pack signing (PRD §11.2, M13).

Two flavours of signature ship side-by-side:

* :mod:`agent_guardian.crypto.hmac_sig` — HMAC-SHA256 with PBKDF2 key
  derivation. Symmetric, lets a verifier with the shared secret confirm
  authorship without any infrastructure.
* :mod:`agent_guardian.crypto.ed25519_sig` — Detached Ed25519 with the
  public key embedded inline. Asymmetric, lets anyone verify without a
  shared secret, while only the holder of ``~/.agentguardian/keys`` can
  forge.

Reports sign with both so consumers can pick whichever model fits their
trust topology.
"""

from __future__ import annotations

from agent_guardian.crypto.ed25519_sig import (
    DEFAULT_KEYS_DIR,
    ED25519_ALGORITHM,
    Ed25519Keypair,
    Ed25519SignatureBlock,
    load_or_create_keypair,
    sign_ed25519,
    verify_ed25519,
)
from agent_guardian.crypto.hmac_sig import (
    DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_SIGNING_SECRET,
    HMAC_ALGORITHM,
    SIGNATURE_VERSION,
    HmacSignatureBlock,
    derive_key,
    sign_hmac,
    verify_hmac,
)

__all__ = [
    "DEFAULT_KEYS_DIR",
    "DEFAULT_PBKDF2_ITERATIONS",
    "DEFAULT_SIGNING_SECRET",
    "ED25519_ALGORITHM",
    "HMAC_ALGORITHM",
    "SIGNATURE_VERSION",
    "Ed25519Keypair",
    "Ed25519SignatureBlock",
    "HmacSignatureBlock",
    "derive_key",
    "load_or_create_keypair",
    "sign_ed25519",
    "sign_hmac",
    "verify_ed25519",
    "verify_hmac",
]
