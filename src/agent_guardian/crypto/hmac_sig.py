"""HMAC-SHA256 signer with PBKDF2-HMAC-SHA256 key derivation (PRD §11.2).

A signature block looks like::

    {
      "algorithm": "HMAC-SHA256",
      "version": "ag-sig-v1",
      "salt": "<b64>",
      "iterations": 600000,
      "signature": "<b64>"
    }

The default signing secret is intended *only* for local development. Set
``AGENT_GUARDIAN_SIGNING_SECRET`` in production / CI to a value sourced from
your secrets manager — otherwise anyone can forge a signature with the
public default.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
from typing import TypedDict

_LOG = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_PBKDF2_ITERATIONS",
    "DEFAULT_SIGNING_SECRET",
    "HMAC_ALGORITHM",
    "SIGNATURE_VERSION",
    "HmacSignatureBlock",
    "derive_key",
    "sign_hmac",
    "verify_hmac",
]

SIGNATURE_VERSION = "ag-sig-v1"
HMAC_ALGORITHM = "HMAC-SHA256"
DEFAULT_PBKDF2_ITERATIONS = 600_000
DEFAULT_SIGNING_SECRET = "agent-guardian-default-secret"
_ENV_VAR = "AGENT_GUARDIAN_SIGNING_SECRET"
_SALT_BYTES = 16
_KEY_BYTES = 32


class HmacSignatureBlock(TypedDict):
    """Shape of an HMAC signature block in a report's ``signatures`` field."""

    algorithm: str
    version: str
    salt: str
    iterations: int
    signature: str


def _resolve_secret(secret: str | None) -> str:
    if secret is not None:
        return secret
    return os.environ.get(_ENV_VAR, DEFAULT_SIGNING_SECRET)


def derive_key(secret: str, salt: bytes, *, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256 → 32-byte signing key.

    600 000 iterations matches OWASP 2023 password-storage guidance; we use
    the same number for symmetric signature key derivation since the threat
    model is identical (offline brute force of a weak ``secret``).
    """
    if iterations <= 0:
        raise ValueError(f"iterations must be > 0, got {iterations}")
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iterations, dklen=_KEY_BYTES)


def sign_hmac(
    payload: bytes,
    *,
    secret: str | None = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> HmacSignatureBlock:
    """Produce an HMAC-SHA256 signature block over ``payload`` bytes.

    Caller is responsible for canonicalising ``payload`` first.
    """
    effective_secret = _resolve_secret(secret)
    salt = secrets.token_bytes(_SALT_BYTES)
    key = derive_key(effective_secret, salt, iterations=iterations)
    sig = hmac.new(key, payload, hashlib.sha256).digest()
    return HmacSignatureBlock(
        algorithm=HMAC_ALGORITHM,
        version=SIGNATURE_VERSION,
        salt=base64.b64encode(salt).decode("ascii"),
        iterations=iterations,
        signature=base64.b64encode(sig).decode("ascii"),
    )


def verify_hmac(
    payload: bytes,
    block: HmacSignatureBlock | dict[str, object],
    *,
    secret: str | None = None,
) -> bool:
    """Constant-time verify of an HMAC signature block.

    Returns ``False`` for any structural defect — wrong algorithm, missing
    fields, malformed base64. Only returns ``True`` when the recomputed
    digest matches and the algorithm/version are recognised.
    """
    try:
        algorithm = block.get("algorithm")
        version = block.get("version")
        salt_b64 = block.get("salt")
        iterations = block.get("iterations", DEFAULT_PBKDF2_ITERATIONS)
        sig_b64 = block.get("signature")
    except AttributeError as exc:
        _LOG.warning("hmac verify: block is not a mapping (%s)", exc)
        return False
    if algorithm != HMAC_ALGORITHM or version != SIGNATURE_VERSION:
        _LOG.warning(
            "hmac verify: algorithm/version mismatch (got %r/%r, expect %r/%r)",
            algorithm,
            version,
            HMAC_ALGORITHM,
            SIGNATURE_VERSION,
        )
        return False
    if not isinstance(salt_b64, str) or not isinstance(sig_b64, str):
        _LOG.warning("hmac verify: salt / signature must be strings")
        return False
    if not isinstance(iterations, int) or iterations <= 0:
        _LOG.warning("hmac verify: iterations must be positive int (got %r)", iterations)
        return False
    try:
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError) as exc:
        _LOG.warning("hmac verify: salt/signature decode failed: %s", exc)
        return False
    effective_secret = _resolve_secret(secret)
    key = derive_key(effective_secret, salt, iterations=iterations)
    actual = hmac.new(key, payload, hashlib.sha256).digest()
    return hmac.compare_digest(actual, expected)
