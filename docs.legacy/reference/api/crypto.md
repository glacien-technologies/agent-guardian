# Crypto

**TL;DR** — The low-level signing primitives: Ed25519 with on-disk keypair persistence (`~/.agentguardian/keys/`) and HMAC-SHA256 with PBKDF2-HMAC-SHA256 key derivation. For the narrative on signing semantics, key ceremony, and trust anchoring, see [Signing & verification](../../security/signing.md); the higher-level `sign_payload` / `verify_signatures` entry points are documented in [Reports — Signing and verification](reports.md#signing-and-verification).

Both signers emit `SIGNATURE_VERSION = "ag-sig-v1"` blocks that round-trip cleanly into the `signatures` field of an `agentguardian-scan-v1` JSON report.

## Ed25519

First call to `sign_ed25519()` generates a fresh keypair in `DEFAULT_KEYS_DIR` (`~/.agentguardian/keys/ed25519.priv` mode-0600, `ed25519.pub` world-readable). Subsequent calls reuse it. The public key is embedded in every signature block under `public_key_b32` (base32, no padding — same encoding TOTP, Onion v3 addresses, and DNSSEC use) so verifiers don't need filesystem access.

`verify_ed25519()` accepts an optional `expected_pubkey_b32` — when supplied, the embedded key must match it (constant-time, normalised through the same base32 round-trip) before the signature is checked. Without a pinned key the signature only attests *integrity* (bytes not tampered), NOT *authenticity* (who signed) — because Ed25519 carries its own verifying key, anyone can re-sign forged content with a fresh key. Callers that need a trust decision (the `verify` CLI, `verify_signatures`) must pass an expected key.

::: agent_guardian.crypto.ed25519_sig
    options:
      show_root_heading: false
      members:
        - Ed25519Keypair
        - Ed25519SignatureBlock
        - sign_ed25519
        - verify_ed25519
        - load_or_create_keypair
        - DEFAULT_KEYS_DIR
        - ED25519_ALGORITHM

```python
from agent_guardian.crypto.ed25519_sig import sign_ed25519, verify_ed25519

payload = b"hello, world"
block = sign_ed25519(payload)
assert verify_ed25519(payload, block)                        # integrity only
assert verify_ed25519(payload, block,
                     expected_pubkey_b32=block["public_key_b32"])  # anchored
```

## HMAC-SHA256

PBKDF2-HMAC-SHA256 (600 000 iterations — matches OWASP 2023 password-storage guidance) derives the 32-byte signing key from a UTF-8 secret and a 16-byte random salt. The salt and iteration count travel in the block so verification reproduces the same key.

`DEFAULT_SIGNING_SECRET = "agent-guardian-default-secret"` is intended *only* for local development; set `AGENT_GUARDIAN_SIGNING_SECRET` in production / CI to a value from your secrets manager. `verify_hmac()` **fails closed** when no secret is supplied and `AGENT_GUARDIAN_SIGNING_SECRET` is unset — a report signed with the public default is unverifiable (its provenance cannot be trusted) until the real secret is supplied.

::: agent_guardian.crypto.hmac_sig
    options:
      show_root_heading: false
      members:
        - HmacSignatureBlock
        - sign_hmac
        - verify_hmac
        - derive_key
        - DEFAULT_PBKDF2_ITERATIONS
        - DEFAULT_SIGNING_SECRET
        - HMAC_ALGORITHM
        - SIGNATURE_VERSION

```python
from agent_guardian.crypto.hmac_sig import sign_hmac, verify_hmac

payload = b"hello, world"
block = sign_hmac(payload, secret="prod-secret-from-vault")
assert verify_hmac(payload, block, secret="prod-secret-from-vault")
assert not verify_hmac(payload, block)                  # fails closed
```
