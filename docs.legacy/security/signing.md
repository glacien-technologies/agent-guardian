# Signing & verification

**TL;DR** — AgentGuardian dual-signs every JSON report: HMAC-SHA256 (PBKDF2-derived key, 600 000 iterations) and Ed25519 (detached, public key embedded). Both signatures are computed over the same canonical-JSON bytes. You can re-derive either signature from scratch with `openssl` or `pyca/cryptography` — every step is deterministic.

## Why two signatures?

The two channels defend against different attackers:

- **HMAC-SHA256** is *symmetric*. Anyone with the secret can sign **and** verify. This is the right tool for CI and SIEM pipelines that already share a secret with the scanner.
- **Ed25519** is *asymmetric*. The scanner holds the private key; an arbitrary number of downstream verifiers hold only the public key. This is the right tool for public attestation (a vendor publishes a signed report; customers verify with a pinned pubkey).

Both must verify against the same canonical bytes. A tampered report cannot pass either channel.

## 1. Canonical-JSON normalization

The signature input is **not** the report file on disk — it is the canonical-JSON serialisation of the report payload *with the `signatures` block removed*. Canonicalisation is implemented in [`src/agent_guardian/reports/canonical.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/canonical.py).

The rules (an RFC 8785-flavoured subset):

| Rule | `json.dumps` argument | Why |
|---|---|---|
| Keys sorted lexicographically | `sort_keys=True` | Stable ordering across Python versions and dict-insertion orders. |
| No whitespace between tokens | `separators=(",", ":")` | One canonical byte sequence. |
| UTF-8 native (no `\uXXXX` escapes for non-ASCII) | `ensure_ascii=False` | Round-trips emoji, RTL text, and CJK without expansion. |
| Forbid `NaN` / `Infinity` | `allow_nan=False` | Non-finite floats are not portable JSON. |
| `datetime` → UTC ISO 8601 with `Z` suffix | custom `default` | `2026-05-30T12:34:56.789012Z` regardless of source tzinfo. |
| `enum.Enum` → `.value` | custom `default` | A `Band.GOOD` serialises as `"GOOD"`, not `"Band.GOOD"`. |
| `pydantic.BaseModel` → `.model_dump(mode="json")` | custom `default` | Pydantic models round-trip via their JSON-mode dump. |
| `pathlib.PurePath` → `str(path)` | custom `default` | POSIX strings, not platform-specific reprs. |
| `bytes` → base64 ASCII | custom `default` | Defensive — report payloads should not carry raw bytes, but the encoder accepts them. |
| `set` / `frozenset` → sorted list (by `str`) | custom `default` | Stable ordering for sets. |
| Anything else → `TypeError` | custom `default` | Explicit failure beats silent inconsistency. |

### Worked example — dict to canonical bytes

```python
from agent_guardian.reports.canonical import to_canonical_json

payload = {"hello": "world", "z": [1, 2]}
canonical = to_canonical_json(payload)
print(canonical)
# b'{"hello":"world","z":[1,2]}'
print(canonical.hex())
# 7b2268656c6c6f223a22776f726c64222c227a223a5b312c325d7d
```

Run that on any machine, any Python 3.10–3.13, with or without the AgentGuardian venv active — you will get the same 27 bytes.

## 2. HMAC-SHA256 channel

Source: [`src/agent_guardian/crypto/hmac_sig.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/hmac_sig.py) (verified by [`tests/unit/test_crypto_hmac.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/test_crypto_hmac.py)).

Constants:

| Name | Value | Source |
|---|---|---|
| `SIGNATURE_VERSION` | `"ag-sig-v1"` | `hmac_sig.py:42` |
| `HMAC_ALGORITHM` | `"HMAC-SHA256"` | `hmac_sig.py:43` |
| `DEFAULT_PBKDF2_ITERATIONS` | `600_000` (OWASP 2023) | `hmac_sig.py:44` |
| `_SALT_BYTES` | `16` | `hmac_sig.py:47` |
| `_KEY_BYTES` | `32` | `hmac_sig.py:48` |

### Signature block shape

```json
{
  "algorithm": "HMAC-SHA256",
  "version":   "ag-sig-v1",
  "salt":      "<base64, 16 bytes raw>",
  "iterations": 600000,
  "signature": "<base64, 32 bytes raw>"
}
```

### Re-derivation with OpenSSL

Given the canonical bytes `{"hello":"world","z":[1,2]}`, the secret `my-secret`, and a salt of `4Q+FyuNCQgqLT48f/zRRjA==` (base64), here is the full re-derivation. The output below is reproducible byte-for-byte.

```sh
# 1. Decode salt to hex so openssl kdf can ingest it.
SALT_HEX=$(echo -n '4Q+FyuNCQgqLT48f/zRRjA==' | openssl base64 -d -A | xxd -p -c 256)
# -> e10f85cae342420a8b4f8f1fff34518c

# 2. Derive the 32-byte key with PBKDF2-HMAC-SHA256, 600k iters.
KEY_HEX=$(openssl kdf -keylen 32 \
  -kdfopt pass:my-secret \
  -kdfopt hexsalt:$SALT_HEX \
  -kdfopt iter:600000 \
  -kdfopt digest:SHA256 \
  PBKDF2 | tr -d ':\n' | tr 'A-F' 'a-f')
# -> c4be5f977de9993ab45c8d8cf9203b3950f9e11f092fa3e27e589ae4b74a8601

# 3. HMAC-SHA256 the canonical payload bytes under that key.
echo -n '{"hello":"world","z":[1,2]}' \
  | openssl dgst -sha256 -mac HMAC -macopt hexkey:$KEY_HEX -binary \
  | openssl base64 -A
# -> YRV/3gqPG9BTlAjbk/fDJTciJ4nQxXvelZWw8tN5CRs=
```

The resulting base64 string is the `signature` field of the HMAC block. If your re-derived value matches the one in the report and the canonical bytes were derived correctly, the integrity of the bytes is proven and you signed (or were signed with) the same secret.

`openssl kdf -keylen` requires OpenSSL 3.0+. On older OpenSSL builds, derive with `python -c "import hashlib; print(hashlib.pbkdf2_hmac('sha256', b'my-secret', bytes.fromhex('$SALT_HEX'), 600000, 32).hex())"`.

### Re-derivation with Python (no AgentGuardian dependency)

```python
import base64, hashlib, hmac

canonical = b'{"hello":"world","z":[1,2]}'
salt      = base64.b64decode('4Q+FyuNCQgqLT48f/zRRjA==')
expected  = base64.b64decode('YRV/3gqPG9BTlAjbk/fDJTciJ4nQxXvelZWw8tN5CRs=')

key      = hashlib.pbkdf2_hmac('sha256', b'my-secret', salt, 600000, dklen=32)
actual   = hmac.new(key, canonical, hashlib.sha256).digest()

assert hmac.compare_digest(actual, expected)
print("HMAC OK")
```

### The default secret is **public**

`DEFAULT_SIGNING_SECRET = "agent-guardian-default-secret"` ([`hmac_sig.py:45`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/hmac_sig.py)). It exists so local development works without setup, and so the *signing* path always produces a syntactically-valid block. Verification **refuses to trust the default**: `_resolve_verify_secret` returns `None` when no real secret is supplied, and `verify_hmac` fails closed on `None` ([`hmac_sig.py:_resolve_verify_secret` + `verify_hmac`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/hmac_sig.py)).

To produce a verifiable HMAC channel, set `AGENT_GUARDIAN_SIGNING_SECRET` in the environment that runs `agent-guardian scan` and supply the same value (or pass it via `--secret`) when running `agent-guardian verify`.

## 3. Ed25519 channel

Source: [`src/agent_guardian/crypto/ed25519_sig.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/ed25519_sig.py).

### Key storage

- **Private key.** `~/.agentguardian/keys/ed25519.priv` — 32 raw bytes (no PEM, no DER), mode `0600` on POSIX file systems ([`ed25519_sig.py:load_or_create_keypair`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/ed25519_sig.py)).
- **Public key.** `~/.agentguardian/keys/ed25519.pub` — 32 raw bytes, world-readable.
- **Lifecycle.** First call to `sign_ed25519()` generates a fresh keypair and writes both files. Subsequent calls reuse the keypair.

The on-disk format is intentionally minimal so the keypair is easy to back up, easy to ship to a verifier, and not coupled to a specific OpenSSL key-encoding version.

### Signature block shape

```json
{
  "algorithm":       "Ed25519",
  "version":         "ag-sig-v1",
  "public_key_b32":  "<RFC 4648 base32, no padding, 32-byte raw pubkey>",
  "signature":       "<base64, 64-byte raw signature>"
}
```

Base32 with no padding is the encoding used by TOTP, Tor v3 onion addresses, and DNSSEC — it round-trips cleanly through copy/paste and is case-insensitive.

### Verification with pyca/cryptography

```python
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519

def _b32_decode(value: str) -> bytes:
    # Re-pad to a multiple of 8 before decoding (matches our encode).
    pad = (-len(value)) % 8
    return base64.b32decode(value + ("=" * pad))

# Load the canonical-JSON payload bytes (the same bytes that were signed).
canonical = b'{"hello":"world","z":[1,2]}'

# Pull the block out of the report.
report_ed_block = {
    "algorithm":      "Ed25519",
    "version":        "ag-sig-v1",
    "public_key_b32": "JZBKGRS6DE75E5KBXBAJ3T4NDKXZRHX3RSY2B2AQJOYWYFFMV7OQ",
    "signature":      "Q6Jm09IjS3RpPD9br8Dec/4BWZCqC0K5E5Q++R7Zw5veuhrp5q7wCynZwqmrrIQbvZNYaQdv77DkZWqJJVljCA==",
}
pub_raw = _b32_decode(report_ed_block["public_key_b32"])
sig     = base64.b64decode(report_ed_block["signature"])

public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
public_key.verify(sig, canonical)  # raises InvalidSignature on mismatch
print("Ed25519 OK")
```

### A pinned key is required for *authenticity*

The embedded `public_key_b32` proves only that *some* Ed25519 key signed these bytes — anyone can generate a fresh key and re-sign forged content. To trust the *identity* of the signer, the verifier must compare the embedded key against a **pinned** expected key.

The verify path implements this:

```python
# src/agent_guardian/crypto/ed25519_sig.py: verify_ed25519
if expected_pubkey_b32 is not None:
    expected_raw = _b32_decode_no_padding(expected_pubkey_b32)
    if not hmac.compare_digest(pub_raw, expected_raw):
        # constant-time mismatch -> refuse to trust
        return False
```

Distribute your public key out-of-band (`cat ~/.agentguardian/keys/ed25519.pub | base32 | tr -d '='`) and pin it when verifying.

## 4. Trust-anchor truth table

`agent-guardian verify` is intentionally fail-closed. The flag combinations and their outcomes:

| Flags passed to `verify` | `trust anchor` line | `HMAC-SHA256` line | `Ed25519` line | Exit code | Source |
|---|---|---|---|---|---|
| (none) — no `--pubkey`, no `--secret`, no env | `UNANCHORED` | `FAIL`* | `FAIL`* | **1** | `cli.py:1296-1304`, [`json_report.py:240-260`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/json_report.py) |
| `--pubkey <correct>` only | `PINNED` | `FAIL` (no secret) | `OK` | **0** | `json_report.py:341-360` |
| `--pubkey <wrong>` only | `UNANCHORED` | `FAIL` | `FAIL` | **1** | `json_report.py:355-360` (ed25519_anchor_failed) |
| `--secret <correct>` only | `PINNED` | `OK` | `FAIL` (no pin) | **0** | `json_report.py:341-354` |
| `--secret <wrong>` only | `UNANCHORED` | `FAIL` | `FAIL` | **1** | `json_report.py:350-354` (hmac_anchor_failed) |
| both correct | `PINNED` | `OK` | `OK` | **0** | both anchors pass |
| both supplied, **one** wrong | `UNANCHORED`** | `OK`/`FAIL` | `OK`/`FAIL` | **1** | "supplying both anchors thus requires both" — `json_report.py:347-348` |

\*"HMAC FAIL" with no secret supplied is **correct behaviour**, not a bug: the HMAC channel has no trustworthy secret to verify against, so it falls closed. This is loud-by-design — silent "no opinion" verifies are how forged reports get rubber-stamped.

\*\*When both anchors are supplied and one fails, `ok` is false and the command exits 1 even if the other anchor passed. The rationale is in [`json_report.py:VerifyResult.ok`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/json_report.py): "an anchored channel must never be silently ignored, so providing both anchors requires both to pass".

### `agent-guardian verify` CLI surface

```sh
agent-guardian verify path/to/report.json
# UNANCHORED, exits 1.

agent-guardian verify path/to/report.json \
  --pubkey JZBKGRS6DE75E5KBXBAJ3T4NDKXZRHX3RSY2B2AQJOYWYFFMV7OQ
# PINNED (Ed25519), HMAC line shows FAIL by design, exits 0.

agent-guardian verify path/to/report.json \
  --pubkey-file pinned.pub \
  --secret "$AGENT_GUARDIAN_SIGNING_SECRET"
# Both channels PINNED + OK, exits 0. The most paranoid configuration.
```

## 5. Key lifecycle & rotation

AgentGuardian does not include a key-rotation command in v1.0 — rotation is a filesystem operation. To rotate:

```sh
# 1. Back up the current keypair (so historical reports' embedded pubkeys are recoverable).
mv ~/.agentguardian/keys ~/.agentguardian/keys.archive.$(date -u +%Y%m%dT%H%M%SZ)

# 2. Next call to `agent-guardian scan` generates a fresh keypair.
agent-guardian scan stub --mode SMART --no-report >/dev/null
ls ~/.agentguardian/keys/
# ed25519.priv  ed25519.pub

# 3. Distribute the new public key to verifiers out-of-band.
cat ~/.agentguardian/keys/ed25519.pub | base32 | tr -d '='
# JZBKGRS6DE75E5KBXBAJ3T4NDKXZRHX3RSY2B2AQJOYWYFFMV7OQ
```

Reports signed before the rotation continue to verify against their **own** embedded `public_key_b32` — but they will no longer match a verifier who has pinned the *new* key. Verifiers must keep the historical pubkey on file (or run two verifies, one per pin).

`AGENT_GUARDIAN_SIGNING_SECRET` rotation is the same shape: change the env var, distribute the new secret to consumers, and old reports continue to verify only against the old secret.

## 6. What this protects against, what it doesn't

| Attack | Defended? | Notes |
|---|---|---|
| Bit-flip / tampering in the JSON report | Yes | Either signature fails verification. |
| Replacing the whole report with one signed by a different AgentGuardian install | Ed25519: yes (pinned pubkey mismatch). HMAC: yes (different secret). | Only if the verifier pins. |
| Forging a report using a leaked HMAC secret | No | The secret IS the trust anchor. Treat like a code-signing key. |
| Forging a report using a leaked Ed25519 private key | No | Same — the private key is the authority. |
| The *binary* you ran was modified before signing | No (out of scope for the report signature) | This is what [supply-chain.md](supply-chain.md) covers: Sigstore signs the wheel; reproducible builds confirm the wheel matches the source. |
| Downstream verifier publishes their pinned pubkey in a log AND an attacker substitutes a new pin | No | Trust-anchor custody is the verifier's job, not AgentGuardian's. |

## Roadmap

The verify CLI is functional but its operator UX has rough edges. Tracked enhancements (see [roadmap.md](../reference/roadmap.md)):

- A single-line `provenance: TRUSTED / UNTRUSTED` summary at the top of `verify` output, so a script can `grep -q 'provenance: TRUSTED'` without parsing per-channel lines.
- A `--no-hmac` flag to hide the HMAC channel entirely when the verifier has no secret and does not want to see "HMAC FAIL by design" in their CI logs.
- Sigstore keyless signing for the *Ed25519 public key itself*, so a verifier can validate the pubkey's provenance without out-of-band distribution. This is part of the same Sigstore work documented in [supply-chain.md](supply-chain.md).

## See also

- [Threat model](threat-model.md) — what we sign for and what we don't.
- [Data flow](data-flow.md) — where the signed report lives on disk.
- [Supply chain](supply-chain.md) — wheel-signing, the layer below this one.
