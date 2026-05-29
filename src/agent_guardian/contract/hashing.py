"""Stable content hash for a contract (Stage 1A).

The hash identifies a contract by its *structure and configuration*, not by
the concrete secret values it points at. We compute it over the
:func:`~agent_guardian.contract.secrets.redact` view of the contract, then
serialise that view with the canonical-JSON encoder
(:func:`agent_guardian.reports.canonical.to_canonical_json`) so the same
logical contract hashes identically across processes and Python versions.

Properties (asserted by the unit tests):

* **Stable** — same contract → same hash on every run / machine.
* **Secret-value invariant** — two contracts that differ only in which secret
  value an env-var/file currently holds produce the same hash (secrets are
  redacted before hashing and never resolved here).
* **Structure sensitive** — any change to the contract's structure or
  configuration changes the hash.
"""

from __future__ import annotations

import hashlib

from agent_guardian.contract.schema import Contract
from agent_guardian.contract.secrets import redact
from agent_guardian.reports.canonical import to_canonical_json

__all__ = ["contract_hash_input", "contract_sha256"]


def contract_hash_input(contract: Contract) -> bytes:
    """Return the canonical-JSON bytes that the contract hash is computed over.

    Exposed for debugging / receipts: it is exactly the input fed to SHA-256.
    """
    redacted = redact(contract)
    return to_canonical_json(redacted)


def contract_sha256(contract: Contract) -> str:
    """Return the hex SHA-256 of the redacted, canonicalised contract."""
    return hashlib.sha256(contract_hash_input(contract)).hexdigest()
