"""Contract package error hierarchy (Stage 1A).

Every failure mode in the ``contract`` package surfaces as one of these so
callers can decide whether the problem is recoverable (e.g. a missing secret
that the operator can provision) or a hard stop (e.g. a contract authored
against an unsupported schema version).

The hierarchy is deliberately flat and string-friendly: each error carries a
human-readable message and, where useful, structured fields the caller can
branch on without parsing the message.
"""

from __future__ import annotations

__all__ = [
    "ContractError",
    "ContractValidationError",
    "MigrationNeeded",
    "SecretResolutionError",
    "UnsupportedContractVersion",
]


class ContractError(Exception):
    """Base class for every error raised by the contract package."""


class ContractValidationError(ContractError):
    """A contract document failed schema / semantic validation.

    Raised by the loader when Pydantic validation fails or when a
    cross-field invariant (e.g. prod-requires-``authorization_ref``) is
    violated. The message wraps the underlying detail loudly rather than
    swallowing it.
    """


class SecretResolutionError(ContractError):
    """A :class:`~agent_guardian.contract.secrets.SecretRef` could not be
    resolved to a concrete value.

    This is intentionally loud: a contract that references a secret which is
    absent from the configured backend must fail the run rather than silently
    proceeding with an empty credential.
    """


class UnsupportedContractVersion(ContractError):
    """The contract declares a ``version`` this build does not understand.

    Distinct from :class:`MigrationNeeded`: a version far ahead of (or behind)
    the supported window has no migration path and is a hard stop.
    """

    def __init__(
        self, message: str, *, found: int | None = None, supported: int | None = None
    ) -> None:
        super().__init__(message)
        self.found = found
        self.supported = supported


class MigrationNeeded(ContractError):
    """The contract declares a known-older ``version`` that requires migration.

    Stage 1A only ships the migration *skeleton*; the loader raises this to
    signal that a future ``migrate`` step is required before the document can
    be loaded as a current-version :class:`~agent_guardian.contract.schema.Contract`.
    """

    def __init__(
        self, message: str, *, found: int | None = None, target: int | None = None
    ) -> None:
        super().__init__(message)
        self.found = found
        self.target = target
