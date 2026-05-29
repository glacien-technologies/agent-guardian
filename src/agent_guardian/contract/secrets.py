"""Secret references and resolution (Stage 1).

A contract never embeds raw credentials. Instead it carries
:class:`SecretRef` pointers — typed strings of the form ``${backend:key}`` —
that are resolved at run time against a concrete backend. This keeps secrets
out of the on-disk document, out of the canonical hash input, and out of logs.

The supported pointer syntax is::

    ${env:VAR_NAME}     # read from an environment variable
    ${file:/path/to}    # read the trimmed contents of a file
    ${vault:secret/key} # reserved (NotImplementedError until wired)
    ${sops:secret/key}  # reserved (NotImplementedError until wired)

Any other string — most importantly a raw inlined credential — is rejected at
validation time so a token can never accidentally land in the document.

A missing key is a *loud* failure (:class:`SecretResolutionError`), never a
silent empty string.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, GetCoreSchemaHandler
from pydantic_core import core_schema

from agent_guardian.contract.errors import SecretResolutionError
from agent_guardian.logging_setup import _REDACTED, redact_secrets

__all__ = [
    "SECRET_REF_PATTERN",
    "SecretBackend",
    "SecretRef",
    "SecretResolver",
    "iter_secret_refs",
    "redact",
    "resolve_secret",
    "resolve_secrets",
]

SecretBackend = Literal["env", "file", "vault", "sops"]

# A SecretRef must look like ``${backend:key}`` where backend is one of the
# known backends and key is a non-empty, non-``}`` run. This is what makes a
# raw inlined credential (``sk-...``) impossible to express as a SecretRef.
SECRET_REF_PATTERN = re.compile(r"^\$\{(?P<backend>env|file|vault|sops):(?P<key>[^}]+)\}$")


class SecretRef(str):
    """A typed string pointing at a secret resolved at run time.

    Construction validates the ``${backend:key}`` shape and rejects anything
    else (including raw inlined credentials), so a literal token can never be
    smuggled into a contract document. The instance *is* the original
    ``${...}`` string, with :attr:`backend` / :attr:`key` parsed out for the
    resolver.
    """

    backend: SecretBackend
    key: str

    __slots__ = ("backend", "key")

    def __new__(cls, value: str) -> SecretRef:
        if isinstance(value, SecretRef):
            return value
        if not isinstance(value, str):
            raise ValueError("SecretRef must be a string of the form '${env:NAME}'")
        match = SECRET_REF_PATTERN.match(value.strip())
        if match is None:
            raise ValueError(
                "SecretRef must be a pointer of the form '${env:NAME}', "
                "'${file:/path}', '${vault:key}' or '${sops:key}' — "
                "never an inlined raw credential"
            )
        key = match.group("key").strip()
        if not key:
            raise ValueError("SecretRef key must not be empty")
        obj = super().__new__(cls, value.strip())
        # ``str`` instances are immutable, but instance attributes are fine via
        # ``object.__setattr__`` on a plain ``str`` subclass (no __slots__ on str).
        object.__setattr__(obj, "backend", match.group("backend"))
        object.__setattr__(obj, "key", key)
        return obj

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"SecretRef({str.__repr__(self)})"

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type[Any], handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Validate ``SecretRef`` from a plain string in Pydantic v2.

        Serialises back to the plain ``${...}`` string so JSON Schema export and
        ``model_dump`` round-trip cleanly.
        """

        def _validate(value: Any) -> SecretRef:
            return cls(value)

        return core_schema.no_info_after_validator_function(
            _validate,
            core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(str),
        )


class SecretResolver:
    """Resolves :class:`SecretRef` pointers against concrete backends.

    ``env`` and ``file_root`` are injectable so tests can drive the resolver
    deterministically without touching the real environment or filesystem. By
    default ``env`` reads :data:`os.environ` and ``file`` resolves relative
    paths against ``file_root`` (defaulting to the cwd).
    """

    def __init__(
        self,
        *,
        env: dict[str, str] | None = None,
        file_root: Path | None = None,
    ) -> None:
        self._env = env
        self._file_root = file_root

    def resolve(self, ref: SecretRef) -> str:
        """Resolve ``ref`` to its concrete secret value.

        Raises:
            SecretResolutionError: the key is absent from the backend.
            NotImplementedError: the backend is reserved but not yet wired.
        """
        if ref.backend == "env":
            return self._resolve_env(ref.key)
        if ref.backend == "file":
            return self._resolve_file(ref.key)
        if ref.backend in ("vault", "sops"):
            raise NotImplementedError(
                f"secret backend {ref.backend!r} is reserved but not implemented in Stage 1"
            )
        # Defensive: ``backend`` is validated against the pattern, so this is
        # unreachable unless the instance is built bypassing validation.
        raise SecretResolutionError(  # pragma: no cover
            f"unknown secret backend: {ref.backend!r}"
        )

    def _resolve_env(self, key: str) -> str:
        env = self._env if self._env is not None else os.environ
        value = env.get(key)
        if value is None:
            raise SecretResolutionError(
                f"env secret {key!r} is not set; export it before running the contract"
            )
        return value

    def _resolve_file(self, key: str) -> str:
        path = Path(key)
        if not path.is_absolute() and self._file_root is not None:
            path = self._file_root / path
        if not path.is_file():
            raise SecretResolutionError(
                f"file secret {str(path)!r} does not exist or is not a regular file"
            )
        return path.read_text(encoding="utf-8").strip()


def resolve_secret(ref: SecretRef, *, resolver: SecretResolver | None = None) -> str:
    """Resolve a single :class:`SecretRef` using ``resolver`` (or a default one)."""
    return (resolver or SecretResolver()).resolve(ref)


def iter_secret_refs(value: Any) -> list[SecretRef]:
    """Recursively collect every :class:`SecretRef` reachable from ``value``.

    Walks Pydantic models field-by-field, plus mappings / sequences, so a
    :class:`SecretRef` nested anywhere in the contract tree is found.
    """
    found: list[SecretRef] = []
    _collect_refs(value, found)
    return found


def _collect_refs(value: Any, acc: list[SecretRef]) -> None:
    # ``SecretRef`` is a ``str`` subclass, so check it before the ``str`` arm.
    if isinstance(value, SecretRef):
        acc.append(value)
        return
    if isinstance(value, BaseModel):
        for _name, val in value:
            _collect_refs(val, acc)
        return
    if isinstance(value, dict):
        for val in value.values():
            _collect_refs(val, acc)
        return
    if isinstance(value, list | tuple):
        for item in value:
            _collect_refs(item, acc)
        return


def resolve_secrets(value: Any, *, resolver: SecretResolver | None = None) -> dict[SecretRef, str]:
    """Resolve every :class:`SecretRef` reachable from ``value``.

    Returns a mapping of pointer → resolved concrete value. Raises
    :class:`SecretResolutionError` (or :class:`NotImplementedError` for reserved
    backends) on the first ref that cannot be resolved.
    """
    res = resolver or SecretResolver()
    return {ref: res.resolve(ref) for ref in iter_secret_refs(value)}


def redact(value: Any) -> Any:
    """Return a redacted, JSON-native *view* of ``value`` for logging / hashing.

    Strings are scrubbed via :func:`logging_setup.redact_secrets`. Mappings and
    sequences are walked recursively. :class:`SecretRef` instances are reduced
    to a structure-preserving, value-independent placeholder ``${backend:***}``
    — the reference *shape* (which backend) survives so structurally-distinct
    contracts still hash differently, while the concrete key is hidden.

    Nested :class:`~pydantic.BaseModel` instances are walked field-by-field via
    iteration rather than ``model_dump`` so embedded :class:`SecretRef` objects
    keep their type and get masked. Non-JSON-native leaf scalars (e.g. Pydantic
    ``AnyUrl``) are normalised with ``str()`` so the result is always safe to
    feed to :func:`agent_guardian.reports.canonical.to_canonical_json`.

    The redaction is *structure-preserving and secret-value-independent*: two
    contracts that differ only in which concrete secret they point at redact to
    the same view, which is what makes the contract hash invariant to secret
    values.
    """
    # ``SecretRef`` is a ``str`` subclass — handle it before the ``str`` arm.
    if isinstance(value, SecretRef):
        return f"${{{value.backend}:{_REDACTED}}}"
    if isinstance(value, BaseModel):
        return {name: redact(val) for name, val in value}
    if isinstance(value, dict):
        return {key: redact(val) for key, val in value.items()}
    if isinstance(value, list | tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    # Non-JSON-native scalar (e.g. Pydantic AnyUrl / Enum-like): normalise to a
    # string so the canonical-JSON encoder never trips on it.
    return str(value)
