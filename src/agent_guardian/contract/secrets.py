"""Secret references and resolution (Stage 1).

A contract never embeds raw credentials. Instead it carries
:class:`SecretRef` pointers — typed strings of the form ``${backend:key}`` —
that are resolved at run time against a concrete backend. This keeps secrets
out of the on-disk document, out of the canonical hash input, and out of logs.

The supported pointer syntax is::

    ${env:VAR_NAME}            # read from an environment variable
    ${file:/path/to}           # read the trimmed contents of a file
    ${vault:secret/path#field} # read a field from a HashiCorp Vault KV secret
    ${sops:enc.yaml#dotted.key}# read a key from a sops-encrypted file

Any other string — most importantly a raw inlined credential — is rejected at
validation time so a token can never accidentally land in the document.

A missing key is a *loud* failure (:class:`SecretResolutionError`), never a
silent empty string.

The ``vault`` and ``sops`` backends are *opt-in*: a contract may reference them,
but a :class:`SecretResolver` only consults them when its
``backends`` allowlist (defaulting to :data:`DEFAULT_BACKENDS` = ``env`` + ``file``)
includes them. This keeps a default install from reaching out to Vault or
shelling out to ``sops`` unless the operator has explicitly enabled those
backends.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml
from pydantic import BaseModel, GetCoreSchemaHandler
from pydantic_core import core_schema

from agent_guardian.contract.errors import SecretResolutionError
from agent_guardian.logging_setup import _REDACTED, redact_secrets

_LOG = logging.getLogger(__name__)

__all__ = [
    "ALL_BACKENDS",
    "DEFAULT_BACKENDS",
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

# The backends always available without external infrastructure. ``vault`` and
# ``sops`` are opt-in (a resolver must be told to enable them) so a default
# install never reaches out to a secret manager.
DEFAULT_BACKENDS: tuple[SecretBackend, ...] = ("env", "file")
# Every backend a resolver can be asked to enable.
ALL_BACKENDS: tuple[SecretBackend, ...] = ("env", "file", "vault", "sops")

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

    ``backends`` is the allowlist of enabled backends. It defaults to
    :data:`DEFAULT_BACKENDS` (``env`` + ``file``). To resolve ``${vault:...}``
    or ``${sops:...}`` references the operator must opt the corresponding
    backend in — e.g. ``SecretResolver(backends=("env", "file", "vault"))``.
    A reference whose backend is *not* enabled fails loudly rather than
    silently reaching out to infrastructure the contract did not authorise.

    ``vault_addr`` / ``vault_token`` and ``sops_bin`` are injectable for tests;
    when ``None`` they fall back to ``VAULT_ADDR`` / ``VAULT_TOKEN`` in the
    environment and the ``sops`` binary on ``PATH``.
    """

    def __init__(
        self,
        *,
        env: dict[str, str] | None = None,
        file_root: Path | None = None,
        backends: Iterable[SecretBackend] | None = None,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        sops_bin: str | None = None,
    ) -> None:
        self._env = env
        self._file_root = file_root
        self._backends: frozenset[SecretBackend] = (
            frozenset(backends) if backends is not None else frozenset(DEFAULT_BACKENDS)
        )
        self._vault_addr = vault_addr
        self._vault_token = vault_token
        self._sops_bin = sops_bin

    def resolve(self, ref: SecretRef) -> str:
        """Resolve ``ref`` to its concrete secret value.

        Raises:
            SecretResolutionError: the key is absent from the backend, or the
                backend is not enabled on this resolver.
        """
        if ref.backend not in self._backends:
            enabled = ", ".join(sorted(self._backends)) or "<none>"
            raise SecretResolutionError(
                f"secret backend {ref.backend!r} is not enabled on this resolver "
                f"(enabled: {enabled}); pass backends=(..., {ref.backend!r}) to opt it in"
            )
        if ref.backend == "env":
            return self._resolve_env(ref.key)
        if ref.backend == "file":
            return self._resolve_file(ref.key)
        if ref.backend == "vault":
            return self._resolve_vault(ref.key)
        if ref.backend == "sops":
            return self._resolve_sops(ref.key)
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

    def _resolve_vault(self, key: str) -> str:
        """Resolve a ``${vault:secret/path#field}`` reference.

        ``key`` is ``"<path>#<field>"``. The KV secret at ``{VAULT_ADDR}/v1/<path>``
        is fetched with the ``X-Vault-Token`` header; the response is parsed as
        KV v2 (``data.data[field]``) with a KV v1 fallback (``data[field]``).
        Missing address / token / path / field all fail loudly with remediation.
        """
        path, sep, field = key.partition("#")
        path = path.strip().strip("/")
        field = field.strip()
        if not sep or not path or not field:
            raise SecretResolutionError(
                f"vault secret {key!r} must be of the form 'secret/path#field' "
                "(a KV path and the field to read, separated by '#')"
            )
        addr = (self._vault_addr or os.environ.get("VAULT_ADDR") or "").strip().rstrip("/")
        if not addr:
            raise SecretResolutionError(
                "vault secret requires VAULT_ADDR; export it (e.g. "
                "VAULT_ADDR=https://vault.example:8200) before running the contract"
            )
        token = (self._vault_token or os.environ.get("VAULT_TOKEN") or "").strip()
        if not token:
            raise SecretResolutionError(
                "vault secret requires VAULT_TOKEN; export a valid token "
                "(e.g. `vault login`) before running the contract"
            )
        url = f"{addr}/v1/{path}"
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(url, headers={"X-Vault-Token": token})
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Any connect/timeout/HTTP-status fault (httpx.HTTPError) or a
            # non-JSON body (ValueError from .json()) is a loud secret failure.
            _LOG.debug("vault GET %s failed: %s", redact_secrets(url), exc)
            raise SecretResolutionError(
                f"could not read vault secret at {path!r} from {addr!r}: {exc}"
            ) from exc
        data = body.get("data") if isinstance(body, dict) else None
        # KV v2 nests the secret under data.data; KV v1 puts fields directly
        # under data.
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            fields = data["data"]
        elif isinstance(data, dict):
            fields = data
        else:
            raise SecretResolutionError(
                f"vault secret at {path!r} returned an unexpected shape "
                "(no 'data' object — is this a KV mount?)"
            )
        if field not in fields:
            available = ", ".join(sorted(map(str, fields))) or "<none>"
            raise SecretResolutionError(
                f"vault secret at {path!r} has no field {field!r} (available: {available})"
            )
        return str(fields[field])

    def _resolve_sops(self, key: str) -> str:
        """Resolve a ``${sops:path/to/file#dotted.key}`` reference.

        Shells out to ``sops -d <file>`` (argv list, never ``shell=True``),
        parses the decrypted YAML/JSON document, and walks the ``#``-suffixed
        dotted key. A missing ``sops`` binary, a decrypt failure, or an absent
        key all fail loudly with remediation.
        """
        file_part, sep, dotted = key.partition("#")
        file_part = file_part.strip()
        dotted = dotted.strip()
        if not sep or not file_part or not dotted:
            raise SecretResolutionError(
                f"sops secret {key!r} must be of the form 'path/to/file#dotted.key' "
                "(an encrypted file and the dotted key to read, separated by '#')"
            )
        path = Path(file_part)
        if not path.is_absolute() and self._file_root is not None:
            path = self._file_root / path
        if not path.is_file():
            raise SecretResolutionError(
                f"sops secret file {str(path)!r} does not exist or is not a regular file"
            )
        sops_bin = self._sops_bin or shutil.which("sops")
        if not sops_bin:
            raise SecretResolutionError(
                "sops secret requires the 'sops' CLI on PATH; install it "
                "(https://github.com/getsops/sops) before running the contract"
            )
        try:
            completed = subprocess.run(
                # argv list (never shell=True): the binary + flags are
                # operator-controlled, the only variable is the file path.
                [sops_bin, "-d", str(path)],
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError as exc:
            _LOG.debug("sops binary %r not found: %s", sops_bin, exc)
            raise SecretResolutionError(
                f"sops binary {sops_bin!r} could not be executed: {exc}"
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            _LOG.debug("sops -d %s failed (rc=%s): %s", path, exc.returncode, stderr)
            raise SecretResolutionError(
                f"sops failed to decrypt {str(path)!r} (exit {exc.returncode}): {stderr}"
            ) from exc
        try:
            document = yaml.safe_load(completed.stdout)
        except yaml.YAMLError as exc:
            _LOG.debug("sops output for %s is not valid YAML/JSON: %s", path, exc)
            raise SecretResolutionError(
                f"sops decrypted {str(path)!r} but the output is not valid YAML/JSON: {exc}"
            ) from exc
        return self._walk_dotted(document, dotted, source=str(path))

    @staticmethod
    def _walk_dotted(document: Any, dotted: str, *, source: str) -> str:
        """Walk a ``.``-separated key path into a decoded mapping."""
        node: Any = document
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                raise SecretResolutionError(
                    f"sops secret {source!r} has no key {dotted!r} (stopped at segment {part!r})"
                )
            node = node[part]
        if isinstance(node, dict | list):
            # A structured value cannot stand in for a single secret string;
            # serialise it so the failure is explicit rather than a stringified
            # dict leaking into a credential.
            return json.dumps(node)
        return str(node)


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
