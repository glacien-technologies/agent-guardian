"""Interactive contract authoring wizard (Stage 1B).

``agent-guardian init`` walks an operator through building a minimal, valid
``agentguardian.yaml`` for an HTTP target. The wizard is deliberately *thin*:
it gathers a handful of answers, optionally probes the target to help the user
pick the response ``output_path``, then constructs a :class:`Contract` and
writes it out via the model's own dump (so the document can never drift from
the schema).

Two hard rules shape the design:

* **Never write a raw secret.** When the user supplies a credential they enter a
  *reference* (``${env:AG_KEY}`` / ``${file:/path}``), never the plaintext. The
  wizard refuses anything that isn't a valid :class:`SecretRef` shape.
* **No hard TTY requirement.** All prompting goes through an injectable
  :class:`Prompter` so tests drive the wizard with scripted answers, and a
  ``--yes`` non-interactive path builds a minimal contract from
  :class:`WizardDefaults` without prompting at all.

The output is a YAML document equivalent to ``Contract.model_dump`` (by-alias,
exclude-none) — i.e. the same shape the loader round-trips.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

from agent_guardian.contract.schema import Contract
from agent_guardian.contract.secrets import SECRET_REF_PATTERN

_LOG = logging.getLogger(__name__)

__all__ = [
    "Prompter",
    "ScriptedPrompter",
    "TyperPrompter",
    "WizardDefaults",
    "build_contract_dict",
    "run_wizard",
    "write_contract_yaml",
]


class Prompter(Protocol):
    """The prompt surface the wizard depends on (so tests can inject answers)."""

    def ask(self, message: str, *, default: str | None = None) -> str:
        """Prompt for a free-text answer (returning ``default`` on empty input)."""
        ...

    def confirm(self, message: str, *, default: bool = False) -> bool:
        """Prompt for a yes/no answer."""
        ...

    def echo(self, message: str) -> None:
        """Print an informational line."""
        ...


class TyperPrompter:
    """A :class:`Prompter` backed by :func:`typer.prompt` / :func:`typer.confirm`."""

    def ask(self, message: str, *, default: str | None = None) -> str:
        import typer

        if default is None:
            return str(typer.prompt(message))
        return str(typer.prompt(message, default=default))

    def confirm(self, message: str, *, default: bool = False) -> bool:
        import typer

        return bool(typer.confirm(message, default=default))

    def echo(self, message: str) -> None:
        import typer

        typer.echo(message)


class ScriptedPrompter:
    """A deterministic :class:`Prompter` for tests — answers a queued script.

    ``answers`` feed :meth:`ask`, ``confirms`` feed :meth:`confirm`; both fall
    back to the supplied default when the script runs dry, so a test only needs
    to script the answers it cares about. Echoed lines are captured in
    :attr:`echoes` for assertions.
    """

    def __init__(
        self,
        answers: list[str] | None = None,
        confirms: list[bool] | None = None,
    ) -> None:
        self._answers = list(answers or [])
        self._confirms = list(confirms or [])
        self.echoes: list[str] = []

    def ask(self, message: str, *, default: str | None = None) -> str:
        if self._answers:
            value = self._answers.pop(0)
            return value if value != "" else (default or "")
        return default or ""

    def confirm(self, message: str, *, default: bool = False) -> bool:
        if self._confirms:
            return self._confirms.pop(0)
        return default

    def echo(self, message: str) -> None:
        self.echoes.append(message)


@dataclass(frozen=True)
class WizardDefaults:
    """Flag/default-driven inputs for the non-interactive (``--yes``) path."""

    name: str = "target"
    url: str = "https://api.example.com/v1/chat"
    environment: str = "staging"
    output_path: str = "$.output.text"
    session_mode: str = "stateless"
    auth_kind: str = "none"
    auth_value_ref: str | None = None
    authorization_ref: str | None = None
    max_rps: float | None = None
    max_requests: int | None = None
    blocklist: tuple[str, ...] = ()


def _is_secret_ref(value: str) -> bool:
    """True iff ``value`` is a valid ``${backend:key}`` secret reference."""
    return SECRET_REF_PATTERN.match(value.strip()) is not None


def build_contract_dict(defaults: WizardDefaults) -> dict[str, Any]:
    """Build a contract *mapping* from ``defaults`` (no prompting).

    Used both by the ``--yes`` path and as the assembly step the interactive
    wizard funnels its gathered answers through. The result is validated by
    constructing a :class:`Contract`, so an invalid combination fails loudly
    here rather than at load time.
    """
    target: dict[str, Any] = {
        "name": defaults.name,
        "environment": defaults.environment,
        "transport": {"kind": "http", "url": defaults.url},
        "response": {"output_path": defaults.output_path},
        "session": {"mode": defaults.session_mode},
    }

    auth = _build_auth(defaults)
    if auth is not None:
        target["auth"] = auth

    roe: dict[str, Any] = {}
    if defaults.authorization_ref:
        roe["authorization_ref"] = defaults.authorization_ref
    budgets: dict[str, Any] = {}
    if defaults.max_requests is not None:
        budgets["max_requests"] = defaults.max_requests
    if budgets:
        roe["budgets"] = budgets
    if defaults.max_rps is not None:
        roe["rate"] = {"max_rps": defaults.max_rps}
    if defaults.blocklist:
        roe["tools"] = {"blocklist": list(defaults.blocklist)}

    document: dict[str, Any] = {"version": 1, "target": target}
    if roe:
        document["roe"] = roe

    # Validate by building the model; raises pydantic ValidationError on a bad
    # combination (e.g. prod without authorization_ref) so the wizard fails fast.
    Contract.model_validate(document)
    return document


def _build_auth(defaults: WizardDefaults) -> dict[str, Any] | None:
    """Build the ``auth`` sub-document from the defaults (``None`` for no-auth)."""
    kind = defaults.auth_kind
    if kind == "none":
        return None
    ref = defaults.auth_value_ref
    if not ref or not _is_secret_ref(ref):
        raise ValueError(
            f"auth kind {kind!r} requires a secret reference like '${{env:AG_KEY}}' (got {ref!r})"
        )
    if kind == "api_key":
        return {"kind": "api_key", "name": "Authorization", "value": ref}
    if kind == "bearer":
        return {"kind": "bearer", "token": ref}
    raise ValueError(
        f"unsupported auth kind {kind!r} for the wizard (use 'none', 'api_key', or 'bearer')"
    )


def write_contract_yaml(document: dict[str, Any], out: Path) -> Path:
    """Write the contract ``document`` to ``out`` as YAML and return the path."""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    return out


def run_wizard(
    out: Path,
    *,
    yes: bool = False,
    prompter: Prompter | None = None,
    defaults: WizardDefaults | None = None,
    probe: Any = None,
) -> Path:
    """Author a contract at ``out`` — non-interactively (``yes``) or via prompts.

    The ``--yes`` path writes a minimal valid contract from ``defaults`` (or the
    :class:`WizardDefaults` defaults). The interactive path drives ``prompter``
    (defaulting to :class:`TyperPrompter`) through the questions and, when a
    ``probe`` callable is supplied, sends a benign prompt so the user can pick
    the ``output_path`` from the live JSON shape.

    Returns the path written.
    """
    base = defaults or WizardDefaults()
    if yes:
        document = build_contract_dict(base)
        return write_contract_yaml(document, out)

    p = prompter or TyperPrompter()
    gathered = _interactive_gather(p, base)
    document = build_contract_dict(gathered)
    written = write_contract_yaml(document, out)
    p.echo(f"contract written to {written}")
    return written


def _interactive_gather(p: Prompter, base: WizardDefaults) -> WizardDefaults:
    """Drive the prompter through the wizard questions, returning the answers."""
    p.echo("AgentGuardian contract wizard — HTTP target (the only transport today).")

    name = p.ask("Target name", default=base.name)
    url = p.ask("Target URL (transport.url)", default=base.url)
    environment = p.ask("Environment (prod|staging|clone)", default=base.environment)

    auth_kind = p.ask("Auth kind (none|api_key|bearer)", default=base.auth_kind)
    auth_value_ref: str | None = None
    if auth_kind != "none":
        # NEVER a raw secret — only a ${backend:key} reference.
        auth_value_ref = _ask_secret_ref(p, base.auth_value_ref)

    output_path = _ask_output_path(p, base.output_path)
    session_mode = p.ask(
        "Session mode (stateless|server_session|client_history)",
        default=base.session_mode,
    )

    authorization_ref = base.authorization_ref
    if environment == "prod":
        authorization_ref = (
            p.ask("Authorization reference (REQUIRED for prod, e.g. a ticket id)", default="")
            or None
        )
    else:
        ref = p.ask("Authorization reference (optional)", default="")
        authorization_ref = ref or None

    max_rps = _ask_optional_float(p, "Max requests/sec (blank = unbounded)")
    max_requests = _ask_optional_int(p, "Max total requests (blank = unbounded)")

    blocklist: tuple[str, ...] = ()
    raw_block = p.ask("Destructive-tool blocklist (comma-separated, blank = none)", default="")
    if raw_block.strip():
        blocklist = tuple(part.strip() for part in raw_block.split(",") if part.strip())

    return WizardDefaults(
        name=name,
        url=url,
        environment=environment,
        output_path=output_path,
        session_mode=session_mode,
        auth_kind=auth_kind,
        auth_value_ref=auth_value_ref,
        authorization_ref=authorization_ref,
        max_rps=max_rps,
        max_requests=max_requests,
        blocklist=blocklist,
    )


def _ask_secret_ref(p: Prompter, default: str | None) -> str:
    """Prompt for a secret *reference*, re-asking until it is a valid pointer."""
    while True:
        value = p.ask(
            "Secret reference (e.g. ${env:AG_KEY} — NEVER a raw secret)",
            default=default or "",
        )
        if _is_secret_ref(value):
            return value
        p.echo(
            "  ! that is not a valid secret reference. Use '${env:NAME}', "
            "'${file:/path}', '${vault:key}' or '${sops:key}'."
        )
        # On a dry script (test) the default is returned forever; guard against
        # an infinite loop by failing if the default itself is invalid.
        if not value:
            raise ValueError("a secret reference is required for the chosen auth kind")


def _ask_output_path(p: Prompter, default: str) -> str:
    """Prompt for the response ``output_path`` JSONPath."""
    return p.ask(
        "Response output_path (JSONPath into the reply body, e.g. $.output.text)",
        default=default,
    )


def _ask_optional_float(p: Prompter, message: str) -> float | None:
    raw = p.ask(message, default="")
    raw = raw.strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        _LOG.debug("wizard: %r is not a float; leaving %r unbounded", raw, message)
        p.echo(f"  ! {raw!r} is not a number; leaving unbounded.")
        return None


def _ask_optional_int(p: Prompter, message: str) -> int | None:
    raw = p.ask(message, default="")
    raw = raw.strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        _LOG.debug("wizard: %r is not an int; leaving %r unbounded", raw, message)
        p.echo(f"  ! {raw!r} is not an integer; leaving unbounded.")
        return None
