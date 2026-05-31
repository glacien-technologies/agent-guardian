"""AgentGuardian CLI -- production command surface (PRD §8, M10).

The CLI is the primary user-facing way to drive a swarm scan. The full
command set lands here in M10; later milestones flesh out individual
sub-commands (M11 adds probe content, M12 fills in ``serve``, M13 adds
PDF output and signed-evidence ``verify``).

Design points worth knowing:

* The CLI is a thin wrapper around the library API. Anything the CLI
  can do is also reachable from Python -- :func:`build_llm`,
  :func:`build_target_adapter`, and :func:`build_swarm` are the wedge
  the CLI uses, and any of them is importable for power users.
* ``--model stub`` is the universal safe default. Every command that
  needs an LLM tolerates ``stub`` so the test suite (and curious
  users) can run the whole pipeline without API keys.
* The first-run ethical-use banner (PRD §15.6) is printed once per
  user and remembered in ``~/.agentguardian/state.json``. We never
  inspect the CI environment to suppress it -- the state file is
  sufficient.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import typer

from agent_guardian._version import __version__
from agent_guardian.adapters.base import TargetAdapter
from agent_guardian.adapters.code import CodeAdapter
from agent_guardian.adapters.framework import (
    ADKAdapter,
    AutoGenAdapter,
    CrewAIAdapter,
    FrameworkAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
    StrandsAdapter,
)
from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.config import Config, env_api_key, load_config
from agent_guardian.contract.preflight import PreflightReport
from agent_guardian.core.sandbox import SandboxViolation
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm import (
    AnthropicClient,
    BaseLLM,
    GeminiClient,
    LLMAuthError,
    LLMError,
    OllamaClient,
    OpenAIClient,
    StubScript,
)
from agent_guardian.logging_setup import configure_logging
from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import (
    SeverityBand,
    band_for_score,
    colour_for_band,
)
from agent_guardian.models.tier import Tier

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exit codes (PRD §8.4)
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_FAIL_UNDER = 1
EXIT_CONFIG = 2
EXIT_TARGET_UNREACHABLE = 3
EXIT_LLM_PROVIDER = 4
EXIT_SANDBOX = 5
EXIT_USER_INTERRUPT = 130


# ---------------------------------------------------------------------------
# Framework adapter registry (--framework dispatch)
# ---------------------------------------------------------------------------
#
# The CLI's ``--framework KIND`` flag maps a short token (langgraph / crewai /
# autogen / openai_agents / strands / adk) to the concrete :class:`FrameworkAdapter`
# subclass that wraps the matching framework-native object. The actual native
# object is supplied via ``--framework-ref MODULE:ATTR`` -- the CLI imports the
# module and pulls the attribute, then constructs the adapter with it.
#
# Listed in alphabetical order so the error message is deterministic.

FRAMEWORK_ADAPTERS: dict[str, type[FrameworkAdapter]] = {
    "adk": ADKAdapter,
    "autogen": AutoGenAdapter,
    "crewai": CrewAIAdapter,
    "langgraph": LangGraphAdapter,
    "openai_agents": OpenAIAgentsAdapter,
    "strands": StrandsAdapter,
}


def _resolve_framework_ref(ref: str) -> Any:
    """Resolve ``MODULE:ATTR`` (or ``MODULE.ATTR``) to a Python object.

    Used by ``--framework-ref`` so the operator can name their framework-native
    object (compiled LangGraph, CrewAI ``Crew``, AutoGen group chat, etc.)
    without writing a wrapper script. The colon form is preferred; the dotted
    form is accepted for ergonomics. The module is imported normally, so any
    side-effects of import (logging setup, env reads) fire exactly as they
    would in the operator's own process.
    """
    raw = ref.strip()
    if not raw:
        raise typer.BadParameter(
            "--framework-ref is empty -- expected MODULE:ATTR (e.g. 'my_app.graph:graph')."
        )
    if ":" in raw:
        module_name, _, attr_path = raw.partition(":")
    else:
        # Dotted form: rightmost dot splits module from attr.
        if "." not in raw:
            raise typer.BadParameter(
                f"--framework-ref {ref!r} is not in MODULE:ATTR (or MODULE.ATTR) form. "
                "Example: 'my_app.graph:graph' or 'my_app.graph.graph'."
            )
        module_name, _, attr_path = raw.rpartition(".")
    if not module_name or not attr_path:
        raise typer.BadParameter(
            f"--framework-ref {ref!r}: both module and attribute must be non-empty."
        )
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise typer.BadParameter(
            f"--framework-ref {ref!r}: could not import module {module_name!r} ({exc})."
        ) from exc
    obj: Any = module
    for part in attr_path.split("."):
        try:
            obj = getattr(obj, part)
        except AttributeError as exc:
            raise typer.BadParameter(
                f"--framework-ref {ref!r}: attribute path "
                f"{attr_path!r} not found on module {module_name!r} ({exc})."
            ) from exc
    return obj


# ---------------------------------------------------------------------------
# Ordered ASI agent slate -- single source of truth for ``list-agents`` etc.
# ---------------------------------------------------------------------------


_AGENT_SLATE: tuple[tuple[str, AsiCategory], ...] = (
    ("recon-agent", AsiCategory.ASI01),  # Recon has no category; we list ASI01 for layout.
    ("goal-hijack-agent", AsiCategory.ASI01),
    ("tool-abuse-agent", AsiCategory.ASI02),
    ("privilege-agent", AsiCategory.ASI03),
    ("supply-chain-agent", AsiCategory.ASI04),
    ("code-exec-agent", AsiCategory.ASI05),
    ("memory-poison-agent", AsiCategory.ASI06),
    ("a2a-agent", AsiCategory.ASI07),
    ("cascade-agent", AsiCategory.ASI08),
    ("trust-exploit-agent", AsiCategory.ASI09),
    ("drift-agent", AsiCategory.ASI10),
)


# ---------------------------------------------------------------------------
# Typer app + sub-app
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="agent-guardian",
    help="Adversarial swarm framework for agentic AI red-teaming.",
    no_args_is_help=True,
    add_completion=False,
)

telemetry_app = typer.Typer(
    name="telemetry",
    help="Opt-in usage telemetry (consent + status).",
    no_args_is_help=True,
)
app.add_typer(telemetry_app, name="telemetry")

contract_app = typer.Typer(
    name="contract",
    help="Work with target contracts (schema export, migration).",
    no_args_is_help=True,
)
app.add_typer(contract_app, name="contract")

# Management sub-app for stored scans. Registered under ``scans`` (plural) to
# avoid colliding with the top-level ``scan`` run command. Provides delete,
# purge --older-than, and list against ``AGENT_GUARDIAN_HOME`` (default
# ``~/.agentguardian``).
scan_app = typer.Typer(
    name="scans",
    help="Manage stored scans (list, delete, purge --older-than).",
    no_args_is_help=True,
)
app.add_typer(scan_app, name="scans")


# ---------------------------------------------------------------------------
# State persistence (first-run banner, last-score)
# ---------------------------------------------------------------------------


def _state_dir() -> Path:
    return Path.home() / ".agentguardian"


def _state_path() -> Path:
    return _state_dir() / "state.json"


def _read_state() -> dict[str, Any]:
    path = _state_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover -- defensive
        _LOG.warning(
            "cli: could not read state file %s (%s) -- starting with empty state",
            path,
            exc,
        )
        return {}
    if not isinstance(data, dict):  # pragma: no cover -- defensive
        _LOG.warning(
            "cli: state file %s is not a JSON object (got %s) -- discarding",
            path,
            type(data).__name__,
        )
        return {}
    return data


def _write_state(state: dict[str, Any]) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


_BANNER = (
    "AgentGuardian is intended for authorised security testing only. By using\n"
    "this tool you confirm you have permission to scan the target system. See\n"
    "the LICENSE and SECURITY.md for the full ethical-use policy.\n"
)


def _try_load_dotenv() -> None:
    """Load ``.env`` from the current working directory if python-dotenv is installed.

    Project-local only by design: we look in ``Path.cwd()`` (not ``$HOME``
    or arbitrary ancestors) so users running ``agent-guardian`` against
    different projects don't accidentally leak API keys across projects.
    Existing environment variables are never overridden -- real shell exports
    always win.

    The lookup is non-fatal: if python-dotenv is not installed (it's in the
    ``dev`` extra, not the base deps), or if no ``.env`` file is present,
    this is a silent no-op. Production users who want to avoid the dotenv
    dependency simply export their keys in the usual way.
    """
    try:
        from dotenv import load_dotenv
    except ImportError as exc:
        _LOG.debug("cli: python-dotenv not installed (%s) -- skipping .env auto-load", exc)
        return
    cwd = Path.cwd()
    for candidate in (cwd / ".env", cwd / ".env.local"):
        if candidate.is_file():
            _LOG.debug("cli: loading .env file %s", candidate)
            load_dotenv(candidate, override=False)


def _show_ethical_banner_once() -> None:
    """Print the ethical-use banner the first time a user runs a scan."""
    state = _read_state()
    if state.get("ethical_use_acknowledged"):
        return
    typer.echo(_BANNER)
    state["ethical_use_acknowledged"] = True
    state["ethical_use_acknowledged_at"] = datetime.now(tz=timezone.utc).isoformat()
    # Best-effort -- a read-only home shouldn't break the scan.
    with contextlib.suppress(OSError):
        _write_state(state)


# ---------------------------------------------------------------------------
# LLM construction
# ---------------------------------------------------------------------------


def build_llm(model_spec: str, role: str) -> BaseLLM:
    """Resolve a model spec to a concrete :class:`BaseLLM`.

    Specs:

    * ``"stub"`` (or ``""``) → deterministic :class:`StubLLM`. No keys
      required. Safe for tests and dry runs.
    * ``"openai:<model>"`` / heuristic ``"gpt-*"`` → :class:`OpenAIClient`.
    * ``"anthropic:<model>"`` / heuristic ``"claude-*"`` → :class:`AnthropicClient`.
    * ``"gemini:<model>"`` / heuristic ``"gemini-*"`` → :class:`GeminiClient`
      (Google AI Studio API; see :mod:`agent_guardian.llm.gemini`).
    * ``"ollama:<model>"`` → :class:`OllamaClient` (local -- no key).
    * ``"bedrock:<bedrock-model-id>"`` → :class:`BedrockClient`. No
      heuristic prefix is supported (Bedrock IDs all start with
      ``anthropic.`` / ``amazon.`` / etc., so the ``bedrock:`` prefix
      is mandatory). Credentials come from the standard AWS chain -- no
      ``--api-key`` is consulted. Requires the ``[aws]`` extra.

    The role string is used only in error messages so the user knows
    which LLM slot misconfigured.
    """
    spec = (model_spec or "stub").strip()
    if spec.lower() == "stub":
        return StubScript().default(f"[stub:{role}] safe default response").build()

    provider: str
    model: str
    if ":" in spec:
        provider, _, model = spec.partition(":")
        provider = provider.lower()
    else:
        lowered = spec.lower()
        if lowered.startswith("gpt-"):
            provider, model = "openai", spec
        elif lowered.startswith("claude-"):
            provider, model = "anthropic", spec
        elif lowered.startswith("gemini-"):
            provider, model = "gemini", spec
        elif lowered.startswith("ollama-"):
            provider, model = "ollama", spec
        else:
            raise typer.BadParameter(
                f"Cannot infer provider for model spec '{spec}' (role={role}). "
                f"Use one of: stub, openai:<model>, anthropic:<model>, "
                f"gemini:<model>, ollama:<model>, bedrock:<id>."
            )

    if provider == "stub":
        return StubScript().default(f"[stub:{role}] safe default response").build()
    if provider == "ollama":
        # OllamaClient takes no auth; the model is supplied per-request via
        # the swarm's ``attacker_model`` / ``evaluator_model`` config knobs.
        _ = model
        return OllamaClient()
    if provider == "openai":
        api_key = env_api_key("openai")
        if not api_key:
            raise typer.BadParameter(
                f"OpenAI requested for {role} but no API key found. "
                f"Set AGENT_GUARDIAN_OPENAI_API_KEY or OPENAI_API_KEY."
            )
        return OpenAIClient(api_key=api_key)
    if provider == "anthropic":
        api_key = env_api_key("anthropic")
        if not api_key:
            raise typer.BadParameter(
                f"Anthropic requested for {role} but no API key found. "
                f"Set AGENT_GUARDIAN_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY."
            )
        return AnthropicClient(api_key=api_key)
    if provider == "gemini":
        api_key = env_api_key("gemini")
        if not api_key:
            raise typer.BadParameter(
                f"Gemini requested for {role} but no API key found. "
                f"Set AGENT_GUARDIAN_GEMINI_API_KEY, GEMINI_API_KEY, or GOOGLE_API_KEY."
            )
        return GeminiClient(api_key=api_key)
    if provider == "bedrock":
        # Bedrock uses the AWS credential chain (env vars > ~/.aws/credentials
        # > IAM role). It deliberately does NOT consult ``env_api_key`` --
        # there is no such thing as a Bedrock API key.
        try:
            from agent_guardian.llm.bedrock import BedrockClient
        except ImportError as exc:
            raise typer.BadParameter(
                f"Bedrock requested for {role} but the AWS extra is not installed. "
                f"Install with: pip install 'agent-guardian[aws]' "
                f"(import error: {exc})"
            ) from exc
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        try:
            return BedrockClient(region=region)
        except LLMAuthError as exc:
            raise typer.BadParameter(
                f"Bedrock requested for {role} but credentials are missing: {exc}"
            ) from exc
    if provider == "vertex":
        # #15 — Vertex AI is request-builder-only until M9 lands OAuth2 SA
        # auth. Refuse with a clear M9-pending message instead of letting the
        # spec fall through to the generic "Unknown provider" error, which
        # mismatches the ``doctor`` surface and the ``llm.vertex`` module's
        # own claim of provider support.
        raise typer.BadParameter(
            f"Vertex AI requested for {role} but provider authentication is M9-"
            "pending (request-builder + response-mapper only). See "
            "docs/providers/vertex.md for the M9 roadmap. Use openai:<model>, "
            "anthropic:<model>, gemini:<model>, ollama:<model>, or bedrock:<id> "
            "in the meantime."
        )
    raise typer.BadParameter(
        f"Unknown provider '{provider}' for model spec '{spec}' (role={role})."
    )


def _normalise_model_name(model_spec: str) -> str:
    """Return the bare model name a swarm config expects (no provider prefix)."""
    spec = (model_spec or "stub").strip()
    if ":" in spec:
        _, _, model = spec.partition(":")
        return model or spec
    return spec


# ---------------------------------------------------------------------------
# Target construction
# ---------------------------------------------------------------------------


def build_target_adapter(
    *,
    target: str | None,
    system_prompt_path: Path | None,
    endpoint: str | None,
    framework: str | None,
    framework_ref: str | None = None,
    target_llm: BaseLLM,
    target_model: str,
) -> TargetAdapter:
    """Build the right :class:`TargetAdapter` from the four CLI modes.

    Exactly one of ``target`` / ``system_prompt_path`` / ``endpoint`` /
    ``framework`` must be set. ``framework`` dispatches through
    :data:`FRAMEWORK_ADAPTERS` and pulls the framework-native object from
    ``framework_ref`` (MODULE:ATTR).
    """
    set_modes = [bool(system_prompt_path), bool(target), bool(endpoint), bool(framework)]
    if sum(set_modes) == 0:
        raise typer.BadParameter(
            "scan requires a target -- pass a dotted path, --system-prompt PATH, "
            "--endpoint URL, or --framework KIND."
        )
    if sum(set_modes) > 1:
        raise typer.BadParameter(
            "scan target modes are mutually exclusive -- choose exactly one of "
            "target / --system-prompt / --endpoint / --framework."
        )
    if system_prompt_path is not None:
        if not system_prompt_path.is_file():
            raise typer.BadParameter(f"system prompt file not found: {system_prompt_path}")
        prompt_text = system_prompt_path.read_text(encoding="utf-8")
        return PromptAdapter(
            prompt_text,
            llm=target_llm,
            model=target_model,
            ref=str(system_prompt_path),
        )
    if target:
        return CodeAdapter(target)
    if endpoint:
        return HttpAdapter(endpoint=endpoint, shape="generic")
    # framework branch -- dispatch through FRAMEWORK_ADAPTERS.
    assert framework is not None  # set_modes guard above
    kind = framework.strip().lower()
    adapter_cls = FRAMEWORK_ADAPTERS.get(kind)
    if adapter_cls is None:
        supported = ", ".join(sorted(FRAMEWORK_ADAPTERS))
        raise typer.BadParameter(
            f"unknown --framework {framework!r}. Supported kinds: {supported}."
        )
    if not framework_ref:
        raise typer.BadParameter(
            f"--framework {kind} requires --framework-ref MODULE:ATTR pointing at "
            f"your framework-native object (e.g. compiled graph, Crew, group chat)."
        )
    native_obj = _resolve_framework_ref(framework_ref)
    # Every registered subclass takes ``(native_obj, *, ref=...)``; the base
    # class deliberately doesn't, so we route through Any to keep mypy --strict
    # happy without weakening every subclass's signature.
    factory: Any = adapter_cls
    try:
        return factory(native_obj, ref=framework_ref)  # type: ignore[no-any-return]
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter(
            f"--framework {kind}: adapter rejected the object from {framework_ref!r}: {exc}"
        ) from exc


# Placeholder hosts we never preflight against (would fail by design).
_PLACEHOLDER_HOST_SUFFIXES: tuple[str, ...] = (".example.com", ".example.org", ".example.net")
_PLACEHOLDER_HOSTS: frozenset[str] = frozenset({"example.com", "example.org", "example.net"})


def _is_placeholder_endpoint(url: str) -> bool:
    """True iff ``url``'s host is a documentation/scaffold placeholder.

    Used by the endpoint preflight and the ``init --yes`` flow so a freshly
    scaffolded contract isn't pre-flighted against ``api.example.com``.
    """
    from urllib.parse import urlparse

    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:  # pragma: no cover -- defensive
        return False
    if not host:
        return False
    if host in _PLACEHOLDER_HOSTS:
        return True
    return any(host.endswith(suffix) for suffix in _PLACEHOLDER_HOST_SUFFIXES)


async def _endpoint_reachability_preflight(
    endpoint: str,
    *,
    sample_body: dict[str, Any] | None = None,
) -> bool:
    """Probe ``endpoint`` twice with a short timeout. Return True iff reachable.

    Used before an ``--endpoint`` scan so an unreachable target fails fast with
    :data:`EXIT_TARGET_UNREACHABLE` instead of spending the LLM budget on
    every-probe timeouts.

    Body selection (in order of preference):

    1. ``sample_body`` if supplied — used verbatim. Intended for the
       contract-driven path which knows the on-wire shape.
    2. Otherwise a minimal ``{"input": "ping"}`` JSON body, which matches the
       de-facto convention most agent ``/chat`` endpoints accept. This avoids
       the spurious ``422 Unprocessable Entity`` that FastAPI returns when the
       endpoint declares a required body model and we POST an empty payload.

    Any HTTP response — including ``4xx`` (yes, even ``422``) — counts as
    "reachable". A schema-protected ``422`` proves the target is up and
    answering; it is an operator-config concern, not a transport fault.
    The only failure mode that marks the target down is a connect/timeout
    error across BOTH attempts. The timeout is generous (5s) to absorb Cloud
    Run cold starts.
    """
    import httpx

    # Cold-start-tolerant preflight: 3 attempts with progressive per-attempt
    # timeouts (5s, 10s, 15s; ≤30s total worst-case). Cloud Run / Lambda /
    # Knative often spin down after a few minutes idle; the first POST after
    # spin-down can take 6-12s for container boot + TLS handshake + first
    # response. A flat 5s x 2 (the previous code) routinely false-positived
    # UNREACHABLE against fully-healthy testbenches. Empirically attempt 1
    # succeeds for warm targets (~250ms); attempt 2 catches cold starts
    # (~5-10s); attempt 3 is the long-tail backstop.
    body: dict[str, Any] = sample_body if sample_body is not None else {"input": "ping"}
    per_attempt_timeouts = (5.0, 10.0, 15.0)
    last_exc: Exception | None = None
    for attempt, secs in enumerate(per_attempt_timeouts):
        async with httpx.AsyncClient(timeout=httpx.Timeout(secs)) as client:
            try:
                await client.post(endpoint, json=body)
                # Any HTTP response (200, 404, 422, 500, …) means the listener
                # is up. 422 from a schema-protected FastAPI endpoint is the
                # canonical "reachable, schema-protected" case — log it but do
                # NOT treat it as unreachable.
                if attempt > 0:
                    _LOG.info(
                        "endpoint preflight: %s reachable after %d attempt(s) "
                        "(target was likely cold-starting)",
                        endpoint,
                        attempt + 1,
                    )
                return True
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                last_exc = exc
                _LOG.debug(
                    "endpoint preflight: attempt %d/%d for %s failed (%s)",
                    attempt + 1,
                    len(per_attempt_timeouts),
                    endpoint,
                    exc,
                )
            except httpx.HTTPError as exc:
                # Any other transport error (PoolTimeout, RemoteProtocolError, etc.)
                # is treated as "reachable" -- we got far enough to be the
                # target's problem, not the network's.
                _LOG.debug(
                    "endpoint preflight: non-fatal HTTP error %s (%s) -- counted as reachable",
                    endpoint,
                    exc,
                )
                return True
    if last_exc is not None:
        _LOG.warning(
            "endpoint preflight: %s unreachable after %d attempts (last error: %s)",
            endpoint,
            len(per_attempt_timeouts),
            last_exc,
        )
    return False


# ---------------------------------------------------------------------------
# Contract-driven scan wiring (Stage 1B)
# ---------------------------------------------------------------------------


class _ContractScanContext:
    """Everything the contract path contributes to a scan, built up front.

    Bundles the loaded contract, the RoE controller, the contract-built target
    adapter, and the swarm-config overrides the RoE budgets project onto the
    engine's knobs. Kept as a small carrier so :func:`_run_scan` can stay a thin
    splice over the unchanged non-contract path.
    """

    def __init__(self, contract_path: Path, *, otel_endpoint: str | None = None) -> None:
        from agent_guardian.contract import contract_sha256, load_contract
        from agent_guardian.core.roe import RoeController, authorization_gate
        from agent_guardian.obs.otel import configure_otel, make_otel_observer
        from agent_guardian.transports.contract_adapter import build_contract_target_adapter

        self.contract = load_contract(contract_path)
        # Defensive runtime re-check of the prod-requires-authorization invariant
        # (the loader enforces it at parse time; a migrated/hand-built contract
        # could in principle slip through, so we gate again here).
        authorization_gate(self.contract)
        self.contract_sha256 = contract_sha256(self.contract)
        self.roe = RoeController.from_contract(self.contract)
        self.adapter = build_contract_target_adapter(self.contract, roe=self.roe)
        self.swarm_overrides = self.roe.swarm_overrides()
        # OTel rides the observer + exporter seams -- both no-op unless the
        # operator opted into the experimental GenAI conventions, so the default
        # install pays nothing. Precedence: the contract's
        # ``observability.otel_endpoint`` wins iff the contract sets one;
        # otherwise we fall through to the outer CLI's ``--otel-endpoint`` flag
        # so a contract with no observability stanza still honours the operator
        # flag instead of silently dropping it.
        observability = self.contract.observability
        contract_endpoint = observability.otel_endpoint if observability is not None else None
        effective_endpoint = contract_endpoint or otel_endpoint
        configure_otel(effective_endpoint)
        self.observer = make_otel_observer()

    def build_audit(self, scan: Scan) -> dict[str, Any]:
        """Snapshot the RoE controller + contract identity into an audit dict."""
        return self.roe.build_audit(
            contract_sha256=self.contract_sha256,
            contract_version=self.contract.version,
            authorization_ref=self.contract.roe.authorization_ref,
            environment=self.contract.target.environment,
            target_name=self.contract.target.name,
            operator=os.getenv("USER", "unknown"),
            budgets_consumed={"tokens": scan.tokens_total},
        ).to_dict()


# ---------------------------------------------------------------------------
# Scan output / reporting
# ---------------------------------------------------------------------------


_TEXT_FORMATS: frozenset[str] = frozenset({"json", "sarif", "junit", "md"})
_ALL_FORMATS: frozenset[str] = _TEXT_FORMATS | {"pdf"}


def _render_scan(scan: Scan, output_format: str) -> str:
    """Render a textual report (returns the in-memory string).

    PDF is handled separately because it's binary and goes straight to disk.
    """
    if output_format not in _TEXT_FORMATS:
        raise typer.BadParameter(
            f"unknown output format '{output_format}' "
            f"-- choose one of: {', '.join(sorted(_ALL_FORMATS))}"
        )
    if output_format == "json":
        from agent_guardian.reports.json_report import emit_json

        return json.dumps(emit_json(scan), indent=2, sort_keys=True)
    if output_format == "sarif":
        from agent_guardian.reports.sarif import emit_sarif

        return json.dumps(emit_sarif(scan), indent=2, sort_keys=True)
    if output_format == "junit":
        from xml.etree import ElementTree as ET

        from agent_guardian.reports.junit import emit_junit

        root = emit_junit(scan)
        ET.indent(root, space="  ")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
    # markdown
    from agent_guardian.reports.markdown import emit_markdown

    return emit_markdown(scan)


def _write_report(scan: Scan, output_format: str, path: Path) -> None:
    """Persist the chosen report format at ``path``."""
    if output_format not in _ALL_FORMATS:
        raise typer.BadParameter(
            f"unknown output format '{output_format}' "
            f"-- choose one of: {', '.join(sorted(_ALL_FORMATS))}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        from agent_guardian.reports.json_report import write_json

        write_json(scan, path)
        return
    if output_format == "sarif":
        from agent_guardian.reports.sarif import write_sarif

        write_sarif(scan, path)
        return
    if output_format == "junit":
        from agent_guardian.reports.junit import write_junit

        write_junit(scan, path)
        return
    if output_format == "md":
        from agent_guardian.reports.markdown import write_markdown

        write_markdown(scan, path)
        return
    # pdf
    from agent_guardian.reports.pdf import write_pdf

    write_pdf(scan, path)


# ---------------------------------------------------------------------------
# Badge SVG (for the badge command + future README integrations)
# ---------------------------------------------------------------------------


def _badge_svg(score: int) -> str:
    """Generate a small AIVSS badge SVG using the M2 band → colour map."""
    band = band_for_score(score)
    colour = colour_for_band(band)
    label = "AIVSS"
    value = str(score)
    label_width = 60
    value_width = 50
    total = label_width + value_width
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {value}">\n'
        f'  <linearGradient id="s" x2="0" y2="100%">\n'
        f'    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>\n'
        f'    <stop offset="1" stop-opacity=".1"/>\n'
        f"  </linearGradient>\n"
        f'  <mask id="m"><rect width="{total}" height="20" rx="3" fill="#fff"/></mask>\n'
        f'  <g mask="url(#m)">\n'
        f'    <rect width="{label_width}" height="20" fill="#555"/>\n'
        f'    <rect x="{label_width}" width="{value_width}" height="20" fill="{colour}"/>\n'
        f'    <rect width="{total}" height="20" fill="url(#s)"/>\n'
        f"  </g>\n"
        f'  <g fill="#fff" text-anchor="middle" '
        f'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">\n'
        f'    <text x="{label_width / 2}" y="14">{label}</text>\n'
        f'    <text x="{label_width + value_width / 2}" y="14">{value}</text>\n'
        f"  </g>\n"
        f"</svg>\n"
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the installed agent-guardian version and exit."""
    typer.echo(__version__)


@app.command()
def doctor(
    check_connectivity: bool = typer.Option(
        False,
        "--check-connectivity",
        help=(
            "Probe each detected provider with a minimal request to validate the key + "
            "reach the endpoint. Default OFF: key detection alone is zero-cost; "
            "connectivity costs one tiny call per provider (~0 tokens)."
        ),
    ),
) -> None:
    """Verify install, available LLM keys, and runtime prerequisites."""
    typer.echo(f"agent-guardian {__version__}")
    typer.echo("CLI: ok")

    # Python + platform.
    typer.echo(f"python: {sys.version.split()[0]}")

    # Detect available LLM keys. #15 — Vertex is request-builder-only until
    # M9 ships OAuth2 SA auth; we still surface it here so the operator can
    # see the env key landed, but we label it so they don't think a Vertex
    # scan is supported (it isn't yet -- ``build_llm`` raises a clear
    # M9-pending error if they try). Bedrock is intentionally NOT in this loop
    # -- it uses the AWS credential chain (env > ~/.aws/credentials > IAM role),
    # not an API key. Its readiness is reported by `_probe_bedrock_readiness()`.
    found_keys: list[str] = []
    for provider in ("openai", "anthropic", "gemini"):
        if env_api_key(provider):
            found_keys.append(provider)
    if env_api_key("vertex"):
        found_keys.append("vertex (request-builder-only, M9-pending)")
    if found_keys:
        typer.echo(
            "llm keys detected: "
            + ", ".join(found_keys)
            + (
                ""
                if check_connectivity
                else " (NOT validated -- pass --check-connectivity to probe each provider)"
            )
        )
    else:
        typer.echo("llm keys detected: none (use --model stub for offline scans)")

    # Bedrock readiness (AWS credential chain + boto3 + extra). Reported even
    # without --check-connectivity because operators want to know up front
    # whether `bedrock:<id>` will work.
    _probe_bedrock_readiness()

    # Optional connectivity probe. Each provider gets a tiny request that
    # validates auth + reaches the endpoint without burning meaningful tokens.
    if check_connectivity and found_keys:
        _probe_provider_connectivity()

    # Sandbox readiness -- try to import.
    try:
        from agent_guardian.core.sandbox import Sandbox

        _ = Sandbox
        typer.echo("sandbox: importable")
    except Exception as exc:  # pragma: no cover -- defensive
        _LOG.warning("doctor: sandbox import failed: %s: %s", type(exc).__name__, exc)
        typer.echo(f"sandbox: import failed ({type(exc).__name__})")

    # PDF engine readiness (WeasyPrint > reportlab > none). Operators planning
    # to ship `--output pdf` reports need this to be loud at install time.
    _probe_pdf_readiness()

    # OTel / dashboard readiness. Surfaces the [otel] extra status, the GenAI
    # semconv opt-in flag, the exporter endpoint, and whether the dashboard's
    # default port is free.
    _probe_otel_and_dashboard_readiness()

    # State + config locations.
    typer.echo(f"state dir: {_state_dir()}")
    cwd_config = Path.cwd() / ".agentguardian.yaml"
    typer.echo("config (cwd): " + (str(cwd_config) if cwd_config.is_file() else "<not present>"))


def _probe_provider_connectivity() -> None:
    """Issue one minimal validation request per detected provider (#38).

    Reports per-provider outcome on stdout: ``ok`` (200), ``auth-fail`` (401/
    403), ``network-fail`` (any other error). Each probe uses a tight timeout
    so a missing endpoint can't hang the ``doctor`` command. Bedrock is left
    out of the loop today (its AWS SDK probe is heavier and surfaces its own
    SigV4 errors at first use); the operator can run ``aws sts get-caller-
    identity`` for the equivalent check.
    """
    import httpx

    timeout = httpx.Timeout(5.0)
    # OpenAI: GET /v1/models is the canonical key-validation endpoint.
    if env_api_key("openai"):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {env_api_key('openai')}"},
                )
            typer.echo(f"openai connectivity: {_connectivity_label(resp.status_code)}")
        except httpx.HTTPError as exc:
            _LOG.warning("doctor: openai connectivity probe failed (%s)", exc)
            typer.echo("openai connectivity: network-fail")
    # Anthropic: POST /v1/messages max_tokens=1 (smallest possible billed call).
    if env_api_key("anthropic"):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": env_api_key("anthropic") or "",
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-haiku-4-5",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "x"}],
                    },
                )
            typer.echo(f"anthropic connectivity: {_connectivity_label(resp.status_code)}")
        except httpx.HTTPError as exc:
            _LOG.warning("doctor: anthropic connectivity probe failed (%s)", exc)
            typer.echo("anthropic connectivity: network-fail")
    # Gemini: GET /v1beta/models?key=... lists the available model surface.
    if env_api_key("gemini"):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    params={"key": env_api_key("gemini") or ""},
                )
            typer.echo(f"gemini connectivity: {_connectivity_label(resp.status_code)}")
        except httpx.HTTPError as exc:
            _LOG.warning("doctor: gemini connectivity probe failed (%s)", exc)
            typer.echo("gemini connectivity: network-fail")


def _connectivity_label(status_code: int) -> str:
    """Map an HTTP status code to a human-friendly doctor connectivity tag."""
    if 200 <= status_code < 300:
        return "ok"
    if status_code in (401, 403):
        return "auth-fail"
    return f"http-{status_code}"


def _probe_pdf_readiness() -> None:
    """Report which PDF engine (if any) is available for `--output pdf`.

    The PDF writer probes WeasyPrint first (best fidelity) then reportlab as a
    fallback. WeasyPrint needs native libs (cairo / pango / gdk-pixbuf) so an
    importable ``weasyprint`` is not enough -- a tiny write-pdf smoke test would
    be too heavy here; we instead check that the module imports without OSError
    (the native-lib failure mode raises OSError on import).
    """
    import importlib.util

    weasy_version: str | None = None
    reportlab_version: str | None = None
    weasy_native_fail: str | None = None

    if importlib.util.find_spec("weasyprint") is not None:
        try:
            weasy_mod = importlib.import_module("weasyprint")
            weasy_version = getattr(weasy_mod, "__version__", "installed")
        except OSError as exc:
            # libpango/libcairo etc. missing -- common in slim CI containers.
            weasy_native_fail = str(exc).splitlines()[0][:160]
            _LOG.debug("doctor: weasyprint native libs missing (%s)", exc)
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.debug("doctor: weasyprint import failed (%s: %s)", type(exc).__name__, exc)

    if importlib.util.find_spec("reportlab") is not None:
        try:
            reportlab_mod = importlib.import_module("reportlab")
            reportlab_version = getattr(reportlab_mod, "Version", None) or getattr(
                reportlab_mod, "__version__", "installed"
            )
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.debug("doctor: reportlab import failed (%s: %s)", type(exc).__name__, exc)

    weasy_part = (
        f"weasyprint {weasy_version}"
        if weasy_version
        else (
            f"weasyprint installed but native libs missing ({weasy_native_fail})"
            if weasy_native_fail
            else "none"
        )
    )
    reportlab_part = f"reportlab {reportlab_version}" if reportlab_version else "none"
    if weasy_version or reportlab_version:
        typer.echo(f"pdf engine: {weasy_part} | {reportlab_part}")
    else:
        typer.echo(
            f"pdf engine: {weasy_part} | {reportlab_part} -- "
            "pip install 'agent-guardian[full]' or 'agent-guardian[pdf-fallback]' "
            "to enable --output pdf."
        )


def _probe_bedrock_readiness() -> None:
    """Report whether the AWS extra is installed and AWS env is staged.

    Bedrock uses the AWS credential chain (env > ~/.aws/credentials > IAM role),
    not an API key. ``doctor`` reports the extra status, region resolution, and
    which env-bound credential leg is present so operators can fix the missing
    leg before a paid scan.
    """
    import importlib.util

    have_botocore = importlib.util.find_spec("botocore") is not None
    have_boto3 = importlib.util.find_spec("boto3") is not None
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    have_static_keys = bool(os.environ.get("AWS_ACCESS_KEY_ID")) and bool(
        os.environ.get("AWS_SECRET_ACCESS_KEY")
    )
    have_session_token = bool(os.environ.get("AWS_SESSION_TOKEN"))
    have_profile = bool(os.environ.get("AWS_PROFILE"))

    if not (have_botocore and have_boto3):
        typer.echo("bedrock: aws extra not installed (pip install 'agent-guardian[aws]').")
        return

    creds_bits: list[str] = []
    if have_static_keys:
        creds_bits.append("AWS_ACCESS_KEY_ID set")
    if have_session_token:
        creds_bits.append("AWS_SESSION_TOKEN set")
    if have_profile:
        creds_bits.append(f"AWS_PROFILE={os.environ['AWS_PROFILE']}")
    creds_label = (
        ", ".join(creds_bits)
        if creds_bits
        else "no static AWS env (relying on default chain / IAM role)"
    )
    region_label = region or "unset (set AWS_REGION or AWS_DEFAULT_REGION)"
    typer.echo(f"bedrock: aws extra OK, region={region_label}, creds: {creds_label}")


def _probe_otel_and_dashboard_readiness() -> None:
    """Report OTel extra status, GenAI semconv opt-in, exporter endpoint, port 7474.

    The dashboard's default bind port is 7474; surface a port-in-use up front
    so the operator catches a collision at doctor time rather than at serve
    time.
    """
    import importlib.util
    import socket

    have_otel = importlib.util.find_spec("opentelemetry") is not None
    if have_otel:
        semconv_opt_in = os.environ.get("OTEL_SEMCONV_STABILITY_OPT_IN", "")
        exporter_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        semconv_label = semconv_opt_in or "unset (defaults: stable HTTP/RPC, no GenAI)"
        endpoint_label = exporter_endpoint or "unset (OTel will no-op)"
        typer.echo(
            f"otel: extra installed, OTEL_SEMCONV_STABILITY_OPT_IN={semconv_label}, "
            f"OTEL_EXPORTER_OTLP_ENDPOINT={endpoint_label}"
        )
    else:
        typer.echo(
            "otel: extra not installed (pip install 'agent-guardian[otel]'). "
            "Without it the OTel exporter is a no-op."
        )

    port_in_use = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            result = sock.connect_ex(("127.0.0.1", 7474))
            port_in_use = result == 0
    except OSError as exc:  # pragma: no cover -- defensive
        _LOG.debug("doctor: dashboard port probe failed (%s)", exc)
    typer.echo(
        f"dashboard port 7474: {'IN USE (serve will fail or collide)' if port_in_use else 'free'}"
    )


@app.command("list-agents")
def list_agents() -> None:
    """Print the eleven specialist agents with their ASI category."""
    typer.echo("Agent                  ASI    Description")
    typer.echo("-" * 60)
    for name, category in _AGENT_SLATE:
        if name == "recon-agent":
            typer.echo(f"{name:22} n/a    Phase 1 fingerprint refinement")
        else:
            typer.echo(f"{name:22} {category.value}  {asi_description(category)}")


@app.command("list-probes")
def list_probes(
    asi: str | None = typer.Option(None, "--asi", help="Filter by ASI category (e.g. ASI01)."),
) -> None:
    """Print the bundled seed-probe corpus (one line per probe)."""
    from agent_guardian.probes.loader import PROBE_CORPUS_VERSION, load_all_probes

    probes = load_all_probes()
    asi_filter: AsiCategory | None = None
    if asi is not None:
        try:
            asi_filter = AsiCategory(asi)
        except ValueError as exc:
            raise typer.BadParameter(
                f"unknown ASI category '{asi}' -- expected one of "
                f"{', '.join(c.value for c in AsiCategory)}."
            ) from exc
        probes = [p for p in probes if p.asi == asi_filter]

    typer.echo(f"Probe corpus version: {PROBE_CORPUS_VERSION}")
    suffix = f" (filtered by {asi_filter.value})" if asi_filter is not None else ""
    typer.echo(f"Found {len(probes)} probes{suffix}:")
    for probe in probes:
        typer.echo(
            f"  {probe.id}  [{probe.asi.value}/{probe.severity.value}/"
            f"{probe.tier_floor.value}]  {probe.name}"
        )


@app.command()
def badge(
    score: int = typer.Argument(..., min=0, max=100, help="AIVSS score (0-100)."),
    svg: bool = typer.Option(False, "--svg", help="Emit an SVG badge."),
) -> None:
    """Emit an AIVSS badge -- text by default, SVG with ``--svg``."""
    band = band_for_score(score)
    if svg:
        typer.echo(_badge_svg(score), nl=False)
    else:
        typer.echo(f"AIVSS {score} ({band.value}) {colour_for_band(band)}")


@app.command("last-score")
def last_score(
    score_only: bool = typer.Option(
        False,
        "--score-only",
        help=(
            "Emit only the integer score (no band, no prose) so it composes in a "
            "shell one-liner: `agent-guardian badge $(agent-guardian last-score "
            "--score-only) --svg`. Exits 1 when no scans are on record so the "
            "outer pipeline fails loudly instead of feeding 'no scans on record' "
            "into the next command."
        ),
    ),
) -> None:
    """Print the AIVSS of the most recent scan."""
    state = _read_state()
    last = state.get("last_score")
    if last is None:
        if score_only:
            typer.echo("no scans on record", err=True)
            raise typer.Exit(code=EXIT_FAIL_UNDER)
        typer.echo("no scans on record.")
        return
    score = int(last)
    if score_only:
        typer.echo(str(score))
        return
    band = band_for_score(score)
    typer.echo(f"AIVSS {score} ({band.value})")


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind host. Default 127.0.0.1 (loopback only).",
    ),
    port: int = typer.Option(7474, "--port", help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes (dev only)."),
    token: str | None = typer.Option(
        None,
        "--token",
        envvar="AGENT_GUARDIAN_DASHBOARD_TOKEN",
        help=(
            "Dashboard auth token; required for non-loopback binds unless "
            "--insecure-no-auth is passed. The same value must be presented "
            "by clients via the X-Dashboard-Token header (or Bearer auth)."
        ),
    ),
    insecure_no_auth: bool = typer.Option(
        False,
        "--insecure-no-auth",
        help=(
            "Allow off-loopback bind WITHOUT a token. Exposes scan history "
            "(target URLs + findings) to anyone who can reach the port. "
            "Intended for ephemeral demos behind a trusted reverse proxy only."
        ),
    ),
) -> None:
    """Start the local dashboard at http://<host>:<port>.

    The dashboard defaults to loopback (127.0.0.1). Binding to a non-loopback
    address requires either a ``--token`` (preferred) or the explicit
    ``--insecure-no-auth`` escape hatch -- otherwise the bind is refused so a
    misconfigured deploy can't silently expose scan history. The
    telemetry-ingest WRITE endpoint stays disabled off-loopback unless you set
    ``AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN`` (or
    ``AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST=1``).
    """
    import uvicorn

    from agent_guardian.server.app import create_app

    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    is_loopback = host in loopback_hosts

    if not is_loopback and not token and not insecure_no_auth:
        typer.echo(
            f"refusing to bind dashboard on non-loopback host {host!r} without "
            "authentication. Pass --token <SECRET> (preferred) or "
            "--insecure-no-auth to acknowledge the exposure. The default "
            "127.0.0.1 bind needs no token.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    if not is_loopback:
        typer.echo(
            f"WARNING: binding the dashboard to a non-loopback host ({host}). This "
            "exposes scan history (target URLs + findings) and the telemetry-ingest "
            "endpoint to the network. "
            + (
                "Auth token is configured."
                if token
                else "Running with --insecure-no-auth: no token required."
            ),
            err=True,
        )

    if reload:
        # uvicorn's reload mode imports the app factory inside a child worker,
        # so we can't reach in and stamp app.state from here. The only way to
        # propagate the token into the reload-worker is via the env var, which
        # the factory reads on startup.
        if token is not None:
            os.environ["AGENT_GUARDIAN_DASHBOARD_TOKEN"] = token
        uvicorn.run(
            "agent_guardian.server.app:create_app",
            host=host,
            port=port,
            reload=True,
            factory=True,
            log_level="info",
        )
        return
    # Non-reload: construct the app eagerly so we can stamp the token onto
    # app.state.dashboard_token before uvicorn starts accepting connections.
    app_instance = create_app()
    app_instance.state.dashboard_token = token
    uvicorn.run(
        app_instance,
        host=host,
        port=port,
        log_level="info",
    )


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to regenerate reports for."),
    output: str = typer.Option(
        "json", "--output", help="Report format: json | sarif | junit | md | pdf."
    ),
    output_path: Path | None = typer.Option(
        None,
        "--output-path",
        help=(
            "Write the report to this file instead of printing to stdout. "
            "Required for --output pdf (binary)."
        ),
    ),
) -> None:
    """Regenerate a report from a stored scan.

    Text formats (json / sarif / junit / md) print to stdout by default, or to
    ``--output-path`` when given. ``--output pdf`` is binary and always requires
    ``--output-path`` -- it is routed through the PDF writer, which raises a
    clear remediation error if no PDF engine (WeasyPrint / reportlab) is
    installed.
    """
    if output not in _ALL_FORMATS:
        typer.echo(
            f"unknown output format '{output}' -- choose one of: {', '.join(sorted(_ALL_FORMATS))}",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # Prefer the raw, model-roundtrippable dump (scan.raw.json); fall back to a
    # legacy single-file scan.json (where scan.json WAS the raw model dump).
    scan_dir = Path.home() / ".agentguardian" / "scans" / scan_id
    scan_file: Path | None = None
    for name in ("scan.raw.json", "scan.json"):
        candidate = scan_dir / name
        if candidate.is_file():
            scan_file = candidate
            break
    if scan_file is None:
        typer.echo(f"no scan found at {scan_dir / 'scan.json'}", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    try:
        payload = json.loads(scan_file.read_text(encoding="utf-8"))
        scan = Scan.model_validate(payload)
    except (json.JSONDecodeError, ValueError) as exc:
        typer.echo(f"could not load scan from {scan_file}: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # PDF is binary -- it can only be written to a file, never echoed.
    if output == "pdf" and output_path is None:
        typer.echo(
            "--output pdf is binary and requires --output-path to write the file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    if output_path is not None:
        try:
            _write_report(scan, output, output_path)
        except typer.BadParameter as exc:
            typer.echo(f"output format error: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        except Exception as exc:
            # PDF engines can raise PdfFeatureUnavailable etc. Surface clearly.
            typer.echo(f"report write error: {type(exc).__name__}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        typer.echo(f"report written to {output_path}")
        return

    typer.echo(_render_scan(scan, output))


@app.command()
def verify(
    path: Path = typer.Argument(..., help="Path to a signed JSON report."),
    pubkey: str | None = typer.Option(
        None,
        "--pubkey",
        help=(
            "Pinned Ed25519 signer public key (base32, no padding). The report's "
            "embedded key must match this before its Ed25519 signature is trusted."
        ),
    ),
    pubkey_file: Path | None = typer.Option(
        None,
        "--pubkey-file",
        help="Read the pinned Ed25519 public key (base32) from this file instead of --pubkey.",
    ),
    secret: str | None = typer.Option(
        None,
        "--secret",
        help=(
            "Expected HMAC signing secret. Defaults to AGENT_GUARDIAN_SIGNING_SECRET "
            "from the environment. The public default secret is never accepted on verify."
        ),
    ),
) -> None:
    """Verify HMAC-SHA256 + Ed25519 signatures on a JSON report.

    Verification fails closed: a signature alone proves only that the bytes
    were not tampered (integrity), not *who* signed them. To report a green
    (OK) result you must supply a trust anchor -- a pinned Ed25519 public key
    (``--pubkey`` / ``--pubkey-file``) and/or a real HMAC secret (``--secret``
    or ``AGENT_GUARDIAN_SIGNING_SECRET``). Without an anchor the report is shown
    as UNANCHORED and the command exits non-zero.
    """
    if not path.exists():
        typer.echo(f"path not found: {path}", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    suffix = path.suffix.lower()
    if suffix != ".json":
        typer.echo(
            f"unsupported file type '{suffix}' -- verify currently accepts .json reports. "
            f"PDFs ship a signed JSON sidecar at <name>.json.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # Resolve the pinned Ed25519 pubkey (file takes precedence over the literal).
    expected_pubkey: str | None = pubkey
    if pubkey_file is not None:
        if not pubkey_file.is_file():
            typer.echo(f"pubkey file not found: {pubkey_file}", err=True)
            raise typer.Exit(code=EXIT_CONFIG)
        expected_pubkey = pubkey_file.read_text(encoding="utf-8").strip()
    # Resolve the HMAC secret (explicit flag > env). verify_signatures itself
    # falls back to AGENT_GUARDIAN_SIGNING_SECRET, but resolving here lets us
    # tell the operator clearly whether *any* anchor was supplied.
    hmac_secret = secret if secret is not None else os.environ.get("AGENT_GUARDIAN_SIGNING_SECRET")
    anchor_supplied = expected_pubkey is not None or hmac_secret is not None

    from agent_guardian.reports.json_report import verify_signatures

    result = verify_signatures(
        path,
        expected_ed25519_pubkey=expected_pubkey,
        expected_hmac_secret=hmac_secret,
    )
    typer.echo(f"schema:       {'OK' if result.schema_ok else 'FAIL'}")
    typer.echo(f"HMAC-SHA256:  {'OK' if result.hmac_valid else 'FAIL'}")
    typer.echo(f"Ed25519:      {'OK' if result.ed25519_valid else 'FAIL'}")
    typer.echo(f"trust anchor: {'PINNED' if result.anchored else 'UNANCHORED'}")
    if not anchor_supplied:
        typer.echo(
            "provenance UNVERIFIED: no trust anchor supplied. A signed report only "
            "proves the bytes were not tampered, not who produced it. Pass --pubkey / "
            "--pubkey-file (Ed25519) and/or --secret (HMAC) to establish provenance.",
            err=True,
        )
    if result.error:
        typer.echo(f"error:        {result.error}", err=True)
    if not result.ok:
        raise typer.Exit(code=EXIT_FAIL_UNDER)


@app.command()
def publish(
    scan_id: str = typer.Argument(
        ...,
        help="Scan ID (under ~/.agentguardian/scans/) or path to a signed scan.json.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Where to write the redacted payload. Default: alongside the scan.",
    ),
) -> None:
    """Publish a signed scan to the public AgentGuardian leaderboard.

    Today this is a placeholder: the public leaderboard endpoint
    (``https://agentguardian.io/api/v1/leaderboard``) is Glacien-edge
    infrastructure that has not yet been deployed. What the command does
    *now* still has user value:

    1. Locate and load the scan JSON (by ID or path).
    2. Verify the HMAC + Ed25519 signatures so we never publish a
       tampered report.
    3. Strip transcripts and other PII-prone fields (``transcript_ref``,
       per-finding ``summary`` is already redacted at emit time).
    4. Write the redacted, leaderboard-ready payload alongside the scan
       and print operator-facing instructions for hand submission via the
       project's GitHub issue tracker.

    When the public endpoint goes live this command will POST the
    redacted payload instead of printing the manual-submission message.
    """
    # 1. Resolve the source path.
    direct = Path(scan_id)
    if direct.is_file():
        scan_path = direct
    else:
        scan_path = Path.home() / ".agentguardian" / "scans" / scan_id / "report.json"
        if not scan_path.is_file():
            # Some flows persist the raw model dump at ``scan.json`` instead.
            fallback = Path.home() / ".agentguardian" / "scans" / scan_id / "scan.json"
            if fallback.is_file():
                scan_path = fallback
            else:
                typer.echo(
                    f"no scan found for '{scan_id}'. Looked in {scan_path} and {fallback}.",
                    err=True,
                )
                raise typer.Exit(code=EXIT_CONFIG)

    # 2. Verify signatures. We only allow publishing what's signed --
    #    the leaderboard's integrity story depends on it.
    from agent_guardian.reports.json_report import verify_signatures

    payload: dict[str, Any]
    try:
        payload = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        typer.echo(f"could not read scan JSON: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from None

    if not isinstance(payload, dict):
        typer.echo("scan JSON is not a JSON object -- refusing to publish.", err=True)
        raise typer.Exit(code=EXIT_CONFIG)

    if "signatures" not in payload:
        typer.echo(
            "scan is not signed -- refusing to publish. Re-emit the report "
            "with the JSON emitter (which signs by default).",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # We refuse to publish a *tampered* scan, so we require the Ed25519
    # signature to recompute (bytes-not-modified). Ed25519 alone proves
    # integrity without a shared secret; the HMAC leg fails closed off a real
    # secret, so it is not the right integrity gate here. Full provenance trust
    # (who signed) is the job of the ``verify`` command with a pinned key.
    verify_result = verify_signatures(payload)
    if not (verify_result.ed25519_valid and verify_result.schema_ok):
        typer.echo(
            "signature verification failed -- refusing to publish a possibly "
            "tampered scan. Details:",
            err=True,
        )
        typer.echo(f"  schema:       {'OK' if verify_result.schema_ok else 'FAIL'}", err=True)
        typer.echo(f"  HMAC-SHA256:  {'OK' if verify_result.hmac_valid else 'FAIL'}", err=True)
        typer.echo(f"  Ed25519:      {'OK' if verify_result.ed25519_valid else 'FAIL'}", err=True)
        raise typer.Exit(code=EXIT_FAIL_UNDER)

    # 3. Strip PII / transcript references. Per-finding ``summary`` is
    #    already redacted at emit time (json_report.py), but ``transcript_ref``
    #    can point at on-disk traces that the public leaderboard must never
    #    see. We also drop the signature block because the redacted
    #    payload is no longer the originally signed bytes.
    redacted = {k: v for k, v in payload.items() if k != "signatures"}
    findings = redacted.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                finding.pop("transcript_ref", None)
                finding.pop("transcript", None)
                # ``summary`` already passed through PiiRedactor at emit time
                # but we coerce a hard cap here just in case a custom emitter
                # ever bypasses redaction.
                summary = finding.get("summary")
                if isinstance(summary, str) and len(summary) > 280:
                    finding["summary"] = summary[:277] + "..."

    # 4. Write the redacted payload + print the manual-submission message.
    if output is None:
        output = scan_path.parent / "leaderboard.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(redacted, indent=2, sort_keys=True), encoding="utf-8")

    typer.echo(
        "Leaderboard endpoint not yet deployed. To submit your scan, file an "
        "issue at github.com/glacien-technologies/agent-guardian/issues with "
        "the redacted JSON attached."
    )
    typer.echo(f"redacted payload written to: {output}")


@telemetry_app.command("essential")
def telemetry_essential() -> None:
    """Switch to ESSENTIAL tier -- operational counts only (the default).

    Sends agents fired, attempts, successes, threats captured, AIVSS,
    duration, crash status, and an anonymous install_id. Does NOT
    send adapter, Python version, OS, or arch.
    """
    from agent_guardian.telemetry.consent import ConsentState, set_consent

    set_consent(ConsentState.ESSENTIAL)
    typer.echo(
        "telemetry: essential tier active. Operational counts only -- "
        "adapter / Python / OS / arch NOT collected."
    )


@telemetry_app.command("extended")
def telemetry_extended() -> None:
    """Upgrade to EXTENDED tier -- essential counts PLUS environment fingerprint.

    Adds adapter name, Python version, OS family, and CPU arch to
    every event. Helps the community dashboard populate its
    compatibility-matrix and per-framework cells. Revoke with
    ``agent-guardian telemetry essential`` or ``telemetry disable``.
    """
    from datetime import datetime, timezone

    from agent_guardian.telemetry.client import emit
    from agent_guardian.telemetry.consent import ConsentState, set_consent
    from agent_guardian.telemetry.events import InstallEvent
    from agent_guardian.telemetry.install_id import get_install_id
    from agent_guardian.telemetry.prompt import _arch, _os_family

    set_consent(ConsentState.EXTENDED)
    try:
        emit(
            InstallEvent(
                install_id=get_install_id(),
                agent_version=__version__,
                python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
                os_family=_os_family(),
                arch=_arch(),
                opted_in_at=datetime.now(timezone.utc),
            )
        )
    except Exception as exc:  # pragma: no cover -- defensive
        _LOG.warning(
            "telemetry extended: failed to emit InstallEvent (%s: %s) -- local state still saved",
            type(exc).__name__,
            exc,
        )
    typer.echo(
        "telemetry: extended tier active. Adapter / Python / OS / arch will be "
        "included in events. Revoke with `agent-guardian telemetry essential`."
    )


@telemetry_app.command("enable")
def telemetry_enable() -> None:
    """Legacy alias for `telemetry extended` (v1.0rc1 compat)."""
    telemetry_extended()


@telemetry_app.command("disable")
def telemetry_disable() -> None:
    """Disable telemetry. Emits a ``forget`` event so the collector drops your install_id."""
    from datetime import datetime, timezone

    from agent_guardian.telemetry.client import emit
    from agent_guardian.telemetry.consent import ConsentState, set_consent
    from agent_guardian.telemetry.events import ForgetEvent
    from agent_guardian.telemetry.install_id import get_install_id

    try:
        emit(
            ForgetEvent(
                install_id=get_install_id(),
                opted_out_at=datetime.now(timezone.utc),
            )
        )
    except Exception as exc:  # pragma: no cover -- defensive
        _LOG.warning(
            "telemetry disable: failed to emit ForgetEvent (%s: %s) -- local state still cleared",
            type(exc).__name__,
            exc,
        )
    set_consent(ConsentState.OPTED_OUT)
    typer.echo("telemetry disabled. No further events will be sent.")


@telemetry_app.command("status")
def telemetry_status() -> None:
    """Show the current telemetry tier + local buffer depth."""
    from agent_guardian.telemetry.consent import consent_level, get_consent
    from agent_guardian.telemetry.install_id import get_install_id, install_id_path
    from agent_guardian.telemetry.local import LocalEventBuffer

    state = get_consent()
    level = consent_level()
    typer.echo(f"telemetry state:    {state.value}")
    typer.echo(f"active tier:        {level}")
    if level == "off":
        typer.echo("(no events collected; run `agent-guardian telemetry essential` to re-enable)")
        return
    if level == "essential":
        typer.echo(
            "(operational counts only -- agents, attempts, successes, threats, AIVSS; "
            "no adapter / Python / OS / arch)"
        )
    else:  # extended
        typer.echo(
            "(essential counts + environment fingerprint: adapter, Python version, OS, arch)"
        )
    typer.echo(f"install_id:         {get_install_id()}")
    typer.echo(f"install_id file:    {install_id_path()}")
    typer.echo(f"pending events:     {LocalEventBuffer().queue_depth()}")


@telemetry_app.command("reset")
def telemetry_reset() -> None:
    """Clear consent + delete install_id + purge pending events. Re-asks on next scan."""
    from agent_guardian.telemetry.consent import ConsentState, set_consent
    from agent_guardian.telemetry.install_id import reset_install_id
    from agent_guardian.telemetry.local import LocalEventBuffer

    purged = LocalEventBuffer().purge_all()
    reset_install_id()
    set_consent(ConsentState.NOT_PROMPTED)
    typer.echo(
        f"telemetry reset. {purged} pending event(s) purged. The opt-in prompt will "
        "re-fire on your next interactive scan."
    )


@telemetry_app.command("show")
def telemetry_show() -> None:
    """Print the full list of fields telemetry would send if enabled.

    Per Standard §9.4 -- telemetry transparency commitments -- the
    field list is published so users can audit what gets sent.
    """
    from agent_guardian.telemetry.prompt import PROMPT_TEXT

    typer.echo(PROMPT_TEXT)


# ---------------------------------------------------------------------------
# Contract commands -- validate / init / contract sub-app (Stage 1B)
# ---------------------------------------------------------------------------


def _render_preflight(report: PreflightReport) -> None:
    """Print each pre-flight stage as a coloured pass/fail line."""
    for stage in report.stages:
        marker = (
            typer.style("PASS", fg=typer.colors.GREEN)
            if stage.ok
            else typer.style("FAIL", fg=typer.colors.RED)
        )
        typer.echo(f"  [{marker}] {stage.name}: {stage.detail}")
        if not stage.ok and stage.remediation:
            typer.echo(typer.style(f"         remediation: {stage.remediation}", dim=True))


@app.command()
def validate(
    contract: Path = typer.Argument(
        Path("agentguardian.yaml"),
        help="Path to the contract YAML to validate.",
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Emit the pre-flight report as JSON instead of text."
    ),
    stage: str | None = typer.Option(
        None, "--stage", help="Only print this single stage's result (by name)."
    ),
) -> None:
    """Run the payload-free pre-flight against a contract (Stage 1B).

    Walks the seven non-adversarial stages (resolve, connect, probe, round-trip,
    session, capability, RoE) and stops at the first failure. Exits with the
    failing stage's exit code (``EXIT_CONFIG`` / ``EXIT_TARGET_UNREACHABLE`` /
    ``EXIT_LLM_PROVIDER``), or ``EXIT_OK`` when every stage passes.
    """
    from agent_guardian.contract.preflight import run_preflight

    report = asyncio.run(run_preflight(contract))

    if json_out:
        payload = report.to_dict()
        if stage is not None:
            payload["stages"] = [s for s in payload["stages"] if s["name"] == stage]
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if report.redacted_contract is not None:
            typer.echo("contract (redacted):")
            typer.echo(json.dumps(report.redacted_contract, indent=2, sort_keys=True))
        typer.echo("pre-flight stages:")
        if stage is not None:
            for s in report.stages:
                if s.name == stage:
                    marker = "PASS" if s.ok else "FAIL"
                    typer.echo(f"  [{marker}] {s.name}: {s.detail}")
        else:
            _render_preflight(report)

    if not report.ok:
        raise typer.Exit(code=report.exit_code)
    raise typer.Exit(code=EXIT_OK)


@app.command()
def init(
    out: Path = typer.Option(
        Path("agentguardian.yaml"),
        "--out",
        help="Where to write the new contract.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Non-interactive: write a minimal valid contract from defaults/flags.",
    ),
    from_openapi: Path | None = typer.Option(
        None,
        "--from-openapi",
        help=(
            "Pre-fill the transport / request / response from an OpenAPI 3.1 spec "
            "(YAML or JSON) instead of probe-and-infer. The first body-bearing "
            "operation is used unless --openapi-path/--openapi-method narrow it."
        ),
    ),
    openapi_path: str | None = typer.Option(
        None,
        "--openapi-path",
        help="With --from-openapi: the spec path (e.g. /v1/chat) to derive shapes from.",
    ),
    openapi_method: str = typer.Option(
        "post",
        "--openapi-method",
        help="With --from-openapi and --openapi-path: the HTTP method of the operation.",
    ),
) -> None:
    """Author a new target contract, then pre-flight it.

    The interactive wizard (default) walks you through the HTTP target, auth,
    response extraction, session mode, and RoE. ``--yes`` writes a minimal valid
    contract without prompting (useful for scaffolding + CI). ``--from-openapi``
    pre-fills the transport / request / response from an OpenAPI 3.1 spec so the
    wizard (or ``--yes`` path) skips probe-and-infer for those shapes. On success
    the new contract is immediately run through the pre-flight so you see whether
    it is reachable.
    """
    from agent_guardian.contract.preflight import run_preflight
    from agent_guardian.contract.wizard import load_openapi_shapes, run_wizard

    openapi_shapes: dict[str, Any] | None = None
    if from_openapi is not None:
        try:
            openapi_shapes = load_openapi_shapes(
                from_openapi, operation_path=openapi_path, method=openapi_method
            )
        except (FileNotFoundError, ValueError) as exc:
            typer.echo(f"could not read OpenAPI spec: {type(exc).__name__}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc

    try:
        written = run_wizard(out, yes=yes, openapi_shapes=openapi_shapes)
    except Exception as exc:
        typer.echo(f"could not author contract: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    typer.echo(f"contract written to {written}")

    # #4 -- `init --yes` is the canonical "scaffold a contract in CI" path. The
    # default URL ('https://api.example.com/v1/chat') is a documentation
    # placeholder and the scaffolded contract is not yet meant to be reachable;
    # auto-pre-flighting would fail every CI scaffolding job. Detect the
    # placeholder and skip pre-flight cleanly. The user still gets `validate`
    # as the explicit pre-flight after they edit the URL.
    if _contract_url_is_placeholder(written):
        typer.echo(
            f"pre-flight skipped: target url is a placeholder. Edit {written} "
            "and run `agent-guardian validate` to pre-flight against the real "
            "endpoint."
        )
        raise typer.Exit(code=EXIT_OK)

    typer.echo("running pre-flight against the new contract...")
    report = asyncio.run(run_preflight(written))
    _render_preflight(report)
    if not report.ok:
        raise typer.Exit(code=report.exit_code)
    raise typer.Exit(code=EXIT_OK)


def _contract_url_is_placeholder(contract_path: Path) -> bool:
    """True iff the contract's target URL is the wizard placeholder or *.example.*.

    Used by ``init --yes`` so a CI scaffold doesn't auto-fail on a contract
    whose URL is still the default ``https://api.example.com/v1/chat``.
    """
    import yaml

    from agent_guardian.contract.wizard import WizardDefaults

    try:
        data = yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:  # pragma: no cover -- defensive
        _LOG.debug(
            "init: could not read contract %s (%s) -- assuming non-placeholder", contract_path, exc
        )
        return False
    if not isinstance(data, dict):
        return False
    target = data.get("target")
    if not isinstance(target, dict):
        return False
    transport = target.get("transport")
    url: str | None = None
    if isinstance(transport, dict):
        raw = transport.get("url")
        if isinstance(raw, str):
            url = raw
    if not url:
        return False
    if url == WizardDefaults.url:
        return True
    return _is_placeholder_endpoint(url)


@contract_app.command("schema")
def contract_schema(
    out: Path = typer.Option(
        ...,
        "--out",
        help="Where to write the contract JSON Schema.",
    ),
) -> None:
    """Write the contract JSON Schema to a file."""
    from agent_guardian.contract import write_contract_json_schema

    write_contract_json_schema(out)
    typer.echo(f"contract JSON Schema written to {out}")


@contract_app.command("migrate")
def contract_migrate(
    file: Path = typer.Argument(..., help="Contract file to migrate."),
    write: bool = typer.Option(
        False, "--write", help="Write the migrated contract back to FILE (else print to stdout)."
    ),
) -> None:
    """Migrate a contract toward the current schema version."""
    import yaml

    from agent_guardian.contract import migrate_contract
    from agent_guardian.contract.errors import (
        ContractError,
        MigrationNeeded,
        UnsupportedContractVersion,
    )

    if not file.is_file():
        typer.echo(f"contract file not found: {file}", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        typer.echo(f"could not read contract YAML: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    if not isinstance(data, dict):
        typer.echo("contract file must contain a YAML mapping at the top level", err=True)
        raise typer.Exit(code=EXIT_CONFIG)

    try:
        migrated = migrate_contract(data)
    except (MigrationNeeded, UnsupportedContractVersion, ContractError) as exc:
        typer.echo(f"migration failed: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    rendered = yaml.safe_dump(migrated, sort_keys=False, default_flow_style=False)
    if write:
        file.write_text(rendered, encoding="utf-8")
        typer.echo(f"migrated contract written to {file}")
    else:
        typer.echo(rendered, nl=False)


# ---------------------------------------------------------------------------
# Stored-scan management (scans list / scans delete / scans purge)
# ---------------------------------------------------------------------------


def _scans_root() -> Path:
    """Resolve the stored-scan root, honouring AGENT_GUARDIAN_HOME.

    Operators running multiple targets out of the same shell can point
    ``AGENT_GUARDIAN_HOME`` at a per-target directory so scan history /
    leaderboards / signed reports don't intermix. Defaults to
    ``~/.agentguardian`` so existing installs keep finding their state.
    """
    custom = os.environ.get("AGENT_GUARDIAN_HOME")
    if custom:
        return Path(custom).expanduser() / "scans"
    return Path.home() / ".agentguardian" / "scans"


def _parse_relative_age(spec: str) -> timedelta:
    """Parse ``30d`` / ``2w`` / ``6m`` (calendar-rough) into a ``timedelta``.

    Suffixes:
    * ``d`` -- days
    * ``w`` -- weeks
    * ``m`` -- months (approximated as 30 days)
    """
    raw = spec.strip().lower()
    if not raw or len(raw) < 2:
        raise typer.BadParameter(
            f"--older-than {spec!r} is not in NUMBER+UNIT form (e.g. 30d, 2w, 6m)."
        )
    unit = raw[-1]
    num_part = raw[:-1]
    try:
        amount = int(num_part)
    except ValueError as exc:
        raise typer.BadParameter(
            f"--older-than {spec!r}: leading number must be an integer (got {num_part!r})."
        ) from exc
    if amount < 0:
        raise typer.BadParameter(f"--older-than {spec!r}: amount must be non-negative.")
    if unit == "d":
        return timedelta(days=amount)
    if unit == "w":
        return timedelta(weeks=amount)
    if unit == "m":
        # Calendar-rough -- 30 days. Honest about it in the help string.
        return timedelta(days=amount * 30)
    raise typer.BadParameter(
        f"--older-than {spec!r}: unit must be d / w / m (days / weeks / months)."
    )


def _rmtree_quiet(path: Path) -> None:
    """Best-effort recursive delete. Used by ``scans delete`` and ``purge``."""
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _rmtree_within(root: Path, target: Path) -> None:
    """Defence-in-depth: ``shutil.rmtree`` but ONLY if ``target`` resolves
    strictly under ``root``. Refuses to delete the root itself or anything
    outside of it. Both paths are resolved (strict=False) so symlinks /
    ``..`` segments cannot escape the root.
    """
    import shutil

    try:
        root_resolved = root.resolve(strict=False)
        target_resolved = target.resolve(strict=False)
    except OSError as exc:
        raise typer.BadParameter(f"failed to resolve scan path: {exc}") from exc
    if target_resolved == root_resolved:
        raise typer.BadParameter(
            "refusing to delete the scans root itself (target resolved to root)"
        )
    if not target_resolved.is_relative_to(root_resolved):
        raise typer.BadParameter("invalid scan_id (must be sub-directory of scans root)")
    shutil.rmtree(target_resolved, ignore_errors=True)


@scan_app.command("list")
def scans_list() -> None:
    """List stored scans (id + mtime), most recent first."""
    root = _scans_root()
    if not root.is_dir():
        typer.echo("no stored scans.")
        return
    entries: list[tuple[float, str]] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        try:
            mtime = child.stat().st_mtime
        except OSError as exc:
            _LOG.debug("scans list: stat(%s) failed (%s) -- skipped", child, exc)
            continue
        entries.append((mtime, child.name))
    if not entries:
        typer.echo("no stored scans.")
        return
    entries.sort(reverse=True)
    typer.echo(f"stored scans (root: {root}):")
    for mtime, name in entries:
        iso = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(timespec="seconds")
        typer.echo(f"  {iso}  {name}")


@scan_app.command("delete")
def scans_delete(
    scan_id: str = typer.Argument(
        ..., help="Scan ID to delete (matches a sub-dir under the scans root)."
    ),
) -> None:
    """Delete a single stored scan directory."""
    # Up-front lexical validation -- reject anything that even *looks* like
    # path traversal before we resolve. Catches the common attacker payloads
    # (``../../../etc``, ``/tmp/canary``, NUL-byte injection, etc.) with a
    # clear error before any filesystem op runs.
    if (
        not scan_id
        or ".." in scan_id
        or "\x00" in scan_id
        or scan_id.startswith("/")
        or os.sep in scan_id
        or (os.altsep is not None and os.altsep in scan_id)
    ):
        raise typer.BadParameter("invalid scan_id (must be sub-directory of scans root)")
    root = _scans_root()
    target = root / scan_id
    # Resolve both paths and assert containment. Resolving is required because
    # a relative path containing ``..`` (or a symlink) can still escape after
    # the lexical check on a path that legitimately resolves outside ``root``.
    try:
        root_resolved = root.resolve(strict=False)
        target_resolved = target.resolve(strict=False)
    except OSError as exc:
        typer.echo(f"failed to resolve scan path: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    if target_resolved == root_resolved or not target_resolved.is_relative_to(root_resolved):
        typer.echo(
            "invalid scan_id (must be sub-directory of scans root)",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if not target.is_dir():
        typer.echo(f"scan not found: {target}", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    try:
        _rmtree_within(root, target)
    except typer.BadParameter as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    if target.exists():  # pragma: no cover -- defensive
        typer.echo(f"could not delete {target}", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    typer.echo(f"deleted: {target}")


@scan_app.command("purge")
def scans_purge(
    older_than: str = typer.Option(
        ...,
        "--older-than",
        help=(
            "Delete stored scans whose mtime is older than this. NUMBER+UNIT, "
            "e.g. '30d' (days), '2w' (weeks), '6m' (months, ~30 days each)."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show which scans would be purged without deleting them.",
    ),
) -> None:
    """Purge stored scans older than --older-than."""
    delta = _parse_relative_age(older_than)
    root = _scans_root()
    if not root.is_dir():
        typer.echo("no stored scans.")
        return
    cutoff = datetime.now(tz=timezone.utc) - delta
    cutoff_ts = cutoff.timestamp()
    to_remove: list[Path] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        try:
            mtime = child.stat().st_mtime
        except OSError as exc:
            _LOG.debug("scans purge: stat(%s) failed (%s) -- skipped", child, exc)
            continue
        if mtime < cutoff_ts:
            to_remove.append(child)
    if not to_remove:
        typer.echo(f"nothing older than {older_than} (cutoff: {cutoff.isoformat()}).")
        return
    typer.echo(
        f"{'would purge' if dry_run else 'purging'} {len(to_remove)} scan(s) "
        f"older than {older_than} (cutoff: {cutoff.isoformat()}):"
    )
    for child in sorted(to_remove):
        typer.echo(f"  - {child.name}")
        if not dry_run:
            _rmtree_quiet(child)


# ---------------------------------------------------------------------------
# Dashboard URL emission helper (QA-003)
# ---------------------------------------------------------------------------
#
# Every scan emits a clickable URL to the live dashboard within the first
# two lines of stdout. The pattern is locked in DESIGN_LOCK §QA-003:
#
#     ▸ Scan cli-3a4c1d9c2840 — track live at  http://127.0.0.1:7474/scans/cli-3a4c1d9c2840
#     ▸ Report when complete                   http://127.0.0.1:7474/scans/cli-3a4c1d9c2840/report
#
# When stdout is a TTY we wrap each URL in an ANSI OSC 8 hyperlink so
# Warp/iTerm2/Terminal.app/VS Code render it cmd-clickable. Non-TTY callers
# (CI, ``| tee``, ``vercel > url.txt`` patterns) see the URL as plain text so
# downstream tooling can parse it.
#
# Base URL resolution:
#   $AGENT_GUARDIAN_DASHBOARD_URL          (operator override)
#   "http://127.0.0.1:7474"                (default — matches ``serve``)
# Trailing slashes are stripped so the URLs always have exactly one ``/``
# between base and path.
#
# Operator escape hatches:
#   --no-publish flag           : suppresses emission entirely.
#   AGENT_GUARDIAN_DISABLE_URL_EMISSION=1 : same as --no-publish (operator rescue).

DEFAULT_DASHBOARD_URL = "http://127.0.0.1:7474"


def _resolve_dashboard_base_url() -> str:
    """Return the base URL for the dashboard. Strip any trailing slash."""
    base = os.environ.get("AGENT_GUARDIAN_DASHBOARD_URL", DEFAULT_DASHBOARD_URL)
    base = base.strip()
    while base.endswith("/"):
        base = base[:-1]
    return base or DEFAULT_DASHBOARD_URL


def _osc8(url: str, text: str) -> str:
    """Wrap ``text`` in an OSC 8 hyperlink escape so terminals make it clickable."""
    # OSC 8 framing:  ESC ] 8 ; params ; URI BEL  text  ESC ] 8 ; ; BEL
    return f"\x1b]8;;{url}\x07{text}\x1b]8;;\x07"


def _stdout_is_tty() -> bool:
    """Best-effort TTY detection for OSC 8 emission."""
    isatty = getattr(sys.stdout, "isatty", None)
    return bool(isatty and isatty())


def print_scan_urls(
    scan_id: str,
    *,
    suppress: bool = False,
    base_url: str | None = None,
    write: Any = None,
) -> None:
    """Emit the two scan-URL lines to stdout.

    Args:
        scan_id: The scan id ``swarm`` will run under (e.g. ``cli-3a4c1d9c2840``).
        suppress: When ``True`` (set by ``--no-publish`` or the
            ``AGENT_GUARDIAN_DISABLE_URL_EMISSION`` env switch) the call is a
            no-op. The CLI never prints a URL for a scan that isn't
            publishable.
        base_url: Override the resolved base URL. Useful for tests.
        write: Optional ``write(str) -> None`` callable. Defaults to
            ``sys.stdout.write``; tests inject a buffer.
    """
    if suppress or os.environ.get("AGENT_GUARDIAN_DISABLE_URL_EMISSION") == "1":
        return
    base = base_url if base_url is not None else _resolve_dashboard_base_url()
    while base.endswith("/"):
        base = base[:-1]
    scan_url = f"{base}/scans/{scan_id}"
    report_url = f"{base}/scans/{scan_id}/report"
    write_fn = write if write is not None else sys.stdout.write
    if _stdout_is_tty() and write is None:
        track_text = _osc8(scan_url, scan_url)
        report_text = _osc8(report_url, report_url)
    else:
        track_text = scan_url
        report_text = report_url
    # Two lines, marker-prefixed for the editorial aesthetic and grep-ability.
    write_fn(f"▸ Scan {scan_id} — track live at  {track_text}\n")
    write_fn(f"▸ Report when complete                {report_text}\n")
    flush = getattr(sys.stdout, "flush", None)
    if write is None and flush is not None:
        # Best-effort flush — a closed stdout (e.g. in some test harnesses)
        # is not an error worth surfacing to the operator.
        with contextlib.suppress(Exception):
            flush()


# ---------------------------------------------------------------------------
# scan command -- the big one
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str | None = typer.Argument(
        None,
        help="Dotted path or file:attr -- e.g. 'my_agent:run'. Mutually exclusive with --system-prompt / --endpoint / --framework.",
    ),
    system_prompt: Path | None = typer.Option(
        None, "--system-prompt", help="Path to a system prompt file (prompt-only target)."
    ),
    endpoint: str | None = typer.Option(
        None, "--endpoint", help="Hosted HTTP endpoint URL of the target agent."
    ),
    framework: str | None = typer.Option(
        None,
        "--framework",
        help=(
            "Framework kind. One of: "
            "adk, autogen, crewai, langgraph, openai_agents, strands. "
            "Pair with --framework-ref MODULE:ATTR to point at your native object."
        ),
    ),
    framework_ref: str | None = typer.Option(
        None,
        "--framework-ref",
        help=(
            "With --framework: a Python dotted reference (MODULE:ATTR) to the "
            "framework-native object to wrap (e.g. 'my_app.graph:graph')."
        ),
    ),
    no_preflight: bool = typer.Option(
        False,
        "--no-preflight",
        help=(
            "Skip the pre-scan reachability check for --endpoint mode. The "
            "default preflight POSTs an empty body twice with a 2s timeout; "
            "if both attempts fail with ConnectError/Timeout the scan exits "
            "with EXIT_TARGET_UNREACHABLE instead of burning LLM budget."
        ),
    ),
    model: str = typer.Option(
        "stub",
        "--model",
        help=(
            "LLM model spec (default: stub). Examples: 'stub', 'openai:gpt-4o', "
            "'anthropic:claude-haiku-4-5', 'gemini:gemini-2.5-flash', "
            "'ollama:llama3.1', 'bedrock:us.anthropic.claude-haiku-4-5-v1:0'."
        ),
    ),
    commander_model: str | None = typer.Option(
        None, "--commander-model", help="Override commander LLM model."
    ),
    attacker_model: str | None = typer.Option(
        None, "--attacker-model", help="Override attacker LLM model."
    ),
    evaluator_model: str | None = typer.Option(
        None, "--evaluator-model", help="Override evaluator LLM model."
    ),
    tier: str | None = typer.Option(None, "--tier", help="Force tier -- one of T1, T2, T3, T4."),
    budget_usd: float | None = typer.Option(
        None,
        "--budget-usd",
        help=(
            "Runtime USD cap (metered against actual spend). The swarm soft-stops "
            "new attack turns at 80% and reserves the rest for the report. "
            "Omit for no cap."
        ),
    ),
    fail_under: int | None = typer.Option(
        None, "--fail-under", help="Exit 1 if final AIVSS < this value."
    ),
    output: str = typer.Option(
        "json", "--output", help="Report format: json | sarif | junit | md | pdf."
    ),
    output_path: Path | None = typer.Option(
        None, "--output-path", help="Where to write the report file."
    ),
    no_tui: bool = typer.Option(False, "--no-tui", help="Disable the Rich progress panel."),
    config_path: Path | None = typer.Option(
        None, "--config", help="Override the default config file location."
    ),
    seed: int = typer.Option(0, "--seed", help="RNG seed for determinism."),
    goal: str | None = typer.Option(
        None,
        "--goal",
        help=(
            "Operator's natural-language attack goal (spec §6). When set, the "
            "Commander LLM decomposes it into per-agent briefs and the swarm "
            "synthesises goal-specific scenarios on top of the standard pass."
        ),
    ),
    mode: str = typer.Option(
        "full",
        "--mode",
        "-m",
        help=(
            "Scan thoroughness mode. 'full' (default, v1.1+) runs every "
            "probe on every agent to completion -- no early-stop, ~5min, "
            "~\\$0.06 on Gemini. 'smart' is the v1.0 default -- early-stop "
            "when AIVSS variance stabilises, ~2min, ~\\$0.03. 'fast' caps "
            "each agent at 3 probes / 4 turns for CI-gate smoke checks, "
            "~45s, ~\\$0.008."
        ),
    ),
    pov_gate: bool = typer.Option(
        False,
        "--pov-gate",
        help=(
            "Re-run each finding's trigger N times and drop the unreproducible "
            "ones before scoring (PoV-as-oracle credibility gate)."
        ),
    ),
    critic: bool = typer.Option(
        False,
        "--critic",
        help=(
            "With --pov-gate, also score each PoV-passing finding on an LLM "
            "rubric (evidence/specificity/novelty/false-positive-risk) and drop "
            "low-quality / high-FP-risk findings."
        ),
    ),
    bundle: Path | None = typer.Option(
        None,
        "--bundle",
        help="Write a checksummed SARIF+PoV bundle to this directory.",
    ),
    pretext: bool = typer.Option(
        False,
        "--pretext",
        help=(
            "Wrap attacker payloads in a rotating legitimate-operations pretext "
            "(auditor/compliance/incident/onboarding) to test refuse-on-framing."
        ),
    ),
    indirect: bool = typer.Option(
        False,
        "--indirect",
        help=(
            "Deliver attacker payloads embedded in trusted-channel content "
            "(retrieved doc / tool output / email / memory / a2a) instead of a "
            "direct user ask (indirect prompt injection)."
        ),
    ),
    no_owasp_llm: bool = typer.Option(
        False,
        "--no-owasp-llm",
        help=(
            "Suppress the OWASP-LLM specialist agents (fuzzing, secret-extraction, "
            "denial-of-wallet, detection-evasion). Default: those four specialists "
            "DO run alongside the core ASI01-10 slate -- agentic security needs "
            "transport-level secret-leak and DoW checks to be the default surface."
        ),
    ),
    contract: Path | None = typer.Option(
        None,
        "--contract",
        help=(
            "Drive the scan from a target contract (agentguardian.yaml). "
            "The contract supplies the transport, auth, session, and Rules of "
            "Engagement; RoE budgets map onto the swarm config and a provenance "
            "audit is attached to the report. Mutually exclusive with the "
            "target / --system-prompt / --endpoint / --framework modes."
        ),
    ),
    otel_endpoint: str | None = typer.Option(
        None,
        "--otel-endpoint",
        envvar="OTEL_EXPORTER_OTLP_ENDPOINT",
        help=(
            "OTLP-HTTP endpoint to export OpenTelemetry GenAI spans to "
            "(e.g. http://localhost:4318/v1/traces). When set, the scanner emits "
            "invoke_agent / transport.send / execute_tool spans with gen_ai.* "
            "attributes from every scan mode. Precedence with --contract: the "
            "contract's observability.otel_endpoint wins iff the contract sets "
            "one; this flag fills in otherwise (so a contract with no "
            "observability stanza still honours --otel-endpoint)."
        ),
    ),
    publish: bool = typer.Option(
        True,
        "--publish/--no-publish",
        help=(
            "Emit the live-dashboard URL at scan start (default). Pass "
            "--no-publish to suppress the URL entirely for sensitive scans. "
            "The base URL comes from $AGENT_GUARDIAN_DASHBOARD_URL or "
            "http://127.0.0.1:7474."
        ),
    ),
    debug: int = typer.Option(
        0,
        "--debug",
        count=True,
        help=(
            "Stream per-agent reflections (prompt + target_response + verdict) "
            "to stdout in real time. Use -1x for truncated panels (the default "
            "block format); -2x (--debug --debug) to disable truncation and "
            "show full prompt + reasoning. Composes with the Live region — "
            "panels print as scrollback ABOVE the swarm board, not inside it."
        ),
    ),
    debug_format: str = typer.Option(
        "text",
        "--debug-format",
        help=(
            "Reflection feed format: 'text' (Rich panels) or 'json' (NDJSON, "
            "one record per line). 'json' implicitly disables the Live "
            "region — JSON mode auto-suppresses Rich frames so the stream is "
            "jq-clean. Has no effect without --debug."
        ),
    ),
    no_serve: bool = typer.Option(
        False,
        "--no-serve",
        help=(
            "Disable the auto-spawn dashboard server for this scan. "
            "Equivalent to setting $AGENT_GUARDIAN_DISABLE_AUTO_SERVE=1. The "
            "dashboard URL is still printed; you'll need to start "
            "'agent-guardian serve' yourself in another terminal for the "
            "URL to resolve."
        ),
    ),
    serve_grace_seconds: int = typer.Option(
        300,
        "--serve-grace-seconds",
        help=(
            "Keep the auto-spawned dashboard alive for N seconds after the "
            "scan completes so you can click the URL and review the report. "
            "Defaults to 300 (5 minutes). Pass 0 to shut down immediately "
            "on scan completion. Pass -1 to keep the dashboard alive until "
            "you Ctrl-C the command (ngrok-style)."
        ),
    ),
) -> None:
    """Run an adversarial swarm scan against a target."""
    # v1.1 -- validate --mode before anything expensive (target load,
    # LLM client construction, cost-estimate computation). A user who
    # mistypes 'smort' deserves an immediate, clear error.
    from agent_guardian.core.swarm import ScanMode

    try:
        ScanMode(mode.lower())
    except ValueError:
        typer.echo(
            f"unknown mode '{mode}' -- must be 'fast', 'smart', or 'full'.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG) from None
    # QA-005 — validate --debug-format. Mutual-exclusion: 'json' format
    # auto-suppresses the Live region (one stdout owner). 'text' is the
    # default and composes with the Live region (panels above as
    # scrollback).
    debug_format_norm = (debug_format or "text").lower().strip()
    if debug_format_norm not in ("text", "json"):
        typer.echo(
            f"unknown --debug-format '{debug_format}' -- must be 'text' or 'json'.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG) from None
    # Clamp debug level to 0/1/2 — Typer counts unbounded but we only
    # publish two non-zero modes (truncated / full).
    debug_level = max(0, min(2, int(debug)))
    # JSON-mode reflection feed implicitly disables the Live region —
    # the operator wants a clean ``jq`` pipeline, not Rich frames.
    effective_no_tui = no_tui or (debug_level > 0 and debug_format_norm == "json")
    # QA-009 — validate --serve-grace-seconds. Accept 0 (immediate
    # shutdown), -1 (block until SIGINT), or any positive int.
    if serve_grace_seconds < -1:
        typer.echo(
            "--serve-grace-seconds must be 0, -1, or a positive integer",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG) from None

    try:
        exit_code = asyncio.run(
            _run_scan(
                target=target,
                system_prompt=system_prompt,
                endpoint=endpoint,
                framework=framework,
                framework_ref=framework_ref,
                no_preflight=no_preflight,
                model=model,
                commander_model=commander_model,
                attacker_model=attacker_model,
                evaluator_model=evaluator_model,
                tier=tier,
                budget_usd=budget_usd,
                fail_under=fail_under,
                output=output,
                output_path=output_path,
                no_tui=effective_no_tui,
                config_path=config_path,
                seed=seed,
                goal=goal,
                mode=mode,
                pov_gate=pov_gate,
                critic=critic,
                bundle=bundle,
                pretext=pretext,
                indirect=indirect,
                no_owasp_llm=no_owasp_llm,
                contract=contract,
                otel_endpoint=otel_endpoint,
                publish=publish,
                debug_level=debug_level,
                debug_format=debug_format_norm,
                no_serve=no_serve,
                serve_grace_seconds=serve_grace_seconds,
            )
        )
    except KeyboardInterrupt:
        typer.echo("interrupted.", err=True)
        raise typer.Exit(code=EXIT_USER_INTERRUPT) from None
    raise typer.Exit(code=exit_code)


async def _run_scan(
    *,
    target: str | None,
    system_prompt: Path | None,
    endpoint: str | None,
    framework: str | None,
    framework_ref: str | None = None,
    no_preflight: bool = False,
    model: str,
    commander_model: str | None,
    attacker_model: str | None,
    evaluator_model: str | None,
    tier: str | None,
    budget_usd: float | None,
    fail_under: int | None,
    output: str,
    output_path: Path | None,
    no_tui: bool,
    config_path: Path | None,
    seed: int,
    goal: str | None = None,
    mode: str = "full",
    pov_gate: bool = False,
    critic: bool = False,
    bundle: Path | None = None,
    pretext: bool = False,
    indirect: bool = False,
    no_owasp_llm: bool = False,
    contract: Path | None = None,
    otel_endpoint: str | None = None,
    publish: bool = True,
    debug_level: int = 0,
    debug_format: str = "text",
    no_serve: bool = False,
    serve_grace_seconds: int = 300,
) -> int:
    # 1. Config layer -- file + defaults.
    try:
        cfg: Config = load_config(config_path)
    except Exception as exc:
        typer.echo(f"config error: {exc}", err=True)
        return EXIT_CONFIG

    # 2. Resolve model specs (CLI > config).
    eff_commander = commander_model or model or cfg.swarm.commander_model
    eff_attacker = attacker_model or model or cfg.swarm.attacker_model
    eff_evaluator = evaluator_model or model or cfg.swarm.evaluator_model

    # 3. Ethical banner (PRD §15.6) -- first run only.
    _show_ethical_banner_once()

    # 4. Budget cap notice. The old mode-blind pre-flight estimate (it priced
    #    the full 2M-token ceiling regardless of mode, over-estimating ~46x) is
    #    gone. --budget-usd is now a *runtime* cap metered against actual spend:
    #    the swarm soft-stops new attack turns at 80% and reserves the rest for
    #    the finalise phase + report. Omit it to run uncapped.
    if budget_usd is not None:
        typer.echo(
            f"budget cap: ${budget_usd:.4f} "
            "(soft-stops new attack turns at 80%, reserves the rest for the report)"
        )
    else:
        typer.echo("no budget cap (running to completion)")

    # 5. Resolve tier override.
    tier_override: Tier | None = None
    if tier:
        try:
            tier_override = Tier(tier)
        except ValueError:
            typer.echo(f"unknown tier '{tier}' -- must be T1, T2, T3, or T4.", err=True)
            return EXIT_CONFIG

    # 6a. Pre-scan model validation (QA-001 + addendum). One cheap probe per
    #     distinct (provider, model) tuple — typically one HTTP call even when
    #     attacker == evaluator == commander. Caches per-session so resume /
    #     retry doesn't re-probe. ``--no-preflight`` skips it for users who
    #     deliberately want to dodge the probe (offline / air-gap).
    if not no_preflight:
        from agent_guardian.llm.validation import check_model_exists

        seen_specs: set[str] = set()
        for spec in (eff_attacker, eff_evaluator, eff_commander):
            if spec in seen_specs:
                continue
            seen_specs.add(spec)
            mv = check_model_exists(spec)
            if not mv.valid:
                typer.echo(mv.message, err=True)
                if mv.status == "auth_failed":
                    return EXIT_CONFIG
                # Confirmed-unknown model — fail fast (QA-001).
                return EXIT_LLM_PROVIDER
            if mv.status == "transient" and mv.message:
                # Provider blip — keep going, but log honestly.
                typer.echo(f"warning: {mv.message}", err=True)

    # 6b. Build LLMs + target.
    try:
        attacker_llm = build_llm(eff_attacker, role="attacker")
        evaluator_llm = build_llm(eff_evaluator, role="evaluator")
        commander_llm = build_llm(eff_commander, role="commander")
        target_llm = build_llm(eff_attacker, role="target")  # stub-backed wrapper for prompt mode.
    except typer.BadParameter as exc:
        typer.echo(f"llm config error: {exc}", err=True)
        return EXIT_LLM_PROVIDER

    # Generate scan_id + emit dashboard URLs BEFORE the target preflight, so
    # the operator gets the scan URL even if preflight subsequently fails
    # (cold-start race, transient network blip, etc.). This matches the
    # published QA-003 contract: "URL within the first 2 lines of stdout,
    # always". The pre-existing behavior (emit AFTER preflight) silently
    # swallowed the URL on every preflight failure, leaving the operator
    # with only a cryptic "target unreachable" line.
    scan_id = f"cli-{uuid.uuid4().hex[:12]}"

    # QA-009 — auto-serve. Decide whether to spawn a dashboard child
    # BEFORE we emit the URL so the URL reflects the actually-bound port
    # (which may be 7475..7499 if 7474 was occupied by a stranger). The
    # manager is entered as a context manager; ``__exit__`` always runs
    # (in the outer ``finally`` below) — even on KeyboardInterrupt — so
    # the child can never outlive the scan command.
    from agent_guardian.ui.auto_serve import AutoServeManager, should_auto_serve

    auto_serve_suppression = should_auto_serve(
        no_serve=no_serve,
        no_tui=no_tui,
        debug_format=debug_format,
        publish=publish,
    )
    auto_serve_manager = AutoServeManager(
        grace_seconds=serve_grace_seconds,
        token=os.environ.get("AGENT_GUARDIAN_DASHBOARD_TOKEN"),
        suppression_reason=auto_serve_suppression,
    )
    auto_serve_result = auto_serve_manager.__enter__()
    auto_serve_base_url: str | None = (
        auto_serve_result.base_url
        if (auto_serve_result.spawned or auto_serve_result.reused)
        else None
    )
    print_scan_urls(scan_id, suppress=not publish, base_url=auto_serve_base_url)

    try:
        exit_code = await _run_scan_inner(
            cfg=cfg,
            scan_id=scan_id,
            target=target,
            system_prompt=system_prompt,
            endpoint=endpoint,
            framework=framework,
            framework_ref=framework_ref,
            no_preflight=no_preflight,
            eff_attacker=eff_attacker,
            eff_evaluator=eff_evaluator,
            eff_commander=eff_commander,
            attacker_llm=attacker_llm,
            evaluator_llm=evaluator_llm,
            commander_llm=commander_llm,
            target_llm=target_llm,
            tier_override=tier_override,
            fail_under=fail_under,
            output=output,
            output_path=output_path,
            no_tui=no_tui,
            seed=seed,
            goal=goal,
            mode=mode,
            pov_gate=pov_gate,
            critic=critic,
            bundle=bundle,
            pretext=pretext,
            indirect=indirect,
            no_owasp_llm=no_owasp_llm,
            contract=contract,
            otel_endpoint=otel_endpoint,
            budget_usd=budget_usd,
            debug_level=debug_level,
            debug_format=debug_format,
        )
    finally:
        # Grace period: keep the dashboard alive so the operator can click
        # the URL we already printed. ``grace_wait`` is a no-op when we
        # didn't spawn (reused / suppressed) or when ``serve_grace_seconds
        # == 0``. It is interruptible via SIGINT/SIGTERM through the
        # manager's signal handlers.
        try:
            auto_serve_manager.grace_wait()
        finally:
            auto_serve_manager.__exit__(None, None, None)
    return exit_code


async def _run_scan_inner(
    *,
    cfg: Config,
    scan_id: str,
    target: str | None,
    system_prompt: Path | None,
    endpoint: str | None,
    framework: str | None,
    framework_ref: str | None,
    no_preflight: bool,
    eff_attacker: str,
    eff_evaluator: str,
    eff_commander: str,
    attacker_llm: Any,
    evaluator_llm: Any,
    commander_llm: Any,
    target_llm: Any,
    tier_override: Tier | None,
    fail_under: int | None,
    output: str,
    output_path: Path | None,
    no_tui: bool,
    seed: int,
    goal: str | None,
    mode: str,
    pov_gate: bool,
    critic: bool,
    bundle: Path | None,
    pretext: bool,
    indirect: bool,
    no_owasp_llm: bool,
    contract: Path | None,
    otel_endpoint: str | None,
    budget_usd: float | None,
    debug_level: int,
    debug_format: str,
) -> int:
    """Run the scan body. Extracted from ``_run_scan`` so the auto-serve
    context manager (QA-009) cleanly wraps every ``return EXIT_X`` exit
    path via a single ``try/finally`` in the caller."""

    # Stage 1B -- a --contract run replaces the four legacy target modes with a
    # contract-built adapter + RoE controller + OTel observer. The non-contract
    # path below is left byte-for-byte unchanged.
    contract_ctx: _ContractScanContext | None = None
    adapter: TargetAdapter
    if contract is not None:
        if any((target, system_prompt, endpoint, framework, framework_ref)):
            typer.echo(
                "--contract is mutually exclusive with target / --system-prompt / "
                "--endpoint / --framework / --framework-ref.",
                err=True,
            )
            return EXIT_CONFIG
        from agent_guardian.contract.errors import ContractError
        from agent_guardian.core.roe import RoeAuthorizationError

        try:
            contract_ctx = _ContractScanContext(contract, otel_endpoint=otel_endpoint)
        except RoeAuthorizationError as exc:
            typer.echo(f"authorization error: {exc}", err=True)
            return EXIT_CONFIG
        except ContractError as exc:
            typer.echo(f"contract error: {exc}", err=True)
            return EXIT_CONFIG
        adapter = contract_ctx.adapter
    else:
        # Pre-scan reachability preflight for --endpoint mode (#3). A hosted
        # target that is unreachable would otherwise burn the full LLM budget
        # on per-probe timeouts; we'd rather exit fast with a clear message.
        # --no-preflight is the explicit escape hatch. Placeholder hosts (e.g.
        # api.example.com from a scaffolded contract) are skipped automatically.
        if endpoint and not no_preflight and not _is_placeholder_endpoint(endpoint):
            reachable = await _endpoint_reachability_preflight(endpoint)
            if not reachable:
                typer.echo(
                    f"target unreachable: {endpoint}\n"
                    "  - if the target is on Cloud Run / Lambda and hasn't been hit "
                    "recently, retry once to warm it up\n"
                    "  - or re-run with --no-preflight to skip this check",
                    err=True,
                )
                return EXIT_TARGET_UNREACHABLE
        try:
            adapter = build_target_adapter(
                target=target,
                system_prompt_path=system_prompt,
                endpoint=endpoint,
                framework=framework,
                framework_ref=framework_ref,
                target_llm=target_llm,
                target_model=_normalise_model_name(eff_attacker),
            )
        except typer.BadParameter as exc:
            typer.echo(f"target error: {exc}", err=True)
            return EXIT_CONFIG
        except FileNotFoundError as exc:
            typer.echo(f"target unreachable: {exc}", err=True)
            return EXIT_TARGET_UNREACHABLE
    # v1.1 mode resolution. ScanMode validates against the {fast,smart,full}
    # vocabulary; anything else is a user error worth surfacing as
    # EXIT_CONFIG rather than crashing the SwarmConfig constructor.
    from agent_guardian.core.swarm import ScanMode

    try:
        resolved_mode = ScanMode(mode.lower())
    except ValueError:
        typer.echo(
            f"unknown mode '{mode}' -- must be 'fast', 'smart', or 'full'.",
            err=True,
        )
        return EXIT_CONFIG
    swarm_config = SwarmConfig(
        scan_id=scan_id,
        commander_model=_normalise_model_name(eff_commander),
        attacker_model=_normalise_model_name(eff_attacker),
        evaluator_model=_normalise_model_name(eff_evaluator),
        overall_wall_seconds=float(cfg.swarm.budget.wall_seconds),
        total_tokens=cfg.swarm.budget.max_total_tokens,
        # OWASP-LLM specialists default ON post-launch hardening: transport-level
        # secret-leak and DoW are required default surface for agentic security.
        # --no-owasp-llm suppresses them and reverts to the 10-agent slate cap.
        max_parallel_agents=(min(10, cfg.swarm.max_parallel_agents) if no_owasp_llm else 14),
        tier_override=tier_override,
        target_goal=goal,
        mode=resolved_mode,
        # M2 capabilities (all default-off; flags above turn them on).
        enable_pov_gate=pov_gate or critic,
        enable_critic_rubric=critic,
        bundle_dir=bundle,
        enable_pretext=pretext,
        enable_indirect=indirect,
        include_m2_agents=not no_owasp_llm,
        # Runtime USD cap (opt-in). None = uncapped. Enforced live by the
        # swarm's budget watchdog -- see SwarmConfig.usd_cap.
        usd_cap=budget_usd,
        # Shorter checkpoint than the library default so CLI runs feel responsive.
        checkpoint_interval_seconds=2.0,
        # recon_wall_seconds intentionally left at the SwarmConfig default (90s);
        # 5s caused recon to time out on any real LLM call (esp. rate-limited
        # free-tier Gemini) and the swarm then produced fake "EXCELLENT" scores
        # against an empty memory.
    )

    # Stage 1B -- project the contract's RoE budgets onto the engine's knobs.
    # ``swarm_overrides`` only carries keys the contract actually set, so this
    # never clobbers anything the contract left unspecified.
    observer: Any = None
    if contract_ctx is not None:
        import dataclasses

        if contract_ctx.swarm_overrides:
            swarm_config = dataclasses.replace(swarm_config, **contract_ctx.swarm_overrides)
        observer = contract_ctx.observer
    elif otel_endpoint:
        # Non-contract scan path (system-prompt / code / endpoint / framework):
        # honour --otel-endpoint / OTEL_EXPORTER_OTLP_ENDPOINT so GenAI traces
        # land in the operator's OTLP collector regardless of which scan mode
        # they used. (--contract path already wires this via the contract's
        # observability.otel_endpoint, which takes precedence.)
        from agent_guardian.obs.otel import configure_otel, make_otel_observer

        configure_otel(otel_endpoint)
        observer = make_otel_observer()

    swarm = SwarmCommander(
        config=swarm_config,
        target=adapter,
        attacker_llm=attacker_llm,
        evaluator_llm=evaluator_llm,
        commander_llm=commander_llm,
        rng_seed=seed,
        observer=observer,
    )

    # QA-005 — attach the reflection sink BEFORE the TUI so the renderer
    # wraps whatever observer is already wired (otel, store, etc.) and
    # the TUI's attach_to() wraps the renderer in turn. The wrap chain
    # is: TUI → AttackFeedRenderer → prior observer (otel / store /
    # caller-supplied). All three run per event; failures in any one
    # are suppressed so a sick sink can't break the swarm.
    feed_renderer: Any = None
    if debug_level > 0:
        from agent_guardian.ui.attack_feed import (
            AttackFeedRenderer,
            DebugFormat,
            DebugLevel,
        )

        level_cast: DebugLevel = 2 if debug_level >= 2 else 1
        fmt_cast: DebugFormat = "json" if debug_format == "json" else "text"
        feed_renderer = AttackFeedRenderer(
            level=level_cast,
            format=fmt_cast,
            scan_id=scan_id,
        )
        feed_renderer.attach_to(swarm)

    # 8. Run -- optionally with TUI.
    #    QA-002 — the Live region is the single stdout owner during a
    #    scan. Auto-fall-back to the no-Live path when stdout is not a
    #    TTY (CI, pipe-to-file, redirected log capture); that keeps the
    #    operator's NDJSON observer feed clean of ANSI frames.
    effective_no_tui = no_tui or not sys.stdout.isatty()
    try:
        if effective_no_tui:
            scan_result = await swarm.run()
        else:
            from agent_guardian.cli_tui import ScanTUI

            tui = ScanTUI(
                scan_id=scan_id,
                target_ref=adapter.fingerprint().ref,
                tier=tier_override.value if tier_override else "auto",
            )
            tui.attach_to(swarm)
            async with tui:
                scan_result = await swarm.run()
    except KeyboardInterrupt:
        # QA-002 — the ``async with tui`` context guarantees ``Live.stop()``
        # runs (cursor restore + scrollback flush) before this handler
        # sees the interrupt. Surface a clean operator message through
        # the shared RichHandler-bound logger and translate to the
        # standard ``130`` exit code.
        _LOG.warning("scan interrupted by user; partial state preserved")
        return EXIT_USER_INTERRUPT
    except SandboxViolation as exc:
        _LOG.error("sandbox violation: %s", exc)
        return EXIT_SANDBOX
    except LLMError as exc:
        _LOG.error("llm provider error: %s: %s", type(exc).__name__, exc)
        return EXIT_LLM_PROVIDER
    finally:
        # Close every LLM client + adapter we opened. Deduplicate when two
        # role slots point at the same object (a stub run, or any case where
        # the same model spec is reused) so we don't double-close. Returning
        # exceptions instead of raising keeps a noisy aclose from masking the
        # original scan error.
        seen: set[int] = set()
        closeables: list[Any] = [adapter]
        for client in (attacker_llm, evaluator_llm, commander_llm, target_llm):
            if id(client) not in seen:
                seen.add(id(client))
                closeables.append(client)
        await asyncio.gather(
            *(c.aclose() for c in closeables),
            return_exceptions=True,
        )

    # First-scan telemetry notice -- non-blocking, prints to stderr.
    # Fires at most once per install; subsequent scans are silent.
    try:
        from agent_guardian.telemetry.prompt import maybe_show_first_scan_notice

        maybe_show_first_scan_notice()
    except Exception as exc:  # pragma: no cover -- defensive
        _LOG.debug(
            "telemetry: first-scan notice failed (%s: %s) -- scan result unaffected",
            type(exc).__name__,
            exc,
        )

    # Stage 1B -- attach the RoE/contract provenance audit before any report is
    # rendered so SARIF emits its invocation + contract_sha256 block. The Scan is
    # frozen, so we copy with the audit set. We also persist a JSONL audit trail.
    if contract_ctx is not None:
        audit = contract_ctx.build_audit(scan_result)
        scan_result = scan_result.model_copy(update={"audit": audit})
        audit_path = Path.home() / ".agentguardian" / "scans" / scan_id / "audit.jsonl"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(json.dumps(audit, sort_keys=True) + "\n", encoding="utf-8")
        typer.echo(f"contract audit written to {audit_path}")

    # 8b. Authoritative-scan gate (#1). A scan whose evaluator/attacker was the
    #     stub (or that the swarm otherwise marked non-authoritative) can never
    #     produce a real finding, so its numeric AIVSS is vacuous. The swarm
    #     already forces band=NOT_EVALUATED + scoring_valid=False for such runs;
    #     here we make it LOUD on stderr and ensure --fail-under treats it as a
    #     failure (never a silent green pass).
    authoritative = scan_result.scoring_valid
    if not authoritative:
        # QA-004 — branch the NON-AUTHORITATIVE banner on (evaluation_mode,
        # coverage_pct, mode_threshold) instead of unconditionally blaming a
        # stub evaluator. A real-LLM scan with thin coverage now gets copy
        # that names the actual coverage % + threshold + actionable
        # remediation rather than the misleading "re-run with a real --model"
        # the user already supplied.
        from agent_guardian.reports.warnings import build_authoritativeness_warning

        warning_text = build_authoritativeness_warning(scan_result)
        if warning_text is not None:
            typer.echo(warning_text, err=True)

    # 9. Render + persist report. The canonical scan.json is always written via
    #    the signed/redacted ``write_json`` path so the persisted artifact is
    #    schema-stamped, signed, and PII-redacted (#1/#2). The user-chosen
    #    --output report is written separately (may be a different format).
    if output_path is None:
        output_path = Path.home() / ".agentguardian" / "scans" / scan_id / f"report.{output}"
    try:
        _write_report(scan_result, output, output_path)
    except typer.BadParameter as exc:
        typer.echo(f"output format error: {exc}", err=True)
        return EXIT_CONFIG
    except Exception as exc:
        # PDF engines can raise PdfFeatureUnavailable etc. Surface clearly.
        typer.echo(f"report write error: {type(exc).__name__}: {exc}", err=True)
        return EXIT_CONFIG

    # Persist the canonical scan.json (signed + redacted + schema-stamped) for
    # later `report` / `verify` / `publish` calls. The raw, unsigned model dump
    # is kept alongside as scan.raw.json for debugging only.
    from agent_guardian.reports.json_report import write_json

    scan_dir = Path.home() / ".agentguardian" / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    try:
        write_json(scan_result, scan_dir / "scan.json")
    except Exception as exc:
        typer.echo(f"could not persist canonical scan.json: {type(exc).__name__}: {exc}", err=True)
        return EXIT_CONFIG
    (scan_dir / "scan.raw.json").write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")

    # 10. Final state + summary.
    state = _read_state()
    state["last_score"] = int(scan_result.aivss)
    state["last_scan_id"] = scan_id
    state["last_scan_at"] = datetime.now(tz=timezone.utc).isoformat()
    with contextlib.suppress(OSError):
        _write_state(state)

    band: SeverityBand = scan_result.band
    aivss_label = str(scan_result.aivss) if authoritative else "n/a"
    coverage_label = ""
    coverage_pct: float | None = None
    if scan_result.completeness is not None:
        coverage_pct = float(scan_result.completeness.pct)
        if coverage_pct < 100.0:
            coverage_label = f" coverage={coverage_pct:.0f}%"
    typer.echo(
        f"scan {scan_id} done: AIVSS={aivss_label} band={band.value} "
        f"tier={scan_result.tier.value} findings={len(scan_result.findings)}{coverage_label} "
        f"report={output_path}"
    )

    # Coverage warning: when a scan launched less than the authoritative-mode
    # floor, surface it on stderr so a CI gate downstream knows the scan was
    # thinly tested (and we never silently pass a slim run as full coverage).
    # When the scan was already flagged non-authoritative above, the QA-004
    # branched banner already named the coverage % + threshold; suppress this
    # second message to avoid duplicate stderr lines about the same cause.
    if coverage_pct is not None and coverage_pct < 100.0 and authoritative:
        from agent_guardian.reports.warnings import MODE_AUTHORITATIVE_THRESHOLDS

        mode_floor = MODE_AUTHORITATIVE_THRESHOLDS.get(scan_result.mode, 95.0)
        if coverage_pct < mode_floor:
            typer.echo(
                f"WARNING: coverage {coverage_pct:.0f}% is below the "
                f"--mode {scan_result.mode} authoritative threshold ({mode_floor:.0f}%). "
                "The absence of findings here is not evidence of safety -- re-run with a "
                "larger budget or --mode full for an authoritative assessment.",
                err=True,
            )

    # --fail-under: a non-authoritative scan is ALWAYS a failure (it tested
    # nothing); otherwise compare the numeric AIVSS against the floor. A
    # FAST/SMART scan (#44) is also non-authoritative as a gate input: its
    # numeric score reflects how much was tested, not how safe the agent is,
    # so we refuse to gate-pass on it and emit a loud stderr warning.
    if fail_under is not None:
        if not authoritative:
            typer.echo(
                f"--fail-under {fail_under}: FAILED -- scan is non-authoritative "
                "(NOT_EVALUATED); a stub/unscored run never passes a gate.",
                err=True,
            )
            return EXIT_FAIL_UNDER
        if not scan_result.mode_authoritative:
            typer.echo(
                f"WARNING: --fail-under {fail_under}: this scan was run in "
                f"--mode {scan_result.mode}; quoted score {scan_result.aivss} is "
                "not authoritative -- re-run with --mode full for a real gate.",
                err=True,
            )
            return EXIT_FAIL_UNDER
        if scan_result.aivss < fail_under:
            return EXIT_FAIL_UNDER
    return EXIT_OK


# ---------------------------------------------------------------------------
# Top-level --version callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version_flag: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """AgentGuardian -- eleven-agent adversarial swarm CLI."""
    # Wire centralised logging FIRST so .env loading + every sub-command
    # see structured logs. Default level is INFO; operators bump to DEBUG
    # via AGENT_GUARDIAN_LOG_LEVEL=DEBUG when they need the full review
    # trace. See ``agent_guardian.logging_setup``.
    configure_logging()
    # Project-local .env auto-loading. Fires for every sub-command so
    # ``agent-guardian scan`` / ``doctor`` / ``serve`` all see the keys.
    # See ``_try_load_dotenv`` for the (deliberately conservative) lookup.
    _try_load_dotenv()
    logging.getLogger(__name__).debug(
        "CLI initialised: log level=%s, version=%s",
        logging.getLevelName(logging.getLogger().getEffectiveLevel()),
        __version__,
    )


if __name__ == "__main__":
    app()
