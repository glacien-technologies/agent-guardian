"""AgentGuardian CLI — production command surface (PRD §8, M10).

The CLI is the primary user-facing way to drive a swarm scan. The full
command set lands here in M10; later milestones flesh out individual
sub-commands (M11 adds probe content, M12 fills in ``serve``, M13 adds
PDF output and signed-evidence ``verify``).

Design points worth knowing:

* The CLI is a thin wrapper around the library API. Anything the CLI
  can do is also reachable from Python — :func:`build_llm`,
  :func:`build_target_adapter`, and :func:`build_swarm` are the wedge
  the CLI uses, and any of them is importable for power users.
* ``--model stub`` is the universal safe default. Every command that
  needs an LLM tolerates ``stub`` so the test suite (and curious
  users) can run the whole pipeline without API keys.
* The first-run ethical-use banner (PRD §15.6) is printed once per
  user and remembered in ``~/.agentguardian/state.json``. We never
  inspect the CI environment to suppress it — the state file is
  sufficient.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer

from agent_guardian._version import __version__
from agent_guardian.adapters.base import TargetAdapter
from agent_guardian.adapters.code import CodeAdapter
from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.config import Config, env_api_key, load_config
from agent_guardian.core.sandbox import SandboxViolation
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.cost import estimate_scan_cost
from agent_guardian.llm import (
    AnthropicClient,
    BaseLLM,
    LLMError,
    OllamaClient,
    OpenAIClient,
    StubScript,
)
from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import (
    SeverityBand,
    band_for_score,
    colour_for_band,
)
from agent_guardian.models.tier import Tier

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
# Ordered ASI agent slate — single source of truth for ``list-agents`` etc.
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
    help="Opt-in usage telemetry (stub for M15).",
    no_args_is_help=True,
)
app.add_typer(telemetry_app, name="telemetry")


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
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
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


def _show_ethical_banner_once() -> None:
    """Print the ethical-use banner the first time a user runs a scan."""
    state = _read_state()
    if state.get("ethical_use_acknowledged"):
        return
    typer.echo(_BANNER)
    state["ethical_use_acknowledged"] = True
    state["ethical_use_acknowledged_at"] = datetime.now(tz=timezone.utc).isoformat()
    # Best-effort — a read-only home shouldn't break the scan.
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
    * ``"ollama:<model>"`` → :class:`OllamaClient` (local — no key).

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
        elif lowered.startswith("ollama-"):
            provider, model = "ollama", spec
        else:
            raise typer.BadParameter(
                f"Cannot infer provider for model spec '{spec}' (role={role}). "
                f"Use one of: stub, openai:<model>, anthropic:<model>, ollama:<model>."
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
                f"OpenAI requested for {role} but AGENT_GUARDIAN_OPENAI_API_KEY is not set."
            )
        return OpenAIClient(api_key=api_key)
    if provider == "anthropic":
        api_key = env_api_key("anthropic")
        if not api_key:
            raise typer.BadParameter(
                f"Anthropic requested for {role} but AGENT_GUARDIAN_ANTHROPIC_API_KEY is not set."
            )
        return AnthropicClient(api_key=api_key)
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
    target_llm: BaseLLM,
    target_model: str,
) -> TargetAdapter:
    """Build the right :class:`TargetAdapter` from the four CLI modes.

    Exactly one of ``target`` / ``system_prompt_path`` / ``endpoint`` /
    ``framework`` must be set. ``framework`` is a placeholder today — it
    raises until M11 ships framework-mode auto-discovery.
    """
    set_modes = [bool(system_prompt_path), bool(target), bool(endpoint), bool(framework)]
    if sum(set_modes) == 0:
        raise typer.BadParameter(
            "scan requires a target — pass a dotted path, --system-prompt PATH, "
            "--endpoint URL, or --framework KIND."
        )
    if sum(set_modes) > 1:
        raise typer.BadParameter(
            "scan target modes are mutually exclusive — choose exactly one of "
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
    raise typer.BadParameter(
        f"--framework {framework!r} target mode lands in M11; not yet supported."
    )


# ---------------------------------------------------------------------------
# Scan output / reporting
# ---------------------------------------------------------------------------


def _scan_to_json(scan: Scan) -> str:
    return scan.model_dump_json(indent=2)


def _scan_to_md(scan: Scan) -> str:
    findings_lines = [
        f"- **{f.severity.value}** — {f.summary} (ASI: {f.asi.value})" for f in scan.findings
    ]
    findings_block = "\n".join(findings_lines) if findings_lines else "_No findings._"
    return (
        f"# AgentGuardian scan {scan.id}\n\n"
        f"- AIVSS: **{scan.aivss}** ({scan.band.value})\n"
        f"- Tier: {scan.tier.value}\n"
        f"- Target: `{scan.target_ref}` ({scan.target_mode})\n"
        f"- Duration: {scan.duration_seconds:.2f}s\n"
        f"- Created: {scan.created_at.isoformat()}\n\n"
        f"## Findings ({len(scan.findings)})\n\n"
        f"{findings_block}\n"
    )


def _scan_to_sarif(scan: Scan) -> str:
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-guardian",
                        "version": scan.package_version,
                        "informationUri": "https://agentguardian.ai",
                    }
                },
                "results": [
                    {
                        "ruleId": f.probe_id,
                        "level": _sarif_level(f.severity.value),
                        "message": {"text": f.summary},
                        "properties": {
                            "asi": f.asi.value,
                            "severity": f.severity.value,
                        },
                    }
                    for f in scan.findings
                ],
                "properties": {
                    "aivss": scan.aivss,
                    "band": scan.band.value,
                    "tier": scan.tier.value,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }.get(severity, "warning")


def _scan_to_junit(scan: Scan) -> str:
    # Tiny SuiteXML — one testcase per ASI category, failed when score < 100.
    cases: list[str] = []
    for category in AsiCategory:
        score = scan.asi_scores.get(category, 100.0)
        name = asi_description(category)
        if score < 100:
            cases.append(
                f'  <testcase classname="agent_guardian.{category.value}" '
                f'name="{name}"><failure message="score={score}"/></testcase>'
            )
        else:
            cases.append(f'  <testcase classname="agent_guardian.{category.value}" name="{name}"/>')
    body = "\n".join(cases)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="agent-guardian" tests="{len(AsiCategory)}" '
        f'failures="{sum(1 for c in AsiCategory if scan.asi_scores.get(c, 100.0) < 100)}">\n'
        f"{body}\n"
        f"</testsuite>\n"
    )


_FORMAT_RENDERERS = {
    "json": _scan_to_json,
    "md": _scan_to_md,
    "sarif": _scan_to_sarif,
    "junit": _scan_to_junit,
}


def _render_scan(scan: Scan, output_format: str) -> str:
    renderer = _FORMAT_RENDERERS.get(output_format)
    if renderer is None:
        raise typer.BadParameter(
            f"unknown output format '{output_format}' "
            f"— choose one of: {', '.join(sorted(_FORMAT_RENDERERS))} (pdf in M13)"
        )
    return renderer(scan)


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
def doctor() -> None:
    """Verify install, available LLM keys, and runtime prerequisites."""
    typer.echo(f"agent-guardian {__version__}")
    typer.echo("CLI: ok")

    # Python + platform.
    typer.echo(f"python: {sys.version.split()[0]}")

    # Detect available LLM keys.
    found_keys = []
    for provider in ("openai", "anthropic", "bedrock", "vertex"):
        if env_api_key(provider):
            found_keys.append(provider)
    if found_keys:
        typer.echo(f"llm keys detected: {', '.join(found_keys)}")
    else:
        typer.echo("llm keys detected: none (use --model stub for offline scans)")

    # Sandbox readiness — try to import.
    try:
        from agent_guardian.core.sandbox import Sandbox

        _ = Sandbox
        typer.echo("sandbox: importable")
    except Exception as exc:  # pragma: no cover — defensive
        typer.echo(f"sandbox: import failed ({type(exc).__name__})")

    # State + config locations.
    typer.echo(f"state dir: {_state_dir()}")
    cwd_config = Path.cwd() / ".agentguardian.yaml"
    typer.echo("config (cwd): " + (str(cwd_config) if cwd_config.is_file() else "<not present>"))


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
                f"unknown ASI category '{asi}' — expected one of "
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
    """Emit an AIVSS badge — text by default, SVG with ``--svg``."""
    band = band_for_score(score)
    if svg:
        typer.echo(_badge_svg(score), nl=False)
    else:
        typer.echo(f"AIVSS {score} ({band.value}) {colour_for_band(band)}")


@app.command("last-score")
def last_score() -> None:
    """Print the AIVSS of the most recent scan."""
    state = _read_state()
    last = state.get("last_score")
    if last is None:
        typer.echo("no scans on record.")
        return
    band = band_for_score(int(last))
    typer.echo(f"AIVSS {int(last)} ({band.value})")


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind host. Default 127.0.0.1 (loopback only).",
    ),
    port: int = typer.Option(7474, "--port", help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes (dev only)."),
) -> None:
    """Start the local dashboard at http://<host>:<port>."""
    import uvicorn

    from agent_guardian.server.app import create_app

    if reload:
        # uvicorn's reload mode requires an import string, not a factory.
        uvicorn.run(
            "agent_guardian.server.app:create_app",
            host=host,
            port=port,
            reload=True,
            factory=True,
            log_level="info",
        )
        return
    uvicorn.run(
        create_app,
        host=host,
        port=port,
        factory=True,
        log_level="info",
    )


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to regenerate reports for."),
    output: str = typer.Option(
        "json", "--output", help="Report format: json | sarif | junit | md."
    ),
) -> None:
    """Regenerate a report from a stored scan."""
    scan_dir = Path.home() / ".agentguardian" / "scans" / scan_id
    scan_file = scan_dir / "scan.json"
    if not scan_file.is_file():
        typer.echo(f"no scan found at {scan_file}", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    payload = json.loads(scan_file.read_text(encoding="utf-8"))
    scan = Scan.model_validate(payload)
    typer.echo(_render_scan(scan, output))


@app.command()
def verify(path: Path = typer.Argument(..., help="Path to an evidence bundle.")) -> None:
    """Verify HMAC/Ed25519 signatures on an evidence bundle (M13 — stub)."""
    if not path.exists():
        typer.echo(f"path not found: {path}", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    typer.echo("M13 ships signed-evidence verification. Stub OK.")


@app.command()
def publish(scan_id: str = typer.Argument(..., help="Scan ID to publish.")) -> None:
    """Publish a scan to the public leaderboard (M15 — stub)."""
    typer.echo(f"M15 ships leaderboard publishing. Would publish scan {scan_id}.")


@telemetry_app.command("enable")
def telemetry_enable() -> None:
    """Enable opt-in usage telemetry."""
    state = _read_state()
    state["telemetry_enabled"] = True
    _write_state(state)
    typer.echo("telemetry enabled.")


@telemetry_app.command("disable")
def telemetry_disable() -> None:
    """Disable opt-in usage telemetry."""
    state = _read_state()
    state["telemetry_enabled"] = False
    _write_state(state)
    typer.echo("telemetry disabled.")


@telemetry_app.command("status")
def telemetry_status() -> None:
    """Show the current telemetry opt-in state."""
    state = _read_state()
    enabled = bool(state.get("telemetry_enabled", False))
    typer.echo(f"telemetry: {'enabled' if enabled else 'disabled'}")


# ---------------------------------------------------------------------------
# scan command — the big one
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str | None = typer.Argument(
        None,
        help="Dotted path or file:attr — e.g. 'my_agent:run'. Mutually exclusive with --system-prompt / --endpoint / --framework.",
    ),
    system_prompt: Path | None = typer.Option(
        None, "--system-prompt", help="Mode A — path to a system prompt file."
    ),
    endpoint: str | None = typer.Option(
        None, "--endpoint", help="Mode C — hosted HTTP endpoint URL."
    ),
    framework: str | None = typer.Option(
        None, "--framework", help="Mode D — framework kind (langgraph, crewai, …)."
    ),
    model: str = typer.Option("stub", "--model", help="LLM model spec (default: stub)."),
    commander_model: str | None = typer.Option(
        None, "--commander-model", help="Override commander LLM model."
    ),
    attacker_model: str | None = typer.Option(
        None, "--attacker-model", help="Override attacker LLM model."
    ),
    evaluator_model: str | None = typer.Option(
        None, "--evaluator-model", help="Override evaluator LLM model."
    ),
    tier: str | None = typer.Option(None, "--tier", help="Force tier — one of T1, T2, T3, T4."),
    budget_usd: float | None = typer.Option(
        None, "--budget-usd", help="Cap; abort if the estimate exceeds this."
    ),
    fail_under: int | None = typer.Option(
        None, "--fail-under", help="Exit 1 if final AIVSS < this value."
    ),
    output: str = typer.Option(
        "json", "--output", help="Report format: json | sarif | junit | md."
    ),
    output_path: Path | None = typer.Option(
        None, "--output-path", help="Where to write the report file."
    ),
    no_tui: bool = typer.Option(False, "--no-tui", help="Disable the Rich progress panel."),
    config_path: Path | None = typer.Option(
        None, "--config", help="Override the default config file location."
    ),
    seed: int = typer.Option(0, "--seed", help="RNG seed for determinism."),
) -> None:
    """Run an adversarial swarm scan against a target."""
    try:
        exit_code = asyncio.run(
            _run_scan(
                target=target,
                system_prompt=system_prompt,
                endpoint=endpoint,
                framework=framework,
                model=model,
                commander_model=commander_model,
                attacker_model=attacker_model,
                evaluator_model=evaluator_model,
                tier=tier,
                budget_usd=budget_usd,
                fail_under=fail_under,
                output=output,
                output_path=output_path,
                no_tui=no_tui,
                config_path=config_path,
                seed=seed,
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
) -> int:
    # 1. Config layer — file + defaults.
    try:
        cfg: Config = load_config(config_path)
    except Exception as exc:
        typer.echo(f"config error: {exc}", err=True)
        return EXIT_CONFIG

    # 2. Resolve model specs (CLI > config).
    eff_commander = commander_model or model or cfg.swarm.commander_model
    eff_attacker = attacker_model or model or cfg.swarm.attacker_model
    eff_evaluator = evaluator_model or model or cfg.swarm.evaluator_model

    # 3. Ethical banner (PRD §15.6) — first run only.
    _show_ethical_banner_once()

    # 4. Cost estimate.
    estimate = estimate_scan_cost(
        commander_model=eff_commander,
        attacker_model=eff_attacker,
        evaluator_model=eff_evaluator,
        total_tokens=cfg.swarm.budget.max_total_tokens,
    )
    typer.echo(f"cost estimate: ${estimate:.4f} (provider list prices, 2026-05-26)")
    if budget_usd is not None and estimate > budget_usd:
        typer.echo(
            f"budget exceeded: estimate ${estimate:.4f} > cap ${budget_usd:.4f}",
            err=True,
        )
        return EXIT_CONFIG

    # 5. Resolve tier override.
    tier_override: Tier | None = None
    if tier:
        try:
            tier_override = Tier(tier)
        except ValueError:
            typer.echo(f"unknown tier '{tier}' — must be T1, T2, T3, or T4.", err=True)
            return EXIT_CONFIG

    # 6. Build LLMs + target.
    try:
        attacker_llm = build_llm(eff_attacker, role="attacker")
        evaluator_llm = build_llm(eff_evaluator, role="evaluator")
        commander_llm = build_llm(eff_commander, role="commander")
        target_llm = build_llm(eff_attacker, role="target")  # stub-backed wrapper for prompt mode.
    except typer.BadParameter as exc:
        typer.echo(f"llm config error: {exc}", err=True)
        return EXIT_LLM_PROVIDER

    try:
        adapter = build_target_adapter(
            target=target,
            system_prompt_path=system_prompt,
            endpoint=endpoint,
            framework=framework,
            target_llm=target_llm,
            target_model=_normalise_model_name(eff_attacker),
        )
    except typer.BadParameter as exc:
        typer.echo(f"target error: {exc}", err=True)
        return EXIT_CONFIG
    except FileNotFoundError as exc:
        typer.echo(f"target unreachable: {exc}", err=True)
        return EXIT_TARGET_UNREACHABLE

    # 7. Build swarm.
    scan_id = f"cli-{uuid.uuid4().hex[:12]}"
    swarm_config = SwarmConfig(
        scan_id=scan_id,
        commander_model=_normalise_model_name(eff_commander),
        attacker_model=_normalise_model_name(eff_attacker),
        evaluator_model=_normalise_model_name(eff_evaluator),
        overall_wall_seconds=float(cfg.swarm.budget.wall_seconds),
        total_tokens=cfg.swarm.budget.max_total_tokens,
        max_parallel_agents=min(10, cfg.swarm.max_parallel_agents),
        tier_override=tier_override,
        # Shorter checkpoint than the library default so CLI runs feel responsive.
        checkpoint_interval_seconds=2.0,
        recon_wall_seconds=5.0,
    )
    swarm = SwarmCommander(
        config=swarm_config,
        target=adapter,
        attacker_llm=attacker_llm,
        evaluator_llm=evaluator_llm,
        commander_llm=commander_llm,
        rng_seed=seed,
    )

    # 8. Run — optionally with TUI.
    try:
        if no_tui:
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
    except SandboxViolation as exc:
        typer.echo(f"sandbox violation: {exc}", err=True)
        return EXIT_SANDBOX
    except LLMError as exc:
        typer.echo(f"llm provider error: {type(exc).__name__}: {exc}", err=True)
        return EXIT_LLM_PROVIDER
    finally:
        await adapter.aclose()

    # 9. Render + persist report.
    try:
        rendered = _render_scan(scan_result, output)
    except typer.BadParameter as exc:
        typer.echo(f"output format error: {exc}", err=True)
        return EXIT_CONFIG

    if output_path is None:
        output_path = Path.home() / ".agentguardian" / "scans" / scan_id / f"report.{output}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")

    # Also persist the raw scan.json for later `report` calls.
    scan_dir = Path.home() / ".agentguardian" / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")

    # 10. Final state + summary.
    state = _read_state()
    state["last_score"] = int(scan_result.aivss)
    state["last_scan_id"] = scan_id
    state["last_scan_at"] = datetime.now(tz=timezone.utc).isoformat()
    with contextlib.suppress(OSError):
        _write_state(state)

    band: SeverityBand = scan_result.band
    typer.echo(
        f"scan {scan_id} done: AIVSS={scan_result.aivss} band={band.value} "
        f"tier={scan_result.tier.value} findings={len(scan_result.findings)} "
        f"report={output_path}"
    )

    if fail_under is not None and scan_result.aivss < fail_under:
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
    """AgentGuardian Open — eleven-agent adversarial swarm CLI."""


if __name__ == "__main__":
    app()
