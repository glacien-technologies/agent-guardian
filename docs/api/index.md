# API Reference

The Python API of `agent_guardian` is the same surface the CLI is built on top of. Anything `agent-guardian scan` can do is reachable from Python; the CLI is a thin wrapper around `build_llm()`, `build_target_adapter()`, and `SwarmCommander.run()`.

This reference is generated from the docstrings in the source. Click through to a module to see signatures, types, and source links.

## Top-level public exports

The package's `__init__.py` re-exports everything in this reference plus a few utilities. All names are stable across patch releases.

| What you want                                  | Where it is                          |
|------------------------------------------------|--------------------------------------|
| Run a swarm scan                               | [`SwarmCommander`](core.md)          |
| Configure a swarm                              | [`SwarmConfig`](core.md)             |
| Build a target adapter (prompt / code / HTTP / framework) | [Adapters](adapters.md)              |
| Wire an LLM provider                           | LLM clients in [Core](core.md)       |
| Inspect a scan's findings / score              | [`Scan`, `Finding`](models.md)       |
| Sign / verify a report                         | `agent_guardian.reports.json_report` |
| Emit a report in any format                    | `emit_json`, `emit_sarif`, `emit_junit`, `emit_markdown`, `write_pdf` (in core re-exports) |
| Compute AIVSS by hand                          | [`compute_aivss`](core.md)           |

## Layout

- [**CLI**](cli.md) — the Typer app and the helpers (`build_llm`, `build_target_adapter`) the CLI exposes.
- [**Models**](models.md) — Pydantic schemas for `Probe`, `Scan`, `Finding`, `JudgeVerdict`, plus the ASI / MITRE / CSA / Severity / Tier enums.
- [**Adapters**](adapters.md) — `PromptAdapter`, `CodeAdapter`, `HttpAdapter`, and the framework adapters (LangGraph, CrewAI, AutoGen, OpenAI Agents, ADK, Strands).
- [**Core (Swarm)**](core.md) — `SwarmCommander`, `SwarmConfig`, `BudgetController`, `SharedMemory`, `Sandbox`, `PiiRedactor`, `compute_aivss`.
