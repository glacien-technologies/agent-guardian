# API Reference

The Python API of `agent_guardian` is the same surface the CLI is built on top of. Anything `agent-guardian scan` can do is reachable from Python; the CLI is a thin wrapper around `build_llm()`, `build_target_adapter()`, and `SwarmCommander.run()` (see [`src/agent_guardian/cli.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

This reference is generated from the docstrings in the source via [`mkdocstrings`](https://mkdocstrings.github.io/). Every symbol on these pages is re-exported from `agent_guardian.__all__` ([`src/agent_guardian/__init__.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/__init__.py)) and stable across patch releases.

## What you want / Where it is

| What you want                                          | Where it is                                                                |
|--------------------------------------------------------|----------------------------------------------------------------------------|
| Run the swarm programmatically                         | [`SwarmCommander`, `SwarmConfig`](core.md) (Core)                          |
| Inspect a scan's findings / score / band               | [`Scan`, `Finding`, `Severity`, `Tier`](models.md) (Models)                |
| Wrap an agent in a `TargetAdapter`                     | [Adapters](adapters.md) — Prompt / Code / HTTP / Framework                 |
| Wire an LLM provider                                   | [LLM clients](llm.md) — OpenAI / Anthropic / Gemini / Bedrock / Ollama / Vertex / Stub |
| Run a multi-turn attack strategy                       | [Strategies](strategies.md) — PAIR / TAP / Crescendo / MAD-MAX             |
| Emit a report in any format                            | [Reports](reports.md) — `emit_json`, `emit_sarif`, `emit_junit`, `emit_markdown`, `write_pdf` |
| Sign / verify a report                                 | [`sign_payload`, `verify_signatures`, `VerifyResult`](reports.md#signing-and-verification) |
| Manage signing keys                                    | [Crypto](crypto.md) — `Ed25519Keypair`, `sign_ed25519`, `verify_ed25519`, `sign_hmac`, `verify_hmac` |
| Build a structured attack `Scenario`                   | [`Scenario`, `ScenarioBatch`](models.md#scenario)                          |
| Read the Commander's per-agent plan                    | [`SwarmBrief`, `AgentBrief`, `SubGoal`](models.md#swarmbrief)              |
| Compute AIVSS by hand                                  | [`compute_aivss`, `AivssResult`](core.md#aivss-scoring)                    |

## Layout

- [**CLI**](cli.md) — the Typer app plus `build_llm()` / `build_target_adapter()` helpers any Python consumer can reuse.
- [**Core (Swarm)**](core.md) — `SwarmCommander`, `SwarmConfig`, `BudgetController`, `SharedMemory`, `Sandbox`, `PiiRedactor`, `compute_aivss`, plus the signing / verification entry points.
- [**Models**](models.md) — Pydantic schemas for `Probe`, `Scan`, `Finding`, `JudgeVerdict`, `Scenario`, `SwarmBrief`, and the ASI / MITRE / CSA / Severity / Tier enums.
- [**Adapters**](adapters.md) — `PromptAdapter`, `CodeAdapter`, `HttpAdapter`, and the framework adapters (LangGraph, CrewAI, AutoGen, OpenAI Agents, ADK, Strands).
- [**LLM clients**](llm.md) — provider-agnostic types (`BaseLLM`, `LLMRequest`, `LLMResponse`) and the seven concrete clients.
- [**Reports**](reports.md) — JSON / SARIF / JUnit / Markdown / PDF emitters and the canonical-JSON helper.
- [**Strategies**](strategies.md) — multi-turn attack state machines (PAIR, TAP, Crescendo, MAD-MAX).
- [**Crypto**](crypto.md) — Ed25519 and HMAC-SHA256 signers, key persistence, signature block schemas.

## Stability

The public surface is everything listed in `agent_guardian.__all__`. Symbols outside `__all__` are internal and may change without notice. The package is currently on a single major-version track — see [Roadmap](../roadmap.md) for the v1.0 / v1.1 / v1.2 plan.
