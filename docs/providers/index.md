# LLM Providers

AgentGuardian's swarm needs an LLM for three roles — **commander** (orchestration), **attacker** (probe generation), and **evaluator** (verdict adjudication). Each role can be wired to a different provider and model, or all three can share one model spec.

## Provider matrix

| Provider          | `--model` prefix         | Auth                                                                    | Required extra | Status                      |
|-------------------|--------------------------|-------------------------------------------------------------------------|----------------|-----------------------------|
| Stub (no network) | `stub`                   | none                                                                    | none           | Stable. Default.            |
| [OpenAI](openai.md)             | `openai:<model>`         | `OPENAI_API_KEY` or `AGENT_GUARDIAN_OPENAI_API_KEY`                     | none           | Stable.                     |
| [Anthropic](anthropic.md)       | `anthropic:<model>`      | `ANTHROPIC_API_KEY` or `AGENT_GUARDIAN_ANTHROPIC_API_KEY`               | none           | Stable.                     |
| [Google Gemini](vertex.md)      | `gemini:<model>`         | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, or `AGENT_GUARDIAN_GEMINI_API_KEY`  | none           | Stable (AI Studio API).     |
| [Google Vertex](vertex.md)      | *(via `VertexClient`)*   | Service-account OAuth2                                                  | none           | M9 — request/response shaping only today. |
| [AWS Bedrock](bedrock.md)       | `bedrock:<bedrock-id>`   | Standard AWS credential chain (no API key)                              | `[aws]`        | Stable.                     |
| [Ollama (local)](ollama.md)     | `ollama:<model>`         | none                                                                    | none           | Stable.                     |

## How model specs are resolved

`build_llm()` (see [`src/agent_guardian/cli.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)) resolves a model spec in this order:

1. **Explicit prefix** — `provider:model` always wins (e.g. `openai:gpt-4o`).
2. **Heuristic prefix** — bare specs starting with `gpt-`, `claude-`, `gemini-`, or `ollama-` are routed to their obvious provider.
3. **`bedrock:`** is the only provider that **requires** the explicit prefix — Bedrock model IDs (`anthropic.claude-haiku-4-5-v1:0`, etc.) overlap with the direct Anthropic naming, so the prefix disambiguates.

## Env-var precedence

For every provider that takes an API key, AgentGuardian looks up keys in this order:

1. `AGENT_GUARDIAN_<PROVIDER>_API_KEY` — namespaced. Use this when running multiple red-team tools side-by-side.
2. The provider's conventional env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`).
3. For Gemini only: `GOOGLE_API_KEY` is also accepted (this is what the Google AI Studio quickstart hands users).

If you have `[dev]` installed, a `.env` file in the current working directory is auto-loaded — but a real shell export always overrides `.env`.

## Splitting roles across providers

Use cheap models for the attacker (which produces lots of low-stakes prompts) and stronger models for the evaluator (which makes the verdict call):

```bash
agent-guardian scan --system-prompt prompt.txt \
  --commander-model anthropic:claude-haiku-4-5 \
  --attacker-model openai:gpt-4o-mini \
  --evaluator-model anthropic:claude-opus-4-7
```

The cost estimator (`cost.py`) prices each role independently against the bundled `PRICE_TABLE` and prints a per-scan estimate before the swarm starts.
