# LLM Providers

> **TL;DR.** AgentGuardian's swarm needs an LLM for three roles —
> commander, attacker, evaluator. Six providers are wired today: OpenAI,
> Anthropic, Gemini (AI Studio), AWS Bedrock, and Ollama are **Stable**;
> Vertex AI is **Preview** (request/response shaping ships, but the
> `complete()` transport is gated on v1.1). Each role takes its own
> `--model` flag, so attacker and evaluator can run on different
> backends.

## Provider matrix

| Provider                       | `--model` prefix         | Auth                                                                       | Required extra | Status                                                                                |
|--------------------------------|--------------------------|----------------------------------------------------------------------------|----------------|---------------------------------------------------------------------------------------|
| Stub (no network)              | `stub`                   | none                                                                       | none           | Stable. Default.                                                                      |
| [OpenAI](openai.md)            | `openai:<model>`         | `OPENAI_API_KEY` or `AGENT_GUARDIAN_OPENAI_API_KEY`                        | none           | Stable.                                                                               |
| [Anthropic](anthropic.md)      | `anthropic:<model>`      | `ANTHROPIC_API_KEY` or `AGENT_GUARDIAN_ANTHROPIC_API_KEY`                  | none           | Stable.                                                                               |
| [Google Gemini (AI Studio)](gemini.md) | `gemini:<model>` | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, or `AGENT_GUARDIAN_GEMINI_API_KEY`     | none           | Stable.                                                                               |
| [Google Vertex AI](vertex.md)  | *(via `VertexClient`)*   | Service-account OAuth2                                                     | none           | **Preview** — request/response shaping only; full transport targeted for v1.1.        |
| [AWS Bedrock](bedrock.md)      | `bedrock:<bedrock-id>`   | Standard AWS credential chain (no API key)                                 | `[aws]`        | Stable.                                                                               |
| [Ollama (local)](ollama.md)    | `ollama:<model>`         | none                                                                       | none           | Stable.                                                                               |

The Status column tracks what actually ships in v1.0. "Preview" means
the code is in the tree and the request/response helpers are tested,
but `complete()` will raise — use one of the Stable rows for now and
see [Roadmap](../../reference/roadmap.md) for the v1.1 target.

## How model specs are resolved

`build_llm()` (see [`src/agent_guardian/cli.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py))
resolves a model spec in this order:

1. **Explicit prefix** — `provider:model` always wins (e.g. `openai:gpt-4o`).
2. **Heuristic prefix** — bare specs starting with `gpt-`, `claude-`,
   `gemini-`, or `ollama-` are routed to their obvious provider.
3. **`bedrock:` requires** the explicit prefix — Bedrock model IDs
   (`anthropic.claude-haiku-4-5-v1:0`, etc.) overlap with the direct
   Anthropic naming, so the prefix disambiguates.

## Env-var precedence

For every provider that takes an API key, AgentGuardian looks up keys
in this order:

1. `AGENT_GUARDIAN_<PROVIDER>_API_KEY` — namespaced. Use this when
   running multiple red-team tools side-by-side.
2. The provider's conventional env var (`OPENAI_API_KEY`,
   `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`).
3. For Gemini only: `GOOGLE_API_KEY` is also accepted — this is what
   the [Google AI Studio](https://aistudio.google.com/app/apikey)
   quickstart hands users.

If you have `[dev]` installed, a `.env` file in the current working
directory is auto-loaded — but a real shell export always overrides
`.env`.

## Splitting roles across providers

Use cheap models for the attacker (which produces lots of low-stakes
prompts) and stronger models for the evaluator (which makes the verdict
call):

```bash
agent-guardian scan --system-prompt prompt.txt \
  --commander-model anthropic:claude-haiku-4-5 \
  --attacker-model openai:gpt-4o-mini \
  --evaluator-model anthropic:claude-opus-4-7
```

The cost estimator (see `src/agent_guardian/cost.py`, table verified
2026-05-27) prices each role independently against the bundled
`PRICE_TABLE` and prints a per-scan estimate before the swarm starts.

## Retry and rate limits

Every provider client funnels its HTTP calls through
`agent_guardian.llm.retry.with_backoff` (`src/agent_guardian/llm/retry.py`).
The defaults: exponential backoff with `factor=2`, `jitter_pct=0.25`,
`max_seconds=60`, `max_retries=6`. The agent loop uses tighter caps
(`AGENT_LOOP_MAX_RETRIES=3`, `AGENT_LOOP_MAX_SECONDS=15.0`) so a single
provider hiccup cannot soak the whole budget.

A persistent 429 surfaces as `LLMRateLimitError` and exits the CLI with
`EXIT_LLM_PROVIDER` (code `4`). See the
[FAQ — exit codes](../../faq/index.md#what-do-the-exit-codes-mean) for the
full table and
[FAQ — Bedrock 403](../../faq/index.md#aws-bedrock-returns-http-403-model-not-enabled-in-this-region)
for a region-enablement walkthrough.
