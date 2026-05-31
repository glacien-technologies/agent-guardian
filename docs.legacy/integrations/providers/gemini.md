# Google Gemini (AI Studio)

> **TL;DR.** Gemini via the Google AI Studio API. Set
> `GEMINI_API_KEY` (or `GOOGLE_API_KEY`), pass `--model gemini:<model>`
> (or any bare `gemini-...`), and you're done. This is the same
> backend that powers the demo targets in `examples/`. For the
> service-account / Vertex AI path, see [Vertex AI](vertex.md).

AgentGuardian uses the Google AI Studio Generative Language API
(`https://generativelanguage.googleapis.com/v1beta`) via the built-in
`GeminiClient` (`src/agent_guardian/llm/gemini.py`). The same client
backs every demo target under `examples/` — both the LangGraph and the
OpenAI Agents SDK trios route their inference through Gemini via this
client (see `examples/_gemini_chat.py`).

This is a separate surface from Vertex AI — see the docstring at
`src/agent_guardian/llm/gemini.py:1-12` for the split.

## Authentication

Set one of:

| Env var                              | When to use                                                       |
|--------------------------------------|-------------------------------------------------------------------|
| `GEMINI_API_KEY`                     | Standard.                                                         |
| `GOOGLE_API_KEY`                     | Also accepted — this is what the [AI Studio](https://aistudio.google.com/app/apikey) quickstart hands you. |
| `AGENT_GUARDIAN_GEMINI_API_KEY`      | Namespaced override.                                              |

Precedence: `AGENT_GUARDIAN_GEMINI_API_KEY` → `GEMINI_API_KEY` →
`GOOGLE_API_KEY`. If none are set, `agent-guardian scan` exits with
`EXIT_LLM_PROVIDER` (code `4`).

```bash
export GEMINI_API_KEY=...
agent-guardian doctor    # should list "gemini" under detected keys
```

## Model spec

```text
--model gemini:<model-name>
# or, by heuristic for any model starting with "gemini-":
--model gemini-2.5-flash
```

### Examples

| Model spec                       | Notes                                                            |
|----------------------------------|------------------------------------------------------------------|
| `gemini:gemini-2.5-pro`          | Strongest tier.                                                  |
| `gemini:gemini-2.5-flash`        | Cheap, fast — default for demo targets.                          |
| `gemini:gemini-2.5-flash-lite`   | Cheapest tier.                                                   |
| `gemini-2.5-flash`               | Same as above — heuristic prefix.                                |

Validation of the model name happens server-side — `GeminiClient`
accepts any string and lets the API decide. The cost table ships rows
for the well-known SKUs so the pre-flight USD estimate is informative
for the common models (`src/agent_guardian/llm/gemini.py:55-58`).

## End-to-end example

```bash
export GEMINI_API_KEY=...
echo "You are a customer-support bot for ACME Corp." > prompt.txt

agent-guardian scan --system-prompt prompt.txt \
  --mode quick \
  --model gemini:gemini-2.5-flash
```

## Cost (list prices, verified 2026-05-27)

The bundled `PRICE_TABLE` (`src/agent_guardian/cost.py`) ships these
Gemini rows in USD per 1M tokens:

| Model                         | Input    | Output  |
|-------------------------------|---------:|--------:|
| `gemini-2.5-pro`              | $1.250   | $10.000 |
| `gemini-2.5-flash`            | $0.300   | $2.500  |
| `gemini-2.5-flash-lite`       | $0.075   | $0.300  |
| `gemini-3.1-pro-preview`      | $1.250   | $10.000 |
| `gemini-3.5-flash`            | $0.300   | $2.500  |

The Gemini SKU lineup moves quickly — re-check
[ai.google.dev/pricing](https://ai.google.dev/pricing) before relying
on these for a long-running scan campaign.

## Retry behaviour

Rate-limit (`429`), timeout, and 5xx errors are retried with
exponential backoff via `agent_guardian.llm.retry.with_backoff`
(`src/agent_guardian/llm/retry.py:136`). A `Retry-After` header
overrides the computed backoff for that single retry
(`src/agent_guardian/llm/gemini.py:180-192`).

Persistent rate-limit failures surface as `LLMRateLimitError` and exit
the CLI with `EXIT_LLM_PROVIDER` (code `4`).

## Seeds

Gemini accepts a deterministic seed inside `generationConfig` for AI
Studio v1beta. `GeminiClient` forwards the seed verbatim
(`src/agent_guardian/llm/gemini.py:80-84`), so swarm replay buys actual
determinism — not just the same prompt.
