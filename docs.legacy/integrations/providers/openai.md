# OpenAI

> **TL;DR.** OpenAI is wired via the Chat Completions API. Set
> `OPENAI_API_KEY`, pass `--model openai:<model>` (or any bare
> `gpt-...`), and you're done. Retries on 429/5xx are automatic;
> cost is estimated up-front from the bundled price table.

AgentGuardian uses the OpenAI [Chat Completions API](https://developers.openai.com/api/reference/resources/chat)
via the built-in `OpenAIClient`
(`src/agent_guardian/llm/openai.py`). No extras required — the client
is in the base install.

## Authentication

Set one of:

| Env var                              | When to use                                                       |
|--------------------------------------|-------------------------------------------------------------------|
| `OPENAI_API_KEY`                     | Standard. Works with every other OpenAI SDK / tool on your machine. |
| `AGENT_GUARDIAN_OPENAI_API_KEY`      | Namespaced override — isolates the key from other tools.          |

The namespaced variable takes precedence. If neither is set,
`agent-guardian scan` exits with `EXIT_LLM_PROVIDER` (code `4`).

```bash
export OPENAI_API_KEY=sk-...
agent-guardian doctor    # should list "openai" under detected keys
```

## Model spec

```text
--model openai:<model-name>
# or, by heuristic for any model starting with "gpt-":
--model gpt-4o
```

### Examples

| Model spec                  | Notes                                                            |
|-----------------------------|------------------------------------------------------------------|
| `openai:gpt-4o`             | Strong, balanced — good evaluator choice.                        |
| `openai:gpt-4o-mini`        | Cheap, fast — good attacker choice for high-volume probes.       |
| `openai:gpt-4.1`            | Long-context.                                                    |
| `openai:gpt-4.1-mini`       | Cheaper long-context variant.                                    |
| `gpt-4o`                    | Same as `openai:gpt-4o` — heuristic prefix.                      |

## End-to-end example

```bash
export OPENAI_API_KEY=sk-...
echo "You are a customer-support bot for ACME Corp." > prompt.txt

agent-guardian scan --system-prompt prompt.txt \
  --mode quick \
  --model openai:gpt-4o-mini \
  --evaluator-model openai:gpt-4o
```

## Cost (list prices, verified 2026-05-27)

The bundled `PRICE_TABLE` (`src/agent_guardian/cost.py`) ships these
OpenAI rows in USD per 1M tokens:

| Model                  | Input  | Output |
|------------------------|-------:|-------:|
| `gpt-4o`               | $2.50  | $10.00 |
| `gpt-4o-mini`          | $0.150 | $0.60  |
| `gpt-4.1`              | $2.00  | $8.00  |
| `gpt-4.1-mini`         | $0.40  | $1.60  |
| `gpt-4.1-nano`         | $0.10  | $0.40  |

Set `--budget-usd <cap>` to abort the scan before it starts if the
pre-flight estimate exceeds your cap.

## Retry behaviour

Rate-limit (`429`), timeout, and 5xx errors are retried with
exponential backoff via `agent_guardian.llm.retry.with_backoff`
(`src/agent_guardian/llm/retry.py:136`). The public client ceiling is
`max_retries=6`, `max_seconds=60`; the agent-loop path uses tighter
caps (`AGENT_LOOP_MAX_RETRIES=3`, `AGENT_LOOP_MAX_SECONDS=15.0`,
`src/agent_guardian/llm/retry.py:51-52`). If a `Retry-After` header is
present, that value overrides the computed backoff for that single
retry.

Persistent rate-limit failures surface as `LLMRateLimitError` and exit
the CLI with `EXIT_LLM_PROVIDER` (code `4`). See
[FAQ — exit codes](../../faq/index.md#what-do-the-exit-codes-mean) for the
full table.

## Custom base URL (Azure OpenAI, gateways, mocks)

`OpenAIClient(base_url=...)` accepts any OpenAI-compatible endpoint —
the request body and headers match the OpenAI spec. For Azure OpenAI
you can either point `base_url` at your Azure deployment (use
`--commander-model openai:<your-deployment-name>` etc.) or use the
dedicated [`AzureFoundryAgentTransport`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/transports/azure_foundry.py)
for the Foundry thread/run data plane.
