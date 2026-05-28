# OpenAI

AgentGuardian uses the OpenAI [Chat Completions API](https://platform.openai.com/docs/api-reference/chat) via the built-in `OpenAIClient`. No extras required — the client is in the base install.

## Authentication

Set one of:

| Env var                              | When to use                                                       |
|--------------------------------------|-------------------------------------------------------------------|
| `OPENAI_API_KEY`                     | Standard. Works with every other OpenAI SDK / tool on your machine. |
| `AGENT_GUARDIAN_OPENAI_API_KEY`      | Namespaced override — isolates the key from other tools.          |

The namespaced variable takes precedence. If neither is set, `agent-guardian scan` exits with `EXIT_LLM_PROVIDER` (code 4).

```bash
export OPENAI_API_KEY=sk-...
agent-guardian doctor    # should now list "openai" under detected keys
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
| `openai:gpt-4-turbo`        | Legacy long-context model.                                       |
| `gpt-4o`                    | Same as `openai:gpt-4o` — heuristic prefix.                      |

## End-to-end example

```bash
export OPENAI_API_KEY=sk-...
echo "You are a customer-support bot for ACME Corp." > prompt.txt

agent-guardian scan --system-prompt prompt.txt \
  --model openai:gpt-4o-mini \
  --evaluator-model openai:gpt-4o
```

## Cost and rate limits

Cost is estimated upfront from the bundled `PRICE_TABLE` (see `src/agent_guardian/cost.py`). Set `--budget-usd <cap>` to abort before scanning if the estimate exceeds your cap.

Rate-limit errors (`429`) are retried with exponential backoff via `agent_guardian.llm.retry.with_backoff`. Persistent rate-limits surface as `LLMRateLimitError` and exit code `4`.
