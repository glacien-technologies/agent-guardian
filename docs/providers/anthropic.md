# Anthropic

AgentGuardian uses the [Anthropic Messages API](https://docs.anthropic.com/en/api/messages) via the built-in `AnthropicClient`. No extras required — the client is in the base install.

For Anthropic Claude models hosted on **AWS Bedrock**, see [AWS Bedrock](bedrock.md) instead.

## Authentication

Set one of:

| Env var                              | When to use                                                       |
|--------------------------------------|-------------------------------------------------------------------|
| `ANTHROPIC_API_KEY`                  | Standard. Works with every other Anthropic SDK / tool.            |
| `AGENT_GUARDIAN_ANTHROPIC_API_KEY`   | Namespaced override — isolates the key from other tools.          |

The namespaced variable takes precedence. If neither is set, `agent-guardian scan` exits with `EXIT_LLM_PROVIDER` (code 4).

```bash
export ANTHROPIC_API_KEY=sk-ant-...
agent-guardian doctor    # should now list "anthropic" under detected keys
```

## Model spec

```text
--model anthropic:<model-name>
# or, by heuristic for any model starting with "claude-":
--model claude-haiku-4-5
```

### Examples

| Model spec                       | Notes                                                            |
|----------------------------------|------------------------------------------------------------------|
| `anthropic:claude-opus-4-7`      | Strongest. Default evaluator pick for high-stakes scans.         |
| `anthropic:claude-sonnet-4-6`    | Balanced.                                                        |
| `anthropic:claude-haiku-4-5`     | Cheap, fast — the default commander model in `config.py`.        |
| `claude-haiku-4-5`               | Same as `anthropic:claude-haiku-4-5` — heuristic prefix.         |

## End-to-end example

```bash
export ANTHROPIC_API_KEY=sk-ant-...

agent-guardian scan --system-prompt prompt.txt \
  --model anthropic:claude-haiku-4-5 \
  --evaluator-model anthropic:claude-opus-4-7
```

## Cost and rate limits

Cost is estimated upfront from the bundled `PRICE_TABLE`. Use `--budget-usd <cap>` to abort if the estimate exceeds your cap.

429s are retried with exponential backoff. Persistent rate-limit or overload errors surface as `LLMRateLimitError` and exit code `4`.
