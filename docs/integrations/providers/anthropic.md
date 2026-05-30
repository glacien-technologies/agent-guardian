# Anthropic

> **TL;DR.** Anthropic is wired via the Messages API. Set
> `ANTHROPIC_API_KEY`, pass `--model anthropic:<model>` (or any bare
> `claude-...`), and you're done. Claude Haiku 4.5 is the default
> commander model. For Claude on AWS, use the
> [Bedrock](bedrock.md) page instead.

AgentGuardian uses the [Anthropic Messages API](https://docs.anthropic.com/en/api/messages)
via the built-in `AnthropicClient`
(`src/agent_guardian/llm/anthropic.py`). No extras required — the
client is in the base install.

For Anthropic Claude models hosted on **AWS Bedrock**, see
[AWS Bedrock](bedrock.md) instead — same model family, different
auth/transport.

## Authentication

Set one of:

| Env var                              | When to use                                                       |
|--------------------------------------|-------------------------------------------------------------------|
| `ANTHROPIC_API_KEY`                  | Standard. Works with every other Anthropic SDK / tool.            |
| `AGENT_GUARDIAN_ANTHROPIC_API_KEY`   | Namespaced override — isolates the key from other tools.          |

The namespaced variable takes precedence. If neither is set,
`agent-guardian scan` exits with `EXIT_LLM_PROVIDER` (code `4`).

```bash
export ANTHROPIC_API_KEY=sk-ant-...
agent-guardian doctor    # should list "anthropic" under detected keys
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
| `anthropic:claude-haiku-4-5`     | Cheap, fast — the default commander model (`config.py:51`).      |
| `claude-haiku-4-5`               | Same as `anthropic:claude-haiku-4-5` — heuristic prefix.         |

## End-to-end example

```bash
export ANTHROPIC_API_KEY=sk-ant-...
echo "You are a customer-support bot for ACME Corp." > prompt.txt

agent-guardian scan --system-prompt prompt.txt \
  --mode quick \
  --model anthropic:claude-haiku-4-5 \
  --evaluator-model anthropic:claude-opus-4-7
```

## Cost (list prices, verified 2026-05-27)

The bundled `PRICE_TABLE` (`src/agent_guardian/cost.py`) ships these
Anthropic rows in USD per 1M tokens:

| Model                  | Input  | Output |
|------------------------|-------:|-------:|
| `claude-haiku-4-5`     | $0.80  | $4.00  |
| `claude-sonnet-4-6`    | $3.00  | $15.00 |
| `claude-opus-4-7`      | $15.00 | $75.00 |

Set `--budget-usd <cap>` to abort the scan before it starts if the
pre-flight estimate exceeds your cap.

## Retry behaviour

Rate-limit (`429`) and overload (`529`) errors are retried with
exponential backoff via `agent_guardian.llm.retry.with_backoff`
(`src/agent_guardian/llm/retry.py:136`). The public client ceiling is
`max_retries=6`, `max_seconds=60`; the agent-loop path uses tighter
caps (`AGENT_LOOP_MAX_RETRIES=3`, `AGENT_LOOP_MAX_SECONDS=15.0`,
`src/agent_guardian/llm/retry.py:51-52`). If a `Retry-After` header
is present, that value overrides the computed backoff for that single
retry.

Persistent rate-limit failures surface as `LLMRateLimitError` and exit
the CLI with `EXIT_LLM_PROVIDER` (code `4`). See
[FAQ — exit codes](../../faq/index.md#what-do-the-exit-codes-mean) for the
full table.

## Seeds

Anthropic does not honour deterministic seeds today. The client logs a
single warning when a seed is supplied and then drops it — see
`_maybe_warn_seed_ignored` in `src/agent_guardian/llm/anthropic.py:51`.
