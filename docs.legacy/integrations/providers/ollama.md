# Ollama (local)

> **TL;DR.** Ollama is the local-development backend. No API key, no
> egress, zero dollars. Start the Ollama daemon on
> `http://localhost:11434`, `ollama pull` a model, and pass
> `--model ollama:<tag>`. Use this when you want every byte of the
> scan to stay on-device.

AgentGuardian talks to a local [Ollama](https://ollama.com) daemon via
the built-in `OllamaClient` (`src/agent_guardian/llm/ollama.py`). No
extras required, no API key.

## Prerequisites

1. Install Ollama: <https://ollama.com/download>.
2. Start the daemon (Ollama starts at first run; verify it's
   listening on `http://localhost:11434`):

   ```bash
   curl -s http://localhost:11434/api/tags
   ```

3. Pull at least one model. Larger models give better attacker /
   evaluator behaviour but cost more memory and inference time:

   ```bash
   ollama pull llama3.1
   ollama pull qwen2.5
   ```

## Model spec

```text
--model ollama:<model-tag>
```

The `<model-tag>` is whatever `ollama list` shows in the left column
(e.g. `llama3.1`, `llama3.1:70b`, `qwen2.5:32b`).

### Examples

| Model spec                  | Notes                                                            |
|-----------------------------|------------------------------------------------------------------|
| `ollama:llama3.1`           | Default. Good general-purpose attacker.                          |
| `ollama:llama3.1:70b`       | Heavier — better evaluator, much slower inference.               |
| `ollama:qwen2.5:32b`        | Strong evaluator alternative.                                    |

## End-to-end example

```bash
# Pull a model (one-time)
ollama pull llama3.1

# Run a scan that never leaves the box
echo "You are a customer-support bot for ACME Corp." > prompt.txt
agent-guardian scan --system-prompt prompt.txt \
  --mode quick \
  --model ollama:llama3.1
```

## Custom endpoint

`OllamaClient(base_url=...)` defaults to `http://localhost:11434`
(`src/agent_guardian/llm/ollama.py`). To point at a remote Ollama
host, instantiate the client directly from the Python API — the CLI
does not expose a `--base-url` flag for Ollama in v1.0.

```python
from agent_guardian.llm import OllamaClient

client = OllamaClient(base_url="http://ollama.internal:11434")
```

## Cost

Ollama scans cost zero dollars but plenty of compute. The cost
estimator returns `$0.00` for `ollama:` model specs, so
`--budget-usd` gates are inert for local runs. Watch
`AGENT_GUARDIAN_TIME_BUDGET_SECONDS` and the swarm's wall-clock
budget instead — those are the gates that bite on a laptop.

## Retry behaviour

Transient failures (timeouts, 5xx) are retried with exponential
backoff via `agent_guardian.llm.retry.with_backoff`
(`src/agent_guardian/llm/retry.py:136`). The Ollama daemon does not
emit `429`s; if it returns `503` mid-scan, the same backoff window
applies.
