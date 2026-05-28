# Ollama (local)

AgentGuardian talks to a local [Ollama](https://ollama.com) daemon via the built-in `OllamaClient`. No extras required, no API key — Ollama is the right pick when you want to keep every byte of the scan on-device.

## Prerequisites

1. Install Ollama: <https://ollama.com/download>
2. Start the daemon (Ollama starts at first run; verify it's listening on `http://localhost:11434`):

   ```bash
   curl -s http://localhost:11434/api/tags
   ```

3. Pull at least one model. Larger models give better attacker / evaluator behaviour but cost more memory and inference time:

   ```bash
   ollama pull llama3.1
   ollama pull qwen2.5
   ```

## Model spec

```text
--model ollama:<model-tag>
```

The `<model-tag>` is whatever `ollama list` shows on the left column (e.g. `llama3.1`, `llama3.1:70b`, `qwen2.5:32b`).

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

# Scan
agent-guardian scan --system-prompt prompt.txt --model ollama:llama3.1
```

## Custom endpoint

`OllamaClient()` defaults to `http://localhost:11434`. To point at a remote Ollama, instantiate the client directly from the Python API (CLI does not expose a `--base-url` flag for Ollama).

## Cost

Ollama scans cost zero dollars but plenty of compute. The cost estimator returns `$0.00` for `ollama:` model specs, so `--budget-usd` gates are inert for local runs.
