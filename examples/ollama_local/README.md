# Ollama demo target

A FastAPI chatbot whose model backend is a local Ollama instance
(`http://localhost:11434` by default). Scan it like any other HTTP
endpoint with `--endpoint`.

## What it tests

* All 10 ASI categories against an HTTP-exposed Ollama agent.
* Behaviour on a real open-weights model (when Ollama is reachable);
  AgentGuardian's stub model is used to keep CI hermetic.

## Run locally (host install)

```bash
ollama serve &
ollama pull llama3.1
uv sync --extra examples
uv run uvicorn examples.ollama_local.serve:app --port 8000
```

## Run via Docker Compose

```bash
docker compose -f examples/ollama_local/docker-compose.yml up
docker compose -f examples/ollama_local/docker-compose.yml exec ollama ollama pull llama3.1
```

## Scan it

```bash
agent-guardian scan \
  --endpoint http://localhost:8000/chat \
  --model stub \
  --mode fast \
  --output md \
  --output-path scan.md
```

Swap `--model stub` for `--model ollama:llama3.1` to grade the run with
the same local Ollama instance.

## Docs

See `docs/try/scan-ollama.mdx` for the full walkthrough.
