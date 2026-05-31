# FastAPI chatbot demo target

A vanilla FastAPI chatbot with no agent framework. The smallest shape
AgentGuardian can scan: an HTTP endpoint that accepts
`{"input": "..."}` and returns `{"output": "..."}`.

## What it tests

* The `--endpoint` HTTP transport end-to-end.
* The pre-flight reachability check (`EXIT_TARGET_UNREACHABLE`).
* All 10 ASI categories at the HTTP boundary.

## Run the server

```bash
uv sync --extra examples
uv run uvicorn examples.fastapi_chatbot.serve:app --port 8000
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

## Docs

See `docs/try/scan-fastapi-chatbot.mdx` for the full walkthrough.
