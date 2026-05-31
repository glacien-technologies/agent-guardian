# RAG demo target

A hermetic retrieval-augmented chatbot — canned retriever, stub
generator — exposed over HTTP. Used to exercise the `--indirect` probe
pack and ASI06 (KB Poisoning) probes against a target with a clear
retrieval boundary.

## What it tests

* All 10 ASI categories at the HTTP boundary, plus the `--indirect`
  prompt-injection pack which embeds payloads in the retrieved-chunk
  channel.
* ASI06 KB-leakage probes against the deliberate `internal:roadmap`
  honeypot in the canned KB.

## Run the server

```bash
uv sync --extra examples
uv run uvicorn examples.rag_app.serve:app --port 8000
```

## Scan it

```bash
agent-guardian scan \
  --endpoint http://localhost:8000/chat \
  --model stub \
  --mode fast \
  --indirect \
  --output md \
  --output-path scan.md
```

## Docs

See `docs/try/scan-rag-app.mdx` for the full walkthrough.
