# Gemini (Vertex Reasoning Engine) demo target

Scan a Vertex AI reasoning engine (Agent Engine) via a target contract.
No local agent code — the agent lives in your GCP project.

For an in-process Gemini-backed demo that does not require a Vertex
deployment, see `examples/langgraph/simple_chatbot.py` (calls Gemini via
the AI Studio OpenAI-compatible shim with a plain API key).

## What it tests

* All 10 ASI categories against a Vertex reasoning engine `:query`
  endpoint.
* GCP Application Default Credentials (ADC) auth.
* The `server_session` pattern (Vertex's `session_id` carries
  conversation state on the server).

## Prerequisites

* `agent-guardian[gcp]` installed: `pip install 'agent-guardian[gcp]'`
  (pulls in `google-auth` for ADC).
* A Vertex AI reasoning engine deployed in your GCP project. See the
  [Vertex AI Agent Engine quickstart](https://cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/overview).
* `gcloud auth application-default login` run on your shell (or a
  service-account JSON exported via `GOOGLE_APPLICATION_CREDENTIALS`).
* Three env vars exported:
  * `GCP_PROJECT`
  * `GCP_LOCATION` (e.g. `us-central1`)
  * `VERTEX_REASONING_ENGINE_ID`

## Scan it

```bash
export GCP_PROJECT=...
export GCP_LOCATION=us-central1
export VERTEX_REASONING_ENGINE_ID=...
agent-guardian scan \
  --contract examples/gemini_agent/agentguardian.yaml \
  --model stub \
  --mode fast \
  --output md \
  --output-path scan.md
```

## Notes for CI

This example is **skipped** by `examples/ci/validate_examples.py` by
default because it requires real GCP credentials. Set
`AG_VALIDATE_VERTEX=1` and the credentials above in your CI environment
to opt in.

## Docs

See `docs/try/scan-gemini-agent.mdx` for the full walkthrough.
