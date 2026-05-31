# Google Vertex AI

> **TL;DR. Preview only — do not use as a swarm role today.** The
> request-builder and response-mapper are pure functions and tested,
> but `VertexClient.complete()` raises `NotImplementedError`. Full
> service-account OAuth2 transport is targeted for v1.1. For Gemini
> models, use the [Gemini AI Studio](gemini.md) client; for service-
> account auth in production today, wire the helpers below into your
> own transport.

## What ships today

`VertexClient` lives at `agent_guardian.llm.vertex`
(`src/agent_guardian/llm/vertex.py`). The module docstring is explicit
about the gap (lines 1-8):

> *Full OAuth2 service-account authentication lands in M9. For M3 we
> ship the request-builder and response-mapper as pure functions
> (testable without auth) and `VertexClient.complete` raises
> `NotImplementedError` with a clear message.*

What's exported today:

| Symbol                                     | Status                                                            |
|--------------------------------------------|-------------------------------------------------------------------|
| `build_vertex_payload(LLMRequest) -> dict` | Stable. Converts the swarm's request shape to Vertex's `generateContent` body (`vertex.py:45`). |
| `map_vertex_response(model, dict)`         | Stable. Maps a Vertex response (including `finish_reason` translation: `STOP→stop`, `MAX_TOKENS→length`, `SAFETY→content_filter`) into `LLMResponse` (`vertex.py:71`). |
| `VertexClient.complete()`                  | **Raises `NotImplementedError`** until the v1.1 transport lands (`vertex.py:122-133`). |

`complete()`'s exception message points users at the same alternatives
this page recommends:

```text
Vertex AI provider is M9-pending: OAuth2 service-account auth has not
been wired yet. Use openai:<model>, anthropic:<model>, gemini:<model>,
ollama:<model>, or bedrock:<id> for now. See docs/providers/vertex.md
for the M9 roadmap.
```

## What to do in the meantime

| Need                                           | Use today                                                                                |
|------------------------------------------------|------------------------------------------------------------------------------------------|
| Gemini models, simple API-key auth             | [Gemini AI Studio](gemini.md) (`gemini:<model>`).                                        |
| Claude on cloud infra with native auth         | [AWS Bedrock](bedrock.md) (`bedrock:<id>`).                                              |
| Local-only inference                           | [Ollama](ollama.md) (`ollama:<model>`).                                                  |
| Vertex AI specifically, with your own auth     | Use `build_vertex_payload` / `map_vertex_response` from a custom transport (sketch below). |

### Sketch: pure-function helpers from your own Vertex transport

```python
import httpx

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.vertex import build_vertex_payload, map_vertex_response

# Caller supplies the OAuth2 bearer (e.g. from
# google.auth.transport.requests.Request + google.auth.default).
bearer = my_service_account_bearer()

req = LLMRequest(
    model="gemini-2.5-flash",
    messages=[LLMMessage(role="user", content="ping")],
    max_tokens=64,
    temperature=0.2,
)
url = (
    "https://us-central1-aiplatform.googleapis.com/v1/projects/"
    "MY_PROJECT/locations/us-central1/publishers/google/models/"
    f"{req.model}:generateContent"
)
resp = httpx.post(
    url,
    headers={
        "authorization": f"Bearer {bearer}",
        "content-type": "application/json",
    },
    json=build_vertex_payload(req),
    timeout=60.0,
)
resp.raise_for_status()
parsed = map_vertex_response(req.model, resp.json())
print(parsed.text, parsed.usage)
```

This is **unsupported** — there is no retry wrapper, no concurrency
cap, no error mapping. Real production use should wait for the v1.1
`VertexClient.complete()` rather than ship this skeleton.

## Tracking

The full v1.1 line item lives in the [Roadmap](../../reference/roadmap.md). The
`agent-guardian` test suite already covers `build_vertex_payload` and
`map_vertex_response` against real Vertex response shapes — see
[`tests/unit/test_llm_vertex.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/test_llm_vertex.py)
if you want to read the verification.
