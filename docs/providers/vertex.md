# Google Gemini / Vertex

AgentGuardian supports Gemini through two paths:

- **`GeminiClient`** — the Google AI Studio API. Stable today. Simple API-key auth.
- **`VertexClient`** — Google Vertex AI's `generateContent` endpoint. **Request/response shaping is implemented, but `complete()` currently raises `NotImplementedError`** until full service-account OAuth2 lands (planned for v1.1). Use `GeminiClient` in the meantime, or wait for the v1.1 release.

## Gemini via Google AI Studio (stable today)

### Authentication

Set one of:

| Env var                              | When to use                                                       |
|--------------------------------------|-------------------------------------------------------------------|
| `GEMINI_API_KEY`                     | Standard.                                                         |
| `GOOGLE_API_KEY`                     | Also accepted — this is what the [AI Studio](https://aistudio.google.com/app/apikey) quickstart hands you. |
| `AGENT_GUARDIAN_GEMINI_API_KEY`      | Namespaced override.                                              |

Precedence: `AGENT_GUARDIAN_GEMINI_API_KEY` → `GEMINI_API_KEY` → `GOOGLE_API_KEY`.

```bash
export GEMINI_API_KEY=...
agent-guardian doctor    # should list "gemini" under detected keys
```

### Model spec

```text
--model gemini:<model-name>
# or, by heuristic for any model starting with "gemini-":
--model gemini-2.5-flash
```

#### Examples

| Model spec                       | Notes                                                            |
|----------------------------------|------------------------------------------------------------------|
| `gemini:gemini-2.5-pro`          | Strongest tier.                                                  |
| `gemini:gemini-2.5-flash`        | Cheap, fast.                                                     |
| `gemini-2.5-flash`               | Same as above — heuristic prefix.                                |

### End-to-end example

```bash
export GEMINI_API_KEY=...
agent-guardian scan --system-prompt prompt.txt --model gemini:gemini-2.5-flash
```

## Vertex AI (preview)

The `VertexClient` lives at `agent_guardian.llm.vertex` and ships:

- `build_vertex_payload(LLMRequest) -> dict` — converts the swarm's request shape to Vertex's `generateContent` body.
- `map_vertex_response(dict) -> LLMResponse` — maps Vertex's response (including `finish_reason` translation: `STOP→stop`, `MAX_TOKENS→length`, `SAFETY→content_filter`).
- `VertexClient.complete()` — **raises `NotImplementedError` until v1.1 ships service-account OAuth2 auth.**

Until then, use `gemini:` via Google AI Studio for Gemini-family models, or wire the underlying request/response helpers into your own Vertex-authenticated transport for advanced use cases.
