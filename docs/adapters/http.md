# HTTP Adapter (Mode C)

Use this adapter when the agent is reachable as a running HTTP endpoint —
the most common production case.

## Usage

```bash
agent-guardian scan --http https://api.example.com/agent
```

The adapter auto-detects the request/response shape. To force a specific
shape:

```bash
agent-guardian scan --http https://api.example.com/agent --http-shape openai-chat
```

## Supported shapes

The HTTP adapter recognises six common request/response shapes
out-of-the-box:

| Shape          | Description                                                     |
|----------------|-----------------------------------------------------------------|
| `openai-chat`  | OpenAI Chat Completions (`/v1/chat/completions`).               |
| `anthropic`    | Anthropic Messages API (`/v1/messages`).                        |
| `text-prompt`  | Plain JSON `{"prompt": "..."}` → `{"completion": "..."}`.       |
| `langserve`    | LangChain LangServe `/invoke` endpoints.                        |
| `mcp`          | Model Context Protocol JSON-RPC servers.                        |
| `custom`       | User-provided request/response template (see below).            |

## Custom shape

For non-standard endpoints, supply a YAML template:

```yaml
# custom-shape.yaml
request:
  method: POST
  headers:
    Authorization: "Bearer ${API_TOKEN}"
    Content-Type: application/json
  body:
    user_input: "{{ probe }}"
response:
  jsonpath: "$.response.text"
```

```bash
agent-guardian scan --http https://api.example.com/agent \
                    --http-shape custom \
                    --http-template custom-shape.yaml
```

## Programmatic

```python
from agent_guardian import scan_http

result = scan_http(
    url="https://api.example.com/agent",
    shape="openai-chat",
    headers={"Authorization": f"Bearer {api_token}"},
    model="anthropic:claude-opus-4-7",
)
```

## Rate limits and safety

The HTTP adapter respects:

- A configurable global QPS cap (`--max-qps`, default 5).
- The endpoint's own `Retry-After` headers on 429 responses.
- A configurable per-scan budget cap (`--max-requests`, default 500).

The adapter will **never** scan a URL outside an explicit allowlist.
Setting `--allow-any-url` is logged and produces a warning in the
report.

## When to use

- CI smoke-test against a staging deployment.
- Continuous monitoring of a production agent.
- Black-box review of a third-party agent you only have an API key for.
