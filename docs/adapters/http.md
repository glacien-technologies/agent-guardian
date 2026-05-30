# HTTP Adapter (Mode C)

Use this adapter when the agent is reachable as a running HTTP endpoint —
the most common production case.

## CLI

```bash
agent-guardian scan --endpoint https://api.example.com/agent
```

For richer wiring (auth headers, custom request/response shape, TLS
options) drive the scan from a target contract:

```bash
agent-guardian init --out agentguardian.yaml   # interactive wizard
agent-guardian scan --contract agentguardian.yaml
```

## Supported shapes

The HTTP adapter ships pluggable shape modules. Pick one with the
`shape` keyword argument on the constructor (or via the contract):

| Shape          | Description                                                     |
|----------------|-----------------------------------------------------------------|
| `openai`       | OpenAI Chat Completions (`/v1/chat/completions`).               |
| `anthropic`    | Anthropic Messages API (`/v1/messages`).                        |
| `bedrock`      | AWS Bedrock InvokeModel request/response shaping.               |
| `vertex`       | Google Vertex AI `generateContent` request/response shaping.    |
| `agentcore`    | Bedrock AgentCore runtime shape.                                |
| `generic`      | Operator-supplied request template + JSONPath response extractor.|

`call()` is fully wired for `openai`, `anthropic`, and `generic`.
`bedrock`, `vertex`, and `agentcore` ship request/response shaping for
unit tests but `call()` raises `NotImplementedError` until SigV4 /
OAuth2 transports land.

## Programmatic

Instantiate `HttpAdapter` directly and hand it to `SwarmCommander`:

```python
import asyncio

from agent_guardian import (
    HttpAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)


async def main() -> None:
    adapter = HttpAdapter(
        endpoint="https://api.example.com/v1/chat/completions",
        shape="openai",
        auth_headers={"Authorization": "Bearer sk-..."},
        model="gpt-4o-mini",
    )
    try:
        swarm = SwarmCommander(
            SwarmConfig(scan_id="demo"),
            adapter,
            attacker_llm=StubLLM(),
            evaluator_llm=StubLLM(),
        )
        scan = await swarm.run()
        print(scan.aivss, scan.band)
    finally:
        await adapter.aclose()


asyncio.run(main())
```

For non-standard endpoints use the `generic` shape with an operator-
supplied request template and response JSONPath:

```python
adapter = HttpAdapter(
    endpoint="https://api.example.com/agent",
    shape="generic",
    request_template='{"user_input": "{prompt}"}',
    response_jsonpath="$.response.text",
    auth_headers={"Authorization": "Bearer ${API_TOKEN}"},
)
```

## Rate limits and safety

`HttpAdapter` honours per-instance concurrency (`max_concurrency`,
default 5), per-request `timeout_seconds` (default 60s), and bounded
`max_retries` (default 3) with exponential backoff on transient errors.
The CLI exposes the swarm-level token / wall-clock budgets that bound
total request volume; see the [Configuration guide](../guide/configuration.md).

## When to use

- CI smoke-test against a staging deployment.
- Continuous monitoring of a production agent.
- Black-box review of a third-party agent you only have an API key for.
