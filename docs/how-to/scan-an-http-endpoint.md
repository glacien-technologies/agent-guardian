# Scan an HTTP endpoint

**TL;DR:** point AgentGuardian at a live URL. The swarm will negotiate
the request shape (OpenAI / Anthropic / generic) and hammer the
endpoint with attacker turns. Production transport, real retries, real
rate-limit handling.

## When to use this

- CI smoke-test against a staging deployment.
- Continuous monitoring of a production agent.
- Black-box review of a third-party agent you only have an API key for.

This is **Mode C** (HTTP transport) in the [adapter taxonomy](../integrations/adapters/index.md).

## What's actually supported today

`HttpAdapter` ships six shape modules (adapters/http.py:55,
adapters/http_shapes/`*.py`):

| Shape       | Wire format                                                | `call()` ready
| :---------- | :--------------------------------------------------------- | :-------------
| `openai`    | OpenAI Chat Completions (`/v1/chat/completions`)           | yes
| `anthropic` | Anthropic Messages API (`/v1/messages`)                    | yes
| `generic`   | Operator-supplied request template + JSONPath response     | yes
| `bedrock`   | AWS Bedrock InvokeModel                                    | **no** — `NotImplementedError` until SigV4 transport lands
| `vertex`    | Google Vertex AI `generateContent`                         | **no** — `NotImplementedError` until OAuth2 transport lands
| `agentcore` | Bedrock AgentCore Runtime `POST /invocations`              | **no** — `NotImplementedError` until SigV4 transport lands

The pure-function request/response shapers for `bedrock` / `vertex` /
`agentcore` are usable from unit tests today; the live `call()` path
refuses to send because the auth transports are not yet wired
(adapters/http.py:55). See [roadmap](../reference/roadmap.md) row M9.

## Prerequisites

- AgentGuardian installed (`pip install agent-guardian`).
- A reachable target URL. AgentGuardian preflights the endpoint
  before the scan by POSTing an empty body twice with a 2s timeout; if
  both attempts fail with ConnectError/Timeout the scan exits **64**
  (`EXIT_TARGET_UNREACHABLE`) instead of burning LLM budget
  (cli.py:2020–2029). Pass `--no-preflight` to skip the check.
- An attacker + evaluator model API key for an authoritative score
  (`--model openai:gpt-4o-mini` etc.). Without it, the scan runs but
  the AIVSS is `NOT_EVALUATED`.

## Run it (CLI)

### Smallest possible invocation

```bash
agent-guardian scan --endpoint https://api.example.com/agent \
    --model stub \
    --no-tui \
    --mode fast
```

This assumes the default shape (`generic`) and no auth — useful only
for a local dev target.

### OpenAI-shaped endpoint

```bash
agent-guardian scan \
    --endpoint https://api.openai.com/v1/chat/completions \
    --model openai:gpt-4o-mini \
    --no-tui \
    --output sarif \
    --output-path agentguardian.sarif
```

`--model` controls the **attacker + evaluator** model
(cli.py:2030–2038). The target endpoint is whatever you POST to;
shape selection for richer endpoints requires a contract (see below).

### Endpoint behind a proxy / custom path

If your agent sits behind Caddy / nginx / API gateway, you can scan
the public URL — the shape is decided by the wire format, not the
URL. As long as the proxy passes the body through verbatim and
preserves `content-type: application/json`, the swarm doesn't care
that it's not the cloud provider's hostname.

### Anything more than auth headers → use a contract

For non-trivial wiring (auth-header rotation, custom request shape,
TLS pinning, session state, mTLS), drive the scan from a target
contract (cli.py:1653, `init` command):

```bash
agent-guardian init --out agentguardian.yaml   # interactive wizard
agent-guardian scan --contract agentguardian.yaml
```

`--contract` is mutually exclusive with `target` / `--system-prompt` /
`--endpoint` / `--framework` (cli.py:2299–2308). The contract supplies
the transport, auth, session, and Rules of Engagement; RoE budgets
map onto the swarm config and a provenance audit is attached to the
report.

## Run it (Python)

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
        endpoint="https://api.openai.com/v1/chat/completions",
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

`HttpAdapter` is `src/agent_guardian/adapters/http.py:196`. The
constructor (line 213) validates `endpoint`, `timeout_seconds`,
`max_retries`, and `max_concurrency`; values default to 60s / 3 / 5
respectively.

## Custom endpoints (the `generic` shape)

When the target speaks a non-standard wire format, the `generic`
shape lets you template the request body and JSONPath the response.
The contract is:

- `request_template` — a JSON string with `{prompt}` (required) and
  optional `{session}` placeholders. Substituted before the body is
  POSTed (adapters/http.py:299–302).
- `response_jsonpath` — a JSONPath into the parsed response body.
  Evaluated by `generic_extract_response_text`
  (adapters/http_shapes/generic_shape.py).

```python
adapter = HttpAdapter(
    endpoint="https://api.example.com/agent",
    shape="generic",
    request_template='{"user_input": "{prompt}", "session_id": "{session}"}',
    response_jsonpath="$.response.text",
    auth_headers={"Authorization": "Bearer ${API_TOKEN}"},
)
```

## Rate limits and safety

`HttpAdapter` honours three caps in this order
(adapters/http.py:223–261):

| Knob                    | Default | What it does
| :---------------------- | :------ | :----------------------------------------
| `max_concurrency`       | 5       | In-flight POSTs per adapter instance.
| `timeout_seconds`       | 60      | Per-request timeout (httpx).
| `max_retries`           | 3       | Exponential backoff on transient errors.

The swarm-level token / wall-clock / USD budgets are configured at the
`SwarmConfig` level (`overall_wall_seconds`, `total_tokens`,
`usd_cap`) and bound total request volume across the whole scan;
see [Configuration](../operations/configuration.md).

## TLS & private CAs

`verify` is honoured for clients the adapter builds itself
(adapters/http.py:255–257):

- `verify=True` (default) — system trust store.
- `verify=False` — disable certificate verification. Insecure; for
  self-signed dev targets only.
- `verify="/path/to/ca.pem"` — pin a private CA bundle. The string is
  lifted into an `ssl.SSLContext` (httpx deprecates `verify=<str>`).

These knobs are not yet surfaced on the bare `--endpoint` flag — use
a contract or the Python constructor.

## Common errors

| Symptom                                                                  | Cause + fix
| :----------------------------------------------------------------------- | :----------
| Exit 64 / `EXIT_TARGET_UNREACHABLE`                                      | Preflight POST failed twice. Run the URL through `curl -v` to confirm DNS/TLS/listener, or pass `--no-preflight` if your target rejects empty bodies but is otherwise reachable.
| `NotImplementedError: bedrock/vertex/agentcore call() not yet wired`     | Auth transport not in v1.0 (adapters/http.py:55). Track [roadmap](../reference/roadmap.md) M9.
| `LLMResponseFormatError: generic_shape: path '...' produced no value`     | The `response_jsonpath` didn't resolve. Capture a real response and re-test the path against it (adapters/http_shapes/generic_shape.py:46).

## Next steps

- Gate the scan in [GitHub Actions](integrate-github-actions.md) /
  [GitLab CI](integrate-gitlab-ci.md) / [Jenkins](integrate-jenkins.md).
- Wire OpenTelemetry to follow the per-turn HTTP traffic in your APM
  ([Set up OpenTelemetry](set-up-opentelemetry.md)).
- Read [Architecture](../concepts/architecture.md) for the full swarm/turn flow.
