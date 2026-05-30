# LLM clients

**TL;DR** — Provider-agnostic types (`BaseLLM`, `LLMRequest`, `LLMResponse`) plus seven concrete clients. The rest of the framework only ever sees `LLMResponse` — no vendor SDK type ever leaks out of the `llm` package. For user-facing setup of each provider, see [LLM providers overview](../../integrations/providers/index.md).

## Provider-agnostic types

`LLMMessage`, `LLMRequest`, `LLMResponse`, `LLMUsage`, and the abstract `BaseLLM` live in [`agent_guardian.llm.base`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/base.py). Every concrete client takes an `LLMRequest` and returns an `LLMResponse`.

::: agent_guardian.llm.base
    options:
      show_root_heading: false
      members:
        - BaseLLM
        - LLMMessage
        - LLMRequest
        - LLMResponse
        - LLMUsage
        - Role
        - FinishReason

## Error types

Every provider client maps HTTP / SDK errors into one of these so the rest of the framework can decide whether to retry, surface to the operator, or abort the scan without knowing the underlying transport ([source](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/errors.py)).

::: agent_guardian.llm.errors
    options:
      show_root_heading: false

## Stub provider

Deterministic canned-response client used everywhere in the test suite. No network, no env, no flakes. Same `LLMRequest` always produces the same `LLMResponse`. Two matching strategies: SHA-256 exact match (via `StubLLM.hash_request`) and substring match against the last user message.

::: agent_guardian.llm.stub
    options:
      show_root_heading: false
      members:
        - StubLLM
        - StubScript

```python
import asyncio
from agent_guardian.llm import StubLLM
from agent_guardian.llm.base import LLMMessage, LLMRequest

async def demo() -> None:
    llm = StubLLM(canned={"hello": "world"}, default="OK")
    resp = await llm.complete(
        LLMRequest(messages=[LLMMessage(role="user", content="hello there")], model="stub")
    )
    print(resp.text, resp.provider)  # -> "world stub"

asyncio.run(demo())
```

## OpenAI

Chat Completions client. Implements the minimum surface AgentGuardian needs — streaming, tools, and vision are out of scope ([source](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/openai.py)). For user setup, see [OpenAI](../../integrations/providers/openai.md).

::: agent_guardian.llm.openai
    options:
      show_root_heading: false
      members:
        - OpenAIClient

## Anthropic

Messages API client. Coalesces all `role=system` messages into Anthropic's split `system` field, preserving order ([source](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/anthropic.py)). For user setup, see [Anthropic](../../integrations/providers/anthropic.md).

::: agent_guardian.llm.anthropic
    options:
      show_root_heading: false
      members:
        - AnthropicClient

## Gemini (Google AI Studio)

API-key client for `generativelanguage.googleapis.com/v1beta` — the AI Studio path. Compatible with every Gemini 2.5+ / 3.x model exposed via AI Studio ([source](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/gemini.py)). For user setup, see [Google Gemini](../../integrations/providers/gemini.md).

::: agent_guardian.llm.gemini
    options:
      show_root_heading: false
      members:
        - GeminiClient

## Vertex AI (preview — `complete()` not implemented)

The Vertex client ships the pure `build_vertex_payload()` and `map_vertex_response()` helpers (testable without auth) but `VertexClient.complete()` raises `NotImplementedError` until full OAuth2 service-account auth is wired ([`src/agent_guardian/llm/vertex.py:122-133`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/vertex.py#L122-L133)). Service-account auth is on the [v1.1 roadmap](../roadmap.md). Use `gemini:<model>` via AI Studio in the meantime — see [Google Vertex AI](../../integrations/providers/vertex.md) for the migration path.

::: agent_guardian.llm.vertex
    options:
      show_root_heading: false
      members:
        - VertexClient
        - build_vertex_payload
        - map_vertex_response
        - VERTEX_HOST_TEMPLATE

## AWS Bedrock

Converse API client with SigV4 signing via the `botocore` extra (`pip install 'agent-guardian[aws]'`). Credentials are resolved through the standard AWS chain at construction so misconfiguration fails fast ([source](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/bedrock.py)). For user setup, see [AWS Bedrock](../../integrations/providers/bedrock.md).

::: agent_guardian.llm.bedrock
    options:
      show_root_heading: false
      members:
        - BedrockClient
        - build_bedrock_payload
        - map_bedrock_response

## Ollama (local)

Local Ollama backend, no auth, default base URL `http://localhost:11434`. The recommended provider for local development and offline tests ([source](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/ollama.py)). For user setup, see [Ollama](../../integrations/providers/ollama.md).

::: agent_guardian.llm.ollama
    options:
      show_root_heading: false
      members:
        - OllamaClient
