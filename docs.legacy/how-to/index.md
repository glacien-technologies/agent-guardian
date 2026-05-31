# How-to guides

**TL;DR:** task-oriented recipes for someone who already knows what
AgentGuardian is and now wants to *do* something specific. For a
narrative walk-through start with the [Quickstart](../tutorials/quickstart.md);
for the conceptual model start with [Architecture](../concepts/architecture.md).

These pages follow the [Diátaxis](https://diataxis.fr/) distinction:
each guide solves **one concrete problem** end-to-end. They are not
tutorials (no narrative, no learning arc) and they are not reference
(no exhaustive flag list — that's [CLI reference](../reference/cli.md)).

## Scan a target

What you have                                                | Use this guide                                                  | Adapter
:----------------------------------------------------------- | :-------------------------------------------------------------- | :-------
A system prompt (`.txt` / `.md`) and nothing else            | [Scan a system prompt](scan-a-system-prompt.md)                 | [Mode A](../how-to/scan-a-system-prompt.md)
A Python callable you can import (`module:attr`)             | [Scan Python source](scan-python-source.md)                     | [Mode B](../how-to/scan-python-source.md)
A deployed HTTP endpoint (OpenAI-shape, Anthropic-shape, …)  | [Scan an HTTP endpoint](scan-an-http-endpoint.md)               | [Mode C](../how-to/scan-an-http-endpoint.md)

For LangGraph / CrewAI / AutoGen / OpenAI Agents / Strands / ADK
targets, the framework adapter classes ship in the package
(`LangGraphAdapter`, `CrewAIAdapter`, `AutoGenAdapter`,
`OpenAIAgentsAdapter`, `StrandsAdapter`, `ADKAdapter`) but the
`--framework` CLI dispatch is **partial in v1.0** — see the
[roadmap](../reference/roadmap.md) row for M8. In the meantime, wrap your
framework-native object with the [Code adapter](../how-to/scan-python-source.md)
via a thin `run()` callable, as the bundled
[`examples/langgraph/`](https://github.com/glacien-technologies/agent-guardian/tree/main/examples/langgraph)
targets do.

## Observability

What you want                                                | Use this guide
:----------------------------------------------------------- | :--------------------------------------------------
Trace AgentGuardian's own scan in your APM                   | [Set up OpenTelemetry](set-up-opentelemetry.md)
Stream scan events, reports, and metrics to a SIEM           | [Forward to a SIEM](forward-to-siem.md)

## CI integration

| CI system        | Use this guide                                                |
| :--------------- | :------------------------------------------------------------ |
| GitHub Actions   | [Integrate with GitHub Actions](integrate-github-actions.md)  |
| GitLab CI        | [Integrate with GitLab CI](integrate-gitlab-ci.md)            |
| Jenkins          | [Integrate with Jenkins](integrate-jenkins.md)                |

Each CI guide pins to a working YAML / `Jenkinsfile` snippet under
[`examples/ci/`](https://github.com/glacien-technologies/agent-guardian/tree/main/examples/ci)
that is lint-checked against the actual `agent-guardian` flag surface.

## What's not (yet) here

The following are honest gaps, tracked in the [roadmap](../reference/roadmap.md):

- **`--framework` CLI dispatch.** The adapter classes ship; the CLI
  one-shot wrapper is M8-partial.
- **Native webhook / syslog event emitter.** Today, forwarding scan
  events to a SIEM means tailing `events.jsonl` from
  [`agent-guardian serve`](../reference/cli.md) or shipping the SARIF report; see
  [Forward to a SIEM](forward-to-siem.md).
- **Circle CI, Azure Pipelines, Bitbucket Pipelines.** Adapt the
  [GitHub Actions](integrate-github-actions.md) recipe — the
  `agent-guardian` CLI surface is identical across CI systems; only the
  YAML wrapping changes.
