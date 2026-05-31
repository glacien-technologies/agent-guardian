# Response templates — for HN, Reddit, Product Hunt, X comments

Use these as a starting point. **Always personalise the second
sentence** — a verbatim paste reads as ChatGPT and the audience picks
it up. The first sentence is the canonical answer; the second sentence
is yours.

## R1 — "How is this different from PyRIT / garak / Promptfoo?"

```
Honest comparison table is in the README at the top: PyRIT and garak
are single-chain (one attack at a time); Promptfoo is evals-first
(designed for output evaluation, not adversarial red-teaming);
AgentGuardian is multi-agent swarm with convergence detection.

{{ personalised second sentence — e.g. "If your workflow is
specifically X, garak is probably a better fit because Y." Always
name a scenario where a competitor is a better choice; the audience
respects honest tradeoffs. }}
```

## R2 — "Does it work with my model?"

```
Anything served on an OpenAI-compatible endpoint works as both target
and attacker — that covers Ollama, vLLM, llama.cpp's llama-server, LM
Studio, OpenRouter, and the major cloud SDKs. Native adapters for
Anthropic Messages, Google Gemini, AWS Bedrock, Azure Foundry, and
Vertex AI ship in the box.

{{ personalised second sentence — name their model and the exact
flag, e.g. "For Llama 3.3 70B on Ollama: `agent-guardian scan
--model ollama:llama3.3 --endpoint http://localhost:11434/v1` —
that should work as-is." }}
```

## R3 — "Where does the AIVSS score come from?"

```
Full formula and derivation at
https://agentguardian.io/reports/aivss-score. Short version: AIVSS
extends CVSS with three agent-specific dimensions (tool-call radius,
memory-write blast radius, A2A propagation potential), weighted
inverse-frequency from a study of 200 agent vulnerabilities.

{{ personalised second sentence — if the asker named a specific
finding, walk through how its AIVSS score was derived. If not, link
to the most relevant case study in docs/reports. }}
```

## R4 — "How do I integrate with CI?"

````
GitHub Action ships in v1.0.x:

```yaml
- uses: glacien-technologies/agent-guardian@v1
  with:
    target: my_app.agent:graph
    framework: langgraph
    fail-on-risk: high
```

For non-GitHub pipelines, Docker image at
`ghcr.io/glacien-technologies/agent-guardian:latest` exits 1 on a
high-risk finding. Pre-commit hook at `.pre-commit-hooks.yaml`.

{{ personalised second sentence — name their CI provider (GitLab,
Jenkins, CircleCI) and link to the matching docs page in
docs/ci-cd/. }}
````

## R5 — "Is the testbench safe to run locally?"

```
Yes — the testbench agents in `examples/vulnerable-langgraph-agent/`
ship with `docker compose up` and run in a sandboxed Docker network
with no host filesystem access and no outbound network beyond the
LLM API. The vulnerabilities are real (planted prompt injection
sinks, tool-call exploits, RAG poisoning) but the blast radius is
confined to the container.

{{ personalised second sentence — if the asker mentioned a specific
concern, address it. Common ones: "the LLM API egress" — yes, that
is the one outbound rule; "agent-to-agent" — no, the vulnerable
agents do not call each other unless you wire them. }}
```

## R6 — "Why a swarm instead of one strong attacker?"

```
Empirically the swarm finds 2.3x more *unique* finding-classes than
serial in the same wall-clock budget — ablation results in the deep-
dive blog at https://agentguardian.io/blog/prompt-injection-in-agents.
The intuition: 14 specialists with different priors explore the
joint (prompts × tools × memory × A2A) surface in parallel, then
the Commander deduplicates on convergence.

{{ personalised second sentence — if the asker has methodological
chops, dig into the convergence threshold (Jaccard 0.6 on the
technique × surface tuple) and ask for their critique. If not, just
share the wall-clock numbers. }}
```

## R7 — "Is there a hosted version?"

```
The scanner is local-first by design — no telemetry, no signup, no
cloud dependency. The testbench at
agent-guardian-testbench-u6tm6gzysq-uc.a.run.app is hosted because
some people want to click before they install; the scanner itself
never calls home.

{{ personalised second sentence — if the asker is interested in a
hosted scanner for ops reasons (no local install allowed), point at
the Docker image + the CI integration pattern rather than implying
a hosted SaaS is coming. }}
```

## R8 — "Does it support {{ framework I have never heard of }}?"

```
Not yet, but if it speaks an OpenAI-compatible API or any standard
agent protocol (LangChain Runnable, MCP, REST), the generic
adapters will work today. For a native adapter, open an issue with
a minimal example and I will scope it.

{{ personalised second sentence — never bluff. If you genuinely do
not know the framework, say "I have not used X — drop a link to the
docs and a 20-line example and I will look at it this week." }}
```

## R9 — "Show me a real finding."

```
Open
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app, pick the
"LangGraph travel-concierge" agent, click "Run scan". You will see a
Critical finding (AIVSS 8.4) in under 5 minutes — prompt-injection
through user memory exfiltrates another user's PII. The evidence
chain shows the exact prompts that triggered the leak.

{{ personalised second sentence — if the asker named a finding type
they care about (memory poisoning, tool abuse), point them at the
specific testbench agent that demonstrates it. }}
```

## R10 — "How is this funded? What is the catch?"

```
Glacien Technologies is bootstrapped. The OSS toolkit is Apache-2.0,
no telemetry, no usage limits, no signup, no feature gates — that is
the entire product for OSS users. A separate enterprise product (with
SaaS scanning, RBAC, dashboards, SLA support) is in development; the
boundary is documented at
https://agentguardian.io/concepts/open-vs-enterprise. No "open-core
trap" — the swarm, the adapters, the AIVSS formula, the attack
library, and the report formats are all in the OSS repo.

{{ personalised second sentence — if the asker is sceptical, name
the specific feature they are worried about being walled and confirm
its OSS status. }}
```

## R11 — "Can I contribute an attacker / adapter?"

```
Yes — see CONTRIBUTING.md. Adapters live under
`src/agent_guardian/adapters/`, attackers under
`src/agent_guardian/probes/`, and the probe schema is at
docs/reference/probe-schema. The cleanest first PR is usually a new
adapter — the abstract base is small and well-documented.

{{ personalised second sentence — if they named a specific adapter
or attack, point them at the closest existing example to crib from.
}}
```

## R12 — "How do I report a security issue?"

```
SECURITY.md at the repo root has the full process: email
security@glacien.ai with a PGP-encrypted report (key fingerprint in
SECURITY.md), 90-day disclosure window, supported versions table.
Initial response SLA is 48 hours.

{{ personalised second sentence — if the asker has already found
something, thank them and confirm the email; do not engage with the
specifics in a public thread. }}
```

## Editing rules

- Replace every `{{ ... }}` slot before posting.
- Never include the `{{ }}` markers themselves in a live reply.
- If a reply does not have a matching template, write it from
  scratch — the templates are a floor, not a ceiling.
