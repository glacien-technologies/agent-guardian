# Community channel pings (OWASP GenAI, LangChain, MCP)

These are conversational pings in active developer communities, not
launch announcements. The tone is "I built a thing that touches your
community's interest area; here it is in case you want to look at it"
— not "exciting news to share".

## OWASP GenAI Slack

**Where:** https://owasp.org/slack/invite — `#project-genai` and
`#project-top10-agentic` channels.
**Target time:** T+3, 18:00 UTC.

### Message

```
Hi all — I have been building an open-source toolkit
(github.com/glacien-technologies/agent-guardian) that runs swarm-based
red-teaming against AI agents and produces a SARIF report triple-
tagged with OWASP ASI 2026, MITRE ATLAS, and CSA Agentic-RT
categories.

Sharing here because the ASI 2026 mapping is the bit I am least
confident in — ASI 2026 is brand new and the mapping of historical
LLM-Top-10 categories into the ASI taxonomy is partly editorial. If
anyone here has reviewed the ASI 2026 working drafts, I would value a
hard look at the mapping in docs/attacks/overview and a roast on
where I have miscategorised.

Live testbench (no install): https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app
Apache-2.0; PRs welcome.
```

## LangChain Discord

**Where:** https://discord.gg/langchain — `#tools` and `#showcase`
channels.
**Target time:** T+4, 18:00 UTC.

### Message

````
Sharing a tool I have been building for LangGraph users —
**AgentGuardian** (https://github.com/glacien-technologies/agent-guardian),
an open-source red-teamer that takes a compiled `StateGraph` and
finds prompt injection, tool abuse, memory exfiltration, and unsafe
tool-call behaviour.

```python
agent-guardian scan --target my_app.agent:graph \
    --mode framework --framework langgraph
```

Live testbench with a vulnerable LangGraph travel-concierge demo:
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

The LangGraph adapter handles compiled `StateGraph` objects and
streams findings live. Apache-2.0. Feedback on the adapter shape
particularly welcome — if you ship LangGraph in production and the
adapter does not fit your topology, I would value a hard look.
````

## MCP community

**Where:** https://modelcontextprotocol.io community Discord; the
`#general` channel and the `#mcp-servers` channel.
**Target time:** T+4, 18:00 UTC.

### Message

````
Built an open-source red-teamer that speaks MCP natively —
**AgentGuardian** (Apache-2.0). Point it at any compliant MCP server
and it runs a swarm of adversarial agents against the exposed
tools / resources / prompts and surfaces unsafe-tool-call, prompt-
injection-via-resource, and over-privileged-tool findings.

```bash
agent-guardian scan --target my-mcp-server --mode mcp \
    --transport stdio
```

Live testbench includes a deliberately vulnerable MCP filesystem
server: https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

Code + docs: https://github.com/glacien-technologies/agent-guardian
The MCP adapter is the youngest of the bunch; would value feedback
from anyone shipping MCP servers in production.
````

## Engagement etiquette

- Never post the same link in three channels of the same community
  within an hour. Discord and Slack moderators see that pattern as
  spam.
- Wait for at least one community member to respond before posting a
  follow-up. If the message gets zero responses in 24 hours, do not
  bump — the community already saw it and chose not to engage; a
  bump reads as desperate.
- If a community member asks a question, answer in-thread, never in
  DMs. The thread is the contribution.
