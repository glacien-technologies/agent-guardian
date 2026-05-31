# r/LLMDevs

**Sub:** https://reddit.com/r/LLMDevs
**Target time:** T+4, 14:00 UTC.
**Post type:** Self-post. Flair `Tools` or `Discussion`.

## Title

```
Open-source red-teamer for LangGraph / CrewAI / MCP agents with a CI-friendly SARIF output
```

## Body

````
For the people on this sub shipping agents to production: I have been
building **AgentGuardian**, an open-source toolkit
(Apache-2.0) that red-teams agents the way Semgrep red-teams code.

**The 30-second pitch.**

```bash
pip install agent-guardian
agent-guardian scan --target my_app.agent:graph --mode framework --framework langgraph
```

Outputs SARIF (uploads to GitHub Code Scanning), JSON (for your own
pipeline), JUnit (for CI dashboards), Markdown, or PDF. Exit code 1
on any high-risk finding — your CI can gate on it.

**Frameworks it speaks today.**

- LangGraph — compiled `StateGraph` (Mode D adapter)
- CrewAI — Crew objects
- OpenAI Agents SDK — Agent + Runner
- MCP servers — any compliant MCP endpoint
- RAG apps — any retriever-compatible interface
- REST endpoints — `--endpoint http://localhost:8000/chat`
- Custom Python — `module:function` dotted path

**The CI/CD story.**

```yaml
- uses: glacien-technologies/agent-guardian@v1
  with:
    target: my_app.agent:graph
    framework: langgraph
    fail-on-risk: high
```

SARIF is auto-uploaded to GitHub Code Scanning — high-risk findings
become PR comments. Docker image on GHCR for non-GitHub pipelines.

**Vulnerable demo, no install needed.**

Live testbench with five intentionally vulnerable agents:
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

Most viral one is the LangGraph travel-concierge — prompt-injection
through user memory exfiltrates another user's PII. AIVSS 8.4. Walk-
through video: {{ YOUTUBE_DEMO_URL }}

**Code + docs.** https://github.com/glacien-technologies/agent-guardian

**Feedback ask.** The CrewAI adapter is the youngest of the bunch.
If you ship CrewAI in production and the adapter does not fit your
topology, I would value a hard look. File an issue or DM.
````

## r/LLMDevs rules

- Posts must be useful to LLM developers (not generic AI
  discussion). The CI/CD code snippet and the framework matrix
  satisfy the "useful" bar.
- Self-promotion is allowed if the content has standalone value.
  The code snippet, the testbench link, and the walkthrough video
  meet that standard.
