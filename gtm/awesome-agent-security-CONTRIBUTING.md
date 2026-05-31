# Contributing to Awesome Agent Security

Thanks for proposing an addition. This list stays useful by being narrow and current. Please follow these rules.

## Acceptance criteria

An entry is accepted if:

1. **Scope fit.** It is directly about the security of agentic AI systems — agents that autonomously choose tools, RAG pipelines, MCP servers, or tool-using LLM applications. Generic LLM-evaluation, generic ML-safety, and generic prompt-engineering content belongs in other awesome-lists.
2. **Open or freely accessible.** Open-source code (any OSI-approved license), a freely readable paper / preprint, or a public dataset / benchmark. Closed-source commercial tools are out of scope.
3. **Active.** Last commit, last release, or last revision within the past 12 months. Dormant projects move to an Archive subsection on the next quarterly refresh.
4. **Documented.** Has a README, abstract, or landing page that explains what it does in the first screen.
5. **Honest description.** One sentence, factual, neutral tone. No "the best", no "revolutionary", no "10x". Describe what the thing does, not how good it is.

## Submission format

Open a PR that adds one entry per line, in alphabetical order within its section:

```
- [Name](https://link) — One sentence describing what it does and what threat it addresses.
```

If your tool fits in multiple sections, pick the most specific one.

## What we will reject

- Marketing pages or product landing pages without underlying open source / open research.
- Tools that are abandoned (no activity > 12 months) at the time of submission.
- Self-promotional descriptions ("the leading", "industry-standard", etc.).
- Duplicates of existing entries.
- Items that belong in a different awesome-list (general LLM tools, general security tools).

## Conflicts of interest

This list is maintained by Glacien Technologies, who also maintain AgentGuardian. AgentGuardian appears exactly once in the list, in alphabetical position within section 1, with a neutral description. We will not add Glacien products to additional sections or boost their placement. If you spot a fairness issue, open an issue.

## Quarterly refresh

Every 90 days the list is audited:

- New entries from open PRs are merged if they pass acceptance.
- Entries with no upstream activity in 12+ months are archived.
- Broken links are fixed or removed.

Refresh changes ship in a single PR per cycle labelled `quarterly-refresh`.
