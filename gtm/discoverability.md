# GTM-006 — Discoverability Tracking

Source-of-truth tracking for GitHub topics, repo description, the curated `awesome-agent-security` resource list, and PR submissions to external awesome-lists. Update this file every time a state change ships.

Owner: Mixed. Claude maintains the topic list + description + this tracker. Human owns the external repo creation and PR submissions to other lists.

---

## 1. GitHub repo metadata (this repo: `glacien-technologies/agent-guardian`)

### 1.1 Topics (locked list — 14 entries)

Set via GitHub web UI: `https://github.com/glacien-technologies/agent-guardian/settings` → "Topics" field.

| Topic              | Discovery vector                              |
|--------------------|-----------------------------------------------|
| `ai-security`      | broad AI security                             |
| `agent-security`   | agent-specific                                |
| `red-team`         | red-team practitioners                        |
| `red-teaming`      | red-team practitioners (canonical hyphenated) |
| `llm-security`     | LLM security practitioners                    |
| `prompt-injection` | OWASP LLM01 / threat-domain                   |
| `owasp`            | OWASP audience                                |
| `rag-security`     | RAG/knowledge-base threat domain              |
| `mcp-security`     | Model Context Protocol threat domain          |
| `ai-agents`        | agent-framework users                         |
| `langgraph`        | LangGraph framework                           |
| `crewai`           | CrewAI framework                              |
| `security-tools`   | tools-discipline cluster                      |
| `devsecops`        | CI/CD integrators                             |

Hard rule: do not pad with `python`, `llm`, `ai`, `machine-learning`, etc. The 14 above are the entire allowed set.

**Status:** open

### 1.2 Repo description (locked copy — 17 words)

```
Open-source red teaming toolkit for AI agents, RAG systems, MCP servers, and tool-using LLM applications.
```

Set via GitHub web UI: `https://github.com/glacien-technologies/agent-guardian/settings` → "Description" field. Must match the `description` field in `pyproject.toml` (line 8) exactly.

**Status:** open

---

## 2. `awesome-agent-security` curated repo

External repo: `glacien-technologies/awesome-agent-security`. Public, MIT-licensed (awesome-list convention is CC0 but MIT is acceptable and matches existing org policy). Minimum 30 entries across 5 sections at first publish.

### 2.1 Sections (locked)

1. Agent Security Tools
2. Prompt Injection & LLM Security
3. RAG / Knowledge Base Security
4. MCP (Model Context Protocol) Security
5. AI Red Teaming Research, Benchmarks, and Datasets

### 2.2 Acceptance criteria for entries

- Open-source or freely accessible (papers, datasets, public tools).
- Active in last 12 months (last commit, last release, or last paper revision).
- Has a clear README / abstract.
- One-sentence description, neutral tone, factual.
- AgentGuardian appears exactly once, in section 1, in alphabetical position. Not pinned, not bolded, not boosted.

### 2.3 Status

| Item                              | Status | Link                                                      |
|-----------------------------------|--------|-----------------------------------------------------------|
| Repo created (public)             | open   | `https://github.com/glacien-technologies/awesome-agent-security` |
| `README.md` with >= 30 entries    | open   |                                                           |
| `LICENSE` (MIT)                   | open   |                                                           |
| `CONTRIBUTING.md`                 | open   |                                                           |
| First quarterly sync scheduled    | open   | tracked in GTM-009                                        |

---

## 3. PR submissions to external awesome-lists

Target order (locked). PR copy template lives in section 4 below. Human posts each PR; record outcome here.

| Order | Target list                 | URL                                                       | Status | PR link | Merged date |
|-------|-----------------------------|-----------------------------------------------------------|--------|---------|-------------|
| 1     | awesome-llm-security        | https://github.com/corca-ai/awesome-llm-security          | open   |         |             |
| 2     | awesome-ai-agents           | https://github.com/e2b-dev/awesome-ai-agents              | open   |         |             |
| 3     | awesome-mcp-servers         | https://github.com/punkpeye/awesome-mcp-servers           | open   |         |             |
| 4     | awesome-langchain           | https://github.com/kyrolabs/awesome-langchain             | open   |         |             |
| 5     | awesome-cybersecurity       | https://github.com/Hack-with-Github/Awesome-Hacking       | open   |         |             |
| 6     | awesome-devsecops           | https://github.com/devsecops/awesome-devsecops            | open   |         |             |
| 7     | awesome-rag (optional)      | https://github.com/frutik/Awesome-RAG                     | open   |         |             |

Acceptance bar for GTM-006: >= 3 submitted, >= 1 merged within 4 weeks of submission.

---

## 4. PR copy templates (locked tone — matches GTM-008)

### 4.1 PR title

```
Add AgentGuardian: open-source red-teaming toolkit for AI agents
```

### 4.2 PR body

```
AgentGuardian is an open-source red-teaming toolkit for AI agents, RAG
systems, MCP servers, and tool-using LLM applications. It runs a swarm of
eleven specialist attacker agents against a target, produces a deterministic
AIVSS-aligned score, and exports SARIF + HTML evidence reports.

- Repo: https://github.com/glacien-technologies/agent-guardian
- Live testbench (vulnerable LangGraph agent + scan output):
  https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app
- License: Apache-2.0
- Coverage: OWASP ASI, MITRE ATLAS, CSA AI controls

Adding under [section name appropriate to the list], alphabetical position.
Happy to adjust description or section placement per maintainer preference.
```

Do not change wording without filing a follow-up note here. The tone is intentionally factual; "excited to announce" / "thrilled" / "introducing" must not appear.

---

## 5. Merge velocity policy

- Submit PRs in batches of 3 (not all at once — looks like spam).
- Wait 7 days between batches.
- After 6 weeks of silence on a PR, post one respectful follow-up comment.
- After 10 weeks of silence, close the PR locally as "unresponsive maintainer" and remove from the count.

---

## 6. Quarterly refresh

Owner: Claude + Human review. Cadence locked in GTM-009.

- Every 90 days, audit `awesome-agent-security` entries for:
  - Tools that went unmaintained (no commit in 12+ months) — move to an "Archive" subsection.
  - New tools / papers — add per acceptance criteria.
  - Broken links — fix or remove.
- Refresh log appended to section 7 below.

## 7. Refresh log

| Date | Reviewer | Entries added | Entries archived | Notes |
|------|----------|---------------|------------------|-------|
|      |          |               |                  |       |
