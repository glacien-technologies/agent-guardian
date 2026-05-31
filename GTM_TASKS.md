# AgentGuardian — GTM Task List

Running list of go-to-market tasks for AgentGuardian OSS. Read-and-pick: pick a task, do the work, flip status, commit. Tasks NOT broken into granular sub-tickets — each entry is one cohesive shippable unit. Add new entries at the top with the date filed.

**Owner field:**
- `Claude` — purely code / markdown / repo-metadata work. The current LLM agent can execute it end-to-end.
- `Human` — blog writing, video production, community outreach, content that needs a real human voice / face / network.
- `Mixed` — partial (e.g., Claude scaffolds copy, human approves and runs the campaign).

**Status field:** `open` / `in-progress` / `done`.

**Process rule:** every shipping event flips the relevant `Status` line here from `open` to `**DONE** (date, commit-sha or campaign-link) — one-line summary`. Mirrors the rule in `QA_FEEDBACKS.md`.

**Strategic premise** (locked, do not relitigate per task):

> The single biggest thing that will make developers trust and use AgentGuardian is a real vulnerable AI agent demo where AgentGuardian finds a serious issue and generates evidence in under 5 minutes. That demo (which the live testbench at `https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app` already proves works) is the center of the whole open-source GTM. Every task below either directly serves that 5-minute experience or removes friction around it.

---

## GTM-009 — Maintenance cadence discipline (Active label, weekly releases, response SLA)

- **Date filed** · 2026-05-31
- **Owner** · Mixed
- **Why now** · A dead-looking security repo loses developer trust fast. For the first 90 days the project must visibly look alive.
- **Deliverables** ·
  - **Claude:** scaffold `CHANGELOG.md` with the Keep-a-Changelog format; write a `scripts/release.sh` that bumps version + tags + drafts release notes from `git log`; add a `RELEASES.md` page to the Mintlify docs explaining the cadence; add a GitHub Action that auto-comments on stale issues with "we'll respond within 48h" and pings maintainers.
  - **Human:** commit to the cadence (weekly release during early development; monthly demo video; <48h issue response). Publish a "Project Status: Active" line in the README. Triage the inbox.
- **Acceptance** · `CHANGELOG.md` has at least 4 weekly entries; README shows "Project status: Active · v1.x · release cadence: weekly"; oldest open issue has a maintainer response timestamp.
- **Cross-cuts** · GTM-001 (README adds the project-status badge); GTM-007 (monthly demo video lives here).
- **Status** · open

---

## GTM-008 — Distribution channel launch sequence (HN, Reddit, Product Hunt, LinkedIn, newsletters)

- **Date filed** · 2026-05-31
- **Owner** · Human
- **Why now** · Post-trust-layer, post-demo, post-assets — the launch is the moment everything compounds or fizzles. Order matters and tone matters (devs notice marketing-speak in seconds).
- **Deliverables** ·
  - **Channel order (locked):** GitHub release → Hacker News (Show HN) → Reddit (r/LocalLLaMA → r/MachineLearning → r/cybersecurity → r/netsec → r/LLMDevs) → Product Hunt → LinkedIn founder post → X/Twitter → Dev.to/Medium repost → YouTube demo → security/AI engineering newsletters → OWASP GenAI + LangChain + MCP communities.
  - **Tone template (locked):** "We built an open-source tool to red team AI agents for prompt injection, tool abuse, RAG poisoning, and unsafe tool calls. Here is a vulnerable demo agent and the report it generates. Feedback welcome." NOT: "Excited to announce..."
  - Each post links to: the live testbench, GitHub repo, Mintlify docs Quickstart, 60-second demo video.
- **Acceptance** · The `gtm/` launch operational kit is shipped (tone rules, schedule, per-channel copy, response templates, newsletter outreach pack, metrics file). Each live channel post is captured as a row in `gtm/launch-posts.md` with the URL, UTC timestamp, and the @24h / @7d traction numbers. Hacker News post does not get flagged. Product Hunt launch has at least one comment thread the founder responds to.
- **Cross-cuts** · GTM-007 (uses the launch blog at `docs/blog/introducing-agentguardian.mdx` as the canonical link); GTM-006 (uses our `awesome-agent-security` repo as a credibility receipt); GTM-003 (the live testbench + `examples/vulnerable-langgraph-agent/` is the central proof point every channel post links to).
- **Status** · open

---

## GTM-007 — Launch assets (60–90s demo video, launch blog, deep-dive, comparison page, demo walkthrough)

- **Date filed** · 2026-05-31
- **Owner** · Mixed (Claude can draft markdown; human shoots video + finals the founder voice)
- **Why now** · Distribution channels need real artefacts to point at. Without these, GTM-008 collapses.
- **Deliverables** (5 assets) ·
  1. **Demo video (60–90s)** — flow: start vulnerable agent → run `agent-guardian scan ...` → show prompt-injection finding → open HTML report → show evidence → show mitigation → re-run → 0 findings. **Human owns production.**
  2. **Launch blog** — *"Introducing AgentGuardian Open: Open-Source Red Teaming for AI Agents"*. Sections: why agents need red teaming, what AG tests, how the attack engine works, example scan (linked to live testbench), how to try it, roadmap, how to contribute. **Claude can draft; human polishes.**
  3. **Technical deep-dive** — *"How Prompt Injection Becomes Tool Abuse in AI Agents"*. The "serious devs + security engineers" attractor. **Claude drafts.**
  4. **Comparison page** — *AgentGuardian vs manual prompt testing · vs generic LLM evals · vs traditional DAST/SAST*. Factual, not aggressive. **Claude drafts.** Lives at `docs/concepts/oss-vs-enterprise.mdx` + `docs/concepts/agent-guardian-vs.mdx`.
  5. **Vulnerable demo walkthrough** — *"Breaking a LangGraph Agent with Prompt Injection and Tool Abuse"*. The most viral piece. **Claude drafts using the testbench's `coding_assistant` agent as the example.**
- **Acceptance** · All 5 assets live in `docs/blog/` (Mintlify supports blogs). Demo video uploaded to YouTube + linked from README. The deep-dive + walkthrough are SEO-targeted (slugs + titles match `intitle:` searches engineers actually run).
- **Cross-cuts** · GTM-006 (awesome lists link to these); GTM-008 (channel posts link to these).
- **Status** · open

---

## GTM-006 — Discoverability: GitHub topics, awesome-list submissions, our own `awesome-agent-security` repo

- **Date filed** · 2026-05-31
- **Owner** · Mixed (Claude does the repo work; human posts the PRs to other awesome-lists and engages with maintainers)
- **Why now** · GitHub search + GitHub trending + curated awesome-lists + AI search (Claude, ChatGPT, Perplexity) are where developers find tools today. Being absent from those = invisible.
- **Deliverables** ·
  - **Claude:** set GitHub repo topics: `ai-security`, `agent-security`, `red-team`, `red-teaming`, `llm-security`, `prompt-injection`, `owasp`, `rag-security`, `mcp-security`, `ai-agents`, `langgraph`, `crewai`, `security-tools`, `devsecops`. Update repo description to: *"Open-source red teaming toolkit for AI agents, RAG systems, MCP servers, and tool-using LLM applications."* Create a separate repo `awesome-agent-security` with sections: Agent Security Tools, Prompt Injection Resources, RAG Security Resources, MCP Security Resources, AI Red Teaming Papers, Benchmarks, Open-Source Projects, Commercial Platforms. **Make it genuinely useful — don't make it only about AgentGuardian.**
  - **Human:** submit PRs to: `awesome-llm-security`, `awesome-ai-agents`, `awesome-langchain`, `awesome-mcp`, `awesome-rag`, `awesome-cybersecurity`, `awesome-devsecops`. PR titles and copy follow the technical-not-marketing tone from GTM-008.
- **Acceptance** · GitHub topics set; `awesome-agent-security` repo public with ≥30 high-quality entries; ≥3 awesome-list PRs merged.
- **Cross-cuts** · GTM-007 (deep-dive + walkthrough are linkable resources); GTM-009 (cadence keeps the awesome-list fresh).
- **Artefacts** · `gtm/discoverability.md` (locked topic list, PR tracker, tone templates); `gtm/awesome-agent-security-README.md` (drop-in content, 30 entries); `gtm/awesome-agent-security-CONTRIBUTING.md`; `gtm/awesome-agent-security-LICENSE`. `pyproject.toml` description updated to match the new GitHub repo description.
- **Status** · open — repo metadata + curated content drafted in `gtm/`; pending operator steps: set topics + description via GitHub UI, push external repo, submit awesome-list PRs (see `gtm/discoverability.md`).

---

## GTM-005 — CI/CD integration pack: GitHub Action, Docker image, PyPI, pre-commit hook, SARIF, HTML report

- **Date filed** · 2026-05-31
- **Owner** · Claude
- **Why now** · Developers adopt tools when they fit existing workflows. The fit-into-existing-pipeline path is the difference between "interesting project" and "shipped".
- **Deliverables** ·
  - **GitHub Action** at `.github/actions/agentguardian-scan/action.yml` — composite action wrapping `pip install agentguardian && agent-guardian scan ... --output sarif`. SARIF auto-uploads to GitHub Code Scanning.
  - **Docker image** published to GitHub Container Registry (`ghcr.io/glacien-technologies/agent-guardian:latest`). `Dockerfile` + a `docker-compose.yml` that runs scan against a target URL.
  - **PyPI** — already published; ensure auto-publish workflow is wired to release tags.
  - **Pre-commit hook** at `.pre-commit-hooks.yaml` so projects can add AG to their existing pre-commit.
  - **SARIF output** — already exists (`--output sarif`); add a docs page showing how to upload to GitHub Code Scanning UI.
  - **HTML report sample** — committed at `docs/_assets/sample-report.html` so the README can show "here's what the report looks like" without running anything.
- **Acceptance** · Action installable from `glacien-technologies/agent-guardian@v1` in any GitHub repo's workflow. Docker image runs the testbench scan from `docker run`. SARIF upload renders as expected in GitHub Code Scanning UI. Pre-commit hook can be added with `pre-commit install`.
- **Cross-cuts** · QA-010 (PDF in base, in flight as `w36fii88l`) — once that lands, the HTML report sample can be paired with a PDF sample too.
- **Status** · closed (composite action at `.github/actions/agentguardian-scan/`, pre-commit registry at `.pre-commit-hooks.yaml`, sample at `docs/_assets/sample-report.html`, validator at `.github/workflows/validate-action.yml`, integration guide at `INTEGRATION.md`).

---

## GTM-004 — Framework adapter examples: LangGraph, CrewAI, OpenAI Agents SDK, MCP, RAG, FastAPI, Ollama, Bedrock, Gemini

- **Date filed** · 2026-05-31
- **Owner** · Claude
- **Why now** · Developers search by the framework they already use. SEO + AI-search discoverability scales linearly with the number of named-framework examples.
- **Deliverables** · 9 per-framework example dirs under `examples/`. Each follows the SAME flow:
  1. Clone example.
  2. Start target (`docker compose up` or `python serve.py`).
  3. Run AgentGuardian scan with the right `--framework` or `--endpoint`.
  4. View report.
  5. Apply suggested mitigation.
  6. Re-run scan; show findings drop.

  Frameworks: `langgraph`, `crewai`, `openai-agents-sdk`, `mcp-server`, `rag-app`, `fastapi-chatbot`, `ollama-local`, `bedrock-agent`, `gemini-agent`. Several already exist in the OSS testbench (`finbot`/`support_bot`/`coding_assistant`/`travel_concierge`); port those plus add missing frameworks.
- **Acceptance** · 9 example dirs, each with `README.md` + runnable code + sample scan output. Mintlify `docs/examples/` has a page per framework following the locked 6-section style rule. Each page is SEO-targeted (`intitle:"<framework> red team"` rank).
- **Cross-cuts** · GTM-003 (the vulnerable demo repo is the harder version; these are quickstart examples). GTM-007 (the deep-dive + walkthrough blogs reference these).
- **Status** · open

---

## GTM-003 — Vulnerable demo agents repo (`agentguardian-vulnerable-agents`)

- **Date filed** · 2026-05-31
- **Owner** · Claude
- **Why now** · The single highest-leverage GTM asset, per the strategic premise: "a real vulnerable AI agent demo where AgentGuardian finds a serious issue and generates evidence in under 5 minutes."
- **Status of head start** · We already have it deployed as the testbench (`agent-guardian-testbench-u6tm6gzysq-uc.a.run.app` + the source folder at `/Users/mobionix/workspace/glacien/agent_guardian_testbench/`). This task formalises it as a public repo + adds the `docker compose up` story.
- **Deliverables** ·
  - New public repo `glacien-technologies/agentguardian-vulnerable-agents` containing the existing testbench source + a top-level `docker-compose.yml` so `docker compose up` brings every demo agent up locally.
  - Each demo agent ships with: a `README.md` describing the planted vulnerabilities (LLM01-LLM10 mapping), the trigger prompts that elicit them, and a one-liner `agent-guardian scan --endpoint http://localhost:<port>/chat` to demo the catch.
  - The 5 agents shipping today (finbot, support_bot, coding_assistant, travel_concierge, clean_control) are renamed for the OSS audience (e.g. `vulnerable-langgraph-agent`, `vulnerable-rag-agent`, `vulnerable-mcp-server`, `vulnerable-tool-agent`, `defended-baseline-agent`).
- **Acceptance** · `docker compose up` + `agent-guardian scan --endpoint http://localhost:8000/chat` produces a real finding in under 5 minutes from a fresh clone, no GCP setup required.
- **Cross-cuts** · GTM-004 (the per-framework examples can lift from this); GTM-005 (Docker image story leverages the docker-compose pattern); GTM-007 (the demo video uses this).
- **New repo location** · `/Users/mobionix/workspace/Glacien/agentguardian-vulnerable-agents/` (local, pre-push). Ports 5 renamed agents from the testbench; stub-mode adapter ships so `GEMINI_API_KEY` is optional.
- **Status** · in-progress

---

## GTM-002 — README + Quickstart polish (sells the value in 30 seconds, includes demo GIF)

- **Date filed** · 2026-05-31
- **Owner** · Mixed (Claude rewrites the README; human records the demo GIF)
- **Why now** · The README is the real landing page for developers. They scan-judge in under 30 seconds.
- **Deliverables** ·
  - **Claude:** rewrite `README.md` to the locked structure:
    ```
    # AgentGuardian Open
    Open-source red teaming for AI agents.
    Find prompt injection, tool abuse, RAG poisoning, memory attacks, and unsafe agent behavior before attackers do.
    pip install agentguardian
    agent-guardian scan --endpoint http://localhost:8000/chat --model gemini:gemini-2.5-flash
    ```
    Then: example output (real scan transcript), screenshot of the HTML report, supported frameworks list, attack categories (ASI01-ASI10), 2-minute Quickstart link. Project status badge: "Active · v1.x · release cadence: weekly". OpenSSF Best Practices badge once GTM-001 lands.
  - **Human:** record a ~30-second demo GIF showing the scan command + the dashboard rendering findings. Crop tight; loop cleanly.
- **Acceptance** · A new developer can read the README, copy-paste the scan command, run it against the live testbench, and see findings in under 5 minutes. README first-paint answers: what / how / result / why-trust within 30 seconds.
- **Cross-cuts** · GTM-001 (badges go in the README header); GTM-005 (HTML report sample is referenced); GTM-003 (the docker-compose path is the alt-Quickstart).
- **Status** · open

---

## GTM-001 — GitHub trust layer files (SECURITY.md, CODE_OF_CONDUCT.md, GOVERNANCE.md, ROADMAP.md, CHANGELOG.md, issue/PR templates, OpenSSF badge, signed releases)

- **Date filed** · 2026-05-31
- **Owner** · Claude
- **Why now** · Developers judge "is this maintained?" in 5 seconds based on which files exist at the repo root. Missing `SECURITY.md` on a security tool is an immediate trust kill. This is the cheapest highest-leverage GTM move.
- **Deliverables** · 8 files at the repo root + the OpenSSF Best Practices badge enrolment:
  1. `SECURITY.md` — vulnerability disclosure process, contact (`security@glacien.ai`), response SLA, supported versions, PGP key.
  2. `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
  3. `GOVERNANCE.md` — maintainer ladder (User → Contributor → Attack Author → Maintainer → Security Research Partner), decision rules, release veto rights.
  4. `ROADMAP.md` — public roadmap for the next 90 days; pulls from the open QA items + the GTM tasks here that ARE in scope.
  5. `CHANGELOG.md` — Keep-a-Changelog format, populated from git log.
  6. `.github/ISSUE_TEMPLATE/bug_report.md` + `feature_request.md` + `security_issue.md` + `attack_idea.md`.
  7. `.github/PULL_REQUEST_TEMPLATE.md` — DCO sign-off prompt + checklist.
  8. `.github/CODEOWNERS` — route reviews to the right maintainers.
  9. Enrol the project in OpenSSF Best Practices (https://www.bestpractices.dev/) — apply for the passing badge as v1.0; target silver within 90 days.
  10. Enable GitHub CodeQL + Dependabot + secret scanning.
  11. Wire signed releases (sigstore cosign + provenance via GitHub Actions).
- **Acceptance** · GitHub community profile shows 100% checklist green. OpenSSF passing badge live in README. CodeQL Action runs on every PR.
- **Cross-cuts** · GTM-002 (badge shows in README); GTM-009 (CHANGELOG cadence depends on this); GTM-005 (signed releases come from the CI/CD integration pack).
- **Status** · open

---

<!-- Add new GTM tasks above this line. Newest first. -->
