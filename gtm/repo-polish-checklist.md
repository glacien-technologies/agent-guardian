# AgentGuardian — Repo Polish Checklist (Operator Actions)

Items in this file must be done by a human via the GitHub UI / org settings — they cannot be
landed via a PR. Tick them off in order before announcing 1.0.0.

## (a) Repository topics

Set the following topics on `glacien-technologies/agent-guardian`
(Repo → Settings cog next to "About" → Topics):

```
agent-security
ai-security
llm-security
red-team
red-teaming
agentic-ai
ai-agents
owasp
owasp-top-10
mitre-atlas
csa
prompt-injection
sarif
security-tools
pentesting
langgraph
crewai
openai-agents-sdk
autogen
python
```

## (b) Repository description

Set the "About" description (same panel) to exactly:

> Open-source red-team testing toolkit for agentic AI systems. 96 probes, 11 attackers, OWASP ASI 2026 / MITRE ATLAS v5.4.0 / CSA Agentic-RT mappings. Apache-2.0.

Website: `https://agentguardian.io`

## (c) Labels to create

Create these labels (Repo → Issues → Labels → New label). Suggested colors in parens.

| Label                  | Color     | Description                                                  |
|------------------------|-----------|--------------------------------------------------------------|
| `good first issue`     | `#7057ff` | Approachable for new contributors                            |
| `help wanted`          | `#008672` | Maintainers want external help on this                       |
| `triage`               | `#fbca04` | Awaiting maintainer triage                                   |
| `bug`                  | `#d73a4a` | Confirmed defect                                             |
| `enhancement`          | `#a2eeef` | Feature request or improvement                               |
| `documentation`        | `#0075ca` | Docs bug or improvement                                      |
| `attack-probe`         | `#b60205` | New probe / probe extension                                  |
| `adapter`              | `#5319e7` | Framework adapter work                                       |
| `dependencies`         | `#0366d6` | Dependabot / dependency bumps                                |
| `python`               | `#3572A5` | Python ecosystem                                             |
| `ci`                   | `#000000` | CI / workflow change                                         |
| `docker`               | `#2496ED` | Docker image / build                                         |
| `security`             | `#ee0701` | Security-relevant                                            |
| `breaking-change`      | `#e11d21` | Backwards-incompatible                                       |
| `roadmap`              | `#bfd4f2` | Tracked on the public roadmap                                |
| `discussion-needed`    | `#d4c5f9` | Needs RFC in Discussions before tracked work                 |
| `wontfix`              | `#ffffff` | Will not be addressed                                        |
| `duplicate`            | `#cfd3d7` | Duplicate of another issue                                   |
| `stale`                | `#ededed` | Set by the stale-issue workflow                              |

## (d) Release discipline checklist (for every tag)

Run through this for every `X.Y.Z` release:

- [ ] `CHANGELOG.md` `[Unreleased]` section is moved to `## [X.Y.Z] — YYYY-MM-DD` with all sub-headings populated.
- [ ] Version bumped in `src/agent_guardian/_version.py` and `pyproject.toml` (if independent).
- [ ] `git tag -s vX.Y.Z -m "X.Y.Z"` (signed tag) → `git push origin vX.Y.Z`.
- [ ] GitHub Release created from the tag with the CHANGELOG section pasted as the body.
- [ ] PyPI publish succeeded (via `publish.yml` workflow on tag).
- [ ] Docker image published (via `docker-publish.yml` workflow on tag) with both `:X.Y.Z` and `:latest` tags.
- [ ] Wheel + sdist + Docker image signed (Sigstore / cosign — see ROADMAP for evidence-bundle signing status).
- [ ] SBOM (`sbom.spdx.json` + `sbom.cyclonedx.json`) attached to the GitHub Release as assets.
- [ ] OpenSSF Scorecard score did not regress vs the previous tag.
- [ ] Docs (`agentguardian.io`) deployed and version-switcher updated.
- [ ] Announce in `#announcements` Discussion and on the Glacien blog.
- [ ] No fictional claims regression: rerun `pytest tests/server tests/unit/test_docs_site.py` and the README claim-grep.
