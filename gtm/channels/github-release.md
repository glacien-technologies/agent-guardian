# GitHub Release — v1.0.0 announcement body

**Target time:** T-0, 06:00 UTC. The tag itself is pushed at T-3
(see `launch-schedule.md`) — that triggers the existing
`.github/workflows/publish.yml` which builds the wheel, generates the
SBOM, signs the artifacts, and publishes to PyPI. The Release **body**
below is filled in via `gh release edit` at T-0 06:00, six hours
before the HN post.

## Release title

```
v1.0.0 — first stable release
```

## Release body

````markdown
First stable release of AgentGuardian, an open-source red-teaming
toolkit for AI agents.

## What this is

AgentGuardian points a swarm of 14 specialist adversarial agents at
your LangGraph / CrewAI / MCP / RAG / REST agent and produces a
deterministic AIVSS-scored, OWASP-ASI-mapped SARIF report.

```bash
pip install agent-guardian
agent-guardian scan --target my_app:graph --framework langgraph
```

## Highlights

- **Swarm Commander** — convergence-detecting meta-agent that
  re-tasks idle specialists.
- **AIVSS scoring** — deterministic 0–100, formula public.
- **Triple-mapping** — OWASP ASI 2026, MITRE ATLAS v5.4.0, CSA
  Agentic AI Red Teaming Guide.
- **Output formats** — SARIF, JSON, JUnit, Markdown, PDF.
- **CI-friendly** — exit code 1 on high-risk findings; SARIF
  uploads cleanly into GitHub Code Scanning.
- **No telemetry** — local-first; the scanner never calls home.
- **Reproducible build** — `SOURCE_DATE_EPOCH` set from the commit
  timestamp; artifacts are bit-identical across re-runs.
- **Signed releases** — every wheel and sdist signed with Sigstore
  (keyless OIDC via Fulcio + Rekor). CycloneDX SBOM attached.

## Try without installing

Live testbench — five vulnerable agents in your browser, no signup:
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

60-second demo video:
{{ YOUTUBE_DEMO_URL }}

## Frameworks shipped today

LangGraph · CrewAI · OpenAI Agents SDK · MCP servers · RAG apps ·
REST endpoints · custom Python (dotted-path entrypoint).

## Docs

https://agentguardian.io

## Verifying this release

```bash
# Verify the wheel signature with cosign (Sigstore keyless)
cosign verify-blob \
  --bundle agent_guardian-1.0.0-py3-none-any.whl.sigstore \
  --certificate-identity-regexp 'https://github\.com/glacien-technologies/agent-guardian/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  agent_guardian-1.0.0-py3-none-any.whl

# Inspect the SBOM
cat agent_guardian-1.0.0.cyclonedx.json | jq '.components | length'
```

## Changelog

Full changelog at
[CHANGELOG.md](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md).

## Feedback

The two open questions:

1. AIVSS dimension weighting — currently inverse-frequency from a
   small study. Principled critique welcome.
2. Framework adapter priorities — ADK, AutoGen, Strands, Bedrock
   Agents are on the shortlist.

File issues at
https://github.com/glacien-technologies/agent-guardian/issues.
````

## Post-publish

After the Release body is live:

1. `gh release view v1.0.0 --json url --jq .url` → paste into
   `launch-posts.md`.
2. Pin the Release on the repo home page (`gh release edit --latest`).
3. The HN post (T-0 13:00) links to the repo home, which now shows
   the v1.0.0 release card at the top — this is the trust signal.
