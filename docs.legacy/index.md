# AgentGuardian

Adversarial-swarm framework for agentic AI red-teaming — deterministic AIVSS score in five minutes.

[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/glacien-technologies/agent-guardian/blob/main/LICENSE)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)

```bash
pip install agent-guardian
agent-guardian doctor
agent-guardian scan --system-prompt prompt.txt --model stub
```

No API keys required for `--model stub`. The first real-provider scan takes about five minutes; see the
[Quickstart](tutorials/quickstart.md) for tabbed walk-throughs with OpenAI, Anthropic, and stub.

![Audit Evidence Report sample — eight agents audited, fleet AIVSS 67, signed with Ed25519 + HMAC-SHA256](assets/landing-report.svg)

## Who's this for?

<div class="grid cards" markdown>

-   __For CISOs__

    ---

    See your real AI attack surface. Test continuously against agentic threats — goal hijack, tool misuse,
    memory poisoning, supply chain — the full OWASP Top 10 for Agentic Applications.

    [:octicons-arrow-right-24: Threat coverage](concepts/threat-coverage.md)

-   __For Chief Risk Officers__

    ---

    Generate signed evidence packs mapped to your governance framework. Hand them to your auditor,
    your board, your regulator.

    [:octicons-arrow-right-24: Signing & verification](security/signing.md)

-   __For Chief AI Officers__

    ---

    Ship agents without security becoming the blocker. Run AIVSS in CI/CD; enforce policy before
    agents act.

    [:octicons-arrow-right-24: CI integration](how-to/integrate-github-actions.md)

</div>

## Standards alignment

Every claim links to the upstream specification AND the in-repo evidence that proves coverage.
Upstream URLs verified 2026-05-30.

| Framework | Coverage | Evidence in AgentGuardian |
|---|---|---|
| [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/initiatives/agentic-security-initiative/) | All ten ASI categories (ASI01–ASI10) — one specialist agent per category | [`src/agent_guardian/probes/asi01/`–`asi10/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/probes), [Threat coverage](concepts/threat-coverage.md) |
| [OWASP AIVSS](https://aivss.owasp.org/) | Deterministic 0–100 score, four severity bands, fixture-locked | [AIVSS scoring](concepts/aivss.md), [`tests/unit/test_docs_aivss_example.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/test_docs_aivss_example.py) |
| [MITRE ATLAS](https://atlas.mitre.org/) | Every finding tagged with one or more ATLAS tactic IDs | [Probes](concepts/probes.md), [`src/agent_guardian/probes/asi01/echoleak-zero-click.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi01/echoleak-zero-click.yaml) |
| [CSA Agentic AI Red Teaming Guide](https://cloudsecurityalliance.org/artifacts/agentic-ai-red-teaming-guide) | Cross-tagged on every probe; covered in coverage matrix | [Threat coverage](concepts/threat-coverage.md) |

## At a glance

- Fifteen specialist agents by default (1 recon + 10 ASI + 4 OWASP-LLM; `--no-owasp-llm` reverts to eleven).
- Deterministic AIVSS score 0–100 with band, colour, and per-ASI breakdown.
- Four target input modes: system prompt, agent code, HTTP endpoint, framework adapter (LangGraph, OpenAI
  Agents SDK, CrewAI, AutoGen, Strands, ADK).
- Local dashboard at `http://localhost:7474`.
- Signed PDF, JSON, SARIF, JUnit, and Markdown reports (Ed25519 + HMAC-SHA256). See
  [Signing & verification](security/signing.md).
- Apache-2.0. Anonymous opt-out telemetry; first-scan consent prompt — see
  [Telemetry transparency](security/telemetry.md).

## What next

<div class="grid cards" markdown>

-   :material-rocket-launch: __Run your first scan__

    ---

    Five-minute copy-paste walk-through with OpenAI / Anthropic / stub tabs.

    [:octicons-arrow-right-24: Quickstart](tutorials/quickstart.md)

-   :material-folder-open: __Working examples__

    ---

    Six runnable target fixtures (LangGraph + OpenAI Agents, tiers T1–T4) with captured output.

    [:octicons-arrow-right-24: Examples gallery](examples/index.md)

-   :material-shield-check: __Trust & evidence__

    ---

    Threat model, signing scheme, data flow, supply chain — the questions every CISO asks.

    [:octicons-arrow-right-24: Security & Trust](security/index.md)

</div>

## License

Apache License 2.0. AgentGuardian is a trademark of Glacien Pte. Ltd.
