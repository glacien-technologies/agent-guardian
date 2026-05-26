# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in `agent-guardian` itself, please report it privately. **Do not file a public GitHub issue.**

- **Email:** `security@glacien.ai`
- **GPG fingerprint:** `TBD` (a key will be published at https://glacien.ai/.well-known/security.asc once the project enters public beta)
- **Embargo:** We follow a **90-day coordinated-disclosure embargo** from the date you first report the issue. We will not publicly disclose details until the embargo expires or a fix is shipped, whichever comes first.

When reporting, please include:

1. A short description of the vulnerability and its impact.
2. The affected version(s) of `agent-guardian` (output of `agent-guardian --version`).
3. A minimal proof-of-concept or reproduction steps.
4. Your name and (optionally) a handle you'd like credited in the advisory.

## Scope

In scope:

- Vulnerabilities in the `agent-guardian` Python package, CLI, and bundled web server.
- Supply-chain risks in our build, release, or signing process.
- Information-disclosure or privilege-escalation bugs in our reference adapters.

Out of scope:

- Bug reports about **target agents** that `agent-guardian` is used to test. Those belong to the respective target's maintainers — `agent-guardian` is the tool that *found* the issue, not the issue itself.
- Issues in third-party LLM providers (OpenAI, Anthropic, Google, etc.) reached via the user's own API keys.
- Issues in user-supplied target code, system prompts, or adapter configuration.
- Denial-of-service through legitimate scan workloads (large probe corpora, high concurrency). Scan throttling and quotas are user-configurable; misconfiguration is not a vulnerability.

## Disclosure

We strongly prefer **coordinated disclosure**. Glacien commits to:

1. Acknowledging your report within **5 business days**.
2. Providing an initial triage assessment within **10 business days**.
3. Delivering a fix or documented mitigation within **90 days**, or providing a written explanation if more time is required.
4. Crediting you in the published advisory (with your permission).
5. Publishing a [GitHub Security Advisory](https://github.com/glacien-technologies/agent-guardian/security/advisories) and a corresponding CVE (where applicable) once the fix ships.

If the issue is being actively exploited in the wild, we may shorten the embargo and ship an emergency patch.

Thank you for helping keep AgentGuardian and its users safe.
