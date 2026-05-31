# Responsible disclosure

**TL;DR** — Report vulnerabilities in `agent-guardian` itself privately via [GitHub Security Advisories](https://github.com/glacien-technologies/agent-guardian/security/advisories/new) (preferred) or `security@glacien.ai` (fallback). 90-day coordinated-disclosure embargo. Handled disclosures are recorded in [disclosure-history.md](disclosure-history.md).

This page is a published mirror of [`SECURITY.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/SECURITY.md) at the repository root, so the policy can be linked from `https://agentguardian.io/docs/security/responsible-disclosure/` without round-tripping through GitHub. The canonical file is in the repo; this rendering matches it.

## Reporting a vulnerability

If you believe you have found a security vulnerability in `agent-guardian` itself, please report it privately. **Do not file a public GitHub issue.**

- **Preferred channel — GitHub Security Advisories (private vulnerability reports):** [Open a draft advisory](https://github.com/glacien-technologies/agent-guardian/security/advisories/new). This is the canonical reporting path: GitHub encrypts the report at rest, scopes visibility to the maintainers, and gives us a private fork for the fix.
- **Email fallback:** `security@glacien.ai` — use this only if you cannot use the GitHub channel. Plain email is acceptable; we do not require encrypted email. (We previously documented a PGP key path here; we removed it because long-lived PGP keys are not a security improvement when GHSA gives end-to-end encryption out of the box. Sigstore keyless OIDC signs every release artifact — see [supply-chain.md](supply-chain.md).)
- **Embargo:** We follow a **90-day coordinated-disclosure embargo** from the date you first report the issue. We will not publicly disclose details until the embargo expires or a fix is shipped, whichever comes first.
- **Public log:** Every handled disclosure is recorded in [disclosure-history.md](disclosure-history.md) once the embargo lifts.

When reporting, please include:

1. A short description of the vulnerability and its impact.
2. The affected version(s) of `agent-guardian` (output of `agent-guardian --version`).
3. A minimal proof-of-concept or reproduction steps.
4. Your name and (optionally) a handle you'd like credited in the advisory.

## Scope

**In scope:**

- Vulnerabilities in the `agent-guardian` Python package, CLI, and bundled web server.
- Supply-chain risks in our build, release, or signing process.
- Information-disclosure or privilege-escalation bugs in our reference adapters.

**Out of scope:**

- Bug reports about **target agents** that `agent-guardian` is used to test. Those belong to the respective target's maintainers — `agent-guardian` is the tool that *found* the issue, not the issue itself.
- Issues in third-party LLM providers (OpenAI, Anthropic, Google, etc.) reached via the user's own API keys.
- Issues in user-supplied target code, system prompts, or adapter configuration.
- Denial-of-service through legitimate scan workloads (large probe corpora, high concurrency). Scan throttling and quotas are user-configurable; misconfiguration is not a vulnerability.

The same split is documented from the technical-controls side in [threat-model.md](threat-model.md).

## Disclosure timeline

We strongly prefer **coordinated disclosure**. Glacien commits to:

1. Acknowledging your report within **5 business days**.
2. Providing an initial triage assessment within **10 business days**.
3. Delivering a fix or documented mitigation within **90 days**, or providing a written explanation if more time is required.
4. Crediting you in the published advisory (with your permission).
5. Publishing a [GitHub Security Advisory](https://github.com/glacien-technologies/agent-guardian/security/advisories) and a corresponding CVE (where applicable) once the fix ships.

If the issue is being actively exploited in the wild, we may shorten the embargo and ship an emergency patch.

## Hall of fame

Researchers we have credited for coordinated disclosures are listed in the [disclosure-history hall of fame](disclosure-history.md#hall-of-fame). Crediting is opt-in; you may choose named, pseudonymous, or anonymous attribution.

## Supply-chain integrity

Every release wheel and sdist is signed via Sigstore (keyless OIDC through GitHub Actions). The publish workflow attaches the signatures, a CycloneDX SBOM, and PEP-740 attestations to the corresponding GitHub Release. See [supply-chain.md](supply-chain.md) for the byte-for-byte rebuild protocol.

If your reproducibility verification fails — i.e., a wheel on PyPI does not match what you can rebuild from the tagged source — treat it as a supply-chain incident and report via this policy.

## See also

- [Disclosure history](disclosure-history.md) — public log of every handled report.
- [Threat model](threat-model.md) — what counts as in-scope from the technical-controls side.
- [Supply chain](supply-chain.md) — how to verify the binary you `pip install`.
- [`SECURITY.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/SECURITY.md) at the repo root — the canonical source.
