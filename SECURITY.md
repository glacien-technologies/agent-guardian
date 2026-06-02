# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in `agent-guardian` itself, please report it privately. **Do not file a public GitHub issue.**

- **Preferred channel — GitHub Security Advisories (private vulnerability reports):**
  [Open a draft advisory](https://github.com/glacien-technologies/agent-guardian/security/advisories/new). This is the canonical reporting path: GitHub encrypts the report at rest, scopes visibility to the maintainers, and gives us a private fork for the fix.
- **Email fallback:** `security@glacien.ai` — use this only if you cannot use the GitHub channel. Plain email is acceptable; we do not require encrypted email. (We previously documented a PGP key path here; we removed it because long-lived PGP keys are not a security improvement when GHSA gives end-to-end encryption out of the box. Sigstore keyless OIDC signs every release artifact — see "Supply-chain integrity" below.)
- **Embargo:** We follow a **90-day coordinated-disclosure embargo** from the date you first report the issue. We will not publicly disclose details until the embargo expires or a fix is shipped, whichever comes first.
- **Public log:** Every handled disclosure is recorded in [`docs/security/disclosure-history.md`](docs/security/disclosure-history.md) once the embargo lifts.

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

## Hall of fame

Researchers we have credited for coordinated disclosures are listed in [`docs/security/disclosure-history.md`](docs/security/disclosure-history.md#hall-of-fame). Crediting is opt-in; you may choose named, pseudonymous, or anonymous attribution.

## Acknowledged transitive risks

We track open advisories on transitive dependencies here so users and
auditors can see what we are (and are not) exposed to. Anything listed
below is a **deliberate holding action** — not an oversight — and
will be cleared once an upstream fix lands.

| Advisory                  | Affected package | Vulnerable range   | First patched | AgentGuardian exposure | Holding action |
|---------------------------|------------------|--------------------|---------------|-----------------------|----------------|
| GHSA-f4j7-r4q5-qw2c / CVE-2026-45829 (pre-auth code injection, CVSSv4 9.3) | `chromadb` | `>=1.0.0,<=1.5.9` | none yet (as of 2026-06-02) | **None at runtime.** `chromadb` is a transitive of `crewai` and only lands in the install tree under the opt-in `examples-crewai` extra. The AgentGuardian package never imports `chromadb`. The CrewAI adapter in `src/agent_guardian/adapters/framework/crewai.py` is duck-typed and does not `import crewai`. The CVE is a server-side RCE — pulling the library into `site-packages` without running its server is not exploitable on its own. | `pyproject.toml` carries a commented overlay pin under `[project.optional-dependencies].examples-crewai` that maintainers will uncomment the moment chroma-core publishes a patched release. Track upstream: [chroma-core/chroma](https://github.com/chroma-core/chroma). |

If you believe one of the rows above mis-characterises the exposure,
please open a private advisory via the channel at the top of this file.

## Supply-chain integrity

Every release wheel and sdist is signed via Sigstore (keyless OIDC through GitHub Actions). The publish workflow attaches the signatures, a CycloneDX SBOM, and PEP-740 attestations to the corresponding GitHub Release. See [`docs/security/reproducible-builds.md`](docs/security/reproducible-builds.md) for the byte-for-byte rebuild protocol.

If your reproducibility verification fails — i.e., a wheel on PyPI does not match what you can rebuild from the tagged source — treat it as a supply-chain incident and report via this policy.

Thank you for helping keep AgentGuardian and its users safe.
