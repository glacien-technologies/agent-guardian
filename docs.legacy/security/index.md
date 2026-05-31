# Security & Trust

**TL;DR** — AgentGuardian runs adversarial workloads against systems you authorise. This section documents exactly what it defends, what it does not, how to verify a report came from the binary you ran, what crosses the network, and how to report a vulnerability.

If you operate AgentGuardian in production, read these five pages in order:

<div class="grid cards" markdown>

- :material-shield-alert: **[Threat model](threat-model.md)**

    What we defend (prompt-injection of swarm agents, evidence-pack tampering, replay of recorded probes). What is out of scope (target compromise, LLM-provider compromise, host-OS sandbox escape, downstream verifier key custody). Trust boundaries and explicit non-goals.

- :material-key-chain: **[Signing & verification](signing.md)**

    Every report is dual-signed: HMAC-SHA256 (PBKDF2, 600 000 iterations) + Ed25519, both over the same canonical-JSON bytes. Trust-anchor truth table, OpenSSL re-derivation, key lifecycle.

- :material-network: **[Data flow](data-flow.md)**

    Per-arrow inventory of what leaves the operator host, what stays on disk, and what each LLM-provider API sees. Includes the egress-allowlist and the `EgressRefused` finding signal.

- :material-package-variant-closed: **[Supply chain](supply-chain.md)**

    Dependency pinning policy, Sigstore keyless signing on every release wheel, CycloneDX SBOM, PEP-740 attestations, and the byte-for-byte reproducible-build protocol.

- :material-chart-line: **[Telemetry transparency](telemetry.md)**

    The three tiers (OFF / ESSENTIAL / EXTENDED), the complete allowlist of fields, the never-collected list, and the CLI surface to inspect or revoke consent.

</div>

## What we defend, what we don't

AgentGuardian is a *security testing tool*. Its threat model is asymmetric: we put significant effort into making the **evidence pack** trustworthy (so a downstream verifier can rely on a finding), and into preventing the **swarm itself** from being subverted by a hostile target. We make no claims about defending the **target agent** under test — that is the system you are testing, not the system we are.

The full in-scope / out-of-scope split lives in [threat-model.md](threat-model.md). Read it before deciding what guarantees AgentGuardian gives you.

## Responsible disclosure

If you believe you have found a vulnerability in `agent-guardian` itself, please report it privately. Do **not** file a public GitHub issue.

- **Preferred channel** — [GitHub Security Advisories](https://github.com/glacien-technologies/agent-guardian/security/advisories/new) (private vulnerability reports).
- **Email fallback** — `security@glacien.ai` (plain email accepted; we do not require PGP).
- **Embargo** — 90-day coordinated disclosure from first report.

Full policy: [responsible-disclosure.md](responsible-disclosure.md). Public log of handled disclosures: [disclosure-history.md](disclosure-history.md).

## Ethics & authorised use

AgentGuardian probes are *functional jailbreak attempts*. Running them against systems you do not own or have not been written authorisation to test is a crime in most jurisdictions. The acceptable-use scope and rationale are in [ethics.md](ethics.md).
