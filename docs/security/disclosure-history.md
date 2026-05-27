# Public disclosure history

Per [Engineering Standards §9.5](../engineering-standards.md) and the policy in [`SECURITY.md`](../../SECURITY.md), AgentGuardian Open maintains a public log of every vulnerability report we've handled. Researchers can use this log to verify that our response times match the published policy. Adopters can use it to audit our incident-handling discipline before depending on the project.

After two or three handled disclosures, this log itself becomes a meaningful trust signal — empirical evidence that the SECURITY.md policy is operationally real, not aspirational.

## Format

Each entry records the full disclosure cycle:

- **Received** — date the report arrived at `security@glacien.ai`.
- **Acknowledged** — date we sent the first substantive response (target: within five business days).
- **Patched** — date the fix landed on `main`.
- **Released** — date the fixed version was published to PyPI.
- **Publicly disclosed** — date the advisory + this log entry went public (target: 90 days from acknowledgement unless the reporter agrees to an extension).
- **CVE** — the CVE identifier if assigned.
- **Severity** — Critical / High / Medium / Low.
- **Reporter** — credited per their preference (named, pseudonymous, or anonymous).
- **Summary** — one sentence on what the vulnerability was and how it was fixed.

## Handled disclosures

| # | Received | Acknowledged | Patched | Released | Disclosed | CVE | Severity | Reporter | Summary |
|---|---|---|---|---|---|---|---|---|---|
| _no disclosures yet_ | | | | | | | | | |

## Hall of fame

Security researchers who have credibly reported vulnerabilities to this project. Listed in chronological order of first credited disclosure. Anyone listed here has explicitly opted into public credit.

| Researcher | First contribution | Disclosures |
|---|---|---|
| _empty until first report is credited_ | | |

## How to be credited

Send your report to `security@glacien.ai` per [SECURITY.md](../../SECURITY.md). When acknowledging the report, we'll ask whether you want public credit, anonymous credit (a row in the table with reporter listed as "Anonymous"), or no public mention at all. Your choice is final and we honour it for the lifetime of this log.

If you prefer pseudonymous credit, give us the handle you want displayed. We won't verify the handle's real-world owner.

## Out-of-scope reports

We do not log reports that are out-of-scope per [SECURITY.md](../../SECURITY.md)'s scope clause (e.g., findings in intentionally-vulnerable test fixtures, findings in third-party LLM providers we adapt to, findings in adapter code authored by the user). Out-of-scope reports get a polite redirect; they do not appear in the table above.

## Related documents

- [`SECURITY.md`](../../SECURITY.md) — vulnerability disclosure policy and contact
- [`docs/security/reproducible-builds.md`](reproducible-builds.md) — supply-chain integrity verification
- [Engineering Standards §9.5](../engineering-standards.md) — the policy this log implements
