# Maintainers

AgentGuardian Open is maintained by [Glacien Pte. Ltd.](https://glacien.ai). This file lists the people responsible for the project by role rather than personal handle, per [Engineering Standards §6.5](docs/engineering-standards.md).

For decision-making rules see [`governance.md`](governance.md). For how to contribute see [`CONTRIBUTING.md`](CONTRIBUTING.md). For security reports see [`SECURITY.md`](SECURITY.md).

## Active maintainers

| Role | Contact | Public key (Ed25519 or GPG fingerprint) |
|---|---|---|
| **Tech Lead** | `tech-lead@glacien.ai` | _to be published_ |
| **Security Lead** | `security@glacien.ai` | _to be published — see [SECURITY.md](SECURITY.md)_ |
| **Community Lead** | `community@glacien.ai` | _to be published_ |
| **Release Manager** | `releases@glacien.ai` | _to be published_ |

> **Onboarding note for maintainers:** before any role here is "live" the holder must (a) generate a long-lived Ed25519 signing key, (b) upload its public component to their GitHub account, (c) replace the `_to be published_` placeholder above with the fingerprint, and (d) configure `git config --global commit.gpgsign true`. Branch protection on `main` requires signed commits.

## On-call rotation

Issue triage and security-report acknowledgement rotate weekly across the four roles. The current week's on-call is posted in the `#oss-rotation` channel on the Glacien Slack and surfaced in the GitHub Discussions pinned post.

| Week | Triage on-call | Security on-call |
|---|---|---|
| `YYYY-Www` | _to be filled at launch_ | _to be filled at launch_ |

## How decisions escalate

1. **Routine technical** — single maintainer + CODEOWNERS review per `.github/CODEOWNERS`.
2. **Cross-cutting / API-shape** — two maintainers concurring, recorded in the PR.
3. **Roadmap / scope / governance** — three of four roles concurring, recorded in `docs/engineering-standards-reviews/`.
4. **Conflict-of-interest / Code-of-Conduct** — escalated to Glacien Office of the CTO via `oss@glacien.ai`; the escalating party may CC the [Code of Conduct contact](CODE_OF_CONDUCT.md).

## Bus-factor and continuity

At least three roles are filled at all times. If a maintainer departs the holder's responsibilities are reassigned within two weeks and this file is updated in the same PR. The fourth role exists explicitly so single-person absences do not stall releases.

## Historic maintainers

| Period | Role | Person/Email |
|---|---|---|
| _none yet — project is pre-launch_ | — | — |

---

*This file is reviewed quarterly alongside the engineering-standards review (Engineering Standards §16.1). The review minutes are committed to `docs/engineering-standards-reviews/YYYY-QN.md`.*
