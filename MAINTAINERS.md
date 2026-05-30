# Maintainers

AgentGuardian is maintained by [Glacien Pte. Ltd.](https://glacien.ai). This file lists the people responsible for the project by role rather than personal handle, per [Engineering Standards §6.5](docs/engineering-standards.md).

For decision-making rules see [`governance.md`](governance.md). For how to contribute see [`CONTRIBUTING.md`](CONTRIBUTING.md). For security reports see [`SECURITY.md`](SECURITY.md).

## Active maintainers

Commit and tag signing on this project uses **Sigstore keyless OIDC** through GitHub
Actions for release artifacts (every wheel, sdist, and SBOM is signed automatically by
the publish workflow against the workflow identity) and **Git's native SSH signing** for
maintainer commits on `main` (each maintainer's GitHub `signingkey` SSH public key is
the canonical identity — verified by GitHub directly with no separate fingerprint to
mirror here). This avoids the long-lived-PGP-key escrow problem older OSS projects hit:
there is no symmetric secret a contributor would need to verify out-of-band.

| Role | Contact | Verification path |
|---|---|---|
| **Tech Lead** | `tech-lead@glacien.ai` | GitHub `Verified` badge on commits via SSH signing key |
| **Security Lead** | `security@glacien.ai` | GitHub Security Advisories (private vulnerability reports) — see [SECURITY.md](SECURITY.md) |
| **Community Lead** | `community@glacien.ai` | GitHub `Verified` badge on commits via SSH signing key |
| **Release Manager** | `releases@glacien.ai` | Sigstore OIDC signature on every release artifact — verifiable via `sigstore verify` |

> **Onboarding note for maintainers:** before any role here is "live" the holder must (a) upload an SSH signing key to GitHub and set it as their `signingkey`, (b) configure `git config --global commit.gpgsign true` and `git config --global gpg.format ssh`, and (c) ensure their `@glacien.ai` author email matches the brand-integrity workflow. Branch protection on `main` requires signed commits.

## On-call rotation

Issue triage and security-report acknowledgement rotate weekly across the four roles. The current week's on-call is posted in the `#oss-rotation` channel on the Glacien Slack and surfaced in the GitHub Discussions pinned post.

| Week | Triage on-call | Security on-call |
|---|---|---|
| `2026-W22` | Tech Lead | Security Lead |

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
| — | — | (none — original maintainers above are still active as of v1.0.0) |

---

*This file is reviewed quarterly alongside the engineering-standards review (Engineering Standards §16.1). The review minutes are committed to `docs/engineering-standards-reviews/YYYY-QN.md`.*
