# Governance

This document explains how decisions are made on AgentGuardian. It is intentionally brief — the rules are short enough to read in five minutes.

## Sponsor

AgentGuardian is funded and operated by [Glacien Pte. Ltd.](https://glacien.ai). Glacien employs the maintainers and underwrites the project's infrastructure (CI minutes, PyPI organisation, docs hosting, status page, etc.). This is a **corporate-backed open-source project**, not a community project. We say so plainly to avoid the ambiguity that erodes trust over time.

That said: every line of code, every probe, and every documented practice is Apache-2.0 licensed and open to community contribution under the rules below.

## Roles

There are four maintainer roles. Per [`MAINTAINERS.md`](MAINTAINERS.md):

- **Tech Lead** — sets architectural direction; final say on engine, agent, and strategy design.
- **Security Lead** — owns SECURITY.md, the disclosure history, and the security-sensitive code paths listed in `.github/CODEOWNERS`.
- **Community Lead** — owns CONTRIBUTING.md, CODE_OF_CONDUCT.md, GitHub Discussions, and the `good-first-issue` curation.
- **Release Manager** — owns the release tag, the changelog, the PyPI upload, and the GitHub Release.

At least three roles are filled at all times for bus-factor depth.

## Decision-making

Decisions on AgentGuardian fall into four tiers, each with its own approval rule. The same rules apply equally to Glacien staff and to external contributors.

| Tier | Examples | Approval rule |
|---|---|---|
| **1. Routine technical** | bug fix, single-file refactor, docstring update, dependency bump | one CODEOWNERS reviewer + CI green |
| **2. Cross-cutting** | new API surface, breaking change to an internal interface, new dependency | two maintainers concurring + CI green |
| **3. Scope / roadmap / governance** | new feature direction, deprecation of public API, this file | three of four maintainer roles concurring; decision recorded in the quarterly review minutes under `docs/engineering-standards-reviews/` |
| **4. Conflict-of-interest or Code-of-Conduct** | maintainer-vs-contributor dispute, suspected harassment, brand integrity | escalated to Glacien Office of the CTO via `oss@glacien.ai` |

CODEOWNERS routing in `.github/CODEOWNERS` assigns the right reviewer automatically. Branch protection on `main` enforces the review requirement at merge time.

## Contributor Certificate of Origin

Every commit on `main` must carry a `Signed-off-by:` trailer per the [Developer Certificate of Origin](https://developercertificate.org/). The DCO is enforced by `.github/workflows/dco.yml`. The check cannot be bypassed by maintainer override — that's by design.

We do not require a separate Contributor License Agreement. The DCO is sufficient.

## Disagreeing with a maintainer

If you disagree with a maintainer's decision on your PR or issue:

1. **Reply on the thread first.** State your reasoning. The maintainer is required to respond within five business days.
2. **Tag a second maintainer.** Use `@glacien-technologies/oss-maintainers` to surface the disagreement to the whole team.
3. **Escalate to the Office of the CTO.** Email `oss@glacien.ai`. Decisions at this level are recorded in the quarterly review minutes and become public.

We commit to public, written rationale for any tier-3 decision so that future contributors can read why a direction was chosen.

## Code of Conduct enforcement

The [Contributor Covenant v2.1](CODE_OF_CONDUCT.md) applies in all project spaces (GitHub, Discord, project email). Reports go to `conduct@glacien.ai` and are handled by a rotating Code of Conduct committee per the file's escalation path.

## Removal of maintainers

A maintainer is removed when:

- They leave Glacien employment, or
- They are inactive (no review or commit on the project) for 90 consecutive days, or
- A Code of Conduct enforcement action requires it, or
- They request removal voluntarily.

Removal is recorded in `MAINTAINERS.md` and the quarterly review minutes.

## Forks and downstream distributions

Forks are encouraged. The Apache-2.0 licence permits redistribution. The [`TRADEMARKS.md`](TRADEMARKS.md) policy applies — the AgentGuardian name and mark are Glacien property and may not be used in fork names or marketing without permission.

## This document

Changes to this file are a tier-3 decision (three of four roles concurring). The current version is canonical; older versions are in git history.

---

*Last revised: 2026-05-27. Reviewed quarterly per Engineering Standards §16.1.*
