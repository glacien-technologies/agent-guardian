# OpenSSF Best Practices badge — enrolment status

This file tracks AgentGuardian's enrolment in the [OpenSSF Best Practices
Badge Program](https://www.bestpractices.dev/). It exists so the badge ID
(once issued) and the self-assessment evidence are auditable from inside the
repo, not buried in a third-party dashboard.

Linked from `SECURITY.md` and `docs/community/oss-roadmap.md` (Theme 3 — Supply-chain security
& trust signals).

## Current state

| Field | Value |
|---|---|
| Programme | OpenSSF Best Practices Badge |
| Tier targeted | Passing |
| Status | Enrolment in progress — see "Operator runbook" below |
| Project URL submitted | `https://github.com/glacien-technologies/agent-guardian` |
| Badge URL | _pending — populated once `bestpractices.dev` issues the project ID_ |
| Badge image URL | _pending_ |
| README badge wired | _no — gated on the badge URL above_ |
| Owner of the application | Security Lead (see `MAINTAINERS.md`) |
| Self-assessment evidence root | This file + the artifacts it references |

When the project ID is issued, update the three "_pending_" rows above, edit
`README.md` to add the badge image (see "README badge snippet" below), and
record the change in `CHANGELOG.md` under `[Unreleased]`.

## Scorecard automation added in-repo

The following OpenSSF Scorecard evidence is now automated by repository files.
These changes improve future scans once they are merged and observed by
Scorecard; historical unsigned releases can still depress the live
`Signed-Releases` score until a new release is cut, re-issued, or old release
artifacts are removed.

| Scorecard check | Repo evidence | Notes |
|---|---|---|
| Signed-Releases | `.github/workflows/publish.yml`, `.github/workflows/docker-publish.yml` | Future PyPI/GitHub release artifacts and GHCR images receive GitHub artifact attestations in addition to existing Sigstore/PEP 740 provenance. |
| Fuzzing | `.github/workflows/clusterfuzzlite.yml`, `.clusterfuzzlite/`, `fuzzers/` | ClusterFuzzLite runs Python fuzz targets for probe YAML, contract parsing, report emitters, redaction, and HTTP response parsing. |
| CII Best Practices | This file + operator runbook | Still requires external registration at `bestpractices.dev`; no repository-only change can issue the project ID. |

## Operator runbook

Estimated time: ~30 minutes once the operator is logged in.

1. **Sign in.** Visit [https://www.bestpractices.dev/](https://www.bestpractices.dev/) and sign in with the
   GitHub account that owns `glacien-technologies/agent-guardian`. The
   Security Lead role holds this credential.
2. **Add the project.** Click *Add Project*, paste the repository URL
   `https://github.com/glacien-technologies/agent-guardian`, and submit.
   The system auto-detects several Passing criteria from repo metadata.
3. **Complete the self-assessment.** Work through the six sections —
   *Basics*, *Change control*, *Reporting*, *Quality*, *Security*,
   *Analysis*. The evidence map below tells you which existing repo file
   answers each criterion.
4. **Submit for Passing tier.** No external review is required for Passing;
   confirmation is automatic once every criterion is marked *Met* with
   evidence.
5. **Capture the badge ID.** The form will issue a numeric project ID and
   two URLs: a project page (`https://www.bestpractices.dev/projects/<id>`)
   and a badge image
   (`https://www.bestpractices.dev/projects/<id>/badge`). Paste both into
   the "Current state" table above and commit the change.
6. **Wire the badge into `README.md`.** See snippet below.
7. **Announce.** Add a single bullet under `CHANGELOG.md` `[Unreleased] →
   Added`: _"OpenSSF Best Practices badge (Passing tier) earned — badge URL
   in README."_

## Evidence map — which file answers each criterion

Use this when filling out the bestpractices.dev form. Every Passing-tier
criterion already has on-repo evidence; no new artifacts need to be
written.

| Section | Criterion (paraphrased) | Evidence in this repo |
|---|---|---|
| Basics | Project website / source URL | `README.md`, `https://agentguardian.io` |
| Basics | Licence is OSI-approved | `LICENSE` (Apache-2.0), `NOTICE` |
| Basics | Documentation for users + contributors | `README.md`, `CONTRIBUTING.md`, `docs/` |
| Basics | Project supports HTTPS | All listed URLs are HTTPS |
| Change control | Public VCS with full history | This repo on GitHub |
| Change control | Unique version identifier for each release | Git tags `v*.*.*` + `pyproject.toml` |
| Change control | Release notes for each release | `CHANGELOG.md` + auto-generated GitHub Release notes |
| Reporting | Process for reporting bugs | `.github/ISSUE_TEMPLATE/1-bug-report.yml` |
| Reporting | Process for reporting vulnerabilities | `SECURITY.md` + GitHub Security Advisories |
| Reporting | Acknowledge bug reports promptly | Issue triage rotation in `MAINTAINERS.md` |
| Quality | Build system + tests + clean build | `pyproject.toml`, `.github/workflows/ci.yml`, `tests/` |
| Quality | New functionality tested | `CONTRIBUTING.md` ("Every new probe must ship with a golden test") |
| Quality | Test coverage is measured | `coverage.xml` + Codecov badge in `README.md` |
| Quality | Coding standards documented | `CONTRIBUTING.md`, `.editorconfig`, `pyproject.toml` (ruff, mypy) |
| Security | Maintainers know how to develop securely | `SECURITY.md`, `docs/community/governance.md`, `CONTRIBUTING.md` |
| Security | Cryptography practices | Sigstore keyless OIDC for releases, SSH commit signing — see `MAINTAINERS.md` |
| Security | Vulnerability response process | `SECURITY.md` (90-day coordinated disclosure) |
| Analysis | Static-analysis tool used | Bandit + Semgrep + Gitleaks (`.github/workflows/ci.yml`), Scorecard (`scorecard.yml`) |
| Analysis | Findings from analysis are fixed | `CHANGELOG.md` `Fixed` / `Security` sections |
| Analysis | Dynamic-analysis tool used (if relevant) | `pytest`, Hypothesis property tests, ClusterFuzzLite (`.github/workflows/clusterfuzzlite.yml`, `fuzzers/`) |

## README badge snippet

Once the project ID is issued, replace `<ID>` in the snippet below and
splice it into `README.md` in the badge row (currently between the
Scorecard badge and the Downloads badge):

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)
```

## Re-affirmation cadence

The Passing-tier criteria are re-affirmed annually as part of the
Engineering Standards review (`docs/engineering-standards-reviews/`).
Promotion to Silver or Gold is **not** a current cycle goal — see
[`docs/community/oss-roadmap.md`](../community/oss-roadmap.md).

---

*Last revised: 2026-06-06. Owner: Security Lead.*
