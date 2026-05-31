# Engineering standards

> **TL;DR.** Structured table-of-contents for the engineering standards the rest of the docs cite (`§4.2`, `§9.4`, …). Each numbered section anchors here; the substance lives in the canonical page linked from each entry so the standard never disagrees with itself by being duplicated.

If you arrived here from a link such as *"per Engineering Standards §9.4"*, scroll to that anchor — the inbound link will take you to the standard's canonical home with one extra hop.

## 4 — Repository and release hygiene

### 4.2 — OpenSSF Best Practices

The badge row on `README.md` tracks the OpenSSF Best Practices passing tier. Registration at <https://www.bestpractices.dev> is a pre-launch gate; the badge is held back until the registration ID resolves so we never ship a `/projects/0000` placeholder badge to PyPI.

### 4.12 — Reproducible builds

AgentGuardian commits to byte-reproducible wheels and the public verification artefacts that prove it. The canonical reference — toolchain pins, the rebuild recipe, and the verification log — lives in [Supply chain & reproducible builds](../security/supply-chain.md).

Annual independent verification artefacts are committed under [`docs/security/reproducibility-verifications/`](https://github.com/glacien-technologies/agent-guardian/tree/main/docs/security/reproducibility-verifications). Re-verifying the most recent stable release is a standing `good-first-issue` invitation.

## 6 — Governance and people

### 6.5 — Roles, not personal handles

[`MAINTAINERS.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/MAINTAINERS.md) identifies people by role (Maintainer, Release Manager, Security Lead, Standards Liaison) rather than personal GitHub handle so the project keeps working when individuals rotate out.

### 6.7 — Community channels

Community channels (Discord / GitHub Discussions) are provisioned before they appear in any user-facing doc — placeholder invite links are not shipped to PyPI. Provisioning steps live in [v1.0 Launch Checklist](operator-checklist.md).

## 9 — Public-facing commitments

### 9.3 — Deprecation policy

AgentGuardian commits to a predictable deprecation cadence. The canonical reference for the rule, warning shape, and timeline lives in [Deprecation policy](deprecation-policy.md).

### 9.4 — Telemetry transparency

Telemetry source code ships *in the package* — anyone can read it before opting out or upgrading. The full data contract, the three tiers (OFF / ESSENTIAL / EXTENDED), and the self-host instructions live in [Telemetry transparency](../security/telemetry.md).

### 9.5 — Vulnerability disclosure history

A public, append-only log of every vulnerability report we have handled — so researchers can verify our response times match the published policy. Canonical home: [Disclosure history](../security/disclosure-history.md). Reporting policy lives in [Responsible disclosure](../security/responsible-disclosure.md).

## 11 — Marketing surface

### 11.1 — README badge row

The badge row on `README.md` is the project's public credibility surface — it must be *defensibly accurate*. Placeholder badges (`/projects/0000`) and broken-link badges are held back rather than shipped. The current set tracks PyPI version, supported Python versions, license, CI status, coverage, OpenSSF Scorecard, downloads, and the docs link.

## 16 — Cadence

### 16.1 — Quarterly review

Maintainer roster, the standards in this page, and any open standing gaps are reviewed quarterly. Review minutes are committed under [`docs/engineering-standards-reviews/`](https://github.com/glacien-technologies/agent-guardian/tree/main/docs/engineering-standards-reviews). The current quarter's tracking issues are visible on [the roadmap](../reference/roadmap.md).

---

*This page intentionally delegates the substance of each standard to its canonical home. If you propose changing a standard, edit the canonical page and update the inbound anchor here in the same commit.*
