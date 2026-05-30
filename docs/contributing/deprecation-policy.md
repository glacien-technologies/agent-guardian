# Deprecation policy

> **TL;DR.** No public API breaks within six months of a `DeprecationWarning`. Deprecations are flagged in the CHANGELOG, the docstring, and a tracking issue; removals are flagged in the CHANGELOG again. The one exception is a security fix that cannot ship without a breaking change — those go out immediately, with the security driver disclosed in the release notes.

Per [Engineering Standards §9.3](engineering-standards.md), AgentGuardian commits to a predictable deprecation cadence so downstream consumers can plan their upgrades. This page is the canonical reference for the rule, the warning shape, the timeline, and the escalation path.

## The rule

> **No public API will be removed or behaviour-changed in a way that breaks consumers within six months of the deprecation notice.**

Six months is the de facto Python-ecosystem standard (Django, requests, NumPy, FastAPI). It's long enough that enterprise adopters can plan their migration, short enough that the codebase doesn't accumulate years of compat shims.

## What counts as "public API"

The deprecation policy applies to:

- Every symbol exported from `agent_guardian.__init__` (the import path users actually `from agent_guardian import X`).
- Every public method (no underscore prefix) on a class exported from `agent_guardian.__init__`.
- Every documented CLI flag, subcommand, environment variable, and config-file key in `agent-guardian --help` and `docs/cli.md`.
- Every documented report-format field in `docs/api/models.md` (the JSON / SARIF / JUnit / Markdown / PDF schemas).
- Every probe-YAML field documented in `docs/concepts/probes.md`.
- Every HTTP endpoint exposed by the dashboard server (`/scan/{id}`, `/scan/{id}/coverage`, etc.) when not behind an explicit `experimental:` route prefix.

It does **not** apply to:

- Underscore-prefixed module-level names or class attributes.
- Anything inside `agent_guardian._internal` (private namespace).
- The dashboard's JS/CSS — these are implementation detail of the UI.
- CLI subcommands documented as `experimental:` or behind a `--experimental` gate.
- Test fixtures and stub LLMs (the `agent_guardian.llm.stub` module is supported but its scripted responses can change at any minor bump).

## Mechanics of a deprecation

When we deprecate a public API:

1. **`DeprecationWarning` is emitted** from the moment the deprecation lands. The warning message names (a) what's deprecated, (b) what replaces it, (c) the planned removal version. Example:
   ```python
   warnings.warn(
       "AsiAgent.legacy_score() is deprecated and will be removed in v2.0.0. "
       "Use AsiAgent.score(weighted=True) instead.",
       DeprecationWarning,
       stacklevel=2,
   )
   ```
2. **The CHANGELOG flags the deprecation** under a `Deprecated` heading in the release that introduces the warning. Keep-a-Changelog format makes this discoverable by upgrade-time readers.
3. **The docstring is updated** with a `.. deprecated::` directive naming the same removal version. mkdocstrings renders the warning prominently in the API reference.
4. **A migration note ships in the CHANGELOG's `Deprecated` and `Removed` sections** so upgrade-time readers see the change in context. Major-version upgrades (v1.x → v2.x) get a dedicated migration page; until that page lands, all v1.x → v1.x upgrades are non-breaking per SemVer and the [CHANGELOG](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md) alone is sufficient.
5. **A tracking issue** is opened with the `deprecation` label and the planned removal milestone attached, so the removal isn't forgotten.

When the planned removal version arrives:

1. **The symbol is removed** (or the behaviour changed).
2. **The CHANGELOG flags it again** under a `Removed` heading in the release that performs the removal.
3. **The tracking issue is closed.**
4. **The migration doc remains** indefinitely as a reference for users still on the old version.

## Timeline summary

| Event | When |
|---|---|
| Deprecation announced (DeprecationWarning emitted) | At time T |
| Final patch release before removal | At least T + 6 months |
| Removal | At least T + 6 months, in the next major (or minor for non-API-shape changes) |
| Migration doc archived | Indefinitely |

## Exceptions

There is one class of exception: **security fixes that require an API change**. If a vulnerability cannot be addressed without breaking the API, we ship the security fix immediately and disclose the breaking change in the same release notes. The six-month rule does not apply because the alternative (preserving a vulnerable API for six months) is worse than the breakage. We commit to:

- Document the security driver in the release notes.
- Provide a migration shim that emits the deprecated behaviour with a `RuntimeWarning` (not `DeprecationWarning`) so adopters can detect they're hitting it.
- Backport the security fix to the previous major if technically feasible.

## How to request a deprecation

Open a tier-3 issue (governance label) per [Governance](governance.md). Three of four maintainer roles must concur. The issue records:

- What's being deprecated and why.
- What replaces it.
- The planned removal version.
- Whether a migration shim is necessary.

## Tracking

Active deprecations are visible at `https://github.com/glacien-technologies/agent-guardian/issues?q=label%3Adeprecation+is%3Aopen`. Closed deprecations (i.e. removals shipped) are in the corresponding closed-issue view.

The CHANGELOG sections `Deprecated` and `Removed` together form the historical record.

## Related documents

- [Engineering Standards §9.3 — Deprecation policy](engineering-standards.md)
- [CHANGELOG](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md) — release-by-release record of deprecations and removals
- [Governance](governance.md) — how tier-3 decisions are made
