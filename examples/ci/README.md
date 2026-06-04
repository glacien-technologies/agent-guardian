# AgentGuardian CI templates

Copy-pasteable CI configs that wire AgentGuardian into the three major forges
as a merge gate. Every template is a **starting point** — replace the
`framework` / `framework-ref` (or `--endpoint`) placeholders with your real
target and add your provider key as a CI secret.

All three templates do the same three things on every pull / merge request:

1. **Run the adversarial swarm** and emit a SARIF / Code Quality report.
2. **Gate the build** on an AIVSS floor (`--fail-under`) and optional
   per-severity ceilings (`--max-critical` / `--max-high` / `--max-medium` /
   `--max-low`), AND-combined.
3. **Upsert a single sticky PR/MR comment** — keyed by a hidden marker so it
   updates in place on every push instead of piling up.

> **Stateless gate — no baseline.** The open-source gate judges every scan on
> its own; it has no memory of a previous scan. A pre-existing finding can fail
> the gate, and every finding counts (`--max-critical 0` fails on *any*
> critical, even one that predates the PR). Baseline-diff — failing only on
> findings a PR *introduces* — is a hosted (SaaS) feature. Tune the floor to
> where your agent is today, then tighten as you land mitigations.

These files are validated as YAML on every push by
[`validate_examples.py`](validate_examples.py), so they cannot silently rot.

## GitHub Actions — [`github/`](github/)

Three presets; copy one to `.github/workflows/agent-guardian.yml`:

| File | Preset | Use it for |
|---|---|---|
| [`agent-guardian-minimal.yml`](github/agent-guardian-minimal.yml) | Fast, advisory-only (`continue-on-error`) | Early-adoption repos — signal without blocking merges. |
| [`agent-guardian.yml`](github/agent-guardian.yml) | Standard `--mode full` gate at AIVSS 70, zero critical/high | The default PR gate. |
| [`agent-guardian-thorough.yml`](github/agent-guardian-thorough.yml) | Hardened release-branch gate at AIVSS 80, zero critical/high/medium | PRs into a protected release branch. |

They use the reusable composite action
(`glacien-technologies/agent-guardian/.github/actions/agentguardian-scan@v1`),
which installs the wheel, runs the scan, uploads SARIF to **Security → Code
scanning**, and posts the sticky comment. The caller must grant three
permissions (composite actions cannot grant repo permissions themselves):

```yaml
permissions:
  contents: read           # checkout
  security-events: write   # codeql-action/upload-sarif
  pull-requests: write     # the sticky AgentGuardian PR comment
```

Trigger on `pull_request`, **never** `pull_request_target` — the latter would
run untrusted fork code with write-scoped secrets. Fork PRs get no secrets, so
the templates fall back to `--model stub` (a non-authoritative offline run that
stays red until a maintainer re-runs from a trusted branch).

Add your provider key under **Settings → Secrets and variables → Actions**
(`GEMINI_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`).

Docs: [GitHub Actions](../../docs/ci-cd/github-actions.mdx) ·
[composite action](../../docs/ci-cd/composite-action.mdx).

## GitLab CI — [`gitlab/`](gitlab/)

Copy [`.gitlab-ci.yml`](gitlab/.gitlab-ci.yml) to your repo root. The job:

- emits **SARIF** for the Security & Compliance widget
  (`artifacts:reports:sast`),
- re-emits the scan as a **GitLab Code Quality** report for the inline MR
  widget (`agent-guardian report <id> --output gitlab`,
  `artifacts:reports:codequality`),
- upserts a single sticky **MR note** (`agent-guardian comment --platform
  gitlab`),
- uses `artifacts:when: always` and captures the gate exit code so the reports
  and note publish even when the gate trips, then re-raises the exit code last.

Set under **Settings → CI/CD → Variables** (masked): your provider key, and a
`GITLAB_TOKEN` (project/personal access token with the `api` scope) so the note
can be written — `CI_JOB_TOKEN` cannot write MR notes on most tiers. The job is
scoped to `merge_request_event` and `main`-push pipelines.

Docs: [GitLab CI](../../docs/ci-cd/gitlab-ci.mdx).

## Bitbucket Pipelines — [`bitbucket/`](bitbucket/)

Copy [`bitbucket-pipelines.yml`](bitbucket/bitbucket-pipelines.yml) to your repo
root. On a PR build the step:

- runs the scan + gate (capturing the exit code with `|| SCAN_EXIT=$?`),
- upserts a sticky **PR comment** (`agent-guardian comment --platform
  bitbucket`),
- publishes a **Code Insights** report + one annotation per finding
  (`agent-guardian code-insights --platform bitbucket`),
- re-raises the captured exit code as the step outcome.

Set under **Repository settings → Repository variables** (secured): your
provider key, and `BITBUCKET_TOKEN` (a repository/workspace access token used as
a Bearer credential; needs `pullrequest:write` + `repository:write`). App
passwords work too via `BITBUCKET_USERNAME` + `BITBUCKET_APP_PASSWORD`.
`BITBUCKET_WORKSPACE` / `BITBUCKET_REPO_SLUG` / `BITBUCKET_PR_ID` /
`BITBUCKET_COMMIT` are injected automatically on a PR build.

Docs: [Bitbucket](../../docs/ci-cd/bitbucket.mdx).

## See also

- [CI/CD overview](../../docs/ci-cd/overview.mdx) — the hub, including the
  stateless-gate caveat in full.
- [Security gates](../../docs/ci-cd/security-gates.mdx) — `--fail-under` and the
  `--max-*` ceilings, and the authoritativeness rules.
- [PR / MR comments](../../docs/ci-cd/pr-comments.mdx) — the sticky-comment
  marker contract, identical across all three forges.
