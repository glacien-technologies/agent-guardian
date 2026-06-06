# Releasing `agent-guardian`

This document is the canonical release process for `agent-guardian`. **Every release ships through GitHub Actions via PyPI Trusted Publisher** — there are no long-lived PyPI tokens on any maintainer machine, no manual `twine upload` step, and no signing keys to rotate. If you find yourself uploading to PyPI from your laptop, stop and read this first.

## Quick start

```bash
# 1. Bump the version
$EDITOR src/agent_guardian/_version.py            # change __version__ to X.Y.Z

# 2. Commit with DCO sign-off
git add src/agent_guardian/_version.py
git commit -s -m "chore: bump version to X.Y.Z"

# 3. Push to main
git push origin main

# 4. Tag + push
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag triggers `.github/workflows/publish.yml`. The workflow handles everything — build, SBOM, Sigstore signing, GitHub artifact attestations, GitHub Release, PyPI publish. **Watch the run, don't touch PyPI manually.**

---

## Prerequisites

| Requirement | How to check |
|---|---|
| Push access to `glacien-technologies/agent-guardian` | `git push origin main` works |
| Push access to refs/tags/* | `git push origin v0.0.0test` (then delete) — if rejected, you don't have it |
| `~/.pypirc` does NOT exist | `ls ~/.pypirc` returns "No such file" |
| No `PYPI_API_TOKEN` env var | `env | grep PYPI` is empty |
| GitHub CLI installed (for monitoring) | `gh --version` |
| DCO sign-off configured | `git config user.email` matches your GitHub commit email |

The `.pypirc` / `PYPI_API_TOKEN` checks matter because **the canonical flow doesn't need them** — if either exists, you may accidentally fall back to manual upload and bypass Trusted Publisher (PyPI will email a security advisory).

---

## Version scheme

We follow [PEP 440](https://peps.python.org/pep-0440/) + [Semantic Versioning](https://semver.org/):

| Format | Example | Use case |
|---|---|---|
| `X.Y.Z` | `1.0.0` | Stable release |
| `X.Y.ZrcN` | `1.0.0rc3` | Release candidate — `pip install --pre` required |
| `X.Y.ZaN` | `1.0.0a2` | Alpha (rare; use `rc` for pre-1.0 testing) |
| `X.Y.Z.postN` | `1.0.0.post1` | Post-release fix (metadata only; don't use for code changes) |
| `X.Y.Z.devN` | `1.0.0.dev3` | Development snapshot (don't push tags for these) |

**The version lives in exactly one place: `src/agent_guardian/_version.py`.** Hatch reads it via `[tool.hatch.version]` in `pyproject.toml`. Never bump `pyproject.toml` — there's no version field there to bump.

### Picking the next version

| Change | Bump |
|---|---|
| Breaking API change (removed function, changed signature, new required field) | Major (`1.X.Y` → `2.0.0`) |
| New feature backwards-compatible (new probe, new strategy, new flag) | Minor (`1.0.X` → `1.1.0`) |
| Bug fix, doc fix, dependency bump | Patch (`1.0.0` → `1.0.1`) |
| Testing new feature before committing to it | Pre-release (`1.1.0rc1`, `1.1.0rc2`) |

When in doubt: **prefer a release candidate**. Users opt in with `pip install --pre`, you get real-world testing without committing the version number.

---

## The full release flow

### Step 1 — Make sure main is in a releasable state

```bash
git checkout main
git pull origin main
git status --short    # must be clean
uv run pytest tests/ -x --tb=short    # must be green
```

If tests are red, **do not release**. Fix first.

### Step 2 — Bump the version

Edit `src/agent_guardian/_version.py`:

```python
"""Single source of truth for the package version."""

__version__ = "1.0.0rc3"    # <— change this line only
```

Sanity check:

```bash
uv run python -c "from agent_guardian._version import __version__; print(__version__)"
# Should print exactly 1.0.0rc3
```

### Step 3 — Commit the bump with DCO sign-off

```bash
git add src/agent_guardian/_version.py
git commit -s -m "chore: bump version to 1.0.0rc3

Pre-release with <one-line reason>.
Previous: <previous version>."
```

**The `-s` flag is mandatory** — DCO check on PR/main rejects unsigned commits. CI will fail without it.

### Step 4 — Push to main

```bash
git push origin main
```

Pre-commit hooks may have rewritten files (ruff format, end-of-file fixes). If so:

```bash
git status --short              # check what was auto-changed
git add -A
git commit -s --amend --no-edit # or git commit -s -m "chore: pre-commit autofix"
git push origin main
```

### Step 5 — Create + push the tag

```bash
git tag -a v1.0.0rc3 -m "Release v1.0.0rc3

Brief release notes here — what's new, breaking changes if any, links to
relevant issues/PRs. This message becomes the body of the GitHub Release."
git push origin v1.0.0rc3
```

**The tag name MUST start with `v` and match `v*.*.*`** — that's the trigger pattern in `.github/workflows/publish.yml:16`. A tag named `1.0.0rc3` (no `v`) will NOT trigger the workflow.

**Tag the commit you just pushed** — never tag a commit that isn't on main. The publish workflow uses the SHA the tag points at; if that SHA isn't on main, the release won't be reproducible from main's history.

### Step 6 — Watch the workflow

```bash
gh run list --workflow=publish.yml --limit 3
gh run watch    # interactive monitor (lets you pick the queued run)
```

Or open <https://github.com/glacien-technologies/agent-guardian/actions/workflows/publish.yml> in a browser.

The workflow runs 4 jobs in sequence:

| Job | What it does | Duration |
|---|---|---|
| `build` | `uv build` (reproducible via `SOURCE_DATE_EPOCH`) + CycloneDX SBOM | ~1 min |
| `sign` | Sigstore keyless OIDC signing (Fulcio + Rekor) + GitHub artifact attestations | ~30s |
| `release` | Creates GitHub Release with auto-generated notes + attaches wheel + sdist + SBOM + signatures | ~10s |
| `publish` | Uploads to PyPI via Trusted Publisher (OIDC), attaches PEP 740 attestations | ~30s |

**Total wall-clock: ~2–3 minutes.** Watch for any red ✗ in the run summary.

### Step 7 — Verify the release landed

After the workflow completes successfully:

```bash
# PyPI page exists + has the right metadata
open https://pypi.org/project/agent-guardian/1.0.0rc3/

# Install from PyPI in a fresh venv to smoke-test
uv venv /tmp/release-smoke --python 3.12
/tmp/release-smoke/bin/pip install --no-cache-dir agent-guardian==1.0.0rc3
/tmp/release-smoke/bin/agent-guardian --version
# Should print exactly 1.0.0rc3

# GitHub Release exists + has all artefacts
gh release view v1.0.0rc3
# Should show wheel, sdist, SBOM, .sigstore signatures

# GitHub artifact attestation exists for the released wheel/sdist/SBOM
gh attestation verify /path/to/agent_guardian-1.0.0rc3-py3-none-any.whl \
  --repo glacien-technologies/agent-guardian
gh attestation verify /path/to/agent_guardian-1.0.0rc3.tar.gz \
  --repo glacien-technologies/agent-guardian
```

Cleanup:

```bash
rm -rf /tmp/release-smoke
```

---

## Verifying provenance (post-release)

The publish workflow attaches Sigstore signatures, GitHub artifact attestations,
and PyPI PEP 740 attestations. Anyone — including consumers — can verify them:

```bash
pip install sigstore
sigstore verify identity \
    --cert-identity-regexp '^https://github.com/glacien-technologies/agent-guardian/.github/workflows/publish.yml@.*' \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    /path/to/agent_guardian-1.0.0rc3.tar.gz.sigstore
```

This proves:
- The artefact was built by `glacien-technologies/agent-guardian` on GitHub Actions
- It came from the `publish.yml` workflow (not a different workflow)
- It was signed in the Rekor transparency log (publicly auditable)

GitHub's attestation API gives the same provenance signal without requiring
the separate `.sigstore` bundle:

```bash
gh attestation verify /path/to/agent_guardian-1.0.0rc3-py3-none-any.whl \
  --repo glacien-technologies/agent-guardian
```

This is the cryptographic substitute for trusting a long-lived signing key.

---

## Troubleshooting

### "Trusted Publisher mismatch" at the publish step

The PyPI TP config has different values than the workflow run identity. Check at <https://pypi.org/manage/project/agent-guardian/settings/publishing/>:

| Field | Must match |
|---|---|
| Owner | `glacien-technologies` |
| Repository | `agent-guardian` |
| Workflow filename | `publish.yml` (just the filename) |
| Environment | `pypi` |

Fix the mismatch on PyPI's UI and re-trigger the workflow with `gh workflow run publish.yml --ref v1.0.0rc3` (or push a new tag).

### "File already exists" / `HTTPError 400`

You pushed a tag for a version that's already on PyPI. PyPI prohibits version re-upload by design. Options:

- If the artefact is correct: delete the local tag (`git tag -d vX.Y.Z`), accept the published version, move on.
- If it's wrong: yank the bad version (see "Yanking a release" below), bump to next version, re-release.

### Workflow doesn't trigger at all

- Tag name must match `v*.*.*` glob (e.g. `v1.0.0` works, `1.0.0` doesn't, `v1.0` doesn't).
- Tag must be pushed to `origin` — local tag isn't enough. `git ls-remote --tags origin | grep vX.Y.Z` confirms it landed.
- The workflow file must exist on the tagged commit. If you tag an old commit that predates `publish.yml`, the workflow doesn't exist there and won't run.

### Pre-commit hook fails the version-bump commit

Run the hook locally + fix:

```bash
uv run pre-commit run --all-files
git add -A
git commit -s -m "chore: bump version to X.Y.Z"
```

**Never use `--no-verify`** — pre-commit catches real issues (mypy, trailing whitespace, large files). If it's stuck, fix the underlying issue.

---

## Yanking a release

If a published version has a critical bug, **yank it** (don't delete — that breaks pinned-version installs). Yank marks the version as "do not install" for new installs but keeps it available for users who pinned it.

Option 1 — via PyPI UI:
<https://pypi.org/manage/project/agent-guardian/release/X.Y.Z/> → "Yank release" → enter reason

Option 2 — via gh CLI:
```bash
# pypi-yank is a community wrapper; or use the JSON API directly
curl -X POST -u __token__:$TOKEN https://pypi.org/legacy/?:action=yank \
    -F "name=agent-guardian" -F "version=X.Y.Z" \
    -F "reason=<short reason>"
```

After yanking, release a fix as `X.Y.Z+1` (or `X.Y.(Z+1)post1` if the bug is metadata-only). **Don't try to re-upload `X.Y.Z`** — PyPI rejects that on principle.

---

## Hotfix release

Sometimes you need to release a fix for an older version (e.g. `1.0.0` is in production, `1.1.0` is broken, ship `1.0.1` from a maintenance branch):

```bash
# 1. Branch from the old release tag
git checkout -b release/1.0.x v1.0.0

# 2. Cherry-pick the fix commit
git cherry-pick <fix-commit-sha>

# 3. Bump version
$EDITOR src/agent_guardian/_version.py    # 1.0.0 → 1.0.1

# 4. Commit + tag + push
git add src/agent_guardian/_version.py
git commit -s -m "chore: bump version to 1.0.1"
git tag -a v1.0.1 -m "Hotfix v1.0.1: <one-line fix description>"
git push origin release/1.0.x v1.0.1
```

The workflow runs as usual against `v1.0.1`. After release, decide whether to merge `release/1.0.x` back into main (usually yes, if the fix is still relevant).

---

## What if I have to release manually (emergency)

If GitHub Actions is down and you absolutely cannot wait:

1. **Don't.** Wait. Manual upload bypasses Trusted Publisher and PyPI will send a security advisory (as they did for `1.0.0rc2` before this doc existed).
2. If you really must:
   ```bash
   uv build
   uv tool run twine upload dist/*    # needs ~/.pypirc temporarily
   ```
3. **After the emergency**: revert to TP-only by deleting any `~/.pypirc` you created + revoking the temporary token at <https://pypi.org/manage/account/token/>.

---

## What changed when we migrated to Trusted Publisher (2026-06-01)

Before: maintainers had a long-lived PyPI API token in `~/.pypirc` and uploaded via `twine`. Token could leak via screenshots, backups, shell history, git history. Token deletion required PyPI admin action.

After: PyPI publishing only works from GitHub Actions, identity verified per-run via OIDC, no secrets to leak. Compromising the release flow now requires compromising GitHub Actions itself — significantly higher bar.

The migration was triggered by [PyPI's security advisory after the `1.0.0rc2` manual upload](https://pypi.org/help/#trusted-publishers). The old `agentguardian-oss-publish` API token was deleted as part of the migration.

---

## Quick reference card

```bash
# Standard release
$EDITOR src/agent_guardian/_version.py
git add src/agent_guardian/_version.py
git commit -s -m "chore: bump version to X.Y.Z"
git push origin main
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z

# Watch the workflow
gh run watch

# Verify it landed
gh release view vX.Y.Z
pip install agent-guardian==X.Y.Z    # in a fresh venv
```

That's it. Don't touch PyPI manually.
