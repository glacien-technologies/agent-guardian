# Releasing to PyPI

> **TL;DR.** Releases ship via PyPI Trusted Publishing (OIDC) from a tagged GitHub Actions workflow — no long-lived API tokens. Bump `_version.py`, push a `v*` tag, the publish workflow uploads to PyPI, attaches Sigstore transparency-log entries to the wheel + sdist, and pushes the container to `ghcr.io/glacien-technologies/agent-guardian`. Maintainers only.

This page is the runbook for cutting a release. For the *checklist* of
manual launch actions around v1.0, see the
[v1.0 Launch Checklist](operator-checklist.md). The corresponding workflow file
is [`.github/workflows/publish.yml`](https://github.com/glacien-technologies/agent-guardian/blob/main/.github/workflows/publish.yml).

## 1. One-time setup on PyPI

We use PyPI's [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC), which lets GitHub Actions upload to PyPI without managing
passwords or API tokens.

To configure OIDC for `agent-guardian`:

1. Log into <https://pypi.org/>.
2. **Account Settings → Publishing**.
3. **Add a publisher → GitHub**.
4. Fill in:
   - **PyPI Project Name**: `agent-guardian`
   - **Owner**: `glacien-technologies`
   - **Repository name**: `agent-guardian`
   - **Workflow name**: `publish.yml`
   - **Environment name**: `pypi`
5. **Add** to register the pending publisher.

Sigstore signing is set up the same way — the publish workflow
exchanges the GitHub-issued OIDC token for a Sigstore certificate and
the per-artefact transparency-log entries are attached as
`.sigstore` files on the GitHub Release.

## 2. Container registry setup (one-time)

The Docker image ships to `ghcr.io/glacien-technologies/agent-guardian`.
Confirm:

- The `publish.yml` workflow has `packages: write` permission.
- The GHCR package visibility is set to public so end users can
  `docker pull` without authenticating.
- The `glacien-technologies` GitHub organisation has GHCR enabled.

## 3. Cutting a release

### Step 1 — bump the version

`src/agent_guardian/_version.py` is the single source of truth:

```python
__version__ = "1.0.0rc1"
```

Bump it on a `chore/release-vX.Y.Z` branch, update `CHANGELOG.md`
under a new top section, and open a PR.

### Step 2 — get the bump merged

The PR runs the same CI as every other PR — `ruff`, `mypy`, `pytest`,
`pre-commit`. CI also rebuilds the wheel and sdist to catch packaging
breakage early. Reviewer signs off; you merge.

### Step 3 — tag from `main`

The tag must match `_version.py` exactly:

```bash
git checkout main && git pull
git tag v1.0.0rc1
git push origin v1.0.0rc1
```

The push of `v*` triggers `publish.yml`.

### Step 4 — watch the publish workflow

In the **Actions** tab pick the latest **Publish to PyPI** run and
verify each step:

1. `build wheel + sdist` — produces `dist/*` in the workflow runner.
2. `pypi-publish` — uploads to PyPI via Trusted Publishing.
3. `sigstore-sign` — attaches the per-artefact `.sigstore` files.
4. `docker buildx + push` — builds the image and pushes to GHCR.
5. `gh release` — creates the GitHub Release with the changelog excerpt
   and the signed artefacts attached.

### Step 5 — verify the install

```bash
python -m venv /tmp/ag-rc && source /tmp/ag-rc/bin/activate
pip install agent-guardian==1.0.0rc1
agent-guardian version          # prints 1.0.0rc1
agent-guardian doctor           # all checks green for a base install
```

And the image:

```bash
docker pull ghcr.io/glacien-technologies/agent-guardian:1.0.0rc1
docker run --rm ghcr.io/glacien-technologies/agent-guardian:1.0.0rc1 version
```

## 4. Promoting `rc` → final

For the v1.0 launch specifically, see the
[v1.0 Launch Checklist](operator-checklist.md). The mechanical version
bump is:

1. Bump `_version.py` from `1.0.0rcN` to `1.0.0`.
2. Bump `CITATION.cff`'s `version` and `date-released`.
3. Add a `[1.0.0]` heading to `CHANGELOG.md` summarising rc → final
   deltas.
4. Tag `v1.0.0` and push.

The site URL for the published docs is <https://agentguardian.io/docs/>
(per `mkdocs.yml`'s `site_url`); the docs build is decoupled from this
workflow and ships via [Deploying the docs site](site-deployment.md).
