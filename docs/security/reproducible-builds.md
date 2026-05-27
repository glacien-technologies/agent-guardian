# Reproducible builds

AgentGuardian Open ships with reproducible builds. Any third party can rebuild a release wheel from source and confirm it matches the artifact published on PyPI byte-for-byte. This defeats an entire class of supply-chain attacks in which the source code on GitHub differs from the binary that consumers `pip install`.

This page documents (a) how releases are built reproducibly, (b) how to verify a release matches its source, and (c) the annual independent-verification protocol.

## How releases are built

The `.github/workflows/publish.yml` workflow is the canonical build path. On every tag matching `v*.*.*`:

1. The job checks out the tagged commit with full git history (`fetch-depth: 0`).
2. It sets `SOURCE_DATE_EPOCH` to the commit timestamp:
   ```sh
   echo "SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)" >> $GITHUB_ENV
   ```
   This timestamp propagates into wheel file metadata, eliminating the only source of non-determinism that affects pure-Python wheels in practice.
3. It runs `uv build`, which invokes `hatchling` per `pyproject.toml`'s build-backend configuration.
4. The resulting wheel and sdist are uploaded as artifacts, then signed by the `sign` job using Sigstore (keyless OIDC) before reaching the `publish` job.

The wheel that lands on PyPI is the same bytes that were built in step 3.

## How to verify a release yourself

You can reproduce any release locally with the following procedure. The expected output is byte-identical to what's published.

```sh
# 1. Pick a published version.
export VERSION=1.0.0
export TAG=v${VERSION}

# 2. Clone at the tag.
git clone --depth 1 --branch ${TAG} https://github.com/glacien-technologies/agent-guardian.git
cd agent-guardian

# 3. Derive SOURCE_DATE_EPOCH from the tagged commit.
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)

# 4. Install uv (the build driver our publish workflow uses).
curl -LsSf https://astral.sh/uv/install.sh | sh

# 5. Build.
uv build

# 6. Compute the hash of your locally-built wheel.
sha256sum dist/agent_guardian-${VERSION}-py3-none-any.whl

# 7. Compare against the hash on PyPI.
curl -s "https://pypi.org/pypi/agent-guardian/${VERSION}/json" \
  | python -c "import json, sys; d=json.load(sys.stdin); \
    print([f['digests']['sha256'] for f in d['urls'] if f['filename'].endswith('.whl')][0])"
```

If both `sha256sum` values match, you have cryptographic confirmation that the wheel on PyPI was built from exactly the source you just cloned.

If they differ, **stop and report the deviation** to `security@glacien.ai`. Either the wheel on PyPI was built from different source (a serious supply-chain incident), or our build process has accidentally introduced non-determinism (a serious build-system bug we want to fix).

## Annual independent verification

Per [Engineering Standards §4.12](../engineering-standards.md), an independent contributor (not a Glacien employee) re-verifies the most recent stable release once a year. The verification artifacts are committed under `docs/security/reproducibility-verifications/YYYY.md`. This is one of the standing `good-first-issue` invitations.

The verification report records:

- Date of verification.
- The contributor's environment (OS, Python version, uv version, machine arch).
- The release version verified.
- The SHA-256 of the rebuilt wheel.
- The SHA-256 of the wheel on PyPI.
- Whether they match.
- If they differ: the byte-level diff (which file changed, what the change looks like).

| Year | Version | Verified by | Local SHA-256 | PyPI SHA-256 | Match? |
|---|---|---|---|---|---|
| _no verification yet — first verification due 12 months after the first stable release_ | | | | | |

## Known sources of non-determinism we control for

- **File timestamps in the zip archive** — controlled by `SOURCE_DATE_EPOCH`.
- **`__pycache__` content** — not included in the wheel.
- **Dependency tree at build time** — `pyproject.toml` only declares build-system requirements (hatchling); no runtime install happens during `uv build`.
- **Compiler invocation** — AgentGuardian Open is pure Python; no C extensions; no compiler in the build path.

## Known sources of non-determinism we do NOT control for

Pure-Python wheels are highly reproducible, but a small number of edge cases can still produce byte-level diffs:

- **`uv` version drift between rebuild and original build.** Pin the same `uv` version (currently `0.4.x`) for byte-identical results.
- **Platform timezone at build time.** If you build with a non-UTC system clock, the wheel timestamp metadata may differ. Set `TZ=UTC` for guaranteed reproducibility.
- **`hatchling` minor version updates** can theoretically change metadata ordering. We pin `hatchling >= 1.21` in `pyproject.toml`; consumers building with significantly newer versions may see diffs.

If your reproducibility verification fails on one of the listed edge cases, document it in your verification report as an "expected difference" rather than a security incident.

## Related documents

- [Engineering Standards §4.12 — Reproducible builds](../engineering-standards.md)
- [SECURITY.md](../../SECURITY.md) — how to report supply-chain anomalies
- [`docs/security/disclosure-history.md`](disclosure-history.md) — public log of handled disclosures
