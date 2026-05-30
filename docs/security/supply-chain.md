# Supply chain

**TL;DR** — Every release wheel ships with a Sigstore signature (keyless OIDC via GitHub Actions), a CycloneDX SBOM, and PEP-740 attestations on PyPI. Pure-Python builds are reproducible byte-for-byte from the tagged commit — anyone can rebuild and confirm.

## 1. Dependency pin policy

AgentGuardian declares its **top-level** dependencies in [`pyproject.toml`](https://github.com/glacien-technologies/agent-guardian/blob/main/pyproject.toml). The split:

- **Runtime deps** (lower-bounded only). Pinning `fastapi==0.115.0` would prevent users from picking up upstream security fixes; we lower-bound (`fastapi>=0.115`) and let pip resolve.
- **Build deps** (exact upper bound where determinism matters). The build-system declares `hatchling>=1.27`; we test against `hatchling 1.27.x` and document the supported range under [reproducible builds](#5-reproducible-builds).
- **Transitive resolution** is locked for the *CI build* via a lockfile (`uv.lock`) so the artifact published from `main` is built against a known dependency graph. Consumers running `pip install agent-guardian` still resolve transitives at install time — the lock is for build determinism, not runtime pin freezing.

What gets explicitly declared (visible in `pyproject.toml`):

- Direct callers of every runtime dep are documented in inline comments where they are non-obvious (`structlog`, `jsonschema`, `cryptography`).
- A regression test (`tests/test_packaging.py::test_structlog_is_not_a_ghost_runtime_dep`) asserts that a runtime-imported dep is also declared, so a quiet `pyproject.toml` edit can't silently turn a runtime dep into an "extras-only" one.

## 2. Sigstore keyless signing

Every release wheel and sdist is signed via Sigstore using the keyless OIDC flow through GitHub Actions. The publish workflow:

1. Builds the wheel + sdist on a tag.
2. Hands the artifacts to a `sign` job that exchanges the workflow's OIDC token for a Sigstore Fulcio certificate, signs the artifacts, and attaches the signatures + transparency-log entries to the GitHub Release.
3. The `publish` job pushes the signed artifacts to PyPI with PEP-740 attestations.

Verifying a signature does not require trusting Glacien's long-term keys — it requires trusting the Sigstore public-good infrastructure (Fulcio, Rekor) and the GitHub OIDC issuer.

```sh
# Install the Sigstore CLI.
pip install sigstore

# Verify a release wheel.
sigstore verify github \
  --cert-identity-regex 'https://github.com/glacien-technologies/agent-guardian/.github/workflows/publish.yml@.*' \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  agent_guardian-1.0.0-py3-none-any.whl
```

A successful verification proves the artifact was produced by the named GitHub Actions workflow on the named repository — not by an attacker who compromised PyPI account credentials.

This is **the** trust anchor for the binary you `pip install`. Read [signing.md](signing.md) for the trust anchor on the *reports* the binary produces.

## 3. CycloneDX SBOM

Every release attaches a [CycloneDX](https://cyclonedx.org/) SBOM to the corresponding GitHub Release. The SBOM enumerates the transitive dependency graph used to *build* the wheel — useful for vulnerability-scanning the supply chain (Grype, Trivy, Dependency-Track).

To consume an SBOM:

```sh
# Download from the GitHub Release page.
gh release download v1.0.0 \
  --repo glacien-technologies/agent-guardian \
  --pattern 'agent-guardian-1.0.0.cdx.json'

# Scan with Grype.
grype sbom:agent-guardian-1.0.0.cdx.json
```

The SBOM format is CycloneDX 1.5 JSON. If you need SPDX, run an SBOM converter (`cyclonedx-cli convert`) — we do not ship a second format because the conversion is lossless.

## 4. PEP-740 attestations

PyPI accepts [PEP-740 attestations](https://peps.python.org/pep-0740/) — provenance documents that bind a release to the GitHub Actions workflow that produced it. AgentGuardian's publish workflow attaches a PEP-740 attestation on every release, so a consumer can check provenance directly from PyPI without leaving the package index.

```sh
# pip's --require-hashes is the conservative path; the PEP-740 attestation
# adds workflow-level provenance on top of artifact-level hashing.
pip install agent-guardian==1.0.0 --require-hashes -r hashes.txt

# Verifying the attestation will be `pip install --attestations` once that
# flag stabilises; check the PEP-740 ecosystem doc for the latest UX.
```

The attestation is the same data Sigstore signs — it just lives alongside the wheel on PyPI rather than on the GitHub Release.

## 5. Reproducible builds

AgentGuardian ships with reproducible builds. Any third party can rebuild a release wheel from source and confirm it matches the artifact published on PyPI byte-for-byte. This defeats an entire class of supply-chain attacks where the source code on GitHub differs from the binary that consumers `pip install`.

### How releases are built

The `.github/workflows/publish.yml` workflow is the canonical build path. On every tag matching `v*.*.*`:

1. The job checks out the tagged commit with full git history (`fetch-depth: 0`).
2. It sets `SOURCE_DATE_EPOCH` to the commit timestamp:
   ```sh
   echo "SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)" >> $GITHUB_ENV
   ```
   This timestamp propagates into wheel file metadata, eliminating the only source of non-determinism that affects pure-Python wheels in practice.
3. It runs `uv build`, which invokes `hatchling` per `pyproject.toml`'s build-backend configuration.
4. The resulting wheel and sdist are uploaded as artifacts, then signed by the `sign` job (Sigstore keyless OIDC, see [§2](#2-sigstore-keyless-signing)) before reaching the `publish` job.

The wheel that lands on PyPI is the same bytes that were built in step 3.

### How to verify a release yourself

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

If they differ, **stop and report the deviation** to `security@glacien.ai` per [responsible-disclosure.md](responsible-disclosure.md). Either the wheel on PyPI was built from different source (a serious supply-chain incident), or our build process has accidentally introduced non-determinism (a serious build-system bug we want to fix).

### Annual independent verification

Per the [contributing engineering standards](../contributing/engineering-standards.md), an independent contributor (not a Glacien employee) re-verifies the most recent stable release once a year. The verification artifacts are committed under `docs/security/reproducibility-verifications/YYYY.md`. This is one of the standing `good-first-issue` invitations.

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

### Sources of non-determinism we control for

- **File timestamps in the zip archive** — controlled by `SOURCE_DATE_EPOCH`.
- **`__pycache__` content** — not included in the wheel.
- **Dependency tree at build time** — `pyproject.toml` only declares build-system requirements (hatchling); no runtime install happens during `uv build`.
- **Compiler invocation** — AgentGuardian is pure Python; no C extensions; no compiler in the build path.

### Sources of non-determinism we do **not** control for

Pure-Python wheels are highly reproducible, but a small number of edge cases can still produce byte-level diffs:

- **`uv` version drift between rebuild and original build.** Pin the same `uv` version (currently `0.4.x`) for byte-identical results.
- **Platform timezone at build time.** If you build with a non-UTC system clock, the wheel timestamp metadata may differ. Set `TZ=UTC` for guaranteed reproducibility.
- **`hatchling` minor version updates** can theoretically change metadata ordering. We pin `hatchling >= 1.27` in `pyproject.toml`; consumers building with significantly newer versions may see diffs.

If your reproducibility verification fails on one of the listed edge cases, document it in your verification report as an "expected difference" rather than a security incident.

## 6. What this protects against, what it doesn't

| Attack | Defended? | By |
|---|---|---|
| PyPI account takeover → malicious wheel uploaded | Yes | Sigstore signature won't match a non-workflow signer; PEP-740 attestation has no provenance from the legitimate workflow. |
| GitHub Actions workflow file tampered with via PR merge | Partial | Branch protection on `main` + required review; not a property of the supply-chain layer itself. |
| Compromised dev machine pushes a tag | Yes | Releases are built **in CI**, not on a developer's laptop. The Sigstore identity bound to the signature is the CI workflow, not a human. |
| Source on GitHub differs from binary on PyPI | Yes | Reproducible build protocol (§5) lets any user rebuild and compare. |
| Vulnerable transitive dependency | Out of scope | The SBOM lets you scan; the upstream dependency must fix the CVE. AgentGuardian bumps lower bounds where a CVE affects us. |
| Local `pip install agent-guardian` over an unencrypted network | No | This is pip's job; use `--require-hashes` if you don't trust your transport. |
| Operator-side wheel cache poisoning | No | If an attacker can write to your `~/.cache/pip`, you have bigger problems than AgentGuardian. |

## 7. Reporting a supply-chain anomaly

If your reproducibility verification fails — i.e., a wheel on PyPI does not match what you can rebuild from the tagged source — treat it as a supply-chain incident and report via [responsible-disclosure.md](responsible-disclosure.md).

Include:

- The version and SHA-256 of the wheel on PyPI.
- The SHA-256 of your locally-rebuilt wheel.
- Your build environment (OS, `uv --version`, `python --version`, `TZ`, `SOURCE_DATE_EPOCH`).
- A `diffoscope` or `unzip -l` diff of the two wheels, if you can produce one.

## See also

- [Signing & verification](signing.md) — the trust layer on the reports the binary produces.
- [Engineering standards (Contributing)](../contributing/engineering-standards.md) — the policy this implements.
- [Responsible disclosure](responsible-disclosure.md) — how to report a supply-chain anomaly.
- [Disclosure history](disclosure-history.md) — public log of handled reports.
