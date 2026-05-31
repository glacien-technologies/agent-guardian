# Path A — manual launch blockers

The engineering side of [Path A](launch-paths.md) is now landed in code. The list below covers the **manual** steps that only a human with admin access to PyPI, GitHub, the Discord console, and the Glacien GPG key can do. Each item is one click-path or one short command.

Walk this list top-to-bottom. The first three are hard blockers — nothing else ships if they're not done.

## Hard blockers

### 1. Flip the repository to public

- **Where:** `https://github.com/glacien-technologies/agent-guardian/settings`
- **Click path:** Settings → scroll to **Danger Zone** → **Change repository visibility** → **Make public** → type the repo name → confirm.
- **Why:** OSS release literally requires this. Also unblocks branch protection (Pro-tier rule), GitHub Discussions enablement, and native secret scanning.

### 2. Create the `pypi` GitHub environment

- **Where:** `https://github.com/glacien-technologies/agent-guardian/settings/environments`
- **Click path:** **New environment** → name `pypi` → **Configure environment** → add **Deployment branches and tags rule** restricted to tags matching `v*.*.*` → save.
- **Why:** `.github/workflows/publish.yml` references `environment: name: pypi`; without this the publish job will fail at startup.

### 3. Configure PyPI Trusted Publisher

- **Where:** `https://pypi.org/manage/account/publishing/`
- **Click path (project not yet published):** **Add a new pending publisher**:
  - PyPI Project Name: `agent-guardian`
  - Owner: `glacien-technologies`
  - Repository name: `agent-guardian`
  - Workflow name: `publish.yml`
  - Environment name: `pypi`
- **Why:** Standard §4.4. Without it the OIDC handshake from GitHub Actions has nothing to authenticate against, and the upload silently fails.

## Soft blockers — do before tagging v1.0.0

### 4. Enable branch protection on `main`

- **Where (after #1):** `https://github.com/glacien-technologies/agent-guardian/settings/branches`
- **Click path:** **Add branch ruleset** → target `main` → require:
  - Pull request before merging (1 approving review, dismiss stale approvals on new commits)
  - Status checks to pass (`CI / lint`, `CI / type`, `CI / test (3.10..3.13)`, `CI / sast`, `CI / secret-scan`, `CI / licenses`, `dco`, `brand-integrity`)
  - Signed commits required
  - Linear history (squash or rebase only)
  - Block force-pushes
- **Why:** Standard §4.10 / §4.11. Required for OpenSSF Scorecard `Branch-Protection` and `Code-Review` checks.

### 5. Enable GitHub Discussions

- **Where (after #1):** `https://github.com/glacien-technologies/agent-guardian/settings`
- **Click path:** scroll to **Features** → tick **Discussions** → save.
- Then visit Discussions and create categories: `Q&A`, `Show and tell`, `Ideas`, `Announcements`.
- Pin a welcome discussion that explains the convention (general usage → Discussions; actionable bugs → Issues).
- **Why:** Standard §6.7. Indexed by Google; absorbs the support load that would otherwise drown the issue tracker.

### 6. Generate + publish the Security Lead GPG key

- **Local commands** (run as the security-lead person, NOT on a shared machine):
  ```sh
  # 1. Generate the key (Ed25519 because it's smaller and faster).
  gpg --quick-gen-key 'AgentGuardian Security <security@glacien.ai>' \
      ed25519 sign 5y

  # 2. Print the fingerprint and the ASCII-armored public key.
  gpg --fingerprint security@glacien.ai
  gpg --armor --export security@glacien.ai > security.asc
  ```
- **Publish:** upload `security.asc` to `https://glacien.ai/.well-known/security.asc` (the path SECURITY.md already references).
- **Update repo:** replace the `_pending public-beta key ceremony_` line in `SECURITY.md` and the corresponding row in `MAINTAINERS.md` with the actual fingerprint.
- **Why:** Standard §4.9. Encrypted vulnerability reports need a real key.

### 7. Provision the Discord server

- **Where:** create a new Discord server at `https://discord.com/channels/@me` → **+** → **Create my own** → community type.
- **Set up:**
  - Channels: `#welcome`, `#announcements`, `#general`, `#help`, `#contribute`, `#security` (private), `#showcase`.
  - Create a vanity invite at `discord.gg/agentguardian` (requires server boost or community-server status).
  - Add the server-ID and rotate the invite into the README badge (currently shows all-zero placeholder).
- **Why:** Standard §6.7 + §13.3. Live community channel for launch day.

### 8. Register OpenSSF Best Practices

- **Where:** `https://www.bestpractices.dev/en/projects/new`
- **Form:** answer the ~50 passing-tier criteria (takes ~2 hours; most are "yes, here's the URL" pointing at files this repo already has).
- After submission, replace the `/projects/0000` placeholder in the README badge URL with the assigned project ID.
- **Why:** Standard §4.2. Widely-checked credibility signal.

### 9. Reserve PyPI name variants

- **Where:** PyPI org dashboard
- After the first 1.0.0 upload succeeds, ALSO upload an empty placeholder package for `agent_guardian` (underscore form) so squatters can't grab it.
- **Why:** Standard §14.1 item 5.

### 10. Cut a GitHub Release for `v1.0.0rc1` (optional, low-effort)

- **Where:** `https://github.com/glacien-technologies/agent-guardian/releases/new`
- **Click path:** Choose tag `v1.0.0rc1` → "Generate release notes" → publish as pre-release.
- **Why:** Standard §9.2. Currently `gh release list` returns empty even though `v1.0.0rc1` was tagged; the empty state makes the project look unreleased.

## Tag the v1.0.0 release (after the above)

When items #1–9 are done:

```sh
# Confirm engineering changes are committed and pushed.
git log --oneline -3

# Tag and push.
git tag -s -a v1.0.0 -m "AgentGuardian v1.0.0"
git push origin v1.0.0

# Watch the publish workflow run.
gh run watch --repo glacien-technologies/agent-guardian
```

The workflow will:
1. Build sdist + wheel reproducibly.
2. Generate the CycloneDX SBOM.
3. Sign everything via Sigstore.
4. Attach signed artifacts to the GitHub Release for the tag.
5. Publish to PyPI via Trusted Publishing.

If any step fails, the release halts before PyPI sees a partial upload. Fix and re-tag with `v1.0.1`.

## After the tag lands

- [ ] Confirm `pip install agent-guardian==1.0.0` works from a clean venv on macOS/Linux/Windows.
- [ ] Confirm the PyPI page shows the Trusted Publisher indicator + PEP-740 attestations.
- [ ] Confirm the GitHub Release page has the wheel, sdist, SBOM, and `.sigstore` signatures attached.
- [ ] Sign the first entry in `MAINTAINERS.md` historical-maintainers table (the launch).
- [ ] Update the badge IDs (Discord server, OpenSSF BP project) once the registration responses come back.
- [ ] Open the first 15 `good-first-issue` tickets per Standard §6.3.

## Items intentionally deferred to v1.1+

Per the audit, these are explicitly **not** Path A blockers — they're scheduled for the first 90 days post-launch:

- Per-framework adapter tutorials (ADK / LangGraph / Strands / OpenAI Agents / AutoGen / CrewAI) — Standard §7.5
- `mike`-versioned docs — Standard §7.2
- Multi-arch Docker images on GHCR — Standard §8.3
- OS matrix in CI (macOS + Windows runners) — Standard §5.5
- `cibuildwheel` — N/A while package stays pure-Python
- Homebrew tap — Standard §8.4 (post-500-stars)
- `status.agentguardian.ai` uptime page — Standard §9.1
- arXiv preprint + DOI — Standard §10.1
- Singapore trademark filing (already in motion; takes weeks regardless) — Standard §14.1 item 20
- Beta-user recruiting drive (target 25+ scans completed) — Standard §14.1 item 25
- Press embargoes (Help Net, HN, AlphaSignal, TLDR InfoSec) — Standard §14.1 item 24

---

*This file is the manual companion to Path A engineering work. Reviewed each time we cut a major release.*
