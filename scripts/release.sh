#!/usr/bin/env bash
# scripts/release.sh — cut a new AgentGuardian release.
#
# What this does (and only this):
#   1. Validates the working tree is clean and on `main`.
#   2. Reads the next version from the first argument (e.g. ``1.1.0``).
#   3. Validates that ``CHANGELOG.md`` has an ``## [Unreleased]`` block
#      with at least one bullet, and that no ``## [<version>]`` heading
#      already exists for the target version.
#   4. Updates ``src/agent_guardian/_version.py`` (hatch reads this).
#   5. Renames the ``## [Unreleased]`` heading in CHANGELOG.md to
#      ``## [<version>] — <YYYY-MM-DD>`` and inserts a fresh empty
#      ``## [Unreleased]`` stub above it.
#   6. Stages the two files, prints a diff, and waits for the operator
#      to confirm.
#   7. On confirmation, commits with ``-s`` (DCO is mandatory — see
#      CONTRIBUTING.md), creates an annotated tag ``v<version>`` whose
#      body is the new release section, and prints the push commands.
#
# What this does NOT do:
#   * Push to the remote. The operator runs the printed commands.
#   * Create the GitHub Release page. That happens automatically when
#     ``.github/workflows/publish.yml`` fires on the ``v*.*.*`` tag.
#   * Publish to PyPI. Same workflow handles it via Trusted Publishing.
#
# Usage:
#   ./scripts/release.sh 1.1.0
#   ./scripts/release.sh 1.1.0 --dry-run

set -euo pipefail

VERSION="${1:-}"
DRY_RUN=0
if [[ "${2:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <version> [--dry-run]" >&2
  echo "example: $0 1.1.0" >&2
  exit 2
fi

if ! [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(rc[0-9]+|a[0-9]+|b[0-9]+)?$ ]]; then
  echo "error: '${VERSION}' is not a valid semver (X.Y.Z or X.Y.ZrcN)" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VERSION_FILE="src/agent_guardian/_version.py"
CHANGELOG="CHANGELOG.md"
TODAY="$(date -u +%Y-%m-%d)"
TAG="v${VERSION}"

# -- Preflight ----------------------------------------------------------------

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${CURRENT_BRANCH}" != "main" ]]; then
  echo "error: must release from 'main', currently on '${CURRENT_BRANCH}'" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree is dirty. Commit or stash first." >&2
  git status --short
  exit 1
fi

if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "error: ${VERSION_FILE} not found" >&2
  exit 1
fi

if [[ ! -f "${CHANGELOG}" ]]; then
  echo "error: ${CHANGELOG} not found" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "error: tag ${TAG} already exists" >&2
  exit 1
fi

if grep -qE "^## \[${VERSION}\]" "${CHANGELOG}"; then
  echo "error: CHANGELOG.md already has a [${VERSION}] section" >&2
  exit 1
fi

if ! grep -qE "^## \[Unreleased\]" "${CHANGELOG}"; then
  echo "error: CHANGELOG.md has no '## [Unreleased]' section to promote" >&2
  exit 1
fi

# Require at least one bullet under [Unreleased]. Extract the block
# between '## [Unreleased]' and the next '## [' heading and grep for a
# bullet line.
UNRELEASED_BODY="$(awk '/^## \[Unreleased\]/{flag=1; next} /^## \[/{flag=0} flag' "${CHANGELOG}")"
if ! echo "${UNRELEASED_BODY}" | grep -qE '^[-*] '; then
  echo "error: '## [Unreleased]' has no bullet entries — nothing to release." >&2
  echo "       Weekly-cadence rule (docs/community/release-cadence.mdx): add at" >&2
  echo "       least one bullet before cutting a release." >&2
  exit 1
fi

# -- Mutations ----------------------------------------------------------------

# 1. Bump the version file.
python3 - "${VERSION_FILE}" "${VERSION}" <<'PY'
import sys, pathlib, re
path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
text = path.read_text()
new = re.sub(r'__version__\s*=\s*"[^"]+"', f'__version__ = "{version}"', text)
if new == text:
    sys.stderr.write(f"error: could not find __version__ in {path}\n")
    sys.exit(1)
path.write_text(new)
PY

# 2. Promote [Unreleased] to [VERSION] — YYYY-MM-DD and insert a fresh stub.
python3 - "${CHANGELOG}" "${VERSION}" "${TODAY}" <<'PY'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
today = sys.argv[3]
text = path.read_text()
old_heading = "## [Unreleased]"
new_heading = f"## [{version}] — {today}"
stub = (
    "## [Unreleased]\n"
    "\n"
    "### Added\n"
    "\n"
    "### Changed\n"
    "\n"
    "### Fixed\n"
    "\n"
)
if text.count(old_heading) != 1:
    sys.stderr.write("error: expected exactly one '## [Unreleased]' heading\n")
    sys.exit(1)
text = text.replace(old_heading, stub + new_heading, 1)
path.write_text(text)
PY

# Extract the new release body (between the new version heading and the
# following ## heading) for the tag message.
RELEASE_BODY="$(awk -v v="${VERSION}" '
  $0 ~ "^## \\[" v "\\]" {flag=1; print; next}
  flag && /^## \[/ {flag=0}
  flag {print}
' "${CHANGELOG}")"

echo "------- diff -------"
git --no-pager diff -- "${VERSION_FILE}" "${CHANGELOG}"
echo "--------------------"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "[dry-run] reverting working-tree changes."
  git checkout -- "${VERSION_FILE}" "${CHANGELOG}"
  echo "[dry-run] would tag: ${TAG}"
  exit 0
fi

read -r -p "Commit and tag ${TAG}? [y/N] " ANSWER
if [[ "${ANSWER}" != "y" && "${ANSWER}" != "Y" ]]; then
  echo "aborting — reverting working-tree changes."
  git checkout -- "${VERSION_FILE}" "${CHANGELOG}"
  exit 1
fi

git add "${VERSION_FILE}" "${CHANGELOG}"
git commit -s -m "chore(release): ${TAG}"

# Annotated, signed tag whose body is the release section. The publish
# workflow keys off the ``v*.*.*`` pattern on push.
TAG_MSG_FILE="$(mktemp -t aggrelease.XXXXXX)"
trap 'rm -f "${TAG_MSG_FILE}"' EXIT
{
  echo "AgentGuardian ${TAG}"
  echo ""
  echo "${RELEASE_BODY}"
} > "${TAG_MSG_FILE}"

git tag -a "${TAG}" -F "${TAG_MSG_FILE}"

cat <<EOF

Created commit and tag ${TAG} locally.

Next steps (run manually):

  git push origin main
  git push origin ${TAG}

The tag push triggers .github/workflows/publish.yml — it builds the
wheel + sdist, signs them with Sigstore, and uploads to PyPI via
Trusted Publishing. The GitHub Release page is created automatically.

After the workflow goes green, paste the changelog section above into
the Release notes textarea on GitHub (the publish workflow attaches
artifacts; it does not author release prose).
EOF
