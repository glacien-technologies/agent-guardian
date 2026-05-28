#!/usr/bin/env bash
# Build the mkdocs site and sync it into the agent-guardian-web Next.js app
# so the next `./deploy.sh` of agent_guardian_web ships the latest docs.
#
# Usage:  ./scripts/build-docs.sh
# Env:    WEB_PUBLIC_DIR  override the destination (default: ../agent_guardian_web/public/docs)

set -euo pipefail

cd "$(dirname "$0")/.."

WEB_PUBLIC_DIR="${WEB_PUBLIC_DIR:-/Users/mobionix/workspace/glacien/agent_guardian_web/public/docs}"

echo "▶ Building mkdocs site (strict mode)…"
uv run mkdocs build --strict

if [[ ! -d "$WEB_PUBLIC_DIR" ]]; then
  echo "Creating $WEB_PUBLIC_DIR"
  mkdir -p "$WEB_PUBLIC_DIR"
fi

echo "▶ Syncing site/ → $WEB_PUBLIC_DIR"
rsync -a --delete site/ "$WEB_PUBLIC_DIR/"

count=$(find "$WEB_PUBLIC_DIR" -type f | wc -l | tr -d ' ')
size=$(du -sh "$WEB_PUBLIC_DIR" | cut -f1)
echo "✓ $count files, $size copied."
echo
echo "Next steps:"
echo "  cd $(dirname "$WEB_PUBLIC_DIR")/.. && ./deploy.sh"
echo "  (or ./deploy-cloud-build.sh for build-in-cloud)"
