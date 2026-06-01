#!/usr/bin/env bash
# capture-demo-assets.sh
#
# Operator-run script. Produces:
#   assets/terminal-demo.gif   — recorded with asciinema, rendered with agg
#   assets/dashboard.png       — Playwright headless screenshot of localhost:7474
#
# Usage:
#   ./scripts/capture-demo-assets.sh
#
# Prereqs (one-time):
#   pipx install asciinema
#   cargo install --git https://github.com/asciinema/agg
#   pip install playwright && playwright install chromium

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="${REPO_ROOT}/assets"
mkdir -p "${ASSETS_DIR}"

echo "==> 1/3  Recording terminal demo with asciinema"

DEMO_CAST="$(mktemp -t agentguardian-demo.XXXXXX.cast)"
cat > "${DEMO_CAST}.script" <<'EOF'
agent-guardian doctor
agent-guardian list-probes | head -20
agent-guardian scan --target stub --mode fast --llm stub
ls reports/latest/
EOF

asciinema rec \
  --overwrite \
  --idle-time-limit 1 \
  --title "AgentGuardian — 60 second demo" \
  --command "bash ${DEMO_CAST}.script" \
  "${DEMO_CAST}"

echo "==> 2/3  Rendering cast to GIF with agg"

agg \
  --theme monokai \
  --font-size 14 \
  --speed 1.5 \
  "${DEMO_CAST}" \
  "${ASSETS_DIR}/terminal-demo.gif"

echo "    wrote ${ASSETS_DIR}/terminal-demo.gif"

echo "==> 3/3  Capturing dashboard screenshot with Playwright"

# Start the dashboard in the background
agent-guardian serve --port 7474 >/tmp/agentguardian-serve.log 2>&1 &
SERVE_PID=$!
trap "kill ${SERVE_PID} 2>/dev/null || true" EXIT

# Wait for it to come up
for _ in $(seq 1 30); do
  if curl -sf http://localhost:7474/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done

python - <<'PY'
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

OUT = Path(__file__).resolve().parent.parent / "assets" / "dashboard.png"

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=2,
        )
        page = await context.new_page()
        await page.goto("http://localhost:7474", wait_until="networkidle")
        await page.screenshot(path=str(OUT), full_page=False)
        await browser.close()
        print(f"    wrote {OUT}")

asyncio.run(main())
PY

echo "==> done. Commit assets/terminal-demo.gif and assets/dashboard.png."
