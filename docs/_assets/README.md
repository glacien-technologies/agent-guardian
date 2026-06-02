# README assets

This directory holds binary / large assets referenced from the repo root
`README.md`. Two files are expected here; both are produced by a human
operator out-of-band.

| File                      | Purpose                                          | Source                                              | Size cap |
|---------------------------|--------------------------------------------------|-----------------------------------------------------|----------|
| `demo-scan.gif`           | 30–45s loop shown at the top of README.md        | Screen capture of a live `agent-guardian scan` run  | 5 MB     |
| `sample-scan-report.html` | One representative HTML report linked from README | `agent-guardian report SCAN_ID --output html`       | 2 MB     |

## How to produce `demo-scan.gif`

1. In one terminal, start the live dashboard:

   ```bash
   agent-guardian serve --host 127.0.0.1 --port 7474
   ```

2. In a second terminal (or split pane), run a stub-mode scan so no API
   key is required and the wall time stays under 45 seconds:

   ```bash
   echo "You are a helpful customer-support bot." > /tmp/prompt.txt
   agent-guardian scan \
     --system-prompt /tmp/prompt.txt \
     --model stub \
     --mode fast
   ```

3. Record both panes with a screen recorder (macOS: `Cmd+Shift+5`,
   record selected portion). Keep the recording tight — terminal on the
   left, browser at `http://localhost:7474` on the right.
4. Convert the MP4 to a GIF with [`gifski`](https://gif.ski/):

   ```bash
   gifski --fps 12 --width 1280 --quality 70 \
     -o docs/_assets/demo-scan.gif recording.mp4
   ```

5. Confirm the result is under 5 MB before committing. If it isn't,
   drop FPS to 10 or width to 1024 and re-encode.

## How to produce `sample-scan-report.html`

1. Run a real scan against any local target (the stub model is fine):

   ```bash
   agent-guardian scan \
     --system-prompt /tmp/prompt.txt \
     --model stub \
     --mode fast
   ```

2. Note the scan ID printed at the end (e.g. `scan_2026...`). Export
   the HTML report:

   ```bash
   agent-guardian report scan_2026... \
     --output html \
     --output-path docs/_assets/sample-scan-report.html
   ```

3. Open the file locally in a browser to sanity-check it renders, then
   commit. If the file exceeds 2 MB, gzip it (`gzip -k` keeps the
   original) and link the `.html.gz` from the README instead.

## Why these paths

The repo root `README.md` links these files via relative paths
(`docs/_assets/demo-scan.gif`, `docs/_assets/sample-scan-report.html`).
GitHub renders the GIF inline and serves the HTML as a raw download.
The Mintlify docs site (`docs/docs.json`) does not nav-include
`_assets/` (see `.mintignore`), so these never leak into the public
docs site.
