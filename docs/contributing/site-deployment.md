# Deploying the documentation site

> **TL;DR.** This MkDocs site is built here in `guardian-oss/`, rsynced into the local-only `agent_guardian_web/public/docs/`, and rolled out as a fresh Cloud Run revision of the Next.js marketing app. End URL: <https://agentguardian.io/docs/>. The whole loop is two scripts: `./scripts/build-docs.sh` then `./deploy-cloud-build.sh`.

## Layout

| Where                                                          | What                                                                |
|----------------------------------------------------------------|---------------------------------------------------------------------|
| `Glacien/guardian-oss/`                                         | Source of truth — Markdown under `docs/`, `mkdocs.yml`.             |
| `Glacien/guardian-oss/site/`                                    | Build output (gitignored). Produced by `mkdocs build`.              |
| `glacien/agent_guardian_web/public/docs/`                       | Where the built site is rsynced for the Next.js app to serve.       |
| `glacien/agent_guardian_web/next.config.mjs`                    | `/docs` and `/docs/` redirect to `/docs/index.html`.                |
| `glacien/agent_guardian_web/components/Header.tsx`              | Top-nav `Docs` link → `/docs`.                                      |
| GCP project `agent-butler-475300`, service `agent-guardian-web` | Cloud Run service (region `us-central1`).                           |

`agent_guardian_web/` is not a git repository — changes there ship
straight from disk via the Cloud Build script.

## Prerequisites

- `uv` (Python project manager) — `pip install uv` if missing.
- `gcloud` CLI authenticated against the `agent-butler-475300` project (`gcloud auth login`).
- One of:
    - **Docker** running locally (faster), or
    - Nothing — use the Cloud Build script (builds in GCP).

## One-shot doc-only update

```bash
cd Glacien/guardian-oss && ./scripts/build-docs.sh
cd ../../glacien/agent_guardian_web && ./deploy-cloud-build.sh
```

That's the whole loop. `build-docs.sh` runs `uv run mkdocs build
--strict`, then rsyncs `site/` into `agent_guardian_web/public/docs/`.
`deploy-cloud-build.sh` rebuilds the image in GCP Cloud Build and rolls
a new Cloud Run revision.

Use `./deploy.sh` (local Docker) instead of `./deploy-cloud-build.sh`
if Docker Desktop has enough disk space — it's faster but needs ~5 GB
free in Docker's VM.

## What the scripts do

### `Glacien/guardian-oss/scripts/build-docs.sh`

```text
1. cd to the guardian-oss repo root.
2. uv run mkdocs build --strict          # produces ./site/
3. rsync -a --delete site/ "$WEB_PUBLIC_DIR/"
   (default $WEB_PUBLIC_DIR = ../../glacien/agent_guardian_web/public/docs)
4. Print file count + size + next-step hint.
```

Override the destination with `WEB_PUBLIC_DIR=/some/other/path ./scripts/build-docs.sh`.

### `glacien/agent_guardian_web/deploy-cloud-build.sh`

```text
1. gcloud config set project agent-butler-475300
2. gcloud services enable cloudbuild.googleapis.com
3. gcloud builds submit --tag gcr.io/.../agent-guardian-web:latest .
4. gcloud run deploy agent-guardian-web ...
5. Print the live Service URL.
```

Roughly 3 minutes end-to-end after cache warms up. Doc-only changes
only invalidate the final `COPY /app/public` layer, so subsequent
builds are much faster than the first.

## Why these choices

- **`use_directory_urls: false`** in `mkdocs.yml` — Next.js's `public/`
  static serving has no directory-index resolution. With this flag,
  mkdocs emits `cli.html` instead of `cli/index.html`, and Next serves
  it cleanly without any rewrite rules. **Do not flip this back** — it
  will break every doc URL.
- **Single Cloud Run service, not two** — the docs are static files
  served by the existing Next.js standalone server. No separate nginx
  container, no separate Cloud Run service, no extra DNS to manage.
  Doc updates ship via the same deploy command as marketing-site
  updates.
- **Cloud Build is the default deploy path** — local Docker on Macs
  requires `--platform linux/amd64` and frequently runs out of Docker
  Desktop VM disk. Cloud Build sidesteps both, and the cache layers
  under `gcr.io/agent-butler-475300/agent-guardian-web/cache:*` make
  subsequent builds fast.

## Live URLs

| URL                                                                 | Where it goes                                 |
|---------------------------------------------------------------------|-----------------------------------------------|
| `https://agentguardian.io/`                                         | Marketing site (Next.js app).                 |
| `https://agentguardian.io/docs/`                                    | This docs site.                               |
| `https://agentguardian.io/docs/reference/cli.html`                  | Any docs page is `/docs/<path>.html`.         |
| `https://agent-guardian-web-u6tm6gzysq-uc.a.run.app/`               | Cloud Run direct URL (same revision).         |

The Cloud Run service also accepts the legacy project-number URL
`agent-guardian-web-684102165551.us-central1.run.app` — both route to
the same revision.

## When `mkdocs build --strict` fails

Most likely cause: a new `.md` file was added under `docs/` that
contains broken internal links or isn't in the nav. Two ways to fix:

1. Wire the page into `nav:` in `mkdocs.yml` and resolve the broken
   links.
2. Add the page (or its directory) to `exclude_docs:` in `mkdocs.yml`.

## Rolling back a bad deploy

Cloud Run keeps every revision:

```bash
gcloud run revisions list --service agent-guardian-web --region us-central1
gcloud run services update-traffic agent-guardian-web \
  --to-revisions=<previous-revision-name>=100 --region us-central1
```

A rollback is a metadata change — takes seconds, no rebuild required.
