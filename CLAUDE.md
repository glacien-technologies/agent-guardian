# Repository notes for Claude

`agent-guardian` is the OSS adversarial-swarm framework. The Python package + CLI live here. The user-facing docs (built with MkDocs) ship as part of a separate Next.js marketing site deployed to Google Cloud Run.

## Companion repositories

| Path                                                         | What it is                                       | Tracked in git?   |
|--------------------------------------------------------------|--------------------------------------------------|-------------------|
| `/Users/mobionix/workspace/Glacien/guardian-oss/` (this)     | Python package + mkdocs source                   | Yes (`main` → `glacien-technologies/agent-guardian`) |
| `/Users/mobionix/workspace/glacien/agent_guardian_web/`      | Next.js marketing site + docs host               | **No** — local-only directory |
| `/Users/mobionix/workspace/prototype/glacien_website/`       | Glacien parent-brand Next.js site                | Separate concern  |

`agent_guardian_web` is **not** a git repository. Changes there live only on disk and ship via `./deploy.sh` to Cloud Run. There is no PR flow for that project today.

## Docs deployment in one paragraph

The mkdocs site is built here (`./scripts/build-docs.sh`), rsynced into `agent_guardian_web/public/docs/`, and ridden along on the next `./deploy-cloud-build.sh` of the Next.js app. End URL: `https://agent-guardian-web-u6tm6gzysq-uc.a.run.app/docs`. Full walk-through and rollback steps are in `docs/site-deployment.md`.

## Things that have tripped past sessions

- The Material theme palette uses `deep purple` + `purple` (set in `mkdocs.yml`). Don't revert to cyan.
- `mkdocs.yml` has `use_directory_urls: false`. This is required for the `public/docs/` static-serving path through Next.js — flipping it back will break every doc URL.
- `mkdocs.yml` has `exclude_docs:` covering `contributing/`, `security/`, `telemetry/`, `launch-manual-blockers.md` — pre-existing orphan docs with broken cross-doc links. Don't try to wire them into nav without first fixing their internal references.
- The old `docs/api-reference.md` (deleted) was aspirational — it documented `scan_system_prompt` / `scan_code` / `scan_http` / `scan_framework` functions that don't exist. The current API reference is mkdocstrings-generated from `__all__` in `src/agent_guardian/__init__.py` and is the canonical surface.
- `docs/quickstart.md` previously contained `agent-guardian report --format pdf --out report.pdf` — wrong syntax. Real CLI is `agent-guardian report SCAN_ID --output FORMAT`. The fix is committed; if you regenerate the quickstart, use the actual `cli.py` Typer decorators as source of truth.
- The product name is **AgentGuardian** (one word). Never "AgentGuardian Open". The "open" was branding scaffolding that was removed.

## DCO + commit policy

Every commit must carry `Signed-off-by:` (CI rejects otherwise). Use `git commit -s`. Conventional Commits prefixes (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`). See `CONTRIBUTING.md` for the canonical rules.

## Don't do

- Don't push to `main` directly unless explicitly told. PRs are the norm.
- Don't commit anything under `examples/reports/` (gitignored anyway, but worth noting).
- Don't add a Cloud Run service for the docs — the integrated-into-the-web-app pattern is intentional. Separate service was rejected in 2026-05-28 planning.
