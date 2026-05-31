# Upgrade

> **TL;DR.** Upgrade in place. Roll back safely. Pin versions in CI.
> Read CHANGELOG.md before every upgrade.

AgentGuardian is a tagged-release Python package. Upgrades are either
`pip install --upgrade` (host install) or a tagged Docker image swap
(container install). Both forms preserve `~/.agentguardian/` —
scan history, the Ed25519 signing keypair, telemetry consent state —
across upgrades.

## pip upgrade

```bash
pip install --upgrade agent-guardian
agent-guardian --version
# 1.0.0
```

What persists:

- `~/.agentguardian/state.json` — first-run banner state, last AIVSS,
  telemetry consent.
- `~/.agentguardian/scans/` — every scan you have ever run on this
  machine, plus the `_index.json` paginated history index.
- `~/.agentguardian/keys/` — the Ed25519 signing keypair (so signed
  reports from before the upgrade still verify).

If anything in the layout above changes between releases, the
[CHANGELOG.md](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md)
will call it out under the corresponding version heading.

## Docker upgrade

```bash
docker pull ghcr.io/glacien-technologies/agent-guardian:<tag>
docker compose down
docker compose up -d
```

The bind-mounted `/home/ag/.agentguardian` volume persists across
container restarts (the bundled
[`docker-compose.yml`](https://github.com/glacien-technologies/agent-guardian/blob/main/docker-compose.yml)
mounts `./.agentguardian` on the host to that path), so scan history
and keys survive.

!!! note "GHCR image is roadmap"
    The GHCR image push lands with v1.0.0; see the M15 line in
    [roadmap.md](../reference/roadmap.md). Until then, the canonical container
    install is `docker build -t agent-guardian:dev .` from the repo —
    see [Deploy — Docker](deploy.md#docker-single-shot-scan). When you
    upgrade a locally-built image, the recipe is:

    ```bash
    git pull
    docker build -t agent-guardian:dev .
    docker compose down && docker compose up -d
    ```

## Rollback

For pip:

```bash
pip install agent-guardian==<previous-version>
```

For Docker, swap the tag back:

```bash
docker pull ghcr.io/glacien-technologies/agent-guardian:<previous-tag>
docker compose down && docker compose up -d
```

!!! warning "Schema-skew is real — read the CHANGELOG first"
    A newer release that adds a field to the `Scan` model can land
    `scan.json` files older versions cannot deserialise. Today the
    repo has no formal scan-store schema-migration story; the safe
    rollback path is:

    1. Read [CHANGELOG.md](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md)
       for the version you are rolling back **from** to confirm
       whether the on-disk format changed.
    2. If it did, copy the affected `~/.agentguardian/scans/<id>/`
       directories out before rolling back. A signed JSON report
       remains independently verifiable with `agent-guardian verify`
       at any future version.

    A first-class schema-migration command is tracked in
    [roadmap.md](../reference/roadmap.md).

## Pin discipline

In CI, pin AgentGuardian to a minor-version range so security-relevant
fixes land automatically but no breaking change can surprise the
build:

```bash
pip install "agent-guardian~=1.0.0"
```

`~=1.0.0` is equivalent to `>=1.0.0, <1.1.0` — every 1.0.x patch
upgrades transparently; the next minor release is opt-in. Pair this
with `pip freeze > requirements.lock` if you want fully reproducible
builds.

For Docker:

```bash
docker pull ghcr.io/glacien-technologies/agent-guardian:1.0.0
```

Pin the *full* tag — `latest` and `1.0` are mutable; `1.0.0` is not.

## Verifying after upgrade

After any upgrade, run two smoke checks:

```bash
# 1. The CLI is wired and the version is what you expected.
agent-guardian --version

# 2. Re-verify your last signed report still passes against the new code.
LAST=$(agent-guardian last-score --score-only)
REPORT=$(ls -t ~/.agentguardian/scans/*/report.json | head -1)
PUBKEY=$(jq -r .signatures.ed25519.public_key_b32 "$REPORT")
agent-guardian verify "$REPORT" --pubkey "$PUBKEY"
# schema:       OK
# HMAC-SHA256:  OK
# Ed25519:      OK
# trust anchor: PINNED
```

A `verify` that drops from `PINNED` to `UNANCHORED` after an upgrade
means the trust-anchor surface has changed and the runbook is
[verify — worked example, unanchored](../reference/cli.md#worked-example-unanchored).

## See also

- [CHANGELOG.md](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md)
  — every released version, what changed, what to watch for.
- [Roadmap](../reference/roadmap.md) — what is coming.
- [Operator runbook](runbook.md) — what to do when the upgrade
  uncovers something.
- [Serving the dashboard](serve.md) — the surface that is most
  likely to need a probe-rewire after a major upgrade.
