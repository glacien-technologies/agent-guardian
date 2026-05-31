# Integrate with GitHub Actions

**TL;DR:** drop the workflow below into `.github/workflows/agentguardian.yml`,
add an `AGENT_GUARDIAN_SIGNING_SECRET` repo secret, and every push gets a
SARIF report uploaded to the **Security** tab plus a JUnit report
attached to the **Tests** tab.

## Prerequisites

- A GitHub repo with Actions enabled.
- A model API key for an authoritative score — `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, or the AWS Bedrock credential
  chain. Without one, the scan runs in stub mode and `--fail-under`
  refuses to pass the build (the non-authoritative gate, cli.py:2578–2596).
- An `AGENT_GUARDIAN_SIGNING_SECRET` repo secret for HMAC-signing the
  report (cli.py:1255–1257). The default public secret is **never**
  accepted on `verify`.

## The workflow

```yaml title=".github/workflows/agentguardian.yml"
name: AgentGuardian

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required for SARIF upload
  checks: write            # required for the JUnit test surface

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install AgentGuardian
        run: |
          python -m pip install --upgrade pip
          python -m pip install agent-guardian

      - name: Scan (SARIF for Security tab)
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          AGENT_GUARDIAN_SIGNING_SECRET: ${{ secrets.AGENT_GUARDIAN_SIGNING_SECRET }}
        run: |
          agent-guardian scan --system-prompt prompts/agent.txt \
              --model openai:gpt-4o-mini \
              --no-tui \
              --fail-under 70 \
              --output sarif \
              --output-path agentguardian.sarif

      - name: Upload SARIF to Code Scanning
        if: always()                     # surface findings even when --fail-under fails
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentguardian.sarif
          category: agentguardian

      - name: Re-emit JUnit for the Tests tab
        if: always()
        run: |
          SCAN_ID=$(agent-guardian last-score --score-only > /dev/null && \
                    ls -t ~/.agentguardian/scans | head -n1)
          agent-guardian report "$SCAN_ID" \
              --output junit \
              --output-path agentguardian.junit.xml

      - name: Publish JUnit
        if: always()
        uses: mikepenz/action-junit-report@v4
        with:
          report_paths: agentguardian.junit.xml
          check_name: AgentGuardian
          fail_on_failure: false

      - name: Upload raw scan artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agentguardian-reports
          path: |
            agentguardian.sarif
            agentguardian.junit.xml
            ~/.agentguardian/scans/
          if-no-files-found: warn
```

## Why each step is here

- **`actions/checkout@v4`** — Pulls your repo so `prompts/agent.txt`
  exists. Replace the path with whatever prompt(s) you keep under
  source control.
- **`actions/setup-python@v5` with `3.11`** — AgentGuardian requires
  Python ≥ 3.11; system Python 3.14 is currently unsupported (see
  `CONTRIBUTING.md`).
- **`pip install agent-guardian`** — Pulls the published PyPI wheel.
  Pin to a specific version (`agent-guardian==1.0.0`) in stable
  pipelines so a release does not silently shift the gate.
- **`agent-guardian scan --system-prompt …`** — The flag inventory
  used here is the minimum that gives you (a) a reproducible scan,
  (b) a CI-friendly progress format (`--no-tui`), (c) a hard gate
  (`--fail-under 70`), and (d) a SARIF artefact. Full flag surface
  is in [CLI reference / scan](../reference/cli.md#scan).
- **`--fail-under 70`** — exit `1` when AIVSS < 70. This is the
  Action's hard gate. A stub / non-LLM evaluator can't credibly grade,
  so the CLI **also** refuses to pass `--fail-under` whenever the
  evaluator is stub (cli.py:2578–2596) — your CI gate is impossible
  to bypass with `--model stub`.
- **`AGENT_GUARDIAN_SIGNING_SECRET`** — the HMAC signer secret. Set
  it once as a repo secret. Without it, the report is signed with the
  bundled public default and `verify` refuses to trust it (cli.py:1255–1257,
  crypto/hmac_sig.py:46–73).
- **`upload-sarif@v3`** — surfaces findings in the **Security** tab.
  `if: always()` ensures findings are visible even when the scan
  failed the gate.
- **`agent-guardian report`** — regenerates the JUnit XML from the
  stored scan without re-running the swarm (cli.py:1162). The JUnit
  format is one of `json | sarif | junit | md | pdf`
  (cli.py:1165–1166).
- **`mikepenz/action-junit-report@v4`** — third-party Action that
  surfaces JUnit results in the PR Checks UI. `fail_on_failure: false`
  delegates the gate decision to AgentGuardian's `--fail-under`.

## Scanning a code target instead

Swap the `scan` step for a dotted-path target:

```yaml
- name: Scan (code target)
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    AGENT_GUARDIAN_SIGNING_SECRET: ${{ secrets.AGENT_GUARDIAN_SIGNING_SECRET }}
  run: |
    pip install -e .   # so the dotted path resolves
    agent-guardian scan my_app.agent:run \
        --model openai:gpt-4o-mini \
        --no-tui \
        --fail-under 70 \
        --output sarif \
        --output-path agentguardian.sarif
```

See [Scan Python source](scan-python-source.md) for the dotted-path
rules.

## Scanning an HTTP endpoint instead

```yaml
- name: Scan (HTTP endpoint)
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    AGENT_GUARDIAN_SIGNING_SECRET: ${{ secrets.AGENT_GUARDIAN_SIGNING_SECRET }}
    STAGING_AGENT_API_KEY: ${{ secrets.STAGING_AGENT_API_KEY }}
  run: |
    agent-guardian scan \
        --endpoint https://staging.example.com/agent \
        --model openai:gpt-4o-mini \
        --no-tui \
        --fail-under 70 \
        --output sarif \
        --output-path agentguardian.sarif
```

For the auth-header / contract wiring patterns, see [Scan an HTTP
endpoint](scan-an-http-endpoint.md).

## Forwarding spans to your APM in the same job

Set the OTel env vars in the same job and the scan will emit spans
without any other code change (see [Set up OpenTelemetry](set-up-opentelemetry.md)):

```yaml
- name: Scan with OTel
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    AGENT_GUARDIAN_SIGNING_SECRET: ${{ secrets.AGENT_GUARDIAN_SIGNING_SECRET }}
    OTEL_SEMCONV_STABILITY_OPT_IN: gen_ai_latest_experimental
    OTEL_EXPORTER_OTLP_ENDPOINT: https://api.honeycomb.io
    OTEL_EXPORTER_OTLP_HEADERS: "x-honeycomb-team=${{ secrets.HONEYCOMB_API_KEY }}"
    OTEL_SERVICE_NAME: agent-guardian-ci
  run: |
    agent-guardian scan --system-prompt prompts/agent.txt \
        --model openai:gpt-4o-mini \
        --no-tui \
        --fail-under 70 \
        --output sarif \
        --output-path agentguardian.sarif
```

## Pinning the runner Python version

The Python version matters: AgentGuardian's wheel targets ≥ 3.11.
A bare `runs-on: ubuntu-latest` *without* an explicit setup-python
will pick whichever Python the image ships with — usually 3.10 — and
the install will fail. Always set `python-version: "3.11"` (or
`"3.12"`, `"3.13"`) explicitly.

## Next steps

- [Integrate with GitLab CI](integrate-gitlab-ci.md)
- [Integrate with Jenkins](integrate-jenkins.md)
- [Forward to a SIEM](forward-to-siem.md) — when you also need the
  per-event JSONL stream out of CI.
