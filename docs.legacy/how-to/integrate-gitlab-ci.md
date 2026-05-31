# Integrate with GitLab CI

**TL;DR:** drop the job below into `.gitlab-ci.yml`. AgentGuardian's
JUnit output lands on the merge-request **Tests** widget; the SARIF
output lands on the **Code Quality** widget. Reports are signed with
your CI variable `AGENT_GUARDIAN_SIGNING_SECRET`.

## Prerequisites

- A GitLab project with CI enabled.
- A model API key set as a masked CI/CD variable — `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, or AWS Bedrock credentials.
- `AGENT_GUARDIAN_SIGNING_SECRET` set as a **masked + protected**
  CI/CD variable. Without it, reports are signed with the bundled
  public default and `agent-guardian verify` refuses to trust them
  (cli.py:1255–1257, crypto/hmac_sig.py:46–73).

## The pipeline

```yaml title=".gitlab-ci.yml"
stages: [security]

agentguardian:
  stage: security
  image: python:3.11-slim
  variables:
    PIP_DISABLE_PIP_VERSION_CHECK: "1"
    PIP_NO_CACHE_DIR: "1"
  timeout: 30 minutes
  before_script:
    - python -m pip install --upgrade pip
    - python -m pip install agent-guardian
  script:
    - |
      agent-guardian scan --system-prompt prompts/agent.txt \
          --model openai:gpt-4o-mini \
          --no-tui \
          --fail-under 70 \
          --output sarif \
          --output-path agentguardian.sarif
    - |
      SCAN_ID=$(ls -t ~/.agentguardian/scans | head -n1)
      agent-guardian report "$SCAN_ID" \
          --output junit \
          --output-path agentguardian.junit.xml
  artifacts:
    when: always
    expire_in: 30 days
    paths:
      - agentguardian.sarif
      - agentguardian.junit.xml
    reports:
      junit: agentguardian.junit.xml
      codequality: agentguardian.sarif    # SARIF is a superset of GitLab's CodeQuality format
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## Why each block is here

- **`image: python:3.11-slim`** — AgentGuardian's wheel targets
  Python ≥ 3.11. `slim` keeps the install small; for the PDF report
  format (WeasyPrint), use the full `python:3.11` image instead since
  WeasyPrint needs Cairo + Pango.
- **`pip install agent-guardian`** — Pulls the published PyPI wheel.
  Pin to a specific version (`agent-guardian==1.0.0`) for stable
  pipelines.
- **`--output sarif`** — emits the same SARIF 2.1.0 the GitHub
  recipe uses (`reports/sarif.py:1`,
  [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py)).
- **`agent-guardian report "$SCAN_ID" --output junit`** — regenerates
  the JUnit XML from the stored scan record without re-running the
  swarm (cli.py:1162–1232). Format set is
  `json | sarif | junit | md | pdf` (cli.py:1165–1166).
- **`reports.junit`** — GitLab parses this on the MR widget and shows
  passed/failed test counts.
- **`reports.codequality`** — GitLab's Code Quality widget accepts a
  CodeClimate-shape JSON; SARIF 2.1.0 is a superset. If your GitLab
  install rejects the SARIF directly, drop the `codequality:` line
  and rely on the artifact path instead. Alternatively, use the
  GitLab-managed [SAST format converter](https://docs.gitlab.com/ee/user/application_security/sast/)
  in a downstream job.
- **`rules:`** — runs on MRs and on default-branch pushes, not on
  every branch push. Tune to your workflow.

## Scanning a code target instead

```yaml
script:
  - python -m pip install -e .                 # so the dotted path resolves
  - |
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
script:
  - |
    agent-guardian scan \
        --endpoint https://staging.example.com/agent \
        --model openai:gpt-4o-mini \
        --no-tui \
        --fail-under 70 \
        --output sarif \
        --output-path agentguardian.sarif
```

For richer wiring (auth-header rotation, mTLS), drive the scan from a
target contract (`agentguardian init --out agentguardian.yaml`) and
commit the contract to source control. See [Scan an HTTP endpoint](scan-an-http-endpoint.md).

## Forwarding spans to your APM in the same job

```yaml
agentguardian:
  variables:
    OTEL_SEMCONV_STABILITY_OPT_IN: gen_ai_latest_experimental
    OTEL_EXPORTER_OTLP_ENDPOINT: https://api.honeycomb.io
    OTEL_EXPORTER_OTLP_HEADERS: "x-honeycomb-team=$HONEYCOMB_API_KEY"
    OTEL_SERVICE_NAME: agent-guardian-ci
  # ... rest as above
```

See [Set up OpenTelemetry](set-up-opentelemetry.md) for the per-vendor
endpoint table.

## Secrets hygiene

- Mark every API key + the signing secret as **Masked** and
  **Protected** in *Settings → CI/CD → Variables*. "Masked" hides the
  value in job logs; "Protected" prevents non-protected branches from
  ever seeing it.
- Do **not** echo the secret in your `script:` block. AgentGuardian
  never logs the secret itself; only the report's HMAC digest.

## Next steps

- [Integrate with GitHub Actions](integrate-github-actions.md)
- [Integrate with Jenkins](integrate-jenkins.md)
- [Forward to a SIEM](forward-to-siem.md) — for the per-event JSONL stream.
