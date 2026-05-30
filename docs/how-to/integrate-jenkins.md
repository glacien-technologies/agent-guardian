# Integrate with Jenkins

**TL;DR:** declarative `Jenkinsfile` below runs AgentGuardian in a
`python:3.11` Docker agent, publishes the JUnit report to Jenkins'
test surface, and archives the signed SARIF as a build artefact. The
HMAC signing secret is wired through Jenkins credentials so it never
leaks into a build log.

## Prerequisites

- A Jenkins controller with the Docker plugin enabled (this pipeline
  uses an `agent { docker { ... } }` block).
- A model API key for an authoritative score, stored as a Jenkins
  **Secret text** credential — `openai-api-key`,
  `anthropic-api-key`, etc.
- An `agentguardian-signing-secret` Jenkins credential. Without it,
  reports are signed with the bundled public default and
  `agent-guardian verify` refuses to trust them (cli.py:1255–1257,
  crypto/hmac_sig.py:46–73).

## The `Jenkinsfile`

```groovy title="Jenkinsfile"
pipeline {
    agent {
        docker {
            image 'python:3.11'
            args '-u root --entrypoint=""'
        }
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        ansiColor('xterm')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
        PIP_NO_CACHE_DIR              = '1'
    }

    stages {
        stage('Install') {
            steps {
                sh '''
                    python -m pip install --upgrade pip
                    python -m pip install agent-guardian
                '''
            }
        }

        stage('Scan') {
            environment {
                OPENAI_API_KEY                  = credentials('openai-api-key')
                AGENT_GUARDIAN_SIGNING_SECRET   = credentials('agentguardian-signing-secret')
            }
            steps {
                sh '''
                    agent-guardian scan --system-prompt prompts/agent.txt \
                        --model openai:gpt-4o-mini \
                        --no-tui \
                        --fail-under 70 \
                        --output sarif \
                        --output-path agentguardian.sarif
                '''
            }
        }

        stage('Report (JUnit)') {
            when { expression { fileExists('agentguardian.sarif') } }
            steps {
                sh '''
                    SCAN_ID=$(ls -t ~/.agentguardian/scans | head -n1)
                    agent-guardian report "$SCAN_ID" \
                        --output junit \
                        --output-path agentguardian.junit.xml
                '''
            }
        }
    }

    post {
        always {
            // JUnit surface — Jenkins' Tests tab + trend graph.
            junit allowEmptyResults: true, testResults: 'agentguardian.junit.xml'

            // Signed SARIF + raw scan record for the Security team.
            archiveArtifacts artifacts: 'agentguardian.sarif',
                             allowEmptyArchive: true,
                             fingerprint: true
        }
    }
}
```

## Why each block is here

- **`agent { docker { image 'python:3.11' } }`** — AgentGuardian's
  wheel targets Python ≥ 3.11. The `--entrypoint=""` argument is
  required so Jenkins can run its own commands inside the container
  rather than the image's `python` entrypoint. Use the full
  `python:3.11` image (not `-slim`) if you also need the PDF output
  format, which depends on WeasyPrint's Cairo/Pango stack.
- **`credentials('openai-api-key')`** — binds the Jenkins secret to
  the `OPENAI_API_KEY` env var for the stage. Jenkins automatically
  masks the value in the build log.
- **`credentials('agentguardian-signing-secret')`** — same pattern
  for the HMAC signing key. AgentGuardian reads it as
  `AGENT_GUARDIAN_SIGNING_SECRET` (cli.py:1255–1257).
- **`--fail-under 70`** — exit `1` when AIVSS < 70. A stub /
  non-LLM evaluator can't credibly grade, so the CLI **also** refuses
  to pass `--fail-under` whenever the evaluator is stub
  (cli.py:2578–2596). Your gate is impossible to bypass with
  `--model stub`.
- **`agent-guardian report "$SCAN_ID" --output junit`** — regenerates
  the JUnit XML from the stored scan record without re-running the
  swarm (cli.py:1162–1232).
- **`when { expression { fileExists('agentguardian.sarif') } }`** —
  the JUnit stage runs only if the scan got far enough to write a
  SARIF; without the guard, a fail-fast scan would burn an
  unnecessary error frame.
- **`post { always { junit ... archiveArtifacts ... } }`** — the
  test surface + artefact archive runs whether or not the build
  passed the gate, so the Security team can read the findings on a
  failed build.

## Scanning a code target instead

```groovy
stage('Scan') {
    steps {
        sh '''
            python -m pip install -e .
            agent-guardian scan my_app.agent:run \
                --model openai:gpt-4o-mini \
                --no-tui \
                --fail-under 70 \
                --output sarif \
                --output-path agentguardian.sarif
        '''
    }
}
```

See [Scan Python source](scan-python-source.md) for the dotted-path rules.

## Scanning an HTTP endpoint instead

```groovy
stage('Scan') {
    environment {
        OPENAI_API_KEY                = credentials('openai-api-key')
        AGENT_GUARDIAN_SIGNING_SECRET = credentials('agentguardian-signing-secret')
        STAGING_AGENT_API_KEY         = credentials('staging-agent-api-key')
    }
    steps {
        sh '''
            agent-guardian scan \
                --endpoint https://staging.example.com/agent \
                --model openai:gpt-4o-mini \
                --no-tui \
                --fail-under 70 \
                --output sarif \
                --output-path agentguardian.sarif
        '''
    }
}
```

For non-trivial wiring, drive the scan from a target contract and
commit `agentguardian.yaml` to your repo. See [Scan an HTTP endpoint](scan-an-http-endpoint.md).

## Forwarding spans to your APM in the same job

```groovy
environment {
    OTEL_SEMCONV_STABILITY_OPT_IN = 'gen_ai_latest_experimental'
    OTEL_EXPORTER_OTLP_ENDPOINT   = 'https://api.honeycomb.io'
    OTEL_EXPORTER_OTLP_HEADERS    = "x-honeycomb-team=${env.HONEYCOMB_API_KEY}"
    OTEL_SERVICE_NAME             = 'agent-guardian-ci'
}
```

See [Set up OpenTelemetry](set-up-opentelemetry.md) for the per-vendor
endpoint table.

## Surfacing findings as PR comments

Jenkins itself does not post PR comments — wire the SARIF into your
SCM via a follow-up stage:

- **GitHub**: post-process `agentguardian.sarif` with `gh api`
  through the [Code Scanning upload](https://docs.github.com/en/rest/code-scanning/code-scanning?apiVersion=2022-11-28#upload-an-analysis-as-sarif-data)
  REST endpoint.
- **Bitbucket Server**: convert the SARIF to a [Code Insights
  report](https://confluence.atlassian.com/bitbucketserver/code-insights-966660485.html)
  via Bitbucket's REST API.
- **Self-hosted GitLab**: copy the SARIF into a downstream pipeline
  that uses the GitLab pipeline-merge-request job to attach it.

## Next steps

- [Integrate with GitHub Actions](integrate-github-actions.md)
- [Integrate with GitLab CI](integrate-gitlab-ci.md)
- [Forward to a SIEM](forward-to-siem.md) — for the per-event JSONL stream.
