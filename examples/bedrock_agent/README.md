# AWS Bedrock Agent demo target

Scan a Bedrock Agent (Agent Runtime `InvokeAgent`) via a target contract.
No local agent code — the agent lives in your AWS account.

## What it tests

* All 10 ASI categories against an `InvokeAgent` target.
* SigV4 auth, AWS credential chain resolution, and the `server_session`
  pattern (Bedrock's `sessionId` carries conversation state on the
  server).

## Prerequisites

* `agent-guardian[aws]` installed: `pip install 'agent-guardian[aws]'`
  (pulls in `botocore` for SigV4).
* A Bedrock Agent deployed in your account. The
  [AWS quickstart](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-create.html)
  walks through the console-based path.
* AWS credentials available via the standard chain (env vars, shared
  config, instance profile).
* Two env vars exported:
  * `BEDROCK_AGENT_ID` — the agent's id (10-char alphanumeric).
  * `BEDROCK_AGENT_ALIAS_ID` — the alias id (10-char alphanumeric, or
    `TSTALIASID` for the working draft).

## Scan it

```bash
export BEDROCK_AGENT_ID=...
export BEDROCK_AGENT_ALIAS_ID=...
agent-guardian scan \
  --contract examples/bedrock_agent/agentguardian.yaml \
  --model stub \
  --mode fast \
  --output md \
  --output-path scan.md
```

## Notes for CI

This example is **skipped** by `examples/ci/validate_examples.py` by
default because it requires real AWS credentials. Set
`AG_VALIDATE_BEDROCK=1` and the credentials above in your CI environment
to opt in.

## Docs

See `docs/try/scan-bedrock-agent.mdx` for the full walkthrough.
