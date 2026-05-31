# AWS Bedrock (Anthropic Claude)

> **TL;DR.** Bedrock drives Anthropic Claude via the AWS Converse API
> with SigV4-signed requests. Install the `[aws]` extra, configure
> AWS creds the normal way, set a region, and pass
> `--model bedrock:<bedrock-id>`. No API key — auth is the standard
> AWS credential chain. Model access is opt-in per account *and*
> per region.

## Prerequisites

1. **Enable model access in the Bedrock console.** Visit
   <https://console.aws.amazon.com/bedrock/home> → *Model access* and
   request the Anthropic Claude family for the region(s) you intend to
   use. Access typically grants within minutes for individuals;
   Enterprise accounts may require approval. See
   [FAQ — Bedrock 403](../../faq/index.md#aws-bedrock-returns-http-403-model-not-enabled-in-this-region)
   for the symptom + fix when this is the missing step.

2. **Install the AWS extra.** Bedrock support is opt-in to keep the
   base install lean:

   ```bash
   uv sync --extra aws
   # or
   pip install 'agent-guardian[aws]'
   ```

3. **Configure credentials.** AgentGuardian uses the standard AWS
   credential chain — anything botocore can resolve works:

   - Environment variables: `AWS_ACCESS_KEY_ID` +
     `AWS_SECRET_ACCESS_KEY` (and optionally `AWS_SESSION_TOKEN` for
     temporary creds).
   - `~/.aws/credentials` + `~/.aws/config` (named profiles, SSO).
   - IAM role on EC2, ECS, or Lambda (no config needed).

4. **Pick a region.** Set `AWS_REGION` (or `~/.aws/config`) so the
   Bedrock client knows which regional endpoint to sign for.

## Model spec

Bedrock requires the explicit `bedrock:` prefix (model IDs all start
with `anthropic.` / `amazon.` / `meta.` etc., so no heuristic prefix
is offered).

| Spec                                            | Model                                              |
|-------------------------------------------------|----------------------------------------------------|
| `bedrock:anthropic.claude-haiku-4-5-v1:0`       | Claude Haiku 4.5 (us-east-1)                       |
| `bedrock:anthropic.claude-sonnet-4-6-v1:0`      | Claude Sonnet 4.6 (us-east-1)                      |
| `bedrock:us.anthropic.claude-haiku-4-5-v1:0`    | Cross-region inference profile (US)                |
| `bedrock:us.anthropic.claude-sonnet-4-6-v1:0`   | Cross-region inference profile (US)                |
| `bedrock:eu.anthropic.claude-sonnet-4-6-v1:0`   | Cross-region inference profile (EU)                |
| `bedrock:apac.anthropic.claude-sonnet-4-6-v1:0` | Cross-region inference profile (APAC)              |
| `bedrock:global.anthropic.claude-sonnet-4-6`    | Global inference profile (tested 2026-05-28)       |
| `bedrock:global.anthropic.claude-opus-4-6-v1`   | Global inference profile (Opus needs `-v1` suffix; Sonnet does **not**) |

Cross-region inference profiles (`us.`, `eu.`, `apac.` prefixes) let
Bedrock load-balance across the regions in that geography; pricing is
identical to the single-region SKU. The inconsistent `-v1` suffix
policy across model families is empirical — Sonnet 4.6 returns
HTTP 400 *"invalid model identifier"* if you add it (see
`src/agent_guardian/cost.py:99-105`).

## Example scan

```bash
export AWS_REGION=us-east-1  # or set via ~/.aws/config

agent-guardian scan my_agent:run \
  --mode quick \
  --attacker-model bedrock:us.anthropic.claude-sonnet-4-6-v1:0 \
  --evaluator-model bedrock:us.anthropic.claude-haiku-4-5-v1:0 \
  --commander-model bedrock:us.anthropic.claude-sonnet-4-6-v1:0 \
  --output json
```

## Cost (list prices, verified 2026-05-27)

Bedrock list prices for the Claude family match the direct Anthropic
per-token rates (Bedrock bills via your AWS invoice instead of
Anthropic). The cost estimator includes Bedrock-Claude rows so the
pre-flight figure is the same whether you choose `anthropic:` or
`bedrock:` for the equivalent model
(`src/agent_guardian/cost.py:79-108`):

| Model                                       | Input  | Output |
|---------------------------------------------|-------:|-------:|
| `anthropic.claude-haiku-4-5-v1:0`           | $0.80  | $4.00  |
| `anthropic.claude-sonnet-4-6-v1:0`          | $3.00  | $15.00 |
| `global.anthropic.claude-opus-4-6-v1`       | $15.00 | $75.00 |
| `*` (unknown Bedrock model — catch-all)     | $3.00  | $15.00 |

The catch-all defaults to the Sonnet rate so estimates err
conservatively.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `LLMAuthError: AccessDeniedException ... Model access not enabled` | Region or model not granted | Visit the Bedrock console → *Model access*. See [FAQ — Bedrock 403](../../faq/index.md#aws-bedrock-returns-http-403-model-not-enabled-in-this-region). |
| `LLMAuthError: no AWS credentials found` | Empty credential chain | Export AWS env vars or configure `~/.aws/credentials` |
| `LLMAuthError: AWS profile not found` | Bad `--profile` / `AWS_PROFILE` | Check `aws configure list-profiles` |
| `LLMPermanentError: ResourceNotFoundException` | Model ID doesn't exist in this region | Try the `us.` / `eu.` / `apac.` inference-profile prefix |
| `LLMRateLimitError: ThrottlingException` | Account-level quota exhausted | Retry handled automatically; raise quota in AWS Service Quotas |

Auth and error mapping live in `src/agent_guardian/llm/bedrock.py` —
see `_raise_for_bedrock_status` (line 178) for the HTTP-status → error
class table.

## Retry behaviour

Bedrock reuses the same `with_backoff` helper as every other
provider (`src/agent_guardian/llm/retry.py:136`). The agent-loop caps
are `AGENT_LOOP_MAX_RETRIES=3` and `AGENT_LOOP_MAX_SECONDS=15.0` so a
single `ThrottlingException` cycle cannot soak the wall-clock budget.
