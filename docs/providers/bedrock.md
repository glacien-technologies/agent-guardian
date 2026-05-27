# AWS Bedrock (Anthropic Claude)

AgentGuardian drives Bedrock-hosted Anthropic Claude models via the
Converse API using SigV4-signed requests. Transport reuses our existing
`httpx.AsyncClient` (so retry, sandbox, and the per-provider concurrency
cap work identically to the direct Anthropic client).

## Prerequisites

1. **Enable model access in the Bedrock console.** Visit
   <https://console.aws.amazon.com/bedrock/home> → *Model access* and
   request the Anthropic Claude family for the region(s) you intend to
   use. Access typically grants within minutes for individuals; Enterprise
   accounts may require approval.
2. **Install the AWS extra.** Bedrock support is an opt-in extra to keep
   the base install lean:

   ```bash
   uv sync --extra aws
   # or
   pip install 'agent-guardian[aws]'
   ```

3. **Configure credentials.** AgentGuardian uses the standard AWS
   credential chain — anything botocore can resolve works:
   - Environment variables: `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
     (and optionally `AWS_SESSION_TOKEN` for temporary creds).
   - `~/.aws/credentials` + `~/.aws/config` (named profiles, SSO).
   - IAM role on EC2, ECS, or Lambda (no config needed).

## Model spec

Bedrock requires the explicit `bedrock:` prefix (model IDs all start with
`anthropic.` / `amazon.` / `meta.` etc., so no heuristic prefix is offered).

| Spec | Model |
|------|-------|
| `bedrock:anthropic.claude-haiku-4-5-v1:0` | Claude Haiku 4.5 (us-east-1) |
| `bedrock:anthropic.claude-sonnet-4-6-v1:0` | Claude Sonnet 4.6 (us-east-1) |
| `bedrock:us.anthropic.claude-haiku-4-5-v1:0` | Cross-region inference profile (US) |
| `bedrock:us.anthropic.claude-sonnet-4-6-v1:0` | Cross-region inference profile (US) |
| `bedrock:eu.anthropic.claude-sonnet-4-6-v1:0` | Cross-region inference profile (EU) |
| `bedrock:apac.anthropic.claude-sonnet-4-6-v1:0` | Cross-region inference profile (APAC) |

Cross-region inference profiles (`us.`, `eu.`, `apac.` prefixes) let
Bedrock load-balance across the regions in that geography; pricing is
identical to the single-region SKU.

## Example scan

```bash
export AWS_REGION=us-east-1  # or set via ~/.aws/config

agent-guardian scan my_agent:run \
  --attacker-model bedrock:us.anthropic.claude-sonnet-4-6-v1:0 \
  --evaluator-model bedrock:us.anthropic.claude-haiku-4-5-v1:0 \
  --commander-model bedrock:us.anthropic.claude-sonnet-4-6-v1:0 \
  --output json
```

## Cost

Bedrock list prices for the Claude family match the direct Anthropic
per-token rates (Bedrock bills via your AWS invoice instead of
Anthropic). The cost estimator includes Bedrock-Claude rows so
`agent-guardian scan` prints the same pre-flight figure whether you
choose `anthropic:` or `bedrock:` for the equivalent model.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `LLMAuthError: AccessDeniedException ... Model access not enabled` | Region or model not granted | Visit the Bedrock console → *Model access* |
| `LLMAuthError: no AWS credentials found` | Empty credential chain | Export AWS env vars or configure `~/.aws/credentials` |
| `LLMAuthError: AWS profile not found` | Bad `--profile` / `AWS_PROFILE` | Check `aws configure list-profiles` |
| `LLMPermanentError: ResourceNotFoundException` | Model ID doesn't exist in this region | Try the `us.` / `eu.` inference-profile prefix |
| `LLMRateLimitError: ThrottlingException` | Account-level quota exhausted | Retry handled automatically; raise quota in AWS Service Quotas |
