# Exit codes

**TL;DR.** Every `agent-guardian` exit code, what triggers it, why, and
how to remediate. Source of truth:
[`cli.py:83-89`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

## Summary

| Code  | Constant                  | Meaning                                                                                                |
|-------|---------------------------|--------------------------------------------------------------------------------------------------------|
| `0`   | `EXIT_OK`                 | Success.                                                                                               |
| `1`   | `EXIT_FAIL_UNDER`         | `--fail-under` triggered, `verify` failed, `publish` refused, or non-authoritative scan in CI gate.    |
| `2`   | `EXIT_CONFIG`             | Configuration error — bad flag, missing file, malformed contract, missing env var, invalid argument.   |
| `3`   | `EXIT_TARGET_UNREACHABLE` | Target endpoint failed pre-flight or the configured target file does not exist.                        |
| `4`   | `EXIT_LLM_PROVIDER`       | LLM provider error — auth, rate limit, transport, model not enabled.                                   |
| `5`   | `EXIT_SANDBOX`            | Sandbox violation in `code` adapter mode.                                                              |
| `130` | `EXIT_USER_INTERRUPT`     | Interrupted by the user (Ctrl-C). Standard POSIX SIGINT exit code.                                     |

## `0` — success

The command completed with no errors. For `scan`, this also means the
final AIVSS met any `--fail-under` threshold and signature verification
(when invoked through `verify`) reported a trusted, anchored result.

## `1` — `EXIT_FAIL_UNDER` / verify failed / publish refused

Three distinct triggers, all surfaced as exit `1`:

1. **`scan --fail-under N` triggered.** The final AIVSS is below `N`.
   Non-authoritative scans (stub model, or `--mode fast` where the
   commander flagged `mode_authoritative=False`) always count as
   failures here — they cannot silently green-pass a CI gate. Look for
   the `WARNING: this scan is NON-AUTHORITATIVE` line on stderr; re-run
   with a real `--model` and ideally `--mode full` for an authoritative
   assessment.
2. **`verify` rejected the report.** Either the schema failed, both
   signature legs failed (tamper), or no trust anchor was supplied and
   the result is `UNANCHORED`. See [reference / cli — verify](cli.md#verify)
   for fail-closed semantics. Remedy: supply `--pubkey` (or
   `--pubkey-file`) and/or `--secret` so the verifier has something to
   anchor against.
3. **`publish` refused.** The report is unsigned or its signatures do
   not validate. Re-emit with `output.sign_evidence: true` (the
   default) and try again.

## `2` — `EXIT_CONFIG`

The CLI rejected the invocation before doing any work. Common causes:

- An unknown `--mode` value (must be one of `fast`, `smart`, `full`).
- An unknown `--tier` (must be one of `T1`, `T2`, `T3`, `T4`).
- A `--framework` value not in the registry (`adk`, `autogen`,
  `crewai`, `langgraph`, `openai_agents`, `strands`).
- A `--framework-ref` that does not resolve to a Python object (bad
  module path or missing attribute).
- A target contract YAML that fails schema validation, or a contract
  that requires schema migration (run `agent-guardian contract migrate
  FILE --write`).
- `--config` pointed at a file that doesn't parse as valid YAML, or has
  unknown top-level keys (Pydantic uses `extra="forbid"`).
- A missing required environment variable (e.g.
  `OPENAI_API_KEY`/`AGENT_GUARDIAN_OPENAI_API_KEY` for `--model openai:…`).
- `--output pdf` with no PDF engine installed and no
  `[full]` / `[pdf-fallback]` extra.

Remedy: read the stderr message — `EXIT_CONFIG` is always accompanied
by a one-line, copy-paste-fixable error. Cross-references:
[reference / configuration schema](contract-schema.md),
[operations / environment variables](../operations/env-vars.md),
[faq / troubleshooting](../faq/troubleshooting.md).

## `3` — `EXIT_TARGET_UNREACHABLE`

For `scan --endpoint`, the pre-scan reachability pre-flight (two POSTs,
5-second timeout each) failed with `ConnectError` or `Timeout`. The CLI
exits early rather than burning the LLM budget on per-probe timeouts.
Any HTTP response — including `422` from a schema-protected FastAPI
endpoint, `404`, or `5xx` — counts as reachable; this exit code only
fires on transport-level failures.

For `scan --system-prompt PATH`, the file does not exist.

Remedy options:

- Confirm the endpoint URL and that the target is up
  (`curl -X POST <endpoint>`).
- The default preflight body is `{"input": "ping"}`. If your target
  requires a completely different body shape and you don't want the
  preflight at all, use `--no-preflight`.
- For `--system-prompt`, check the file path.

## `4` — `EXIT_LLM_PROVIDER`

One of the LLM clients failed to authenticate or talk to its provider.
Causes:

- Missing or invalid API key.
- Provider returned a `4xx` / `5xx` the client could not retry through
  (rate limit ceiling, model-not-enabled-in-region for Bedrock,
  unsupported model id, etc.).
- Network issue between you and the provider endpoint.

Remedy:

- Run `agent-guardian doctor --check-connectivity` to probe each
  detected provider with a minimal request.
- Check the per-provider notes:
  [OpenAI](../integrations/providers/openai.md),
  [Anthropic](../integrations/providers/anthropic.md),
  [Gemini](../integrations/providers/gemini.md),
  [Vertex](../integrations/providers/vertex.md),
  [Bedrock](../integrations/providers/bedrock.md),
  [Ollama](../integrations/providers/ollama.md).

## `5` — `EXIT_SANDBOX`

The `code` adapter detected a sandbox violation while loading the
target callable. The CLI refuses to execute untrusted code outside the
sandbox boundary. See [how-to / scan Python source](../how-to/scan-python-source.md)
and [security / threat model](../security/threat-model.md) for the
boundary definition.

## `130` — user interrupt

Standard POSIX SIGINT exit code. You hit Ctrl-C; the swarm acknowledged
the cooperative cancel, closed every LLM client and adapter, and exited
cleanly. Stored scan artefacts are not persisted for interrupted runs.

## See also

- [Reference / CLI](cli.md) — full command surface and each command's
  one-line exit-code summary.
- [Operations / runbook (symptom → fix)](../operations/runbook.md) —
  symptom-first triage.
- [FAQ / troubleshooting](../faq/troubleshooting.md) — common
  end-user-facing failure modes.
