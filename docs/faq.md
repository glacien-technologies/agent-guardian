# FAQ

## Why does `agent-guardian verify` print `trust anchor: UNANCHORED`?

`verify` fails closed. A signature alone proves only that the bytes
were not tampered with (integrity) — it does **not** prove who signed
them. To anchor the report you must supply at least one of:

- `--pubkey` or `--pubkey-file` (Ed25519, pinned out-of-band).
- `--secret` or `AGENT_GUARDIAN_SIGNING_SECRET` (HMAC).

Without an anchor the command exits **1** and prints `trust anchor:
UNANCHORED`. The default HMAC secret is never accepted on verify, so a
report signed only with the public default also exits non-zero. See
[CLI — verify](cli.md#verify) for the full anchor semantics and a
worked example.

## `pip install 'agent-guardian[full]'` fails on WeasyPrint native deps

WeasyPrint needs Pango, Cairo, and HarfBuzz. On Debian/Ubuntu:

```bash
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 \
                        libharfbuzz0b libcairo2 libjpeg62-turbo \
                        fonts-dejavu-core
```

On macOS:

```bash
brew install pango cairo harfbuzz
```

If you cannot install those system packages, fall back to the
lighter ReportLab engine:

```bash
pip install 'agent-guardian[pdf-fallback]'
```

`agent_guardian.available_pdf_engines()` tells you which engines the
package can resolve at runtime; the CLI raises `PdfFeatureUnavailable`
and exits `EXIT_CONFIG` (`2`) if you ask for PDF output without one.

## Presidio model download fails / is slow

The `[full]` extra includes Presidio for PII detection. Presidio
fetches its spaCy + transformer models on first run. If your CI
runner blocks egress to Hugging Face / PyPI, either pre-bake the
models into your image or fall back to the base install (PII
redaction still runs via the bundled regex `PiiRedactor`; only the
model-driven NER step is skipped).

## AWS Bedrock returns HTTP 403 / "model not enabled in this region"

Bedrock model access is opt-in per AWS account *and* per region. In
the AWS console go to **Bedrock → Model access** and enable the
specific model (e.g. `anthropic.claude-haiku-4-5-v1:0`) in the
region your credentials point to. AgentGuardian then resolves the
model via the standard AWS credential chain — no API key is needed,
only the `[aws]` extra and a configured profile / role.

## The dashboard says port 7474 is already in use

Pick another port:

```bash
agent-guardian serve --port 7479
```

`7474` is the default because it is also Neo4j's default browser
port — chosen so that if you are already running both, the conflict
is obvious. The dashboard binds to `127.0.0.1` by default; if you
intentionally bound to `0.0.0.0` to expose it over the network,
remember to put it behind your usual reverse proxy.

## I see `EgressRefused` errors mid-scan

The sandbox refuses outbound network calls to destinations that are
not on the scan's explicit allowlist. This is intentional —
specialist agents that probe egress channels (ASI04, ASI07) need to
see the refusal as evidence, not actually make the call.

If you are running `agent-guardian` itself behind an egress proxy
and *legitimate* LLM provider traffic is being refused, set the
matching allowlist entries in your `agentguardian.yaml` contract
under `transport.allowed_egress` (see the contract schema —
`agent-guardian contract schema --out contract.schema.json`).

## What do the exit codes mean?

| Code | Constant                  | Meaning                                                                            |
|------|---------------------------|------------------------------------------------------------------------------------|
| `0`  | `EXIT_OK`                 | Scan completed; `--fail-under` (if set) passed; signatures verified.               |
| `1`  | `EXIT_FAIL_UNDER`         | `--fail-under` tripped — *or* `verify` returned `UNANCHORED` / failed signatures.  |
| `2`  | `EXIT_CONFIG`             | Configuration error (bad flag, missing file, malformed contract).                  |
| `3`  | `EXIT_TARGET_UNREACHABLE` | Target endpoint / dotted path could not be reached or imported.                    |
| `4`  | `EXIT_LLM_PROVIDER`       | LLM provider returned an unrecoverable error (auth, quota, region).                |
| `5`  | `EXIT_SANDBOX`            | Sandbox violation — a probe attempted a forbidden action and the policy stopped it.|
| `130`| `EXIT_USER_INTERRUPT`     | Interrupted by SIGINT (Ctrl-C).                                                    |

The full table is also in [CLI reference — Exit codes](cli.md#exit-codes).

## Where do I file a bug / request a probe / propose an adapter?

GitHub Issues:
<https://github.com/glacien-technologies/agent-guardian/issues>.
Security reports go to <security@glacien.ai> — see
[`SECURITY.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/SECURITY.md).
