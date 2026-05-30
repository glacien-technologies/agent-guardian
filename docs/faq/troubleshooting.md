# Troubleshooting

> **TL;DR.** Symptom catalogue — one row per failure mode you might see in the terminal, each pointing at the page that actually fixes it. For the longer-form Q&A (security review, scoring, scope), see the [FAQ](index.md).

## Common symptoms

| What you see                                                                  | What is happening                                                                      | Go fix it at                                                                  |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `pip install 'agent-guardian[full]'` errors on a `weasyprint` native dep      | Pango / Cairo / HarfBuzz system libs missing or unreachable.                            | [FAQ — WeasyPrint native deps](index.md#pip-install-agent-guardianfull-fails-on-weasyprint-native-deps) |
| `weasyprint: native libs not loadable` on Apple Silicon                       | Homebrew under `/opt/homebrew`; ctypes can't find the libs.                             | [FAQ — WeasyPrint native deps](index.md#pip-install-agent-guardianfull-fails-on-weasyprint-native-deps) (DYLD_FALLBACK note) |
| `Presidio: model download failed` on first run                                | CI runner cannot reach Hugging Face / PyPI for spaCy models.                            | [FAQ — Presidio model download](index.md#presidio-model-download-fails-is-slow) |
| `boto3` raises `AccessDeniedException` / HTTP 403 on Bedrock invoke           | Region or account doesn't have Bedrock model access enabled.                            | [FAQ — Bedrock 403](index.md#aws-bedrock-returns-http-403-model-not-enabled-in-this-region) |
| `OSError: [Errno 48] Address already in use` on `agent-guardian serve`        | Port 7474 is occupied (Neo4j or a previous run).                                        | [FAQ — dashboard port](index.md#the-dashboard-says-port-7474-is-already-in-use) |
| `EgressRefused` mid-scan, exit code `5` (`EXIT_SANDBOX`)                      | A probe / the runtime hit a destination not on the contract's egress allowlist.         | [FAQ — EgressRefused](index.md#egressrefused)                                 |
| `verify` prints `trust anchor: UNANCHORED`, exits `1`                         | No `--pubkey` or `--secret` supplied; verify fails closed.                              | [FAQ — UNANCHORED](index.md#why-does-agent-guardian-verify-print-trust-anchor-unanchored) |
| `verify` prints `HMAC-SHA256: FAIL`                                           | Wrong HMAC secret (or report was tampered).                                             | [CLI — verify](../reference/cli.md#verify), then [FAQ — UNANCHORED](index.md#why-does-agent-guardian-verify-print-trust-anchor-unanchored) for the anchor model |
| `last-score` says `EXCELLENT` for a stub-LLM scan but report says `NOT_EVALUATED` | Authoritative-flag plumbing landed; `last-score` UX fix lands in v1.1.                  | [FAQ — stub `EXCELLENT`](index.md#why-does-my-stub-scan-say-aivss100-excellent-in-last-score-but-the-report-says-bandnot_evaluated) |
| `agent-guardian doctor` exits `2` (`EXIT_CONFIG`)                             | A required runtime prerequisite is missing (Python version, PDF engine, an LLM key…).   | Run `agent-guardian doctor --verbose` and follow the per-check hints.         |
| `--fail-under` tripped, CI build red                                          | The scan finished but the AIVSS is below the gate threshold.                            | [Concepts → Scan modes — picking a `--fail-under`](../concepts/scan-modes.md#picking-a-fail-under-per-mode) |
| `EXIT_TARGET_UNREACHABLE` (`3`)                                               | The dotted path / HTTP endpoint couldn't be imported / reached.                         | Check the [exit-code table](index.md#what-do-the-exit-codes-mean); re-run with `--verbose`. |

If your symptom is not here, search the FAQ and the
[CLI reference](../reference/cli.md). If still stuck, open a GitHub issue with
the failing command, the full output, the OS, and the installed
version (`agent-guardian version`).

## Reporting issues

GitHub Issues: <https://github.com/glacien-technologies/agent-guardian/issues>.

Security reports: <security@glacien.ai>. See
[Security → Responsible disclosure](../security/responsible-disclosure.md).
