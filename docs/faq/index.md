# FAQ

> **TL;DR.** The questions adopters most often ask before running AgentGuardian in anger — operational hiccups (WeasyPrint, Presidio, Bedrock 403, port collisions), security-review questions (what leaves the box, is the score reproducible, SIEM integration), and the boring-but-important stuff (exit codes, bug reports). For a *symptom → runbook* lookup, see [Troubleshooting](troubleshooting.md).

## Why does `agent-guardian verify` print `trust anchor: UNANCHORED`?

`verify` fails closed. A signature alone proves only that the bytes
were not tampered with (integrity) — it does **not** prove who signed
them. To anchor the report you must supply at least one of:

- `--pubkey` or `--pubkey-file` (Ed25519, pinned out-of-band).
- `--secret` or `AGENT_GUARDIAN_SIGNING_SECRET` (HMAC).

Without an anchor the command exits **1** and prints `trust anchor:
UNANCHORED`. The default HMAC secret is never accepted on verify, so a
report signed only with the public default also exits non-zero. See
[CLI — verify](../reference/cli.md#verify) for the full anchor semantics and a
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

On Apple Silicon, Homebrew installs into `/opt/homebrew` and WeasyPrint's
ctypes-style native lookup does not always find the libraries on its
own. If `agent-guardian doctor` says `weasyprint: native libs not
loadable`, point `DYLD_FALLBACK_LIBRARY_PATH` at Homebrew's lib dir:

```bash
export DYLD_FALLBACK_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_FALLBACK_LIBRARY_PATH"
agent-guardian doctor          # should now say weasyprint: ok
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
models into your image or fall back to the base install. PII
redaction still runs via the bundled regex `PiiRedactor`
(`src/agent_guardian/core/redact.py`); only the model-driven NER step
is skipped.

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

## I see `EgressRefused` errors mid-scan { #egressrefused }

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

The full table is also in [CLI reference — Exit codes](../reference/cli.md#exit-codes).

---

## What data leaves the box when I run a scan?

Nothing, by default, except calls to the LLM provider you explicitly
configure. AgentGuardian runs in-process — adapter, swarm, judges, and
report writers all execute locally. The bits that do touch the network
are:

- **The configured LLM provider** (OpenAI, Anthropic, Bedrock, Vertex,
  Ollama, or your own HTTP endpoint). Prompts, completions, and judge
  rationales go through whichever provider you pick.
- **The HTTP target itself**, if you are scanning a hosted endpoint
  with `--http`.
- **OTLP traces**, only if you set `--otel-endpoint` or
  `OTEL_EXPORTER_OTLP_ENDPOINT`. Off by default.
- **Telemetry**, only if you opted in with `agent-guardian telemetry
  enable`. Off by default. See `src/agent_guardian/telemetry/`.

The signed evidence pack is written to local disk under
`$AGENT_GUARDIAN_HOME/scans/<id>/` and is never auto-uploaded. The
`agent-guardian publish` command is the only path that would ship a
scan elsewhere, and it requires an explicit destination flag.

PII redaction (`src/agent_guardian/core/redact.py`) is applied to the
report payload before signing, so a saved JSON does not carry raw
prompts verbatim. See [Security → Data flow](../security/data-flow.md) and [Security → Signing & verification](../security/signing.md).

## Is the AIVSS score reproducible?

Yes, with two preconditions: deterministic scan mode and the same
seed-probe corpus version. AgentGuardian propagates a user-supplied
RNG seed end-to-end, freezes the seed-probe corpus per release
(currently `2026.05`, see
`src/agent_guardian/probes/loader.py:PROBE_CORPUS_VERSION`), and
serialises reports canonically before signing. The same target +
same seed + same corpus version + same scan mode produces a
byte-identical signed JSON. See [Concepts → Scan modes](../concepts/scan-modes.md)
for the determinism guarantees per mode.

The signed report also carries a `mode_authoritative` boolean: if the
probe corpus failed to load or the scan was a stub-run, the report
explicitly marks itself NON-AUTHORITATIVE so downstream consumers do
not aggregate it into real numbers.

## How do I integrate with my SIEM?

The OSS package emits SARIF 2.1.0 (`src/agent_guardian/reports/sarif.py`,
covered by `tests/unit/reports/test_sarif_contract.py`) plus JUnit XML
and JSON; that is enough to wire into Splunk, Sentinel, Chronicle, and
Elastic via their standard SARIF/JSON ingest. Native connectors and
CEF/ECS event streaming are part of the commercial platform — see the
[Roadmap](../reference/roadmap.md) for the open-source delta. A "forward SARIF to
SIEM" how-to is planned for v1.1; in the meantime the SARIF file written
under `$AGENT_GUARDIAN_HOME/scans/<id>/scan.sarif` is the integration
surface.

## Which agent frameworks does the OSS swarm support today?

The v1.0 wheel ships six framework adapters as concrete subclasses of
`FrameworkAdapter`
([`src/agent_guardian/adapters/framework/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/adapters/framework)):

- **LangGraph** (`LangGraphAdapter`)
- **CrewAI** (`CrewAIAdapter`)
- **AutoGen** (`AutoGenAdapter`)
- **OpenAI Agents SDK** (`OpenAIAgentsAdapter`)
- **Strands** (`StrandsAdapter`)
- **Google ADK** (`ADKAdapter`)

The adapter *classes* are stable; the CLI `--framework` dispatcher is
the path that wires them up for non-Python callers — see
[Targets & Adapters → Framework](../integrations/adapters/framework.md).

Adapters explicitly **not yet** shipped, with the issue they live in:

- **PydanticAI** — v1.1.
- **Anthropic Claude Agent SDK** — v1.1.
- **MCP server adapter** (scan a running MCP server directly) — v1.1.
- **LlamaIndex, AG2, Semantic Kernel** — v1.2.

See [Roadmap](../reference/roadmap.md) for the current status. Anything not on
that list is "not in the OSS package today"; the
marketing site's longer integration grid covers the commercial
platform.

## Why does the same target read a different AIVSS in `--mode smart` than in `--mode full`?

That is expected and the gate catches it. The three modes are an
explicit thoroughness-vs-cost trade-off (see
[Scan modes](../concepts/scan-modes.md)) — `full` runs every probe to
completion, `smart` honours an early-stop on a stable signal, `fast`
caps turns/probes. So on the same target the *numeric* AIVSS can
swing — in our internal regression run the same defenceless target
read AIVSS=66 in REAL `--mode full`, 41 in `smart`, and 55 in `fast`.

What is guaranteed is that **smart / fast cannot mint a `GOOD` or
`EXCELLENT` verdict that `full` would not have given** (#44). When the
mode runs below its completeness threshold (FAST 60 % / SMART 80 % /
FULL 95 %), the swarm sets `mode_authoritative=False`, the band is
forced to `NOT_EVALUATED`, `--fail-under` fails the run with a
non-zero exit, and a stderr warning fires. The flag rides inside the
signature on the JSON report, so a downstream consumer can also tell
a partial-coverage scan from a real assessment.

Practical rules:

- **For a CI gate**, always run `--mode full` and key your
  `--fail-under` against `band` (or `scan.mode_authoritative`), not
  the raw `aivss` number — a partial-mode run is designed to fail
  fail-under so you can never silently green-light an under-tested
  scan.
- **For a fast pre-flight in development**, `--mode fast` /
  `--mode smart` is fine to surface obvious issues — just treat its
  AIVSS as a *floor on risk*, not an authoritative grade.
- The `mode_authoritative` field is in the signed JSON report
  (`jq -r '.mode_authoritative' scan.json`) and in the `audit` block
  on every SARIF / Markdown / JUnit emission.

The gate is enforced in `core/swarm.py:_phase_finalise`; the
completeness thresholds live on `SwarmConfig`. A successful
CRITICAL / HIGH finding additionally clamps the headline band out of
`GOOD` / `EXCELLENT` regardless of mode (#46 belt-and-suspenders) —
see `core/scoring.py:_HIGH_SEVERITY_BAND_CAP`.

---

## Why does my stub scan say `AIVSS=100 EXCELLENT` in `last-score` but the report says `band=NOT_EVALUATED`?

Up through 1.0.0rc1 there was a gap where `agent-guardian last-score`
read the cached numeric score independently of the report's
authoritative flag. A scan run against the bundled stub LLM (no real
attacker, no real probes that landed) would score 100/100 because no
probes failed — but the report itself correctly carried `band =
NOT_EVALUATED` because the corpus had not actually executed.

The fix lands in v1.1: `last-score` consults
`scan.mode_authoritative` and prints `NOT_EVALUATED` instead of
`EXCELLENT` for stub / vacuous scans. Until then, treat any
`EXCELLENT` from a stub LLM as decorative and read the band from the
signed JSON report directly (`jq -r '.band' scan.json`).

The underlying authoritative-flag plumbing is in
`src/agent_guardian/probes/loader.py:last_load_was_authoritative()`
and the band override happens in the swarm finaliser; both are stable
since 989fab1.

---

## Where do I file a bug / request a probe / propose an adapter?

GitHub Issues:
<https://github.com/glacien-technologies/agent-guardian/issues>.
Security reports go to <security@glacien.ai> — see
[`SECURITY.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/SECURITY.md).
