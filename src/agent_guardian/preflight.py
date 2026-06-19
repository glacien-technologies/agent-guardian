"""QA-068 — top-of-scan PREFLIGHT phase narration.

Operator request (2026-06-02): before recon kicks off, narrate four readiness
sub-stages so the scrollback opens with a clean PREFLIGHT block:

  preflight model.invoke: <model> reachable (200 OK in <latency_ms>ms)
  preflight target.ping: <url> validated (HTTP 200, <latency_ms>ms)
  preflight contract.schema_check: <path> ok
  preflight budget.parse: usd=$<budget>, seconds=<seconds>

The target.ping stage is status-aware: a 2xx is "validated", a 401/403 is
"reachable but returned HTTP 403 — check authorization", a 4xx/5xx is called
out as reachable-but-unhealthy, and a connect/timeout is "unreachable".

Each sub-stage emits ONE INFO line on success and ONE WARNING line on failure
with a remediation hint. Failures do NOT abort the scan — the operator may
intentionally scan against an unreachable model for testing. The scan command
fails at its natural failure point regardless.

The MVP implementation uses small helper functions over the existing primitives
(``check_model_exists``, ``_endpoint_reachability_preflight``) so the wire is a
single sequential block at the top of the scan command. Each primitive already
does the network probe; this module wraps them to surface ONE structured INFO
line per stage in operator-friendly shape.
"""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass
from typing import Final

__all__ = [
    "PreflightOutcome",
    "PreflightQuotaError",
    "preflight_budget_parse",
    "preflight_contract_schema",
    "preflight_gemini_quota",
    "preflight_model_invoke",
    "preflight_target_ping",
    "run_scan_preflight",
]

_LOG = logging.getLogger("agent_guardian.preflight")


class PreflightQuotaError(RuntimeError):
    """Raised by :func:`run_scan_preflight` when the active provider's quota is
    already exhausted (a 429 on a cheap pre-flight completion).

    rc38 P0-#5 (#263): the CLI catches this and fails fast with
    ``EXIT_LLM_PROVIDER`` BEFORE recon, so a doomed scan never spends the
    recon / seat-prep budget only to 429 in flight.
    """

    def __init__(self, spec: str, detail: str = "") -> None:
        self.spec = spec
        self.detail = detail
        super().__init__(
            f"provider quota exhausted for {spec}"
            + (f" ({detail})" if detail else "")
            + " — check billing/quota"
        )


# Env-var hint per provider, keyed by ``split_spec`` provider prefix.
_PROVIDER_ENV_HINT: Final[dict[str, str]] = {
    "openai": "AGENT_GUARDIAN_OPENAI_API_KEY (or OPENAI_API_KEY)",
    "anthropic": "AGENT_GUARDIAN_ANTHROPIC_API_KEY (or ANTHROPIC_API_KEY)",
    "gemini": "AGENT_GUARDIAN_GEMINI_API_KEY (or GEMINI_API_KEY / GOOGLE_API_KEY)",
    "vertex": "GOOGLE_APPLICATION_CREDENTIALS (gcloud auth)",
    "ollama": "OLLAMA_HOST",
    "bedrock": "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (or IAM role)",
}


@dataclass(frozen=True)
class PreflightOutcome:
    """Per-stage outcome. ``ok=True`` even on transient/skip so callers can
    log uniformly. ``ok=False`` only when the stage is confirmed-broken with
    a remediation hint worth printing."""

    stage: str
    ok: bool
    detail: str = ""
    remediation: str = ""


def preflight_model_invoke(spec: str) -> PreflightOutcome:
    """Stage 1 — model.invoke. Probe the provider's models endpoint.

    Reuses :func:`agent_guardian.llm.validation.check_model_exists` (cached
    per-spec for the rest of the scan) and surfaces the outcome as one INFO
    or WARNING line.
    """
    from agent_guardian.llm.validation import check_model_exists, split_spec

    provider, _model = split_spec(spec)
    if provider in {"stub", "unknown"}:
        _LOG.info("preflight model.invoke: %s skipped (stub/unrecognised provider)", spec)
        return PreflightOutcome(stage="model.invoke", ok=True, detail="skipped")

    t0 = time.monotonic()
    result = check_model_exists(spec)
    latency_ms = int((time.monotonic() - t0) * 1000)

    if result.valid and result.status == "valid":
        _LOG.info(
            "preflight model.invoke: %s reachable (200 OK in %dms)",
            spec,
            latency_ms,
        )
        return PreflightOutcome(stage="model.invoke", ok=True, detail=f"{latency_ms}ms")
    if result.status == "auth_failed":
        env_hint = _PROVIDER_ENV_HINT.get(provider, f"<{provider.upper()}_API_KEY>")
        _LOG.warning(
            "preflight model.invoke: %s auth_failed — check %s env var",
            spec,
            env_hint,
        )
        return PreflightOutcome(
            stage="model.invoke",
            ok=False,
            detail="auth_failed",
            remediation=f"set {env_hint}",
        )
    if result.status == "not_found":
        suggestion = result.suggestion or ""
        _LOG.warning(
            "preflight model.invoke: %s not_found — provider returned 404%s",
            spec,
            f" (did you mean: {suggestion})" if suggestion else "",
        )
        return PreflightOutcome(
            stage="model.invoke",
            ok=False,
            detail="not_found",
            remediation=suggestion,
        )
    # transient / unsupported — treat as informational; continue.
    _LOG.info(
        "preflight model.invoke: %s status=%s (continuing — will surface at first call if persistent)",
        spec,
        result.status,
    )
    return PreflightOutcome(stage="model.invoke", ok=True, detail=result.status)


async def preflight_target_ping(endpoint: str | None) -> PreflightOutcome:
    """Stage 2 — target.ping. Reuse the existing endpoint reachability probe.

    Skips when there is no ``--endpoint`` to probe (prompt mode, Python target
    mode, framework mode). Failures emit WARNING but do not abort the scan.
    """
    if not endpoint:
        _LOG.info("preflight target.ping: skipped (no --endpoint configured)")
        return PreflightOutcome(stage="target.ping", ok=True, detail="skipped")

    # Lazy import to avoid pulling httpx at module-import time in tests that
    # never exercise the ping path. Sourced from the leaf
    # ``_endpoint_preflight`` module so we don't pull the whole CLI module
    # graph (and don't form an import cycle).
    from agent_guardian._endpoint_preflight import (
        _classify_endpoint_health,
        _is_placeholder_endpoint,
    )

    if _is_placeholder_endpoint(endpoint):
        _LOG.info(
            "preflight target.ping: skipped (%s is a placeholder host)",
            endpoint,
        )
        return PreflightOutcome(stage="target.ping", ok=True, detail="placeholder")

    t0 = time.monotonic()
    try:
        health = await _classify_endpoint_health(endpoint)
    except Exception as exc:  # pragma: no cover — defensive
        _LOG.warning(
            "preflight target.ping: %s probe raised %s: %s — continuing",
            endpoint,
            type(exc).__name__,
            exc,
        )
        return PreflightOutcome(
            stage="target.ping",
            ok=False,
            detail=f"{type(exc).__name__}: {exc}",
            remediation="verify endpoint URL + network reachability",
        )
    latency_ms = int((time.monotonic() - t0) * 1000)

    # Classify the outcome so the operator sees WHAT happened, not just that
    # *something* answered. A 2xx is validated; a 401/403 means the box is up
    # but our credentials/headers are wrong; a 4xx/5xx means it answered but
    # unhealthily; unreachable means transport-level down.
    if health.classification == "healthy":
        _LOG.info(
            "preflight target.ping: %s validated (HTTP %d, %dms)",
            endpoint,
            health.status_code,
            latency_ms,
        )
        return PreflightOutcome(
            stage="target.ping",
            ok=True,
            detail=f"HTTP {health.status_code}, {latency_ms}ms",
        )
    if health.classification == "auth_failed":
        _LOG.warning(
            "preflight target.ping: %s reachable but returned HTTP %d — check authorization "
            "(credentials/headers), the target is up (%dms)",
            endpoint,
            health.status_code,
            latency_ms,
        )
        return PreflightOutcome(
            stage="target.ping",
            ok=False,
            detail=f"auth_failed (HTTP {health.status_code}, {latency_ms}ms)",
            remediation="check authorization — verify credentials/auth headers for the target",
        )
    if health.classification == "client_error":
        _LOG.warning(
            "preflight target.ping: %s reachable but returned HTTP %s — request rejected "
            "by the target (check URL/route + request shape), the target is up (%dms)",
            endpoint,
            health.status_code if health.status_code is not None else "error",
            latency_ms,
        )
        return PreflightOutcome(
            stage="target.ping",
            ok=False,
            detail=f"client_error (HTTP {health.status_code}, {latency_ms}ms)",
            remediation="verify the endpoint URL/route and the request body shape",
        )
    if health.classification == "server_error":
        _LOG.warning(
            "preflight target.ping: %s reachable but returned HTTP %d — target erroring "
            "internally, the listener is up (%dms)",
            endpoint,
            health.status_code,
            latency_ms,
        )
        return PreflightOutcome(
            stage="target.ping",
            ok=False,
            detail=f"server_error (HTTP {health.status_code}, {latency_ms}ms)",
            remediation="target returned 5xx — check the target's own logs/health",
        )
    # unreachable — transport-level fault (connect/timeout).
    _LOG.warning(
        "preflight target.ping: %s unreachable — verify URL and that the target is live",
        endpoint,
    )
    return PreflightOutcome(
        stage="target.ping",
        ok=False,
        detail="unreachable",
        remediation="verify URL + network reachability",
    )


def preflight_contract_schema(contract_path: object | None) -> PreflightOutcome:
    """Stage 3 — contract.schema_check. Cheap shape check of the contract path.

    Full contract preflight (the 7-stage transport probe in
    ``contract/preflight.py``) runs separately when ``--contract`` is supplied.
    This narration just confirms the contract path resolves to a readable
    file so the operator catches a typo'd path BEFORE the swarm spins up.
    """
    if contract_path is None:
        _LOG.info("preflight contract.schema_check: skipped (no --contract supplied)")
        return PreflightOutcome(stage="contract.schema_check", ok=True, detail="skipped")

    from pathlib import Path

    path = Path(str(contract_path)).expanduser()
    if not path.exists():
        _LOG.warning(
            "preflight contract.schema_check: %s not found — check the --contract path",
            path,
        )
        return PreflightOutcome(
            stage="contract.schema_check",
            ok=False,
            detail="missing",
            remediation=f"create {path} or correct --contract",
        )
    if not path.is_file():
        _LOG.warning(
            "preflight contract.schema_check: %s is not a file",
            path,
        )
        return PreflightOutcome(
            stage="contract.schema_check",
            ok=False,
            detail="not_a_file",
            remediation=f"point --contract at the YAML file under {path}",
        )
    _LOG.info("preflight contract.schema_check: %s ok", path)
    return PreflightOutcome(stage="contract.schema_check", ok=True, detail=str(path))


def preflight_budget_parse(
    budget_usd: float | None,
    budget_seconds: float | None,
) -> PreflightOutcome:
    """Stage 4 — budget.parse. Confirm both budget knobs are parseable / non-negative.

    Today these knobs fail late (at scan-start) when malformed; this stage
    emits a single INFO line so the operator sees the actual parsed values
    before the swarm spins up. Negative values trigger a WARNING and a
    remediation hint, but do not abort.
    """
    usd_repr = "uncapped" if budget_usd is None else f"${budget_usd:.4f}"
    sec_repr = "uncapped" if budget_seconds is None else f"{budget_seconds:.0f}s"

    errs: list[str] = []
    if budget_usd is not None and budget_usd < 0:
        errs.append("budget_usd must be ≥ 0")
    if budget_seconds is not None and budget_seconds < 0:
        errs.append("budget_seconds must be ≥ 0")

    if errs:
        _LOG.warning(
            "preflight budget.parse: invalid — %s (got usd=%s seconds=%s)",
            "; ".join(errs),
            usd_repr,
            sec_repr,
        )
        return PreflightOutcome(
            stage="budget.parse",
            ok=False,
            detail="invalid",
            remediation="pass non-negative --budget-usd and --budget-seconds",
        )
    _LOG.info(
        "preflight budget.parse: usd=%s, seconds=%s",
        usd_repr,
        sec_repr,
    )
    return PreflightOutcome(stage="budget.parse", ok=True, detail=f"usd={usd_repr} sec={sec_repr}")


async def preflight_gemini_quota(spec: str) -> PreflightOutcome:
    """rc38 P0-#5 (#263) — Gemini quota fail-fast probe.

    The generic :func:`preflight_model_invoke` stage only probes the *models*
    listing endpoint (``check_model_exists``); a key whose listing succeeds can
    still be hard-429'd on ``generateContent``. This stage sends ONE cheap
    completion via :meth:`GeminiClient.preflight` so a quota-exhausted key is
    caught BEFORE recon commits the scan budget.

    Only runs for the ``gemini`` provider; every other provider (and stub) is a
    no-op skip so non-Gemini scans are unaffected. ``ok=False`` is returned ONLY
    on a confirmed quota miss (429); every other failure mode (auth / network /
    format) is left to surface on the first real completion, matching the
    fail-soft contract of the other stages.
    """
    from agent_guardian.llm.validation import split_spec

    provider, model = split_spec(spec)
    if provider != "gemini":
        # Silent skip for non-Gemini providers — no extra narration line so the
        # PREFLIGHT block stays clean for the common case.
        return PreflightOutcome(stage="model.quota", ok=True, detail="skipped")

    from agent_guardian.llm.errors import LLMRateLimitError

    try:
        from agent_guardian.llm.registry import build_llm

        client = build_llm(spec, role="preflight")
    except Exception as exc:  # pragma: no cover — construction failure surfaces later
        _LOG.debug(
            "preflight model.quota: %s client construction failed (%s) — "
            "letting the real call surface it",
            spec,
            exc,
        )
        return PreflightOutcome(stage="model.quota", ok=True, detail="skipped")

    try:
        try:
            # ``preflight`` is a GeminiClient-only cheap-completion probe. Look it
            # up defensively (mirrors the ``aclose`` lookup below) so the typed
            # ``BaseLLM`` return of ``build_llm`` doesn't force a hard dependency on
            # the concrete class; a client without it degrades to a silent skip.
            probe = getattr(client, "preflight", None)
            if probe is None:
                return PreflightOutcome(stage="model.quota", ok=True, detail="skipped")
            await probe(model or "gemini-2.5-flash")
        finally:
            close = getattr(client, "aclose", None)
            if close is not None:
                with contextlib.suppress(Exception):
                    await close()
    except LLMRateLimitError as exc:
        _LOG.warning(
            "preflight model.quota: %s quota exhausted (429) — failing fast before recon; "
            "check the provider's billing/quota dashboard",
            spec,
        )
        return PreflightOutcome(
            stage="model.quota",
            ok=False,
            detail=f"quota_exhausted: {exc}",
            remediation="Gemini quota exhausted — check billing/quota and retry later",
        )
    _LOG.info("preflight model.quota: %s ok (cheap completion accepted)", spec)
    return PreflightOutcome(stage="model.quota", ok=True, detail="ok")


async def run_scan_preflight(
    *,
    model_spec: str,
    endpoint: str | None,
    contract_path: object | None,
    budget_usd: float | None,
    budget_seconds: float | None,
) -> list[PreflightOutcome]:
    """Run the readiness stages in order. Always returns the full outcome list.

    Failure of most individual stages does NOT raise — the caller can inspect
    the outcomes list if they want to act on a specific failure, so the
    operator can scan against a known-unreachable target for testing.

    rc38 P0-#5 (#263) — the Gemini quota stage is the ONE exception: a
    confirmed quota miss (429 on a cheap pre-flight completion) raises
    :class:`PreflightQuotaError` so the scan fails fast BEFORE recon rather
    than spending the recon budget on a doomed run. Non-Gemini providers and
    stub mode never reach the raising path.
    """
    outcomes: list[PreflightOutcome] = []
    outcomes.append(preflight_model_invoke(model_spec))
    # Gemini quota fail-fast — runs (and can raise) only for the gemini
    # provider; a no-op skip for every other provider and stub mode.
    quota = await preflight_gemini_quota(model_spec)
    outcomes.append(quota)
    if not quota.ok:
        raise PreflightQuotaError(model_spec, quota.detail)
    outcomes.append(await preflight_target_ping(endpoint))
    outcomes.append(preflight_contract_schema(contract_path))
    outcomes.append(preflight_budget_parse(budget_usd, budget_seconds))
    return outcomes
