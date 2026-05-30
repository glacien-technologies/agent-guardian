"""Fail-fast model-spec validation (QA-001).

Closes QA-001 + addendum: before we burn an 87-second swarm scan + a stack of
tokens on a typo'd model id, ping the provider's models endpoint once at scan
startup, classify the response, and exit cleanly with a "did you mean" hint.

The probe is deliberately:

* **Cheap.** One HTTP call per ``(provider, model)`` tuple. Cached per-session
  so dispatching the same id across the attacker / evaluator / commander triple
  costs exactly one round-trip.
* **Conservative on transient errors.** 5xx, network blip, or timeout
  downgrades to a *warning* — we'd rather run a scan that surfaces the real
  error at first call than block on a 30-second AI Studio outage.
* **Auth-free where possible.** The Vertex cross-check probe deliberately
  hits the anonymous publisher catalog endpoint — no ADC required to *check
  existence*, only to *invoke*. That keeps the "did you mean vertex:<id>"
  affordance available for users who haven't run ``gcloud auth`` yet.

Public surface:

* :func:`check_model_exists` — main entry point. Returns a
  :class:`ModelValidationResult`.
* :class:`ModelValidationResult` — frozen dataclass with ``valid``, ``status``,
  ``message``, ``suggestion``.
* :data:`KNOWN_MODELS` — per-provider stable-name allow-list used for the
  ``difflib`` "did you mean" suggestion when the provider responds 404 (or
  before we even probe, when the user is offline).
* :func:`clear_cache` — testing helper to reset the per-session cache.
"""

from __future__ import annotations

import difflib
import logging
import os
from dataclasses import dataclass, field
from typing import Final, Literal

import httpx

__all__ = [
    "EXIT_LLM_PROVIDER",
    "KNOWN_MODELS",
    "ModelValidationResult",
    "ValidationStatus",
    "check_model_exists",
    "clear_cache",
    "split_spec",
]

_LOG = logging.getLogger(__name__)

#: Exit code returned by the CLI when a model is confirmed-unknown. Kept in
#: lockstep with ``cli.EXIT_LLM_PROVIDER`` (value 4 — see DESIGN_LOCK §QA-001).
EXIT_LLM_PROVIDER: Final[int] = 4

# Default network budget per probe. Operators on a flaky link can override via
# the ``AGENT_GUARDIAN_MODEL_PROBE_TIMEOUT`` env var; we cap at 4s by default so
# fail-fast stays within the QA-001 acceptance target of ≤ 5s wallclock.
_DEFAULT_TIMEOUT_S: Final[float] = 4.0

# Anonymous Vertex publisher-catalog endpoint. No auth required for the
# existence check (the catalog is public). Region-agnostic — the publisher
# catalog is global, not per-region.
_VERTEX_PUBLISHER_URL: Final[str] = (
    "https://us-central1-aiplatform.googleapis.com/v1/publishers/google/models/{model}"
)

# AI Studio (generativelanguage.googleapis.com) models endpoint.
_GEMINI_MODELS_URL: Final[str] = "https://generativelanguage.googleapis.com/v1beta/models/{model}"

# OpenAI / Anthropic / Ollama endpoints.
_OPENAI_MODELS_URL: Final[str] = "https://api.openai.com/v1/models/{model}"
_ANTHROPIC_MODELS_URL: Final[str] = "https://api.anthropic.com/v1/models/{model}"
_OLLAMA_API_SHOW_PATH: Final[str] = "/api/show"
_DEFAULT_OLLAMA_HOST: Final[str] = "http://localhost:11434"


ValidationStatus = Literal[
    "valid",  # Provider confirms the model exists.
    "not_found",  # Provider returned 404 — confirmed-unknown.
    "auth_failed",  # 401 / 403 — surface as config error (EXIT_CONFIG).
    "transient",  # 5xx / network / timeout — warn and continue.
    "unsupported",  # Provider exists but we don't yet probe it cleanly (e.g. legacy stub).
]


#: Stable known-good model ids per provider. Used to power the ``difflib``
#: "did you mean" suggestion. Intentionally short: the *current* stable
#: family per provider, not an exhaustive historical list. New entries are
#: cheap to add but the surface should not grow without need — every entry
#: is a string the user might plausibly type today and have it work.
KNOWN_MODELS: Final[dict[str, tuple[str, ...]]] = {
    "openai": (
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-4",
        "gpt-3.5-turbo",
        "o1",
        "o1-mini",
        "o3-mini",
    ),
    "anthropic": (
        "claude-opus-4-5",
        "claude-sonnet-4-5",
        "claude-haiku-4-5",
        "claude-3-7-sonnet-latest",
        "claude-3-5-sonnet-latest",
        "claude-3-5-haiku-latest",
    ),
    "gemini": (
        "gemini-2.5-flash",
        "gemini-2.5-pro",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-1.5-flash-8b",
    ),
    "vertex": (
        "gemini-2.5-flash",
        "gemini-2.5-pro",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
    ),
}


@dataclass(frozen=True)
class ModelValidationResult:
    """Outcome of one ``check_model_exists`` call.

    Fields:

    * ``valid`` — ``True`` when the CLI should continue (model exists OR the
      probe was transient/skipped).
    * ``status`` — narrow literal for callers that want to branch.
    * ``provider`` / ``model`` — echoed back so the caller can build the error
      message without re-parsing the spec.
    * ``message`` — operator-readable explanation. Empty when ``valid`` and the
      probe came back clean.
    * ``suggestion`` — optional "did you mean" line. Always one of:
      ``"--model <prefix>:<candidate>"`` or empty.
    """

    valid: bool
    status: ValidationStatus
    provider: str = ""
    model: str = ""
    message: str = ""
    suggestion: str = ""


# ---------------------------------------------------------------------------
# Per-session cache. Lives only for the lifetime of the CLI process.
# ---------------------------------------------------------------------------


_CACHE: dict[tuple[str, str], ModelValidationResult] = {}


def clear_cache() -> None:
    """Drop every cached probe result.

    Testing helper. Production code does not need this — the cache is
    process-scoped and dies with the CLI process.
    """
    _CACHE.clear()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def split_spec(spec: str) -> tuple[str, str]:
    """Split a ``"<provider>:<model>"`` spec into its parts.

    Mirrors :func:`agent_guardian.cli.build_llm`'s parsing rules so the
    validation probe sees the exact same provider/model pair the LLM
    factory will see at scan time. Heuristic prefixes (``gpt-*``,
    ``claude-*``, ``gemini-*``, ``ollama-*``) are honoured.

    Returns ``(provider, model)``. ``provider`` is lower-cased. ``"stub"``
    and the empty string normalise to ``("stub", "")``.
    """
    raw = (spec or "stub").strip()
    if raw.lower() == "stub" or raw == "":
        return ("stub", "")
    if ":" in raw:
        provider, _, model = raw.partition(":")
        return (provider.lower(), model)
    lowered = raw.lower()
    if lowered.startswith("gpt-") or lowered.startswith("o1") or lowered.startswith("o3"):
        return ("openai", raw)
    if lowered.startswith("claude-"):
        return ("anthropic", raw)
    if lowered.startswith("gemini-"):
        return ("gemini", raw)
    if lowered.startswith("ollama-"):
        return ("ollama", raw)
    # Unknown / inferable — let the LLM factory raise its own error; the
    # validator returns ``unsupported`` so the CLI doesn't fail-fast on a
    # spec the factory has not yet rejected.
    return ("unknown", raw)


def check_model_exists(
    spec: str,
    *,
    timeout_s: float | None = None,
    client_factory: type[httpx.Client] | None = None,
) -> ModelValidationResult:
    """Validate a model spec against the provider's models endpoint.

    Caches per ``(provider, model)`` for the lifetime of the process.

    * Stub / empty spec → ``valid`` without any network call.
    * Recognised providers (openai, anthropic, gemini, vertex, ollama,
      bedrock) → one probe call. Gemini 404 triggers an additional Vertex
      cross-check; if Vertex has the id, the suggestion line is
      ``--model vertex:<id>``.
    * Unrecognised providers → ``status="unsupported"``, ``valid=True``
      (let the LLM factory raise the user-facing error at construction
      time — keeps the validator behaviour conservative).

    Network / 5xx / timeout downgrades to ``status="transient"`` with
    ``valid=True``: the scan continues. The first agent's first call will
    surface the underlying error if the outage persists.

    The ``client_factory`` parameter is for testing — it accepts an
    ``httpx.Client`` subclass (so tests can pass ``httpx.MockTransport``
    via a partial). Production callers leave it ``None``.
    """
    if os.environ.get("AGENT_GUARDIAN_SKIP_MODEL_PROBE") == "1":
        _LOG.debug("AGENT_GUARDIAN_SKIP_MODEL_PROBE=1; bypassing model probe")
        return ModelValidationResult(valid=True, status="valid")

    provider, model = split_spec(spec)
    cache_key = (provider, model)
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    effective_timeout = timeout_s if timeout_s is not None else _resolve_default_timeout()

    if provider == "stub":
        result = ModelValidationResult(valid=True, status="valid", provider="stub", model="")
    elif provider == "unknown":
        # Cannot probe what we cannot route. Conservative pass-through —
        # the LLM factory's own BadParameter is the right surface.
        result = ModelValidationResult(
            valid=True,
            status="unsupported",
            provider=provider,
            model=model,
        )
    elif provider == "openai":
        result = _probe_openai(model, timeout_s=effective_timeout, factory=client_factory)
    elif provider == "anthropic":
        result = _probe_anthropic(model, timeout_s=effective_timeout, factory=client_factory)
    elif provider == "gemini":
        result = _probe_gemini(model, timeout_s=effective_timeout, factory=client_factory)
    elif provider == "vertex":
        result = _probe_vertex(model, timeout_s=effective_timeout, factory=client_factory)
    elif provider == "ollama":
        result = _probe_ollama(model, timeout_s=effective_timeout, factory=client_factory)
    elif provider == "bedrock":
        result = _probe_bedrock(model)
    else:
        # Defensive — split_spec already collapses unknown shapes to
        # "unknown"; this branch only fires if a future provider is added
        # to split_spec without a probe.
        result = ModelValidationResult(
            valid=True,
            status="unsupported",
            provider=provider,
            model=model,
            message=f"no probe implemented for provider '{provider}'",
        )

    _CACHE[cache_key] = result
    return result


# ---------------------------------------------------------------------------
# Per-provider probes
# ---------------------------------------------------------------------------


def _resolve_default_timeout() -> float:
    """Pick the per-probe timeout: env override > default 4s."""
    raw = os.environ.get("AGENT_GUARDIAN_MODEL_PROBE_TIMEOUT")
    if not raw:
        return _DEFAULT_TIMEOUT_S
    try:
        return max(0.5, float(raw))
    except ValueError:
        _LOG.warning(
            "AGENT_GUARDIAN_MODEL_PROBE_TIMEOUT=%r is not a float; using default %.1fs",
            raw,
            _DEFAULT_TIMEOUT_S,
        )
        return _DEFAULT_TIMEOUT_S


def _new_client(
    factory: type[httpx.Client] | None,
    *,
    timeout_s: float,
) -> httpx.Client:
    if factory is not None:
        return factory(timeout=timeout_s)
    return httpx.Client(timeout=timeout_s)


@dataclass(frozen=True)
class _ProbeOutcome:
    """Narrow internal type — one HTTP probe's classified response."""

    status: ValidationStatus
    detail: str = ""
    extra: dict[str, object] = field(default_factory=dict)


def _classify_response(
    response: httpx.Response,
    *,
    not_found_codes: tuple[int, ...] = (404,),
    auth_codes: tuple[int, ...] = (401, 403),
) -> _ProbeOutcome:
    code = response.status_code
    if 200 <= code < 300:
        return _ProbeOutcome(status="valid")
    if code in not_found_codes:
        body = ""
        try:
            body = response.text[:512]
        except Exception:  # pragma: no cover - defensive
            body = ""
        return _ProbeOutcome(status="not_found", detail=body)
    if code in auth_codes:
        return _ProbeOutcome(status="auth_failed", detail=f"HTTP {code}")
    # 400 from AI Studio with API_KEY_INVALID is logically an auth failure,
    # not a transient blip — surface it as such so the user gets an actionable
    # message instead of a "blip, will retry at scan time" warning that the
    # scan will then immediately hit again.
    if code == 400:
        body = ""
        try:
            body = response.text[:512]
        except Exception:  # pragma: no cover - defensive
            body = ""
        if "API_KEY_INVALID" in body or "API key not valid" in body:
            return _ProbeOutcome(status="auth_failed", detail="HTTP 400 (API_KEY_INVALID)")
        # Other 400s are user-error on our side (e.g. malformed model id);
        # treat as not-found so the user sees the "did you mean" suggestion
        # rather than a vague transient warning.
        return _ProbeOutcome(status="not_found", detail=body)
    # 5xx — transient. Surface anything else as transient too: better to
    # warn and keep going than fail-fast on a provider hiccup.
    return _ProbeOutcome(status="transient", detail=f"HTTP {code}")


def _classify_exception(exc: Exception) -> _ProbeOutcome:
    """Network errors all collapse to transient — never fail-fast on a blip."""
    return _ProbeOutcome(status="transient", detail=type(exc).__name__)


def _suggest_for(provider: str, model: str) -> str:
    """Return a ``"--model <prefix>:<candidate>"`` line, or empty string."""
    candidates = KNOWN_MODELS.get(provider, ())
    if not candidates or not model:
        return ""
    matches = difflib.get_close_matches(model, candidates, n=1, cutoff=0.4)
    if not matches:
        return ""
    return f"--model {provider}:{matches[0]}"


# --- OpenAI --------------------------------------------------------------


def _probe_openai(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    api_key = os.environ.get("AGENT_GUARDIAN_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider="openai",
            model=model,
            message=(
                "OpenAI API key missing. Set AGENT_GUARDIAN_OPENAI_API_KEY or "
                "OPENAI_API_KEY before running the scan."
            ),
        )
    url = _OPENAI_MODELS_URL.format(model=model)
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.get(url, headers=headers)
    except Exception as exc:
        outcome = _classify_exception(exc)
    else:
        outcome = _classify_response(response)
    return _finalise("openai", model, outcome)


# --- Anthropic ----------------------------------------------------------


def _probe_anthropic(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    api_key = os.environ.get("AGENT_GUARDIAN_ANTHROPIC_API_KEY") or os.environ.get(
        "ANTHROPIC_API_KEY"
    )
    if not api_key:
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider="anthropic",
            model=model,
            message=(
                "Anthropic API key missing. Set AGENT_GUARDIAN_ANTHROPIC_API_KEY "
                "or ANTHROPIC_API_KEY before running the scan."
            ),
        )
    url = _ANTHROPIC_MODELS_URL.format(model=model)
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.get(url, headers=headers)
    except Exception as exc:
        outcome = _classify_exception(exc)
    else:
        outcome = _classify_response(response)
    return _finalise("anthropic", model, outcome)


# --- Gemini (AI Studio) -------------------------------------------------


def _probe_gemini(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    api_key = (
        os.environ.get("AGENT_GUARDIAN_GEMINI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
    )
    if not api_key:
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider="gemini",
            model=model,
            message=(
                "Gemini (AI Studio) API key missing. Set "
                "AGENT_GUARDIAN_GEMINI_API_KEY, GEMINI_API_KEY, or "
                "GOOGLE_API_KEY before running the scan."
            ),
        )
    url = _GEMINI_MODELS_URL.format(model=model)
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.get(url, params={"key": api_key})
    except Exception as exc:
        outcome = _classify_exception(exc)
    else:
        outcome = _classify_response(response)

    if outcome.status != "not_found":
        return _finalise("gemini", model, outcome)

    # QA-001 addendum: cross-check Vertex. When AI Studio 404s on a
    # gemini id, probe the public publisher catalog. If Vertex has it,
    # suggest the vertex: prefix instead of a difflib near-name.
    vertex_outcome = _probe_vertex_anonymous_existence(model, timeout_s=timeout_s, factory=factory)
    if vertex_outcome.status == "valid":
        message = (
            f"Unknown model id '{model}' on Google AI / AI Studio.\n"
            f"Hint: this id IS available on Vertex AI — try "
            f"--model vertex:{model}.\n"
            "Run `agent-guardian models list` to see all available ids."
        )
        return ModelValidationResult(
            valid=False,
            status="not_found",
            provider="gemini",
            model=model,
            message=message,
            suggestion=f"--model vertex:{model}",
        )
    # Vertex doesn't have it either — fall back to difflib hint.
    suggestion = _suggest_for("gemini", model)
    similar = ", ".join(KNOWN_MODELS["gemini"][:3])
    if suggestion:
        hint = f"Available similarly-named: {suggestion.split(':', 1)[1]}."
    else:
        hint = f"Stable Gemini ids include: {similar}."
    message = (
        f"Unknown model id '{model}' on Google AI / AI Studio.\n"
        f"{hint}\n"
        "Run `agent-guardian models list` to see all available ids."
    )
    return ModelValidationResult(
        valid=False,
        status="not_found",
        provider="gemini",
        model=model,
        message=message,
        suggestion=suggestion,
    )


# --- Vertex (publisher catalog, anonymous) ------------------------------


def _probe_vertex_anonymous_existence(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> _ProbeOutcome:
    """Anonymous Vertex existence check. No auth header.

    Used both as the primary probe for ``--model vertex:<id>`` and as the
    Gemini cross-check (QA-001 addendum). Publisher catalog is public —
    invoking the model still requires gcloud auth, but *asking whether
    the id exists* does not. That keeps the dispatch hint usable even
    for users who haven't run ``gcloud auth application-default login``.
    """
    url = _VERTEX_PUBLISHER_URL.format(model=model)
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.get(url)
    except Exception as exc:
        return _classify_exception(exc)
    return _classify_response(response)


def _probe_vertex(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    outcome = _probe_vertex_anonymous_existence(model, timeout_s=timeout_s, factory=factory)
    return _finalise("vertex", model, outcome)


# --- Ollama --------------------------------------------------------------


def _probe_ollama(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    host = os.environ.get("OLLAMA_HOST") or _DEFAULT_OLLAMA_HOST
    url = f"{host.rstrip('/')}{_OLLAMA_API_SHOW_PATH}"
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.post(url, json={"name": model})
    except Exception as exc:
        outcome = _ProbeOutcome(
            status="transient",
            detail=(
                f"Ollama daemon unreachable at {host} "
                f"({type(exc).__name__}); set OLLAMA_HOST if non-default."
            ),
        )
    else:
        outcome = _classify_response(response)
    return _finalise("ollama", model, outcome)


# --- Bedrock -------------------------------------------------------------


def _probe_bedrock(model: str) -> ModelValidationResult:
    """Bedrock: try ``boto3 bedrock.get_foundation_model``.

    Returns ``unsupported`` (valid=True) if boto3 isn't installed — the
    CLI's LLM factory already surfaces that as a clear ImportError, and
    we'd rather defer than re-create the message here.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        return ModelValidationResult(
            valid=True,
            status="unsupported",
            provider="bedrock",
            model=model,
            message="boto3 not installed; deferring Bedrock validation to scan time.",
        )

    try:
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        client = boto3.client("bedrock", region_name=region) if region else boto3.client("bedrock")
        client.get_foundation_model(modelIdentifier=model)
    except NoCredentialsError as exc:
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider="bedrock",
            model=model,
            message=(
                f"Bedrock credentials missing: {exc}. Configure the AWS "
                "credential chain (env vars, ~/.aws/credentials, or IAM role)."
            ),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            return ModelValidationResult(
                valid=False,
                status="not_found",
                provider="bedrock",
                model=model,
                message=(
                    f"Unknown Bedrock model id '{model}'.\n"
                    "Run `aws bedrock list-foundation-models` to see "
                    "what your account / region can access."
                ),
            )
        return ModelValidationResult(
            valid=True,
            status="transient",
            provider="bedrock",
            model=model,
            message=f"Bedrock probe transient error: {code or exc}",
        )
    except Exception as exc:  # pragma: no cover - safety net
        return ModelValidationResult(
            valid=True,
            status="transient",
            provider="bedrock",
            model=model,
            message=f"Bedrock probe transient error: {type(exc).__name__}: {exc}",
        )
    return ModelValidationResult(
        valid=True,
        status="valid",
        provider="bedrock",
        model=model,
    )


# ---------------------------------------------------------------------------
# Outcome → ModelValidationResult mapping (shared by non-gemini providers).
# ---------------------------------------------------------------------------


def _finalise(provider: str, model: str, outcome: _ProbeOutcome) -> ModelValidationResult:
    if outcome.status == "valid":
        return ModelValidationResult(valid=True, status="valid", provider=provider, model=model)
    if outcome.status == "transient":
        return ModelValidationResult(
            valid=True,
            status="transient",
            provider=provider,
            model=model,
            message=(
                f"could not validate {provider}:{model} before scan "
                f"({outcome.detail}); will surface at first call"
            ),
        )
    if outcome.status == "auth_failed":
        envvar = {
            "openai": "AGENT_GUARDIAN_OPENAI_API_KEY (or OPENAI_API_KEY)",
            "anthropic": "AGENT_GUARDIAN_ANTHROPIC_API_KEY (or ANTHROPIC_API_KEY)",
            "gemini": ("AGENT_GUARDIAN_GEMINI_API_KEY (or GEMINI_API_KEY / GOOGLE_API_KEY)"),
        }.get(provider, "the provider's credential env var")
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider=provider,
            model=model,
            message=(f"{provider} authentication failed ({outcome.detail}). Check {envvar}."),
        )
    if outcome.status == "not_found":
        suggestion = _suggest_for(provider, model)
        provider_label = {
            "openai": "OpenAI",
            "anthropic": "Anthropic",
            "vertex": "Vertex AI",
            "ollama": "Ollama",
            "bedrock": "Amazon Bedrock",
        }.get(provider, provider)
        candidates = KNOWN_MODELS.get(provider, ())
        if suggestion:
            hint_body = f"Available similarly-named: {suggestion.split(':', 1)[1]}."
        elif candidates:
            hint_body = f"Stable {provider_label} ids include: {', '.join(candidates[:3])}."
        else:
            hint_body = "Check the provider's catalog for the current model id."
        message = (
            f"Unknown model id '{model}' on {provider_label}.\n"
            f"{hint_body}\n"
            "Run `agent-guardian models list` to see all available ids."
        )
        return ModelValidationResult(
            valid=False,
            status="not_found",
            provider=provider,
            model=model,
            message=message,
            suggestion=suggestion,
        )
    # Unsupported / fall-through.
    return ModelValidationResult(
        valid=True,
        status=outcome.status,
        provider=provider,
        model=model,
        message=outcome.detail,
    )
