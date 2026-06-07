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
        "gemini-2.5-flash-lite",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
    ),
    # Azure deployment names are user-defined, so there is no stable corpus to
    # power a "did you mean" suggestion — kept empty intentionally.
    "azure": (),
    # OpenAI-compatible gateway catalogs rotate constantly and use
    # vendor-namespaced ids; we do not ship a difflib corpus for them. The
    # probe checks live existence against the gateway's ``/models`` endpoint.
    "openrouter": (),
    "groq": (),
    "together": (),
    "fireworks": (),
    "vllm": (),
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
    """Split a ``"<provider>:<model>[+qualifier=value]*"`` spec into its parts.

    Delegates to :func:`agent_guardian.llm.registry.parse_model_spec` so the
    validation probe sees the EXACT same provider/model pair the LLM factory
    will see at scan time (single source of truth). Heuristic prefixes
    (``gpt-*``, ``claude-*``, ``gemini-*``, ``ollama-*``) are honoured, and any
    ``+qualifier=value`` tail is stripped off the model id.

    Returns ``(provider, model)``. ``provider`` is lower-cased. ``"stub"`` and
    the empty string normalise to ``("stub", "")``.
    """
    from agent_guardian.llm.registry import parse_model_spec

    parsed = parse_model_spec(spec)
    return (parsed.provider, parsed.model)


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
    elif provider == "azure":
        result = _probe_azure(model, timeout_s=effective_timeout, factory=client_factory)
    elif provider in _GATEWAY_BASE_URLS:
        result = _probe_openai_compat(
            provider, model, timeout_s=effective_timeout, factory=client_factory
        )
    elif provider == "vllm":
        result = _probe_vllm(model, timeout_s=effective_timeout, factory=client_factory)
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


# --- Azure OpenAI -------------------------------------------------------


def _probe_azure(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    """Azure: confirm the deployment exists at the resource endpoint.

    ``model`` is the Azure *deployment name*. We GET the deployment metadata
    on the standard dated path (reviewer correction #2):
    ``{endpoint}/openai/deployments/{deployment}?api-version=...``. A missing
    endpoint is a definite misconfiguration for a paid provider — fail fast
    with ``auth_failed`` rather than deferring.
    """
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    api_key = os.environ.get("AGENT_GUARDIAN_AZURE_API_KEY") or os.environ.get(
        "AZURE_OPENAI_API_KEY"
    )
    use_entra = os.environ.get("AZURE_USE_ENTRA") == "1"
    if not endpoint:
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider="azure",
            model=model,
            message=(
                "Azure OpenAI endpoint missing. Set AZURE_OPENAI_ENDPOINT "
                "(e.g. https://my-resource.openai.azure.com) before running the scan."
            ),
        )
    if not api_key and not use_entra:
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider="azure",
            model=model,
            message=(
                "Azure OpenAI API key missing. Set AGENT_GUARDIAN_AZURE_API_KEY or "
                "AZURE_OPENAI_API_KEY, or enable Entra auth with AZURE_USE_ENTRA=1."
            ),
        )
    if use_entra:
        # Minting an Entra token here would require azure-identity + network;
        # defer existence validation to scan time rather than half-probe.
        return ModelValidationResult(
            valid=True,
            status="unsupported",
            provider="azure",
            model=model,
            message="Azure Entra auth: deferring deployment validation to scan time.",
        )
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION") or "2024-12-01-preview"
    url = f"{endpoint.rstrip('/')}/openai/deployments/{model}"
    headers = {"api-key": api_key or ""}
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.get(url, params={"api-version": api_version}, headers=headers)
    except Exception as exc:
        outcome = _classify_exception(exc)
    else:
        outcome = _classify_response(response)
    return _finalise("azure", model, outcome)


# --- OpenAI-compatible gateways -----------------------------------------


# Gateway provider → fully-versioned base URL. Kept in lockstep with the
# registry's ``_GATEWAY_PROVIDERS`` (the probe hits ``{base_url}/models``).
_GATEWAY_BASE_URLS: Final[dict[str, str]] = {
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz/v1",
    "fireworks": "https://api.fireworks.ai/inference/v1",
}

_GATEWAY_LABELS: Final[dict[str, str]] = {
    "openrouter": "OpenRouter",
    "groq": "Groq",
    "together": "Together AI",
    "fireworks": "Fireworks AI",
}


def _gateway_api_key(provider: str) -> str | None:
    namespaced = os.environ.get(f"AGENT_GUARDIAN_{provider.upper()}_API_KEY")
    if namespaced:
        return namespaced
    return os.environ.get(f"{provider.upper()}_API_KEY")


def _probe_openai_compat(
    provider: str,
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    """Gateway existence check: GET ``{base_url}/models`` and look for ``model``.

    The gateways expose a list endpoint (not a per-model path), so we fetch the
    catalog once and check membership. A transient/list-parse failure downgrades
    to ``transient`` (valid=True) so a gateway hiccup never blocks the scan.
    """
    base_url = _GATEWAY_BASE_URLS[provider]
    label = _GATEWAY_LABELS.get(provider, provider)
    api_key = _gateway_api_key(provider)
    if not api_key:
        return ModelValidationResult(
            valid=False,
            status="auth_failed",
            provider=provider,
            model=model,
            message=(
                f"{label} API key missing. Set AGENT_GUARDIAN_{provider.upper()}_API_KEY "
                f"or {provider.upper()}_API_KEY before running the scan."
            ),
        )
    url = f"{base_url}/models"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.get(url, headers=headers)
    except Exception as exc:
        return _finalise(provider, model, _classify_exception(exc))
    if response.status_code in (401, 403):
        return _finalise(provider, model, _ProbeOutcome(status="auth_failed", detail="HTTP "))
    if response.status_code >= 400:
        return _finalise(
            provider,
            model,
            _ProbeOutcome(status="transient", detail=f"HTTP {response.status_code}"),
        )
    try:
        ids = {entry.get("id") for entry in (response.json() or {}).get("data", [])}
    except Exception as exc:  # pragma: no cover - defensive
        return _finalise(
            provider, model, _ProbeOutcome(status="transient", detail=type(exc).__name__)
        )
    if model in ids:
        return _finalise(provider, model, _ProbeOutcome(status="valid"))
    return _finalise(provider, model, _ProbeOutcome(status="not_found"))


def _probe_vllm(
    model: str,
    *,
    timeout_s: float,
    factory: type[httpx.Client] | None,
) -> ModelValidationResult:
    """vLLM: GET ``{base_url}/models`` on the user-supplied (local) server.

    vLLM is self-hosted with an optional key; a daemon-unreachable error
    downgrades to ``transient`` (valid=True) — same posture as the Ollama probe.
    """
    base_url = os.environ.get("VLLM_BASE_URL") or "http://localhost:8000/v1"
    api_key = os.environ.get("AGENT_GUARDIAN_VLLM_API_KEY") or os.environ.get("VLLM_API_KEY")
    url = f"{base_url.rstrip('/')}/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        with _new_client(factory, timeout_s=timeout_s) as client:
            response = client.get(url, headers=headers)
    except Exception as exc:
        return _finalise(
            "vllm",
            model,
            _ProbeOutcome(
                status="transient",
                detail=f"vLLM server unreachable at {base_url} ({type(exc).__name__})",
            ),
        )
    if response.status_code >= 400:
        return _finalise(
            "vllm", model, _ProbeOutcome(status="transient", detail=f"HTTP {response.status_code}")
        )
    try:
        ids = {entry.get("id") for entry in (response.json() or {}).get("data", [])}
    except Exception as exc:  # pragma: no cover - defensive
        return _finalise(
            "vllm", model, _ProbeOutcome(status="transient", detail=type(exc).__name__)
        )
    if model in ids:
        return _finalise("vllm", model, _ProbeOutcome(status="valid"))
    return _finalise("vllm", model, _ProbeOutcome(status="not_found"))


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
            "azure": "AGENT_GUARDIAN_AZURE_API_KEY (or AZURE_OPENAI_API_KEY) + AZURE_OPENAI_ENDPOINT",
            "openrouter": "AGENT_GUARDIAN_OPENROUTER_API_KEY (or OPENROUTER_API_KEY)",
            "groq": "AGENT_GUARDIAN_GROQ_API_KEY (or GROQ_API_KEY)",
            "together": "AGENT_GUARDIAN_TOGETHER_API_KEY (or TOGETHER_API_KEY)",
            "fireworks": "AGENT_GUARDIAN_FIREWORKS_API_KEY (or FIREWORKS_API_KEY)",
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
            "azure": "Azure OpenAI",
            "openrouter": "OpenRouter",
            "groq": "Groq",
            "together": "Together AI",
            "fireworks": "Fireworks AI",
            "vllm": "vLLM",
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
