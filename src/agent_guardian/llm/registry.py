"""Declarative provider registry + model-spec parser (PRD §14.3).

Single source of truth for turning a ``provider:model[+qualifier=value]*`` spec
string into a concrete :class:`BaseLLM`. Replaces the long if/elif chain that
used to live in ``cli.build_llm``.

Adding a provider is one entry in ``_REGISTRY`` plus (for non-trivial cases) a
small factory function — no existing code changes.

Model-spec grammar
------------------

``provider:model_id[+key=value]*``

* ``stub`` / ``""`` → :class:`StubLLM` (no qualifiers needed).
* If a ``:`` is present, split on the FIRST colon (so OpenRouter's
  ``openrouter:anthropic/claude-3.5-sonnet`` keeps its slash-namespaced model).
* No colon → heuristic prefix inference (``gpt-*``/``o1``/``o3`` → openai,
  ``claude-*`` → anthropic, ``gemini-*`` → gemini, ``ollama-*`` → ollama).
* ``+key=value`` qualifiers are split off the model part FIRST, are
  order-independent, and are provider-scoped. Unknown qualifiers are ignored
  (forward-compat). Backward-compatible: existing specs contain no ``+``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_guardian.config import _STANDARD_ENV_VAR, env_api_key
from agent_guardian.llm.base import BaseLLM
from agent_guardian.llm.errors import LLMError

__all__ = [
    "ProviderSpec",
    "RegistryError",
    "build_llm",
    "parse_model_spec",
]

_LOG = logging.getLogger(__name__)


class RegistryError(Exception):
    """Raised when a spec cannot be resolved to a client.

    The CLI catches this and re-raises as ``typer.BadParameter`` so the user
    sees a clean, role-tagged message. Keeping it provider-agnostic here means
    the registry has no Typer dependency.
    """


@dataclass(frozen=True)
class ProviderSpec:
    """A parsed ``provider:model[+qualifier=value]*`` spec.

    * ``provider`` — lowercased canonical provider name.
    * ``model`` — the bare model id (no provider prefix, no qualifiers). Case
      is preserved (Fireworks / Together model ids are case-sensitive).
    * ``qualifiers`` — ``+key=value`` pairs as a dict.
    """

    provider: str
    model: str
    qualifiers: dict[str, str] = field(default_factory=dict)


def parse_model_spec(spec: str) -> ProviderSpec:
    """Parse a model spec into a :class:`ProviderSpec`. See module docstring."""
    raw = (spec or "stub").strip()
    if raw == "" or raw.lower() == "stub":
        return ProviderSpec(provider="stub", model="")

    # Split provider:model from the qualifier tail. Qualifiers attach to the
    # whole spec; we partition the provider half off FIRST so a qualifier that
    # contains a ``:`` (e.g. an https endpoint) is never mistaken for the
    # provider separator.
    if ":" in raw:
        provider_part, _, remainder = raw.partition(":")
        provider = provider_part.strip().lower()
        model_and_quals = remainder
    else:
        lowered = raw.lower()
        if lowered.startswith(("gpt-", "o1", "o3")):
            provider = "openai"
        elif lowered.startswith("claude-"):
            provider = "anthropic"
        elif lowered.startswith("gemini-"):
            provider = "gemini"
        elif lowered.startswith("ollama-"):
            provider = "ollama"
        else:
            provider = "unknown"
        model_and_quals = raw

    model, qualifiers = _split_qualifiers(model_and_quals)
    return ProviderSpec(provider=provider, model=model, qualifiers=qualifiers)


def _split_qualifiers(model_and_quals: str) -> tuple[str, dict[str, str]]:
    """Split ``model+k1=v1+k2=v2`` into ``("model", {"k1": "v1", "k2": "v2"})``."""
    if "+" not in model_and_quals:
        return (model_and_quals, {})
    head, _, tail = model_and_quals.partition("+")
    qualifiers: dict[str, str] = {}
    for chunk in tail.split("+"):
        if not chunk:
            continue
        key, sep, value = chunk.partition("=")
        if sep:
            qualifiers[key.strip()] = value.strip()
        else:
            # Bare flag form (``+v1_compat``) → treated as ``"true"``.
            qualifiers[key.strip()] = "true"
    return (head, qualifiers)


# ---------------------------------------------------------------------------
# Provider factories
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProviderEntry:
    """One registry row: a factory plus whether a key is mandatory."""

    factory: Callable[[ProviderSpec, str], BaseLLM]
    requires_api_key: bool


def _require_key(provider: str, role: str) -> str:
    key = env_api_key(provider)
    if not key:
        # Enumerate every accepted env var so the operator can pick whichever
        # fits their setup (e.g. Gemini accepts GEMINI_API_KEY or GOOGLE_API_KEY).
        conventional = _STANDARD_ENV_VAR.get(provider, (f"{provider.upper()}_API_KEY",))
        vars_list = ", ".join((f"AGENT_GUARDIAN_{provider.upper()}_API_KEY", *conventional))
        raise RegistryError(
            f"{provider} requested for {role} but no API key found. Set one of: {vars_list}."
        )
    return key


def _build_stub(spec: ProviderSpec, role: str) -> BaseLLM:
    from agent_guardian.llm.stub import StubScript

    return StubScript().default(f"[stub:{role}] safe default response").build()


def _build_openai(spec: ProviderSpec, role: str) -> BaseLLM:
    from agent_guardian.llm.openai import OpenAIClient

    return OpenAIClient(api_key=_require_key("openai", role))


def _build_anthropic(spec: ProviderSpec, role: str) -> BaseLLM:
    from agent_guardian.llm.anthropic import AnthropicClient

    return AnthropicClient(api_key=_require_key("anthropic", role))


def _build_gemini(spec: ProviderSpec, role: str) -> BaseLLM:
    from agent_guardian.llm.gemini import GeminiClient

    return GeminiClient(api_key=_require_key("gemini", role))


def _build_ollama(spec: ProviderSpec, role: str) -> BaseLLM:
    from agent_guardian.llm.ollama import OllamaClient

    return OllamaClient()


def _build_bedrock(spec: ProviderSpec, role: str) -> BaseLLM:
    import os

    try:
        from agent_guardian.llm.bedrock import BedrockClient
    except ImportError as exc:  # pragma: no cover — guarded by lazy import
        _LOG.debug("registry: bedrock import failed (AWS extra missing): %s", exc)
        raise RegistryError(
            f"Bedrock requested for {role} but the AWS extra is not installed. "
            f"Install with: pip install 'agent-guardian[aws]' (import error: {exc})"
        ) from exc
    region = (
        spec.qualifiers.get("region")
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
    )
    try:
        return BedrockClient(region=region)
    except LLMError as exc:
        raise RegistryError(
            f"Bedrock requested for {role} but credentials are missing: {exc}"
        ) from exc


def _build_vertex(spec: ProviderSpec, role: str) -> BaseLLM:
    import os

    from agent_guardian.llm.vertex import VertexClient

    project = spec.qualifiers.get("project") or os.environ.get("GOOGLE_CLOUD_PROJECT") or ""
    if not project:
        raise RegistryError(
            f"Vertex AI requested for {role} but no project found. Set "
            "GOOGLE_CLOUD_PROJECT or pass +project=<id> in the model spec "
            "(e.g. vertex:gemini-2.5-flash+project=my-proj)."
        )
    location = (
        spec.qualifiers.get("location") or os.environ.get("GOOGLE_CLOUD_LOCATION") or "us-central1"
    )
    return VertexClient(project=project, location=location)


def _build_azure(spec: ProviderSpec, role: str) -> BaseLLM:
    from agent_guardian.llm.azure_openai import AzureOpenAIClient

    endpoint = spec.qualifiers.get("endpoint")
    api_version = spec.qualifiers.get("api_version")
    deployment = spec.qualifiers.get("deployment") or spec.model
    api_key = env_api_key("azure")
    try:
        return AzureOpenAIClient(
            deployment=deployment,
            endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )
    except LLMError as exc:
        raise RegistryError(f"Azure OpenAI requested for {role}: {exc}") from exc


# OpenAI-compatible gateways: (env-var-provider-name, fully-versioned base_url).
_GATEWAY_PROVIDERS: dict[str, tuple[str, str]] = {
    "openrouter": ("openrouter", "https://openrouter.ai/api/v1"),
    "groq": ("groq", "https://api.groq.com/openai/v1"),
    "together": ("together", "https://api.together.xyz/v1"),
    "fireworks": ("fireworks", "https://api.fireworks.ai/inference/v1"),
}


def _build_gateway(provider: str) -> Callable[[ProviderSpec, str], BaseLLM]:
    import os

    key_provider, base_url = _GATEWAY_PROVIDERS[provider]

    def factory(spec: ProviderSpec, role: str) -> BaseLLM:
        from agent_guardian.llm.openai_compat import OpenAICompatClient

        api_key = _require_key(key_provider, role)
        extra_headers: dict[str, str] = {}
        if provider == "openrouter":
            # Attribution headers — never gate requests; forwarded when set.
            referer = os.environ.get("OPENROUTER_HTTP_REFERER")
            title = os.environ.get("OPENROUTER_SITE_NAME")
            if referer:
                extra_headers["HTTP-Referer"] = referer
            if title:
                extra_headers["X-Title"] = title
        return OpenAICompatClient(
            provider=provider,
            base_url=base_url,
            api_key=api_key,
            extra_headers=extra_headers or None,
        )

    return factory


def _build_vllm(spec: ProviderSpec, role: str) -> BaseLLM:
    import os

    from agent_guardian.llm.openai_compat import OpenAICompatClient

    base_url = (
        spec.qualifiers.get("base_url")
        or os.environ.get("VLLM_BASE_URL")
        or "http://localhost:8000/v1"
    )
    # vLLM auth is optional — only enforced if the server was started with a key.
    api_key = env_api_key("vllm")
    return OpenAICompatClient(provider="vllm", base_url=base_url, api_key=api_key)


_REGISTRY: dict[str, _ProviderEntry] = {
    "stub": _ProviderEntry(_build_stub, requires_api_key=False),
    "openai": _ProviderEntry(_build_openai, requires_api_key=True),
    "anthropic": _ProviderEntry(_build_anthropic, requires_api_key=True),
    "gemini": _ProviderEntry(_build_gemini, requires_api_key=True),
    "ollama": _ProviderEntry(_build_ollama, requires_api_key=False),
    "bedrock": _ProviderEntry(_build_bedrock, requires_api_key=False),
    "vertex": _ProviderEntry(_build_vertex, requires_api_key=False),
    "azure": _ProviderEntry(_build_azure, requires_api_key=True),
    "openrouter": _ProviderEntry(_build_gateway("openrouter"), requires_api_key=True),
    "groq": _ProviderEntry(_build_gateway("groq"), requires_api_key=True),
    "together": _ProviderEntry(_build_gateway("together"), requires_api_key=True),
    "fireworks": _ProviderEntry(_build_gateway("fireworks"), requires_api_key=True),
    "vllm": _ProviderEntry(_build_vllm, requires_api_key=False),
}


def build_llm(model_spec: str, role: str) -> BaseLLM:
    """Resolve a model spec to a concrete :class:`BaseLLM`.

    Raises :class:`RegistryError` for unknown providers / missing credentials —
    the CLI translates that into ``typer.BadParameter``. The ``role`` string is
    used only in error messages so the operator knows which LLM slot
    misconfigured.
    """
    spec = parse_model_spec(model_spec)
    entry = _REGISTRY.get(spec.provider)
    if entry is None:
        # ``provider == "unknown"`` means the heuristic could not infer a
        # provider from a bare (colon-less) name; any other value is a genuinely
        # unrecognised explicit provider. Either way we show the canonical
        # ``provider:model`` spec forms so the operator can correct it.
        raise RegistryError(
            f"Cannot infer provider for model spec '{model_spec}' (role={role}). "
            f"Use one of: stub, openai:<model>, anthropic:<model>, "
            f"gemini:<model>, ollama:<model>, bedrock:<id>, vertex:<model>, "
            f"azure:<deployment>, openrouter:<vendor/model>, groq:<model>, "
            f"together:<model>, fireworks:<model>, vllm:<model>. "
            f"Supported providers: {', '.join(sorted(_REGISTRY))}."
        )
    return entry.factory(spec, role)
