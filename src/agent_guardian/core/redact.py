"""PII / secret redaction wrapper (PRD §14.3).

Wraps ``presidio-analyzer`` (MIT) behind a Protocol-style interface. When
presidio is not installed (it lives behind the ``[full]`` extra), we fall
back to a regex-based redactor covering structured PII — EMAIL, PHONE,
IP_V4, IP_V6, SSN, CREDIT_CARD, IBAN — *plus* credential/secret shapes
(OpenAI / AWS / GitHub / Google API keys, JWTs, bearer tokens, and generic
``password=`` / ``api_key:`` assignments). A security scanner must never
re-emit captured secrets, so the credential patterns ship in the OSS
default (they do not require the ``[full]`` extra).
"""

from __future__ import annotations

import logging
import re
from dataclasses import replace
from typing import Any, Protocol, runtime_checkable

__all__ = ["PiiRedactor", "redact_finding"]

_LOG = logging.getLogger(__name__)

# --- fallback regex bank ------------------------------------------------

# Order matters: more-specific patterns first so e.g. SSN is caught before
# a stray phone-number match would grab it.
#
# The credential/secret patterns are placed BEFORE PHONE_NUMBER so that the
# digit-tails of keys like ``sk-LEAKED-9999`` aren't mis-split and mislabelled
# ``[REDACTED:PHONE_NUMBER]`` (which would leave the ``sk-`` prefix leaking).
_FALLBACK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "EMAIL_ADDRESS",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ),
    # --- credential / secret shapes (BEFORE the numeric PII so digit tails
    # of keys/tokens are captured as a single secret, not split into a phone
    # number with a leaking prefix) ---------------------------------------
    (
        "OPENAI_API_KEY",
        # OpenAI / Anthropic-style keys: sk-…, sk-proj-…, sk-ant-api03-….
        # We deliberately match the *whole* ``sk-`` token — including short,
        # dash-bearing placeholders like ``sk-LEAKED-9999`` — so the ``sk-``
        # prefix is never left behind for a numeric tail to be mislabelled a
        # phone number (the #2 leak). A real key is a long alnum run; a
        # placeholder is a dash-joined word group. Either is masked whole.
        re.compile(
            r"\bsk-(?:proj-|ant-api03-)?"
            r"(?:[A-Za-z0-9_]{16,}|[A-Za-z0-9_]{2,}(?:-[A-Za-z0-9_]+)+)"
        ),
    ),
    (
        "AWS_ACCESS_KEY",
        # AWS access-key IDs: AKIA… / ASIA… + 16 upper-alphanumerics.
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "GITHUB_TOKEN",
        # GitHub PAT / OAuth / server / refresh / user tokens.
        re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    ),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{10,}"),
    ),
    (
        "GENERIC_SECRET",
        # password=…, api_key: …, secret = …, token=… — capture the value.
        re.compile(r"(?i)\b(?:password|api[_-]?key|secret|token)\s*[:=]\s*\S+"),
    ),
    (
        "CREDIT_CARD",
        # 13-19 digits, optionally separated by spaces or dashes (Luhn not enforced
        # at this level — presidio handles that when available).
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
    ),
    (
        "IBAN_CODE",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    ),
    (
        "US_SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    # IP_ADDRESS runs before PHONE_NUMBER because IPv6 literals (full of digits
    # and colons) would otherwise be mistaken for phone numbers.
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
            r"|(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}"
        ),
    ),
    (
        "PHONE_NUMBER",
        # Permissive: optional +, optional country, then 7-15 digits with
        # spaces / dashes / parens.
        re.compile(
            r"(?<!\d)(?:\+?\d{1,3}[ -]?)?(?:\(\d{1,4}\)[ -]?)?"
            r"\d{2,4}[ -]?\d{2,4}(?:[ -]?\d{2,4}){0,2}(?!\d)"
        ),
    ),
)


def _has_presidio() -> bool:
    try:
        import presidio_analyzer  # type: ignore[import-not-found,unused-ignore]  # noqa: F401
    except ImportError as exc:
        _LOG.debug("redact: presidio not installed (%s); using regex fallback", exc)
        return False
    return True


class PiiRedactor:
    """Redact PII from free-form text.

    When ``presidio-analyzer`` is installed, we use it (slow but accurate,
    catches names too). Otherwise we fall back to a small regex bank that
    covers structured PII only.
    """

    DEFAULT_ENTITIES: tuple[str, ...] = (
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "US_SSN",
        "CREDIT_CARD",
        "IBAN_CODE",
        "IP_ADDRESS",
        "PERSON",
        # Credential / secret shapes — a security scanner must never re-emit a
        # captured key/token. These are matched by the regex fallback; presidio
        # has no recognisers for most of them, so they are merged in even on the
        # presidio path (see :meth:`_redact_with_presidio`).
        "OPENAI_API_KEY",
        "AWS_ACCESS_KEY",
        "GITHUB_TOKEN",
        "GOOGLE_API_KEY",
        "JWT",
        "BEARER_TOKEN",
        "GENERIC_SECRET",
    )

    # Entities that presidio's AnalyzerEngine has no recogniser for; we always
    # run the regex fallback for these even when presidio is active so captured
    # credentials never slip through the (PII-only) presidio path.
    _SECRET_ENTITIES: frozenset[str] = frozenset(
        {
            "OPENAI_API_KEY",
            "AWS_ACCESS_KEY",
            "GITHUB_TOKEN",
            "GOOGLE_API_KEY",
            "JWT",
            "BEARER_TOKEN",
            "GENERIC_SECRET",
        }
    )

    def __init__(
        self,
        entities: tuple[str, ...] | None = None,
        allow_list: frozenset[str] = frozenset(),
    ) -> None:
        self.entities = tuple(entities) if entities is not None else self.DEFAULT_ENTITIES
        self.allow_list = frozenset(allow_list)
        self._analyzer: Any | None = None
        self._using_presidio = False
        self._init_presidio()

    def _init_presidio(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError as exc:
            _LOG.debug("redact: presidio import failed (%s); using regex fallback", exc)
            return
        try:
            self._analyzer = AnalyzerEngine()
            self._using_presidio = True
            _LOG.info("redact: presidio AnalyzerEngine initialised")
        except Exception as exc:
            # spaCy model not downloaded, or some other init failure —
            # fall back to regex with a clear warning so operators who
            # installed the [full] extra know to download the spaCy model.
            _LOG.warning(
                "redact: presidio AnalyzerEngine init failed (%s: %s); "
                "falling back to regex. Run `python -m spacy download en_core_web_lg` to fix.",
                type(exc).__name__,
                exc,
            )
            self._analyzer = None
            self._using_presidio = False

    def is_using_presidio(self) -> bool:
        return self._using_presidio

    def _mask(self, entity: str) -> str:
        return f"[REDACTED:{entity}]"

    def _redact_with_presidio(self, text: str) -> str:
        assert self._analyzer is not None
        # presidio recognises the PII entities but not the credential/secret
        # shapes; run those through the regex bank FIRST so a captured key/token
        # is masked even when presidio is active.
        out = self._redact_secret_entities(text)
        # Filter to entities we care about that presidio knows.
        results = self._analyzer.analyze(text=out, entities=list(self.entities), language="en")
        # presidio returns spans with .start, .end, .entity_type
        # Sort by start descending so we can splice without reindexing.
        results = sorted(results, key=lambda r: r.start, reverse=True)
        for r in results:
            span = out[r.start : r.end]
            if span in self.allow_list:
                continue
            out = out[: r.start] + self._mask(r.entity_type) + out[r.end :]
        return out

    def _redact_secret_entities(self, text: str) -> str:
        """Run only the credential/secret regex patterns over ``text``."""
        out = text
        for entity, pattern in _FALLBACK_PATTERNS:
            if entity not in self._SECRET_ENTITIES or entity not in self.entities:
                continue

            def _replace(match: re.Match[str], _entity: str = entity) -> str:
                if match.group(0) in self.allow_list:
                    return match.group(0)
                return self._mask(_entity)

            out = pattern.sub(_replace, out)
        return out

    def _redact_with_fallback(self, text: str) -> str:
        out = text
        for entity, pattern in _FALLBACK_PATTERNS:
            if entity not in self.entities:
                continue

            def _replace(match: re.Match[str], _entity: str = entity) -> str:
                if match.group(0) in self.allow_list:
                    return match.group(0)
                return self._mask(_entity)

            out = pattern.sub(_replace, out)
        return out

    def redact(self, text: str) -> str:
        """Return ``text`` with PII replaced by ``[REDACTED:<ENTITY>]`` markers.

        Strings in :attr:`allow_list` pass through untouched.
        """
        if not text:
            return text
        if self._using_presidio and self._analyzer is not None:
            try:
                return self._redact_with_presidio(text)
            except Exception as exc:
                # presidio failed mid-call — fall back rather than crash.
                _LOG.warning(
                    "redact: presidio analyze raised %s: %s — falling back to regex for this text",
                    type(exc).__name__,
                    exc,
                )
                return self._redact_with_fallback(text)
        return self._redact_with_fallback(text)


# --- shared finding-level redaction entry point -------------------------------

# Module-level redactor reused by every report surface so the credential/PII
# patterns are compiled once. The default entity set covers PII *and* secrets.
_FINDING_REDACTOR = PiiRedactor()

# Finding string fields that may carry attacker-reflected PII / captured
# secrets and must be scrubbed before re-emission to any output surface.
_REDACTABLE_FINDING_FIELDS = (
    "summary",
    "description",
    "trigger_prompt",
    "transcript_ref",
    "evidence",
)


@runtime_checkable
class _FindingLike(Protocol):
    """Structural type for the Pydantic ``Finding`` (just what we touch)."""

    summary: str

    def model_copy(self, *, update: dict[str, Any]) -> Any: ...

    def model_dump(self, *, mode: str = ...) -> dict[str, Any]: ...


def _redact_text(text: Any) -> Any:
    """Redact a single field value; pass through non-strings/empties."""
    if isinstance(text, str) and text:
        return _FINDING_REDACTOR.redact(text)
    return text


def redact_finding(finding: Any, *, enabled: bool) -> Any:
    """Return a copy of ``finding`` with sensitive string fields redacted.

    A single shared entry point so every report writer (JSON / SARIF / JUnit /
    Markdown / PDF) and the dashboard scrub identically. The fields
    ``summary``, ``description``, ``trigger_prompt``, ``transcript_ref`` and
    ``evidence`` are passed through :class:`PiiRedactor` (PII + credential
    shapes) when ``enabled`` is true.

    Accepts either a Pydantic ``Finding`` (returns a redacted ``model_copy``),
    a mapping (returns a redacted ``dict``), or any object exposing the
    redactable attributes (returns a ``dataclasses.replace`` copy when it is a
    dataclass, otherwise a redacted ``dict``). When ``enabled`` is false the
    input is returned unchanged.
    """
    if not enabled:
        return finding

    # Pydantic model (e.g. models.finding.Finding) — frozen-safe copy.
    if isinstance(finding, _FindingLike) and hasattr(finding, "model_copy"):
        model_fields = getattr(type(finding), "model_fields", {})
        update: dict[str, Any] = {}
        for field in _REDACTABLE_FINDING_FIELDS:
            if field in model_fields:
                update[field] = _redact_text(getattr(finding, field, None))
        return finding.model_copy(update=update)

    # Mapping / dict-like finding.
    if isinstance(finding, dict):
        out = dict(finding)
        for field in _REDACTABLE_FINDING_FIELDS:
            if field in out:
                out[field] = _redact_text(out[field])
        return out

    # dataclass instance.
    if hasattr(finding, "__dataclass_fields__"):
        dc_fields = finding.__dataclass_fields__
        update_dc: dict[str, Any] = {
            field: _redact_text(getattr(finding, field))
            for field in _REDACTABLE_FINDING_FIELDS
            if field in dc_fields
        }
        return replace(finding, **update_dc)

    # Unknown shape — scrub into a plain dict so we never re-emit raw secrets.
    out_any: dict[str, Any] = {}
    for field in _REDACTABLE_FINDING_FIELDS:
        if hasattr(finding, field):
            out_any[field] = _redact_text(getattr(finding, field))
    return out_any if out_any else finding
