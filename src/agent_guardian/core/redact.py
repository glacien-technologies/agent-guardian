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
        # dash-bearing placeholders like ``sk-LEAKED-9999`` and dash-tailed
        # Anthropic-style keys — so the ``sk-`` prefix is never left behind
        # for a numeric tail to be mislabelled a phone number (the #2 leak).
        # The body alt accepts ``[A-Za-z0-9_-]{16,}`` (dashes included) so an
        # anthropic dash-tail is absorbed in a single span; a placeholder is
        # a dash-joined word group. Either is masked whole.
        re.compile(
            r"\bsk-(?:proj-|ant-api03-)?"
            r"(?:[A-Za-z0-9_-]{16,}|[A-Za-z0-9_]{2,}(?:-[A-Za-z0-9_]+)+)"
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
        "GITLAB_PAT",
        # GitLab personal-access tokens: ``glpat-`` + 20+ alphanumerics/_/-.
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    ),
    (
        "SLACK_TOKEN",
        # Slack bot/user/app tokens: ``xoxb-``/``xoxa-``/``xoxp-``/``xoxr-``/``xoxs-``.
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "SLACK_WEBHOOK",
        # Slack incoming-webhook URLs leak the same secret value the token
        # carries; treat the whole URL as a secret.
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ),
    (
        "STRIPE_KEY",
        # Stripe live/test secret + publishable + restricted keys.
        re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "TWILIO_SK",
        # Twilio API keys: ``SK`` + 32 hex digits.
        re.compile(r"\bSK[a-f0-9]{32}\b"),
    ),
    (
        "DISCORD_BOT_TOKEN",
        # Discord bot tokens: three dot-separated base64url parts with the
        # first being the snowflake-encoded bot id (24+ chars).
        re.compile(r"\b[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}\b"),
    ),
    (
        "AZURE_STORAGE_KEY",
        # Azure storage account-key connection-string fragment. AccountKey is
        # the high-value credential in any Azure connection-string leak; mask
        # the value through to the next delimiter.
        re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{16,}"),
    ),
    (
        "PEM_PRIVATE_KEY",
        # PEM-wrapped private-key blocks: RSA / OPENSSH / EC / DSA /
        # ENCRYPTED / PGP / plain PRIVATE KEY. The whole armoured block —
        # header, body and footer — is one secret span.
        re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?"
            r"PRIVATE KEY-----[\s\S]+?-----END (?:RSA |OPENSSH |EC |DSA |"
            r"ENCRYPTED |PGP )?PRIVATE KEY-----"
        ),
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
        # password=…, api_key: …, secret = …, token=…, aws_secret_access_key=…
        # — capture the keyword-and-value span. We drop the leading word-
        # boundary anchor so a prefixed identifier (``aws_secret_access_key``,
        # ``MY_API_KEY``) still matches: the keyword can appear after ``_``
        # which is not a word boundary in Python's regex engine. The fixed-
        # width lookbehind requires the match to start at a real delimiter
        # (or the line start) and an optional ``[A-Za-z0-9_-]*?`` prefix
        # absorbs identifier-prefix runs like ``aws_secret_access_key`` or
        # ``MY_OPENAI_TOKEN`` without leaving the leading prefix unredacted.
        re.compile(
            r"(?im)(?:^|(?<=[\s,;\"'`(\[{=]))"
            r"[A-Za-z0-9_-]*?"
            r"(?:password|passwd|pwd|api[_-]?key|secret(?:[_-]?key)?|token|"
            r"access[_-]?key|client[_-]?secret|auth[_-]?token)"
            r"\s*[:=]\s*\S+"
        ),
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
        # WHY: exclude letter-adjacent digit runs (e.g. ``AML.T0040``, ``T0050``,
        # ``SP800-53``) — the old ``(?<!\d) / (?!\d)`` guards let MITRE technique
        # IDs and similar identifier shapes get eaten as phone numbers. The
        # letter-context exclusion preserves real phone hits (``+1 415 555 1234``,
        # ``02-1234``) because their separators are not letters.
        re.compile(
            r"(?<![\dA-Za-z])(?:\+?\d{1,3}[ -]?)?(?:\(\d{1,4}\)[ -]?)?"
            r"\d{2,4}[ -]?\d{2,4}(?:[ -]?\d{2,4}){0,2}(?![\dA-Za-z])"
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
        "GITLAB_PAT",
        "GOOGLE_API_KEY",
        "SLACK_TOKEN",
        "SLACK_WEBHOOK",
        "STRIPE_KEY",
        "TWILIO_SK",
        "DISCORD_BOT_TOKEN",
        "AZURE_STORAGE_KEY",
        "PEM_PRIVATE_KEY",
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
            "GITLAB_PAT",
            "GOOGLE_API_KEY",
            "SLACK_TOKEN",
            "SLACK_WEBHOOK",
            "STRIPE_KEY",
            "TWILIO_SK",
            "DISCORD_BOT_TOKEN",
            "AZURE_STORAGE_KEY",
            "PEM_PRIVATE_KEY",
            "JWT",
            "BEARER_TOKEN",
            "GENERIC_SECRET",
        }
    )

    # Structured-PII entities where presidio's recogniser reliably misses
    # matches at default thresholds without the heavy spaCy NLP model
    # (e.g. ``US_SSN`` returns 0 results unless the en_core_web_lg model is
    # downloaded). We always run the regex fallback for these so a launch-
    # critical PII span never slips through the presidio path. The regex bank
    # is idempotent: already-masked ``[REDACTED:...]`` tokens do not match.
    _STRUCTURED_PII_BACKSTOP: frozenset[str] = frozenset(
        {
            "US_SSN",
            "CREDIT_CARD",
            "IBAN_CODE",
            "IP_ADDRESS",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
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
        # Pass presidio only the entities it has a recognizer for. The
        # credential/secret types in _SECRET_ENTITIES are already masked by the
        # regex bank above; presidio has no recognizer for them, so requesting
        # them produces nothing but a flood of one "no recognizer" WARNING per
        # type per call (presidio's own logger, not suppressible via -q).
        presidio_entities = [e for e in self.entities if e not in self._SECRET_ENTITIES]
        results = self._analyzer.analyze(text=out, entities=presidio_entities, language="en")
        # presidio returns spans with .start, .end, .entity_type
        # Sort by start descending so we can splice without reindexing.
        results = sorted(results, key=lambda r: r.start, reverse=True)
        for r in results:
            span = out[r.start : r.end]
            if span in self.allow_list:
                continue
            out = out[: r.start] + self._mask(r.entity_type) + out[r.end :]
        # Defence-in-depth: presidio's recognisers for structured PII
        # (US_SSN / CREDIT_CARD / IBAN / IP_ADDRESS / EMAIL_ADDRESS /
        # PHONE_NUMBER) silently miss matches when the spaCy NLP model isn't
        # downloaded or the surrounding context lacks the keywords presidio
        # expects. A security-scanner redactor that ships SSNs through the
        # dashboard is a launch-blocker, so always run the regex backstop for
        # those entities after presidio. The fallback regex is idempotent
        # against ``[REDACTED:...]`` masks already in ``out``.
        out = self._redact_structured_pii_backstop(out)
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

    def _redact_structured_pii_backstop(self, text: str) -> str:
        """Regex backstop for structured PII presidio's recognisers can miss."""
        out = text
        for entity, pattern in _FALLBACK_PATTERNS:
            if entity not in self._STRUCTURED_PII_BACKSTOP or entity not in self.entities:
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

# rc29 finding-aggregation redesign — every nested Attempt also carries
# leak-prone strings (the per-turn copies of ``summary``, ``trigger_prompt``,
# ``trigger_response``, ``evidence_quote``). The legacy v1 compat reader
# synthesises these per-Attempt copies from the outer Finding fields, so
# scrubbing the outer fields without scrubbing the Attempt copies would
# re-expose the same secret one nesting level deeper. Keep these in lock-step
# with the corresponding Attempt model field names.
_REDACTABLE_ATTEMPT_FIELDS = (
    "summary",
    "trigger_prompt",
    "trigger_response",
    "evidence_quote",
)


@runtime_checkable
class _FindingLike(Protocol):
    """Structural type for the Pydantic ``Finding`` (just what we touch)."""

    summary: str

    def model_copy(self, *, update: dict[str, Any]) -> Any:
        """Pydantic ``model_copy(update=...)``: return a copy with overrides."""

    def model_dump(self, *, mode: str = ...) -> dict[str, Any]:
        """Pydantic ``model_dump(mode=...)``: serialise to a plain dict."""


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
        # rc29 — scrub nested Attempts so the per-turn copies of the
        # leak-prone fields don't survive into the report. Each Attempt is
        # itself a frozen Pydantic model, so we model_copy with the redacted
        # field set. ``getattr(..., None)`` keeps the path safe for older
        # Finding instances that don't yet expose ``attempts``.
        attempts_val = getattr(finding, "attempts", None)
        if attempts_val:
            redacted_attempts: list[Any] = []
            for attempt in attempts_val:
                if hasattr(attempt, "model_copy"):
                    a_fields = getattr(type(attempt), "model_fields", {})
                    a_update: dict[str, Any] = {}
                    for af in _REDACTABLE_ATTEMPT_FIELDS:
                        if af in a_fields:
                            a_update[af] = _redact_text(getattr(attempt, af, None))
                    redacted_attempts.append(attempt.model_copy(update=a_update))
                else:
                    redacted_attempts.append(attempt)
            update["attempts"] = redacted_attempts
        return finding.model_copy(update=update)

    # Mapping / dict-like finding.
    if isinstance(finding, dict):
        out = dict(finding)
        for field in _REDACTABLE_FINDING_FIELDS:
            if field in out:
                out[field] = _redact_text(out[field])
        # rc29 — same nested-Attempts scrub as the Pydantic branch above.
        attempts_field = out.get("attempts")
        if isinstance(attempts_field, list) and attempts_field:
            cleaned: list[Any] = []
            for raw_attempt in attempts_field:
                if isinstance(raw_attempt, dict):
                    a = dict(raw_attempt)
                    for af in _REDACTABLE_ATTEMPT_FIELDS:
                        if af in a:
                            a[af] = _redact_text(a[af])
                    cleaned.append(a)
                else:
                    cleaned.append(raw_attempt)
            out["attempts"] = cleaned
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
