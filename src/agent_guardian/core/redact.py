"""PII redaction wrapper (PRD §14.3).

Wraps ``presidio-analyzer`` (MIT) behind a Protocol-style interface. When
presidio is not installed (it lives behind the ``[full]`` extra), we fall
back to a small regex-based redactor covering structured PII — EMAIL,
PHONE, IP_V4, IP_V6, SSN, CREDIT_CARD, IBAN. The fallback is deliberately
limited; production users install ``agent-guardian[full]``.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["PiiRedactor"]

# --- fallback regex bank ------------------------------------------------

# Order matters: more-specific patterns first so e.g. SSN is caught before
# a stray phone-number match would grab it.
_FALLBACK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "EMAIL_ADDRESS",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
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
    except ImportError:
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
        except ImportError:
            return
        try:
            self._analyzer = AnalyzerEngine()
            self._using_presidio = True
        except Exception:
            # spaCy model not downloaded, or some other init failure —
            # silently fall back to regex. Production users see this only
            # if they installed the [full] extra but skipped `python -m spacy
            # download en_core_web_lg`.
            self._analyzer = None
            self._using_presidio = False

    def is_using_presidio(self) -> bool:
        return self._using_presidio

    def _mask(self, entity: str) -> str:
        return f"[REDACTED:{entity}]"

    def _redact_with_presidio(self, text: str) -> str:
        assert self._analyzer is not None
        # Filter to entities we care about that presidio knows.
        results = self._analyzer.analyze(text=text, entities=list(self.entities), language="en")
        # presidio returns spans with .start, .end, .entity_type
        # Sort by start descending so we can splice without reindexing.
        results = sorted(results, key=lambda r: r.start, reverse=True)
        out = text
        for r in results:
            span = out[r.start : r.end]
            if span in self.allow_list:
                continue
            out = out[: r.start] + self._mask(r.entity_type) + out[r.end :]
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
            except Exception:
                # presidio failed mid-call — fall back rather than crash.
                return self._redact_with_fallback(text)
        return self._redact_with_fallback(text)
