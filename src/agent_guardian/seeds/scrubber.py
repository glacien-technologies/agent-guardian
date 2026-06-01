"""PII scrubber for winning-seed persistence (Phase B.B6).

A conservative regex-based redactor. We intentionally do NOT depend on
Presidio (it is a heavy optional dep behind the ``[full]`` extra). The
trade-off is documented: this scrubber may miss some PII patterns
(false negatives) but will never crash on any input. False positives —
e.g. legitimate attack payloads that contain the string ``sk-`` as part
of a test value — are acceptable; a slightly-redacted winning seed is
still useful for replay because the surrounding mutation pattern is what
matters most.

Each redaction event is logged at DEBUG with the ``PhaseB.B6`` tag so a
grep over ``events.jsonl`` can confirm the scrubber actually fired.
"""

from __future__ import annotations

import logging
import re

__all__ = ["PiiScrubber"]

_LOG = logging.getLogger("agent_guardian.seeds.scrubber")


# Conservative regex set. Each pattern maps to a (token, kind) pair.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Email addresses — RFC 5321 simplified.
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")),
    # OpenAI-style key (sk-...). Common in attack payloads.
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    # AWS access key (AKIA + 16 chars).
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS secret keys are 40 chars base64-ish — pattern: long high-entropy.
    # Match the explicit assignment form so we don't redact every long token.
    (
        "aws_secret_key",
        re.compile(
            r"(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?",
            re.IGNORECASE,
        ),
    ),
    # GitHub PAT.
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    # Generic Bearer tokens in header form.
    (
        "bearer_token",
        re.compile(r"(?:Bearer|bearer)\s+([A-Za-z0-9._\-]{16,})"),
    ),
    # Phone numbers — E.164 (+15551234567) and NANP (555-123-4567).
    (
        "phone_e164",
        re.compile(r"\+\d{8,15}\b"),
    ),
    (
        "phone_nanp",
        re.compile(r"\b\d{3}[\-\.\s]\d{3}[\-\.\s]\d{4}\b"),
    ),
    # IPv4 addresses.
    (
        "ipv4",
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\."
            r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\."
            r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\."
            r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
        ),
    ),
    # US SSN (NNN-NN-NNNN).
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


class PiiScrubber:
    """Stdlib-regex PII redactor.

    Use :meth:`scrub` to replace matches with ``[REDACTED:<kind>]`` tokens.
    The number of redactions performed is tracked per-call so callers can
    log how aggressive the scrub was.
    """

    def __init__(self) -> None:
        self._last_redaction_count = 0

    @property
    def last_redaction_count(self) -> int:
        """Number of redactions performed by the most recent scrub call."""
        return self._last_redaction_count

    def scrub(self, text: str) -> str:
        """Return ``text`` with every PII match replaced by ``[REDACTED:<kind>]``."""
        if not text:
            self._last_redaction_count = 0
            return text or ""
        scrubbed = text
        total = 0
        for kind, pattern in _PATTERNS:
            replacement = f"[REDACTED:{kind}]"
            scrubbed, n = pattern.subn(replacement, scrubbed)
            if n:
                _LOG.debug(
                    "PhaseB.B6 scrubber.redaction: kind=%s count=%d",
                    kind,
                    n,
                )
                total += n
        self._last_redaction_count = total
        return scrubbed
