"""Multimodal attachments — Phase C.C4 vision primitive.

This module ships the data shape for vision-injection probes (ASI11) without
touching the canonical :class:`agent_guardian.models.asi.AsiCategory` enum
or :class:`agent_guardian.models.probe.Probe` schema. Both of those would
ripple downstream cardinality assumptions (asi_scores defaults, AIVSS
sub-score map, corpus-size assertions) that aren't ready to absorb a new
category in this commit.

What lands here:
  - :class:`ProbeAttachment`: frozen dataclass for a single binary
    payload (mime_type, b64_payload, alt_text, size_bytes) with a 1 MB
    cap enforced at construction.
  - :data:`ASI11_VISION`: the canonical string identifier used in vision
    probe YAMLs, kept separate from :class:`AsiCategory` until the full
    schema migration lands.

What's deliberately *not* here:
  - Audio is explicitly out of scope for v1 multimodal per operator
    decision. Future expansion would add ``ASI11_AUDIO`` or split into
    ``ASI11_VISION`` / ``ASI12_AUDIO`` once corpus + adapter coverage exists.
  - Probe schema migration to carry ``attachments: tuple[ProbeAttachment, ...]``
    on the canonical :class:`Probe` model. Tracked separately so the
    test_corpus_size_is_ninety_six gate stays green.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

# Canonical string identifier for the multimodal-vision attack category.
# Probe YAMLs targeting vision injection carry ``asi: ASI11_VISION``. When the
# full enum migration ships, this constant will be replaced by an
# ``AsiCategory.ASI11_VISION`` enum value and downstream code can still grep
# for the same literal.
ASI11_VISION = "ASI11_VISION"


# 1 MB cap on a single attachment. Picked so a probe YAML stays under the
# 5 MB git-friendly threshold even with a few attachments + metadata, and so
# loading a probe corpus stays under typical memory budgets. Operators who
# need larger attachments should ship them out-of-band and reference by URL.
_MAX_ATTACHMENT_SIZE_BYTES = 1_048_576  # 1 MiB exact


@dataclass(frozen=True, slots=True)
class ProbeAttachment:
    """One binary payload riding alongside a probe seed.

    Fields:
      mime_type: standard MIME identifier, MUST start with ``image/`` in v1.
        Other prefixes are reserved for future expansion (audio, etc.) and
        currently rejected at construction.
      b64_payload: base64-encoded raw bytes. We carry the encoded form (not
        raw bytes) so the probe YAML round-trips cleanly through every
        serialisation surface (YAML, JSON, signed-bundle envelopes).
      alt_text: REQUIRED human-readable description of the attachment.
        Accessibility is non-negotiable + it's also the audit trail for
        which payload a reviewer is looking at without having to render
        the image.
      size_bytes: cached decoded length. Set at construction so call sites
        don't have to base64-decode just to size-check. Enforced ≤
        :data:`_MAX_ATTACHMENT_SIZE_BYTES` (1 MiB).
    """

    mime_type: str
    b64_payload: str
    alt_text: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not self.mime_type:
            raise ValueError("ProbeAttachment.mime_type must be non-empty")
        if not self.mime_type.startswith("image/"):
            # v1 = vision only. Audio (audio/*) is deliberately rejected
            # rather than silently accepted so a future audio probe can't
            # accidentally land before its adapter does.
            raise ValueError(
                f"ProbeAttachment.mime_type must start with 'image/' in v1 (audio deferred); "
                f"got {self.mime_type!r}"
            )
        if not self.b64_payload:
            raise ValueError("ProbeAttachment.b64_payload must be non-empty")
        if not self.alt_text:
            raise ValueError(
                "ProbeAttachment.alt_text must be non-empty — accessibility + audit-trail requirement"
            )
        if self.size_bytes <= 0:
            raise ValueError(f"ProbeAttachment.size_bytes must be > 0; got {self.size_bytes!r}")
        if self.size_bytes > _MAX_ATTACHMENT_SIZE_BYTES:
            raise ValueError(
                f"ProbeAttachment.size_bytes ({self.size_bytes}) exceeds the 1 MiB cap "
                f"({_MAX_ATTACHMENT_SIZE_BYTES}) — ship larger payloads out-of-band by URL reference"
            )

    @classmethod
    def from_bytes(cls, raw: bytes, *, mime_type: str, alt_text: str) -> ProbeAttachment:
        """Construct from raw bytes; base64-encodes for storage."""
        return cls(
            mime_type=mime_type,
            b64_payload=base64.b64encode(raw).decode("ascii"),
            alt_text=alt_text,
            size_bytes=len(raw),
        )

    def decoded_bytes(self) -> bytes:
        """Decode the base64 payload back to raw bytes.

        Verifies the decoded length matches ``size_bytes``; if a probe YAML
        was tampered between authoring and load the mismatch surfaces here.
        """
        decoded = base64.b64decode(self.b64_payload, validate=True)
        if len(decoded) != self.size_bytes:
            raise ValueError(
                f"ProbeAttachment.size_bytes ({self.size_bytes}) does not match decoded payload "
                f"length ({len(decoded)}) — corrupt or tampered probe YAML"
            )
        return decoded


__all__ = ["ASI11_VISION", "ProbeAttachment"]
