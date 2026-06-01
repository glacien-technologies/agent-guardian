"""Phase C.C4 — vision multimodal primitive tests.

Covers ProbeAttachment validation (mime-type prefix gate, alt_text
required, size cap), immutability, byte round-trip, and the
``from_bytes`` helper.
"""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError

import pytest

from agent_guardian.models.multimodal import ASI11_VISION, ProbeAttachment

# Minimal 1x1 transparent PNG (header + IHDR + IDAT + IEND).
_TINY_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\rIDATx\x9cc\xfc\xff\xff?\x03\x00\x06\x04\x02\xfeb\x0e\xb2\x9d\x00\x00\x00\x00IEND\xaeB`\x82"
)


# --------------------------------------------------------------------------- #
# Construction + validation
# --------------------------------------------------------------------------- #


class TestAttachmentConstruction:
    def test_minimal_valid_attachment(self) -> None:
        att = ProbeAttachment(
            mime_type="image/png",
            b64_payload=base64.b64encode(b"hi").decode("ascii"),
            alt_text="tiny test image",
            size_bytes=2,
        )
        assert att.mime_type == "image/png"
        assert att.size_bytes == 2

    def test_from_bytes_helper_computes_size_and_b64(self) -> None:
        att = ProbeAttachment.from_bytes(
            _TINY_PNG_BYTES, mime_type="image/png", alt_text="1x1 transparent png"
        )
        assert att.size_bytes == len(_TINY_PNG_BYTES)
        assert att.mime_type == "image/png"
        # b64 round-trip preserves bytes exactly.
        assert att.decoded_bytes() == _TINY_PNG_BYTES


class TestAttachmentValidation:
    def test_empty_mime_type_raises(self) -> None:
        with pytest.raises(ValueError, match="mime_type must be non-empty"):
            ProbeAttachment(mime_type="", b64_payload="abc", alt_text="x", size_bytes=2)

    def test_non_image_mime_type_rejected(self) -> None:
        # Audio is deliberately rejected in v1.
        with pytest.raises(ValueError, match=r"must start with 'image/'"):
            ProbeAttachment(mime_type="audio/mpeg", b64_payload="abc", alt_text="x", size_bytes=2)

    def test_empty_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="b64_payload must be non-empty"):
            ProbeAttachment(mime_type="image/png", b64_payload="", alt_text="x", size_bytes=2)

    def test_empty_alt_text_rejected_for_accessibility(self) -> None:
        with pytest.raises(ValueError, match="alt_text must be non-empty"):
            ProbeAttachment(mime_type="image/png", b64_payload="abc", alt_text="", size_bytes=2)

    def test_zero_size_raises(self) -> None:
        with pytest.raises(ValueError, match="size_bytes must be > 0"):
            ProbeAttachment(mime_type="image/png", b64_payload="abc", alt_text="x", size_bytes=0)

    def test_negative_size_raises(self) -> None:
        with pytest.raises(ValueError, match="size_bytes must be > 0"):
            ProbeAttachment(mime_type="image/png", b64_payload="abc", alt_text="x", size_bytes=-1)

    def test_size_cap_1mib(self) -> None:
        # Exactly 1 MiB is allowed.
        ProbeAttachment(
            mime_type="image/png",
            b64_payload="abc",
            alt_text="exactly 1 MiB",
            size_bytes=1_048_576,
        )

    def test_oversize_attachment_rejected(self) -> None:
        with pytest.raises(ValueError, match="exceeds the 1 MiB cap"):
            ProbeAttachment(
                mime_type="image/png",
                b64_payload="abc",
                alt_text="too big",
                size_bytes=1_048_577,
            )


# --------------------------------------------------------------------------- #
# Immutability
# --------------------------------------------------------------------------- #


class TestImmutability:
    def test_cannot_reassign_field(self) -> None:
        att = ProbeAttachment(mime_type="image/png", b64_payload="abc", alt_text="x", size_bytes=2)
        with pytest.raises(FrozenInstanceError):
            att.mime_type = "image/jpeg"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Round-trip + tampered-payload detection
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    def test_decoded_bytes_round_trip(self) -> None:
        raw = b"\x89PNG\r\n test payload data"
        att = ProbeAttachment.from_bytes(raw, mime_type="image/png", alt_text="round trip")
        assert att.decoded_bytes() == raw

    def test_tampered_size_mismatch_surfaces(self) -> None:
        # Construct with an inconsistent size_bytes — decode should raise.
        att = ProbeAttachment(
            mime_type="image/png",
            b64_payload=base64.b64encode(b"actual").decode("ascii"),
            alt_text="tamper test",
            size_bytes=999,  # lying — real bytes are 6
        )
        with pytest.raises(ValueError, match="does not match decoded payload"):
            att.decoded_bytes()


# --------------------------------------------------------------------------- #
# ASI11 sentinel
# --------------------------------------------------------------------------- #


class TestAsi11Sentinel:
    def test_constant_is_stable(self) -> None:
        # Probe YAMLs grep for this exact literal; changing it without a
        # migration would silently break every vision probe.
        assert ASI11_VISION == "ASI11_VISION"
