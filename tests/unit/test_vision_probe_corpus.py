"""Phase C.C4d — ASI11_VISION seed probe corpus.

Covers:
  - exactly 8 vision probes load
  - each carries at least one attachment with non-empty alt_text
  - vision probes do NOT inflate ``load_all_probes`` (Route B)
  - probe IDs follow the ``ASI11-VIS-*`` convention
  - each YAML parses cleanly through the standard probe validator
"""

from __future__ import annotations

from agent_guardian.models.multimodal import ASI11_VISION
from agent_guardian.probes.loader import load_all_probes, load_vision_probes


class TestVisionCorpusSize:
    def test_eight_vision_probes_load(self) -> None:
        probes = load_vision_probes()
        assert len(probes) == 8

    def test_vision_probes_excluded_from_attack_corpus(self) -> None:
        # Route B: keep the 120/4/124 corpus-size assertion stable.
        all_probes = load_all_probes()
        attack = [p for p in all_probes if not p.id.startswith("JDG-")]
        judges = [p for p in all_probes if p.id.startswith("JDG-")]
        assert len(attack) == 120
        assert len(judges) == 4
        assert len(all_probes) == 124
        # Spot check: no vision probe leaked through the ASI exclusion.
        assert not [p for p in all_probes if p.id.startswith("ASI11-")]


class TestVisionProbeShape:
    def test_each_vision_probe_carries_at_least_one_attachment(self) -> None:
        for probe in load_vision_probes():
            assert len(probe.attachments) >= 1, f"{probe.id} has no attachments"

    def test_each_attachment_has_non_empty_alt_text(self) -> None:
        for probe in load_vision_probes():
            for att in probe.attachments:
                assert att.alt_text, f"{probe.id}: attachment alt_text empty"

    def test_each_attachment_is_image_mime(self) -> None:
        for probe in load_vision_probes():
            for att in probe.attachments:
                assert att.mime_type.startswith("image/"), (
                    f"{probe.id}: non-image mime {att.mime_type}"
                )

    def test_each_attachment_round_trips_bytes(self) -> None:
        for probe in load_vision_probes():
            for att in probe.attachments:
                decoded = att.decoded_bytes()
                assert len(decoded) == att.size_bytes


class TestVisionProbeIdentity:
    def test_ids_use_asi11_vis_prefix(self) -> None:
        for probe in load_vision_probes():
            assert probe.id.startswith("ASI11-VIS-"), (
                f"unexpected vision probe id format: {probe.id}"
            )

    def test_ids_are_unique(self) -> None:
        ids = [p.id for p in load_vision_probes()]
        assert len(ids) == len(set(ids))

    def test_eight_distinct_attack_families(self) -> None:
        # Names map to the 8 attack families in the task brief.
        names = {p.name for p in load_vision_probes()}
        assert names == {
            "typographic-injection",
            "screenshot-injection",
            "steganographic-channel",
            "ascii-art-injection",
            "qr-code-payload",
            "homoglyph-image",
            "alt-text-bypass",
            "rendered-prompt-leak",
        }

    def test_asi11_vision_sentinel_still_stable(self) -> None:
        # WHY: probe IDs greppable for ASI11_VISION rely on the constant.
        assert ASI11_VISION == "ASI11_VISION"
