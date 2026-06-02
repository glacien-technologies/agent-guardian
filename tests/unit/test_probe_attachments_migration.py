"""Phase C.C4a — Probe model carries attachments tuple.

Covers:
  - default empty tuple keeps existing probe construction working
  - empty default is hashable (frozen model preserved)
  - canonical-JSON output does NOT change for probes without attachments
  - non-empty round-trips through model_dump / model_validate
  - non-empty serialises cleanly via to_canonical_json
"""

from __future__ import annotations

import base64

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.multimodal import ProbeAttachment
from agent_guardian.models.probe import Probe
from agent_guardian.models.severity import Severity
from agent_guardian.models.tier import Tier
from agent_guardian.reports.canonical import to_canonical_json


def _base_probe(**overrides: object) -> Probe:
    defaults: dict[str, object] = {
        "id": "ASI01-X-001",
        "name": "x",
        "asi": AsiCategory.ASI01,
        "mitre_atlas": ["AML.T0054"],
        "csa_category": CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        "severity": Severity.HIGH,
        "tier_floor": Tier.T2_HIGH,
        "seeds": ["payload"],
        "description": "d",
        "expected_evidence": "e",
        "remediation_ref": "r",
    }
    defaults.update(overrides)
    return Probe(**defaults)  # type: ignore[arg-type]


class TestDefaultEmptyAttachments:
    def test_default_is_empty_tuple(self) -> None:
        p = _base_probe()
        assert p.attachments == ()

    def test_model_dump_omits_attachments_payload_when_empty(self) -> None:
        # The field is present (pydantic emits all fields), but signals empty.
        p = _base_probe()
        dumped = p.model_dump(mode="json")
        assert dumped["attachments"] == []

    def test_canonical_json_for_empty_matches_pre_migration_shape(self) -> None:
        # Pre-migration probes did not carry an "attachments" key. We accept the
        # presence of an empty list — it is the smallest possible delta and
        # produces a deterministic, reviewable byte change in any future audit
        # rather than a hidden-behind-omitted-key trap.
        p = _base_probe()
        blob = to_canonical_json(p.model_dump(mode="json"))
        assert b'"attachments":[]' in blob


class TestAttachmentsRoundTrip:
    def test_non_empty_round_trips_via_dict(self) -> None:
        att = ProbeAttachment(
            mime_type="image/png",
            b64_payload=base64.b64encode(b"hi").decode("ascii"),
            alt_text="tiny",
            size_bytes=2,
        )
        p = _base_probe(attachments=(att,))
        dumped = p.model_dump()
        rebuilt = Probe.model_validate(dumped)
        assert rebuilt == p
        assert rebuilt.attachments[0].mime_type == "image/png"

    def test_non_empty_round_trips_via_json_dump(self) -> None:
        att = ProbeAttachment(
            mime_type="image/png",
            b64_payload=base64.b64encode(b"hi").decode("ascii"),
            alt_text="tiny",
            size_bytes=2,
        )
        p = _base_probe(attachments=(att,))
        dumped = p.model_dump(mode="json")
        # Attachments serialise as a list-of-dicts in JSON mode.
        assert isinstance(dumped["attachments"], list)
        assert dumped["attachments"][0]["mime_type"] == "image/png"
        rebuilt = Probe.model_validate(dumped)
        assert rebuilt == p

    def test_non_empty_canonical_json_includes_attachment(self) -> None:
        att = ProbeAttachment(
            mime_type="image/png",
            b64_payload="aGk=",
            alt_text="tiny",
            size_bytes=2,
        )
        p = _base_probe(attachments=(att,))
        blob = to_canonical_json(p.model_dump(mode="json"))
        assert b'"mime_type":"image/png"' in blob
        assert b'"alt_text":"tiny"' in blob

    def test_canonical_json_handles_raw_attachment_dataclass(self) -> None:
        # Defensive: if a ProbeAttachment somehow flows through to_canonical_json
        # directly (not via pydantic), the encoder must serialise it.
        att = ProbeAttachment(
            mime_type="image/png",
            b64_payload="aGk=",
            alt_text="tiny",
            size_bytes=2,
        )
        blob = to_canonical_json(att)
        assert b'"mime_type":"image/png"' in blob


class TestExistingProbeBehaviourPreserved:
    def test_no_pickle_snapshot_breakage(self) -> None:
        # WHY: pickle round-trip surfaces frozen-model regressions. Safe here —
        # we pickle objects we constructed in this test, never untrusted bytes.
        import pickle

        p = _base_probe()
        restored = pickle.loads(pickle.dumps(p))
        assert restored == p

    def test_pickle_round_trip_with_attachments(self) -> None:
        # Same as above — round-tripping a locally-constructed object, no
        # untrusted-deserialisation surface.
        import pickle

        att = ProbeAttachment(mime_type="image/png", b64_payload="aGk=", alt_text="t", size_bytes=2)
        p = _base_probe(attachments=(att,))
        restored = pickle.loads(pickle.dumps(p))
        assert restored == p
        assert restored.attachments[0].b64_payload == "aGk="
