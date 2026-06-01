"""Phase C.C4b — Probe YAML loader parses attachments.

Covers inline b64 mode, sibling-path mode, mutual-exclusivity guard,
path-traversal refusal, and graceful failure on missing/invalid input.
"""

from __future__ import annotations

import base64
from pathlib import Path
from textwrap import dedent

import pytest

from agent_guardian.models.probe import ProbeValidationError, load_probe

# Minimal 1x1 transparent PNG.
_TINY_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\rIDATx\x9cc\xfc\xff\xff?\x03\x00\x06\x04\x02\xfeb\x0e\xb2\x9d\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _write(path: Path, content: str) -> Path:
    path.write_text(dedent(content).lstrip("\n"), encoding="utf-8")
    return path


def _probe_yaml(*, attachments_block: str = "") -> str:
    return f"""
        id: ASI11-VIS-001
        name: vision-test
        asi: ASI01
        mitre_atlas:
          - AML.T0054
        csa_category: goal-instruction-manipulation
        severity: high
        tier_floor: T2
        seeds:
          - "describe the image"
        description: vision attachment test probe
        expected_evidence: vision_directive_obeyed
        remediation_ref: REM-VIS-001
{attachments_block}
    """


class TestInlineB64Mode:
    def test_inline_b64_payload_loads(self, tmp_path: Path) -> None:
        b64 = base64.b64encode(_TINY_PNG_BYTES).decode("ascii")
        body = _probe_yaml(
            attachments_block=(
                "        attachments:\n"
                "          - mime_type: image/png\n"
                f"            b64_payload: {b64}\n"
                f"            size_bytes: {len(_TINY_PNG_BYTES)}\n"
                "            alt_text: tiny test png\n"
            )
        )
        path = _write(tmp_path / "p.yaml", body)
        probe = load_probe(path)
        assert len(probe.attachments) == 1
        att = probe.attachments[0]
        assert att.mime_type == "image/png"
        assert att.size_bytes == len(_TINY_PNG_BYTES)
        assert att.decoded_bytes() == _TINY_PNG_BYTES


class TestSiblingPathMode:
    def test_sibling_binary_resolves_and_encodes(self, tmp_path: Path) -> None:
        asset_path = tmp_path / "tiny.png"
        asset_path.write_bytes(_TINY_PNG_BYTES)
        body = _probe_yaml(
            attachments_block=(
                "        attachments:\n"
                "          - mime_type: image/png\n"
                "            path: tiny.png\n"
                "            alt_text: tiny via path\n"
            )
        )
        path = _write(tmp_path / "p.yaml", body)
        probe = load_probe(path)
        assert len(probe.attachments) == 1
        att = probe.attachments[0]
        assert att.mime_type == "image/png"
        assert att.size_bytes == len(_TINY_PNG_BYTES)
        # b64 round-trips back to the original bytes.
        assert att.decoded_bytes() == _TINY_PNG_BYTES
        assert att.alt_text == "tiny via path"

    def test_missing_sibling_path_raises(self, tmp_path: Path) -> None:
        body = _probe_yaml(
            attachments_block=(
                "        attachments:\n"
                "          - mime_type: image/png\n"
                "            path: not-there.png\n"
                "            alt_text: missing asset\n"
            )
        )
        path = _write(tmp_path / "p.yaml", body)
        with pytest.raises(ProbeValidationError, match="sibling asset not found"):
            load_probe(path)

    def test_path_traversal_refused(self, tmp_path: Path) -> None:
        # WHY: a YAML in the corpus must not be able to read /etc/passwd.
        body = _probe_yaml(
            attachments_block=(
                "        attachments:\n"
                "          - mime_type: image/png\n"
                "            path: ../escape.png\n"
                "            alt_text: traversal test\n"
            )
        )
        path = _write(tmp_path / "p.yaml", body)
        with pytest.raises(ProbeValidationError, match="escapes the probe directory"):
            load_probe(path)


class TestMutualExclusivity:
    def test_path_and_b64_both_set_rejected(self, tmp_path: Path) -> None:
        asset_path = tmp_path / "tiny.png"
        asset_path.write_bytes(_TINY_PNG_BYTES)
        body = _probe_yaml(
            attachments_block=(
                "        attachments:\n"
                "          - mime_type: image/png\n"
                "            path: tiny.png\n"
                "            b64_payload: aGk=\n"
                "            size_bytes: 2\n"
                "            alt_text: both modes\n"
            )
        )
        path = _write(tmp_path / "p.yaml", body)
        with pytest.raises(ProbeValidationError, match="cannot set both 'path' and 'b64_payload'"):
            load_probe(path)


class TestAttachmentValidationErrors:
    def test_attachments_must_be_list(self, tmp_path: Path) -> None:
        body = _probe_yaml(attachments_block="        attachments: not-a-list\n")
        path = _write(tmp_path / "p.yaml", body)
        with pytest.raises(ProbeValidationError, match="attachments must be a list"):
            load_probe(path)

    def test_attachment_entry_must_be_mapping(self, tmp_path: Path) -> None:
        body = _probe_yaml(attachments_block=("        attachments:\n          - just-a-string\n"))
        path = _write(tmp_path / "p.yaml", body)
        with pytest.raises(ProbeValidationError, match="must be a mapping"):
            load_probe(path)

    def test_alt_text_required(self, tmp_path: Path) -> None:
        asset_path = tmp_path / "tiny.png"
        asset_path.write_bytes(_TINY_PNG_BYTES)
        body = _probe_yaml(
            attachments_block=(
                "        attachments:\n"
                "          - mime_type: image/png\n"
                "            path: tiny.png\n"
                "            alt_text: ''\n"
            )
        )
        path = _write(tmp_path / "p.yaml", body)
        with pytest.raises(ProbeValidationError, match="alt_text"):
            load_probe(path)

    def test_no_attachments_block_leaves_default_empty(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "p.yaml", _probe_yaml())
        probe = load_probe(path)
        assert probe.attachments == ()
