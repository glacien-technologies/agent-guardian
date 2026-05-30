"""Tests for :class:`agent_guardian.core.memory.SharedMemory` (M5).

The ``[full]`` extra (faiss, sentence-transformers) is NOT installed in the
default test environment. Without numpy, :meth:`vector_search` raises
:class:`MemoryFeatureUnavailable` — this is exercised here. The
hash-fallback embedder is exercised for *storage* of reflection vectors,
and the in-memory similarity ordering it produces is verified to be
deterministic.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.core.memory import (
    MemoryFeatureUnavailable,
    MemoryRecord,
    MemoryStats,
    SharedMemory,
    VectorHit,
    _hash_embed,
)
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity


def _make_finding(
    *,
    fid: str = "f-001",
    asi: AsiCategory = AsiCategory.ASI01,
    success: bool = True,
    summary: str = "test finding",
) -> Finding:
    return Finding(
        id=fid,
        probe_id="probe-1",
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success=success,
        confidence=0.9,
        summary=summary,
        created_at=datetime(2026, 5, 26, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_fingerprint(ref: str = "test-target") -> TargetFingerprint:
    return TargetFingerprint(
        mode="prompt",
        ref=ref,
        has_tools=True,
        has_memory=False,
        touches_pii=False,
        is_multi_agent=False,
    )


# ---------------------------------------------------------------------------
# Construction & layout
# ---------------------------------------------------------------------------


def test_constructor_creates_scan_dir(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    assert mem.scan_dir == tmp_path / "scan-A"
    assert mem.scan_dir.is_dir()
    assert mem.jsonl_path == tmp_path / "scan-A" / "memory.jsonl"


def test_empty_scan_id_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        SharedMemory("", root_dir=tmp_path)


def test_stats_empty_memory(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    stats = mem.stats()
    assert isinstance(stats, MemoryStats)
    assert stats.findings == 0
    assert stats.reflections == 0
    assert stats.attempted_seeds == 0
    assert stats.has_fingerprint is False
    assert stats.vector_index_size == 0
    assert stats.embedder_kind == "none"


def test_default_root_dir_is_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Redirect $HOME so we don't pollute the user's real ~.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    mem = SharedMemory("scan-X")
    assert mem.scan_dir == tmp_path / ".agentguardian" / "scans" / "scan-X"


# ---------------------------------------------------------------------------
# Write & read findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_finding_appears_in_index(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    f = _make_finding()
    await mem.write_finding(f)
    assert mem.findings_by_asi(AsiCategory.ASI01) == (f,)
    assert mem.all_findings() == (f,)


@pytest.mark.asyncio
async def test_write_finding_persists_to_jsonl(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    f = _make_finding()
    await mem.write_finding(f)
    lines = mem.jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["record_type"] == "finding"
    assert record["payload"]["id"] == "f-001"


@pytest.mark.asyncio
async def test_findings_by_asi_partitions_correctly(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    f1 = _make_finding(fid="f-1", asi=AsiCategory.ASI01)
    f2 = _make_finding(fid="f-2", asi=AsiCategory.ASI02)
    f3 = _make_finding(fid="f-3", asi=AsiCategory.ASI01)
    await mem.write_finding(f1)
    await mem.write_finding(f2)
    await mem.write_finding(f3)
    assert {f.id for f in mem.findings_by_asi(AsiCategory.ASI01)} == {"f-1", "f-3"}
    assert {f.id for f in mem.findings_by_asi(AsiCategory.ASI02)} == {"f-2"}
    assert mem.findings_by_asi(AsiCategory.ASI03) == ()


@pytest.mark.asyncio
async def test_stats_after_writes(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_finding(_make_finding(fid="f-1"))
    await mem.write_finding(_make_finding(fid="f-2"))
    await mem.set_target_fingerprint(_make_fingerprint())
    await mem.write_attempted_seed(AsiCategory.ASI01, "seed-1")
    await mem.write_reflection("recon", "found a tool surface", embed=False)
    stats = mem.stats()
    assert stats.findings == 2
    assert stats.has_fingerprint is True
    assert stats.attempted_seeds == 1
    assert stats.reflections == 1


# ---------------------------------------------------------------------------
# Reflections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_reflection_round_trip(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_reflection("asi01", "hijack vector observed", embed=False)
    await mem.write_reflection("asi01", "system prompt leak attempted", embed=False)
    refs = mem.reflections_for("asi01")
    assert refs == ("hijack vector observed", "system prompt leak attempted")
    assert mem.reflections_for("asi02") == ()


@pytest.mark.asyncio
async def test_write_reflection_with_embed_grows_vector_index(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_reflection("recon", "agent has memory and PII tools", embed=True)
    stats = mem.stats()
    assert stats.vector_index_size == 1
    # Either path is correct: hash-fallback on a minimal CI install,
    # sentence-transformers when the [full] extra is present locally.
    # ``none`` would mean embedding silently no-op'd — that is a regression.
    assert stats.embedder_kind in {"hash-fallback", "sentence-transformers"}


@pytest.mark.asyncio
async def test_write_reflection_embed_false_skips_vector_index(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_reflection("recon", "scratchpad", embed=False)
    assert mem.stats().vector_index_size == 0
    assert mem.stats().embedder_kind == "none"


@pytest.mark.asyncio
async def test_write_reflection_validates_input(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    with pytest.raises(ValueError):
        await mem.write_reflection("", "content", embed=False)
    with pytest.raises(ValueError):
        await mem.write_reflection("agent", "", embed=False)


# ---------------------------------------------------------------------------
# Attempted seeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attempted_seeds_round_trip(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_attempted_seed(AsiCategory.ASI01, "seed-a")
    await mem.write_attempted_seed(AsiCategory.ASI01, "seed-b")
    seeds = mem.attempted_seeds(AsiCategory.ASI01)
    assert seeds == frozenset({"seed-a", "seed-b"})


@pytest.mark.asyncio
async def test_attempted_seeds_dedup_in_index(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_attempted_seed(AsiCategory.ASI01, "seed-a")
    await mem.write_attempted_seed(AsiCategory.ASI01, "seed-a")
    # In-memory set deduplicates …
    assert mem.attempted_seeds(AsiCategory.ASI01) == frozenset({"seed-a"})
    # … but the JSONL preserves the audit trail.
    lines = mem.jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


@pytest.mark.asyncio
async def test_attempted_seed_rejects_empty_id(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    with pytest.raises(ValueError):
        await mem.write_attempted_seed(AsiCategory.ASI01, "")


@pytest.mark.asyncio
async def test_attempted_seeds_isolated_per_asi(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_attempted_seed(AsiCategory.ASI01, "seed-1")
    await mem.write_attempted_seed(AsiCategory.ASI02, "seed-2")
    assert mem.attempted_seeds(AsiCategory.ASI01) == frozenset({"seed-1"})
    assert mem.attempted_seeds(AsiCategory.ASI02) == frozenset({"seed-2"})
    assert mem.attempted_seeds(AsiCategory.ASI03) == frozenset()


# ---------------------------------------------------------------------------
# Target fingerprint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_target_fingerprint(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    assert mem.target_fingerprint() is None
    fp = _make_fingerprint("target-1")
    await mem.set_target_fingerprint(fp)
    assert mem.target_fingerprint() == fp


@pytest.mark.asyncio
async def test_set_target_fingerprint_idempotent_latest_wins(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    fp1 = _make_fingerprint("first")
    fp2 = _make_fingerprint("second")
    await mem.set_target_fingerprint(fp1)
    await mem.set_target_fingerprint(fp2)
    current = mem.target_fingerprint()
    assert current is not None
    assert current.ref == "second"
    # JSONL retains both for audit.
    lines = mem.jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# Restore from JSONL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_restore_rebuilds_indexes(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_finding(_make_finding(fid="f-1", asi=AsiCategory.ASI01))
    await mem.write_finding(_make_finding(fid="f-2", asi=AsiCategory.ASI02))
    await mem.set_target_fingerprint(_make_fingerprint("the-target"))
    await mem.write_attempted_seed(AsiCategory.ASI05, "seed-x")
    await mem.write_reflection("recon", "thinking out loud", embed=False)
    await mem.aclose()

    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    assert {f.id for f in restored.all_findings()} == {"f-1", "f-2"}
    fp = restored.target_fingerprint()
    assert fp is not None
    assert fp.ref == "the-target"
    assert restored.attempted_seeds(AsiCategory.ASI05) == frozenset({"seed-x"})
    assert restored.reflections_for("recon") == ("thinking out loud",)


@pytest.mark.asyncio
async def test_restore_skips_malformed_lines(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_finding(_make_finding(fid="f-1"))
    # Inject a malformed line in the middle.
    with mem.jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write("this is not valid json\n")
        fh.write("{}\n")  # valid json, but not a MemoryRecord
        fh.write('{"record_type": "finding"}\n')  # MemoryRecord-shaped but missing fields
    await mem.write_finding(_make_finding(fid="f-2"))

    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    ids = {f.id for f in restored.all_findings()}
    assert ids == {"f-1", "f-2"}


@pytest.mark.asyncio
async def test_restore_skips_unparseable_finding_payload(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_finding(_make_finding(fid="f-1"))
    with mem.jsonl_path.open("a", encoding="utf-8") as fh:
        # Valid MemoryRecord envelope but the payload isn't a Finding.
        fh.write(
            json.dumps(
                {
                    "record_type": "finding",
                    "scan_id": "scan-A",
                    "timestamp": datetime(2026, 5, 26, tzinfo=timezone.utc).isoformat(),
                    "payload": {"not": "a finding"},
                }
            )
            + "\n"
        )
    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    assert {f.id for f in restored.all_findings()} == {"f-1"}


@pytest.mark.asyncio
async def test_restore_skips_invalid_fingerprint(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    with mem.jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "record_type": "fingerprint",
                    "scan_id": "scan-A",
                    "timestamp": datetime(2026, 5, 26, tzinfo=timezone.utc).isoformat(),
                    "payload": {"mode": "INVALID_MODE"},
                }
            )
            + "\n"
        )
    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    assert restored.target_fingerprint() is None


@pytest.mark.asyncio
async def test_restore_skips_invalid_attempted_seed_asi(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    with mem.jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "record_type": "attempted_seed",
                    "scan_id": "scan-A",
                    "timestamp": datetime(2026, 5, 26, tzinfo=timezone.utc).isoformat(),
                    "payload": {"asi": "ASI99", "seed_id": "bad"},
                }
            )
            + "\n"
        )
    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    for asi in AsiCategory:
        assert restored.attempted_seeds(asi) == frozenset()


@pytest.mark.asyncio
async def test_restore_skips_reflection_missing_fields(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    with mem.jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "record_type": "reflection",
                    "scan_id": "scan-A",
                    "timestamp": datetime(2026, 5, 26, tzinfo=timezone.utc).isoformat(),
                    "payload": {"agent": "", "content": ""},
                }
            )
            + "\n"
        )
    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    assert restored.reflections_for("anything") == ()


@pytest.mark.asyncio
async def test_restore_blank_lines_ignored(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_finding(_make_finding(fid="f-1"))
    with mem.jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write("\n\n   \n")
    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    assert len(restored.all_findings()) == 1


@pytest.mark.asyncio
async def test_two_instances_same_scan_share_jsonl(tmp_path: Path) -> None:
    """If one instance writes and a second calls restore(), the read sees the write."""
    mem_a = SharedMemory("scan-shared", root_dir=tmp_path)
    await mem_a.write_finding(_make_finding(fid="f-from-a"))
    # Brand-new instance pointed at the same scan_id.
    mem_b = SharedMemory.restore("scan-shared", root_dir=tmp_path)
    assert {f.id for f in mem_b.all_findings()} == {"f-from-a"}


# ---------------------------------------------------------------------------
# JSONL durability / fsync
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jsonl_each_write_is_one_line(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_finding(_make_finding(fid="f-1"))
    await mem.write_finding(_make_finding(fid="f-2"))
    await mem.write_attempted_seed(AsiCategory.ASI01, "seed-1")
    await mem.set_target_fingerprint(_make_fingerprint())
    lines = mem.jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    for line in lines:
        record = MemoryRecord.model_validate_json(line)
        assert record.scan_id == "scan-A"


@pytest.mark.asyncio
async def test_stats_json_snapshot_written(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_finding(_make_finding(fid="f-1"))
    assert mem.stats_path.exists()
    snapshot = json.loads(mem.stats_path.read_text(encoding="utf-8"))
    assert snapshot["scan_id"] == "scan-A"
    assert snapshot["findings"] == 1


# ---------------------------------------------------------------------------
# Hash-fallback embedder
# ---------------------------------------------------------------------------


def test_hash_embed_is_deterministic() -> None:
    a = _hash_embed("hello world")
    b = _hash_embed("hello world")
    assert a == b


def test_hash_embed_is_unit_norm() -> None:
    vec = _hash_embed("some test string")
    assert len(vec) == 128
    norm = sum(v * v for v in vec) ** 0.5
    assert abs(norm - 1.0) < 1e-9


def test_hash_embed_different_inputs_differ() -> None:
    a = _hash_embed("agent guardian")
    b = _hash_embed("agent saboteur")
    assert a != b


@pytest.mark.asyncio
async def test_init_embedder_is_idempotent(tmp_path: Path) -> None:
    """A second :meth:`_init_embedder` call must early-return."""
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    mem._init_embedder()
    first_kind = mem._embedder_kind
    mem._init_embedder()  # second call — covers the early-return branch
    assert mem._embedder_kind == first_kind


def test_init_faiss_noop_when_use_faiss_false(tmp_path: Path) -> None:
    """When ``use_faiss=False`` the FAISS index stays ``None``."""
    mem = SharedMemory("scan-A", root_dir=tmp_path, use_faiss=False)
    mem._init_faiss(128)
    assert mem._faiss_index is None


# ---------------------------------------------------------------------------
# Vector search — degrades gracefully without numpy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vector_search_raises_without_numpy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In an environment lacking numpy, vector_search must surface a clear error."""
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.write_reflection("recon", "agent has tools", embed=True)

    # Try to import numpy; if it's actually available, we monkey-patch it out
    # via sys.modules so the import inside vector_search raises ImportError.
    import sys

    try:
        import numpy  # noqa: F401
    except ImportError:
        # Genuine no-numpy environment — the bare call should raise.
        with pytest.raises(MemoryFeatureUnavailable, match="numpy"):
            await mem.vector_search("query")
        return

    # numpy is installed → simulate its absence.
    monkeypatch.setitem(sys.modules, "numpy", None)
    with pytest.raises(MemoryFeatureUnavailable, match="numpy"):
        await mem.vector_search("query")


@pytest.mark.asyncio
async def test_vector_search_empty_index_returns_empty(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    # No reflections embedded; even when numpy is absent, an empty index
    # short-circuits before the numpy import (the contract: nothing stored
    # means nothing to return).
    pytest.importorskip("numpy", reason="vector_search needs numpy; covered by [full] extra")
    out = await mem.vector_search("anything")
    assert out == []


@pytest.mark.asyncio
async def test_vector_search_k_zero_returns_empty(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    out = await mem.vector_search("query", k=0)
    assert out == []


@pytest.mark.asyncio
async def test_vector_search_returns_topk_with_numpy(tmp_path: Path) -> None:
    """When numpy is installed, vector_search returns ranked hits."""
    pytest.importorskip("numpy", reason="vector_search needs numpy; covered by [full] extra")
    mem = SharedMemory("scan-A", root_dir=tmp_path, use_faiss=False)
    await mem.write_reflection("asi01", "goal hijack via system prompt", embed=True)
    await mem.write_reflection("asi02", "tool misuse on filesystem", embed=True)
    await mem.write_reflection("asi05", "code execution sandbox escape", embed=True)
    hits = await mem.vector_search("goal hijack", k=2)
    assert len(hits) <= 2
    for hit in hits:
        assert isinstance(hit, VectorHit)
        assert 0.0 <= hit.score <= 1.0
        assert hit.record_type == "reflection"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aclose_idempotent(tmp_path: Path) -> None:
    mem = SharedMemory("scan-A", root_dir=tmp_path)
    await mem.aclose()
    await mem.aclose()  # second call must not raise


@pytest.mark.asyncio
async def test_async_context_manager(tmp_path: Path) -> None:
    async with SharedMemory("scan-A", root_dir=tmp_path) as mem:
        await mem.write_finding(_make_finding(fid="cm-1"))
        assert len(mem.all_findings()) == 1
    # After context exit, the JSONL should still be readable.
    restored = SharedMemory.restore("scan-A", root_dir=tmp_path)
    assert {f.id for f in restored.all_findings()} == {"cm-1"}


# ---------------------------------------------------------------------------
# Sorted __all__
# ---------------------------------------------------------------------------


def test_public_all_has_no_duplicates() -> None:
    import agent_guardian

    assert len(agent_guardian.__all__) == len(set(agent_guardian.__all__))


def test_public_all_memory_types_grouped_alphabetically() -> None:
    """The memory types remain alphabetically ordered within ``__all__``.

    ``__all__`` follows the existing convention (constants first, then
    PascalCase classes, then snake_case functions). Within the PascalCase
    block, alphabetical order is preserved. We assert relative ordering
    rather than tight contiguous slices so additive milestones (M6+)
    don't force this test to be rewritten every time.
    """
    import agent_guardian

    order = agent_guardian.__all__
    # All five Memory*-cluster names appear, in alphabetical order, between
    # LangGraphAdapter and ObservedSurface.
    idx_lang = order.index("LangGraphAdapter")
    idx_observed = order.index("ObservedSurface")
    memory_names = ["MemoryFeatureUnavailable", "MemoryRecord", "MemoryStats"]
    indices = [order.index(n) for n in memory_names]
    assert all(idx_lang < i < idx_observed for i in indices)
    assert indices == sorted(indices)

    # SharedMemory falls between SeverityBand and StrandsAdapter.
    assert order.index("SeverityBand") < order.index("SharedMemory")
    assert order.index("SharedMemory") < order.index("StrandsAdapter")

    # VectorHit falls between Tier and VertexClient (other PascalCase
    # entries may now interleave; we only care about the relative order).
    assert order.index("Tier") < order.index("VectorHit")
    assert order.index("VectorHit") < order.index("VertexClient")


def test_public_surface_exposes_memory_types() -> None:
    import agent_guardian

    for name in (
        "SharedMemory",
        "MemoryRecord",
        "MemoryStats",
        "VectorHit",
        "MemoryFeatureUnavailable",
    ):
        assert hasattr(agent_guardian, name), name
        assert name in agent_guardian.__all__


# ---------------------------------------------------------------------------
# MemoryRecord pydantic surface
# ---------------------------------------------------------------------------


def test_memory_record_round_trips_json() -> None:
    rec = MemoryRecord(
        record_type="reflection",
        scan_id="s1",
        timestamp=datetime(2026, 5, 26, tzinfo=timezone.utc),
        payload={"agent": "recon", "content": "hi"},
    )
    raw = rec.model_dump_json()
    again = MemoryRecord.model_validate_json(raw)
    assert again == rec


def test_memory_record_rejects_unknown_record_type() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        MemoryRecord(
            record_type="garbage",  # type: ignore[arg-type]
            scan_id="s1",
            timestamp=datetime(2026, 5, 26, tzinfo=timezone.utc),
            payload={},
        )


def test_memory_record_is_frozen() -> None:
    from pydantic import ValidationError

    rec = MemoryRecord(
        record_type="finding",
        scan_id="s1",
        timestamp=datetime(2026, 5, 26, tzinfo=timezone.utc),
        payload={},
    )
    with pytest.raises(ValidationError):
        rec.scan_id = "other"  # type: ignore[misc]


def test_memory_stats_is_a_dataclass() -> None:
    s = MemoryStats(
        findings=3,
        reflections=2,
        attempted_seeds=1,
        has_fingerprint=True,
        vector_index_size=2,
        embedder_kind="hash-fallback",
    )
    assert s.findings == 3
    # Frozen dataclass — assignment is blocked.
    with pytest.raises(Exception):  # noqa: B017 — frozen-dataclass raises FrozenInstanceError
        s.findings = 4  # type: ignore[misc]


def test_vector_hit_is_a_dataclass() -> None:
    h = VectorHit(text="hello", agent="recon", score=0.8, record_type="reflection")
    assert h.score == 0.8
