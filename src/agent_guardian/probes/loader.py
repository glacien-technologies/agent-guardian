"""Discover and load the bundled seed probe corpus (M11).

The corpus lives at ``src/agent_guardian/probes/`` — one YAML file per probe,
grouped into ``asi01/`` … ``asi10/`` subdirectories. A sibling ``_meta/``
folder holds non-probe metadata (currently just the ``version.yaml`` stamp).

The top-level corpus version is also exposed as :data:`PROBE_CORPUS_VERSION`
so importers don't have to read YAML at import time.
"""

from __future__ import annotations

import logging
from pathlib import Path

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.probe import Probe, ProbeValidationError, load_probe
from agent_guardian.strategies.base import ProbeSeed

__all__ = [
    "PROBE_CORPUS_VERSION",
    "find_corpus_root",
    "last_load_was_authoritative",
    "load_all_probes",
    "load_probes_for_asi",
    "seeds_for_asi_with_provenance",
]


_LOG = logging.getLogger(__name__)


# Bumped whenever the corpus changes — kept in sync with ``_meta/version.yaml``.
PROBE_CORPUS_VERSION = "2026.05"


# Module-level flag set by the most recent ``load_all_probes`` call. ``True``
# means the loader actually found at least one probe YAML on disk; ``False``
# means the corpus root was missing OR contained no probe YAMLs (in which case
# scans built from this load are NON-AUTHORITATIVE and the scoring layer must
# force ``scoring_valid=False`` / ``band=NOT_EVALUATED``). The flag is global
# rather than a return-tuple element so existing callers keep working without
# touching their signatures; new callers (e.g. the swarm finaliser) can check
# the flag immediately after a load.
_last_load_was_authoritative: bool = False


def last_load_was_authoritative() -> bool:
    """Whether the last ``load_all_probes`` call returned a non-empty corpus.

    Returns ``False`` when the root directory was missing OR when it existed
    but contained no probe YAML files. The swarm finaliser uses this to mark
    the scan as NOT_EVALUATED so callers don't silently get a 100/100 AIVSS
    from a vacuous probe set.
    """
    return _last_load_was_authoritative


def find_corpus_root() -> Path:
    """Return the on-disk root of the bundled probe corpus.

    The loader walks downwards from this directory so any new ASI sub-folder
    is picked up without code changes.
    """
    return Path(__file__).parent


def _iter_probe_files(root: Path) -> list[Path]:
    """Return every ``*.yaml`` and ``*.yml`` probe file under ``root`` (sorted).

    Files inside any ``_meta/`` directory are filtered out — those hold corpus
    metadata, not probes.
    """
    candidates = [*root.rglob("*.yaml"), *root.rglob("*.yml")]
    return sorted(p for p in candidates if "_meta" not in p.parts)


def load_all_probes(*, root: Path | None = None, strict: bool = False) -> list[Probe]:
    """Load every probe under ``root`` (or the bundled corpus by default).

    Files inside any ``_meta/`` directory are skipped — those hold corpus
    metadata, not probes. Probes are returned sorted by ``id`` for stable
    ordering across runs.

    A malformed probe YAML is logged at WARNING and skipped so one bad file
    cannot empty the entire corpus. Pass ``strict=True`` (used by CI and
    ``agent-guardian doctor``) to re-raise instead.

    The module-level :func:`last_load_was_authoritative` flag is updated as a
    side effect: it becomes ``False`` when the root is missing OR when no
    probe YAMLs are found, so the swarm finaliser can downgrade the scan to
    ``NOT_EVALUATED`` instead of silently reporting a vacuous 100/100.
    """
    global _last_load_was_authoritative
    root = root or find_corpus_root()
    if not root.exists():
        _LOG.warning(
            "probe corpus root %s missing or empty — scan will be NON-AUTHORITATIVE",
            root,
        )
        _last_load_was_authoritative = False
        return []
    yaml_files = _iter_probe_files(root)
    if not yaml_files:
        _LOG.warning(
            "probe corpus root %s missing or empty — scan will be NON-AUTHORITATIVE",
            root,
        )
        _last_load_was_authoritative = False
        return []
    probes: list[Probe] = []
    for yml in yaml_files:
        try:
            probes.append(load_probe(yml))
        except ProbeValidationError as exc:
            if strict:
                raise
            _LOG.warning("skipping malformed probe %s: %s", yml, exc)
            continue
    probes.sort(key=lambda p: p.id)
    _last_load_was_authoritative = bool(probes)
    if not probes:
        _LOG.warning(
            "probe corpus root %s missing or empty — scan will be NON-AUTHORITATIVE",
            root,
        )
    return probes


def load_probes_for_asi(asi: AsiCategory) -> list[Probe]:
    """Load just the probes that belong to a single ASI category.

    Returns an empty list when the corpus directory for ``asi`` is missing —
    useful for editable-installs that don't yet have the bundled YAML files.
    A WARNING is emitted in that case so the scan can be flagged as
    NON-AUTHORITATIVE upstream.
    """
    root = find_corpus_root() / asi.value.lower()
    if not root.exists():
        _LOG.warning(
            "probe corpus root %s missing or empty — scan will be NON-AUTHORITATIVE",
            root,
        )
        return []
    yaml_files = _iter_probe_files(root)
    if not yaml_files:
        _LOG.warning(
            "probe corpus root %s missing or empty — scan will be NON-AUTHORITATIVE",
            root,
        )
        return []
    return load_all_probes(root=root)


def seeds_for_asi_with_provenance(asi: AsiCategory) -> list[ProbeSeed]:
    """Load every (probe_id, seed_text) pair for an ASI category as ProbeSeeds.

    Each ``Probe`` in the corpus may declare multiple ``seeds``; this helper
    emits one :class:`ProbeSeed` per ``(probe, seed_text)`` pair so the
    strategy layer can thread per-seed probe-id provenance through to the
    turn record. ASI and severity are pre-filled so downstream finding
    emission doesn't have to re-load the probe.

    Returns an empty list when the corpus directory is missing — callers
    should fall back to hand-authored placeholders wrapped as ProbeSeeds.
    """
    out: list[ProbeSeed] = []
    for probe in load_probes_for_asi(asi):
        for text in probe.seeds:
            out.append(
                ProbeSeed(
                    probe_id=probe.id,
                    text=text,
                    asi=probe.asi.value,
                    severity=probe.severity.value,
                    mitre_atlas=tuple(probe.mitre_atlas),
                    csa_category=probe.csa_category.value,
                )
            )
    return out
