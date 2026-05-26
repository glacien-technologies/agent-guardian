"""Discover and load the bundled seed probe corpus (M11).

The corpus lives at ``src/agent_guardian/probes/`` — one YAML file per probe,
grouped into ``asi01/`` … ``asi10/`` subdirectories. A sibling ``_meta/``
folder holds non-probe metadata (currently just the ``version.yaml`` stamp).

The top-level corpus version is also exposed as :data:`PROBE_CORPUS_VERSION`
so importers don't have to read YAML at import time.
"""

from __future__ import annotations

from pathlib import Path

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.probe import Probe, load_probe

__all__ = [
    "PROBE_CORPUS_VERSION",
    "find_corpus_root",
    "load_all_probes",
    "load_probes_for_asi",
]


# Bumped whenever the corpus changes — kept in sync with ``_meta/version.yaml``.
PROBE_CORPUS_VERSION = "2026.05"


def find_corpus_root() -> Path:
    """Return the on-disk root of the bundled probe corpus.

    The loader walks downwards from this directory so any new ASI sub-folder
    is picked up without code changes.
    """
    return Path(__file__).parent


def load_all_probes(*, root: Path | None = None) -> list[Probe]:
    """Load every probe under ``root`` (or the bundled corpus by default).

    Files inside any ``_meta/`` directory are skipped — those hold corpus
    metadata, not probes. Probes are returned sorted by ``id`` for stable
    ordering across runs.
    """
    root = root or find_corpus_root()
    if not root.exists():
        return []
    probes: list[Probe] = []
    for yml in sorted(root.rglob("*.yaml")):
        if "_meta" in yml.parts:
            continue
        probes.append(load_probe(yml))
    probes.sort(key=lambda p: p.id)
    return probes


def load_probes_for_asi(asi: AsiCategory) -> list[Probe]:
    """Load just the probes that belong to a single ASI category.

    Returns an empty list when the corpus directory for ``asi`` is missing —
    useful for editable-installs that don't yet have the bundled YAML files.
    """
    root = find_corpus_root() / asi.value.lower()
    if not root.exists():
        return []
    return load_all_probes(root=root)
