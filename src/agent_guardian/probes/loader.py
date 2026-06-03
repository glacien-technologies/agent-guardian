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
    "load_recon_probes",
    "load_vision_probes",
    "seeds_for_asi_with_provenance",
]


_LOG = logging.getLogger(__name__)


# Bumped whenever the corpus changes — kept in sync with ``_meta/version.yaml``.
PROBE_CORPUS_VERSION = "2026.06"


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

    Files inside ``_meta/`` (corpus metadata), ``recon/`` (Phase C, C5:
    reconnaissance probes that run inside the ReconAgent, not the ASI swarm)
    and ``multi_turn_plans/`` (Phase C, C1: declarative MultiTurnPlan YAML
    consumed by :func:`agent_guardian.strategies.load_multi_turn_plan_from_yaml`,
    not a Probe schema) directories are filtered out — none belong in the
    standard ASI attack-probe corpus.
    """
    candidates = [*root.rglob("*.yaml"), *root.rglob("*.yml")]
    # WHY: asi11/ holds vision-injection probes (Phase C.C4d) exposed via
    # load_vision_probes() — kept out of the ASI attack corpus so the
    # 120/4/124 corpus-size assertion and per-AsiCategory counts stay stable
    # until the full ASI11_VISION enum migration lands.
    excluded = {"_meta", "recon", "multi_turn_plans", "asi11"}
    return sorted(p for p in candidates if not excluded.intersection(p.parts))


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
    # Phase A.A3 — emit a runtime visibility log so a probe-corpus replay
    # can confirm the backfilled AML.T006x/T007x technique IDs landed and
    # propagated through the loader rather than being silently dropped.
    backfill_count = sum(
        1
        for p in probes
        if any(t.startswith("AML.T006") or t.startswith("AML.T007") for t in p.mitre_atlas)
    )
    _LOG.debug(
        "probe corpus loaded: total=%d probes with AML.T006x/T007x techniques=%d",
        len(probes),
        backfill_count,
    )
    # Phase A.A4 — judge-probe count visible at load time so a forensic
    # replay can confirm the judges/ subfolder is being discovered.
    judge_probes = [p for p in probes if p.id.startswith("JDG-")]
    _LOG.debug(
        "judge-probe-loader: judge_probes_loaded=%d ids=%s",
        len(judge_probes),
        [p.id for p in judge_probes],
    )
    return probes


def load_probes_for_asi(asi: AsiCategory) -> list[Probe]:
    """Load just the probes that belong to a single ASI category.

    Walks the per-ASI subdirectory (``probes/asiNN/``) AND the sibling
    ``probes/judges/`` cross-corpus, filtering judge probes by their
    declared ``asi:`` field so judge-injection (JDG-*) coverage is unioned
    into each ASI dispatch instead of being orphaned in a directory no
    agent ever scans.

    Returns an empty list when neither source yields probes — useful for
    editable-installs that don't yet have the bundled YAML files. A
    WARNING is emitted in that case so the scan can be flagged as
    NON-AUTHORITATIVE upstream.
    """
    corpus_root = find_corpus_root()
    asi_root = corpus_root / asi.value.lower()
    asi_probes: list[Probe] = []
    if asi_root.exists() and _iter_probe_files(asi_root):
        asi_probes = load_all_probes(root=asi_root)
    else:
        _LOG.warning(
            "probe corpus root %s missing or empty — scan will be NON-AUTHORITATIVE",
            asi_root,
        )
    # WHY: judges/ is a peer corpus; union its probes whose declared asi matches.
    judges_root = corpus_root / "judges"
    judge_probes: list[Probe] = []
    if judges_root.exists() and _iter_probe_files(judges_root):
        judge_probes = [p for p in load_all_probes(root=judges_root) if p.asi == asi]
    combined = asi_probes + judge_probes
    combined.sort(key=lambda p: p.id)
    return combined


def load_recon_probes(*, strict: bool = False) -> list[Probe]:
    """Load every probe under the bundled ``recon/`` subdirectory.

    Recon probes are Phase C, C5: they describe reconnaissance attacks the
    :class:`~agent_guardian.agents.recon.ReconAgent` (and its tool-name diff
    re-entry hook) executes, NOT ASI attack probes the swarm fan-out runs.
    Kept separate so the standard ASI corpus tests (counts, ASI coverage,
    finding routing) are unaffected by recon-probe additions.

    Each recon probe must still declare an ``asi`` category to satisfy the
    triple-framework gate in :func:`load_probe`; pick whichever ASI category
    the recon goal aligns with (e.g. inference-family fingerprinting maps
    onto ASI09 / Trust Exploitation — discovering the model family is a
    precursor to family-targeted prompt-injection).
    """
    root = find_corpus_root() / "recon"
    if not root.exists():
        _LOG.debug("recon probe root %s missing — returning empty list", root)
        return []
    candidates = sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")])
    if not candidates:
        return []
    probes: list[Probe] = []
    for yml in candidates:
        try:
            probes.append(load_probe(yml))
        except ProbeValidationError as exc:
            if strict:
                raise
            _LOG.warning("skipping malformed recon probe %s: %s", yml, exc)
            continue
    probes.sort(key=lambda p: p.id)
    _LOG.debug(
        "load_recon_probes: loaded=%d ids=%s",
        len(probes),
        [p.id for p in probes],
    )
    return probes


def load_vision_probes(*, strict: bool = False) -> list[Probe]:
    """Load every probe under the bundled ``asi11/`` subdirectory.

    Phase C.C4d ASI11_VISION corpus: probes that carry one or more
    image attachments (typographic injection, screenshot injection,
    steganography, ASCII art, QR codes, homoglyph, alt-text bypass,
    rendered-prompt leak). Kept separate from ``load_all_probes`` so
    the canonical ASI attack corpus size + per-ASI counts stay stable
    until the full ASI11_VISION enum migration lands.

    Each vision probe still carries an ``asi: ASI0N`` enum value to
    satisfy the triple-framework gate — vision injection is treated as
    an ASI01 (Goal Hijack) variant in the schema. The ASI11_VISION
    sentinel lives in the probe ``id`` prefix.
    """
    root = find_corpus_root() / "asi11"
    if not root.exists():
        _LOG.debug("vision probe root %s missing — returning empty list", root)
        return []
    candidates = sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")])
    if not candidates:
        return []
    probes: list[Probe] = []
    for yml in candidates:
        try:
            probes.append(load_probe(yml))
        except ProbeValidationError as exc:
            if strict:
                raise
            _LOG.warning("skipping malformed vision probe %s: %s", yml, exc)
            continue
    probes.sort(key=lambda p: p.id)
    _LOG.debug(
        "load_vision_probes: loaded=%d ids=%s",
        len(probes),
        [p.id for p in probes],
    )
    return probes


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
    # Phase A.A3 — log the unique MITRE technique IDs threaded through
    # ProbeSeed.mitre_atlas for this ASI so coverage tooling can confirm
    # the backfill is propagating into the strategy layer.
    _LOG.debug(
        "seeds_for_asi_with_provenance: asi=%s seeds=%d unique_techniques=%s",
        asi.value,
        len(out),
        sorted({t for seed in out for t in seed.mitre_atlas}),
    )
    # Phase A.A4 — count JDG seeds going into the strategy layer.
    judge_seed_count = sum(1 for s in out if s.probe_id.startswith("JDG-"))
    _LOG.debug(
        "judge-probe seeds dispatched to strategy: asi=%s judge_seeds=%d",
        asi.value,
        judge_seed_count,
    )
    return out
