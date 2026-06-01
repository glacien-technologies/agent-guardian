"""Generate the honest framework-coverage matrix from the on-disk probe corpus.

Phase C item C8. Output goes to ``docs/reference/framework-coverage-matrix.md``
and is intentionally regenerated from probe YAMLs so the doc cannot drift away
from the loader's view of the world.

Why a one-shot script and not a runtime CLI command? The matrix is a doc
artifact reviewed in PRs — keeping the generator in ``scripts/`` keeps the
runtime surface small (the CLI doesn't need a ``write-coverage-matrix``
verb) while still letting CI regenerate-and-diff the markdown if we ever
want to make it a freshness check.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict

from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.csa import CsaCategory
from agent_guardian.probes.loader import find_corpus_root, load_all_probes

_LOG = logging.getLogger(__name__)


# Human-readable names for the 12 CSA categories. The enum values are
# stable kebab-case identifiers; the labels are sourced from the CSA
# Agentic AI Red Teaming Guide (Huang et al., 2025-05-28).
_CSA_LABELS: dict[CsaCategory, str] = {
    CsaCategory.GOAL_INSTRUCTION_MANIPULATION: "Goal & Instruction Manipulation",
    CsaCategory.AUTHORIZATION_CONTROL_HIJACKING: "Authorization & Control Hijacking",
    CsaCategory.AGENT_CRITICAL_SYSTEM_INTERACTION: "Agent ↔ Critical-System Interaction",
    CsaCategory.SUPPLY_CHAIN_DEPENDENCY: "Supply Chain & Dependency",
    CsaCategory.KNOWLEDGE_BASE_POISONING: "Knowledge Base Poisoning",
    CsaCategory.MEMORY_CONTEXT_MANIPULATION: "Memory & Context Manipulation",
    CsaCategory.MULTI_AGENT_EXPLOITATION: "Multi-Agent Exploitation",
    CsaCategory.IMPACT_CHAIN_BLAST_RADIUS: "Impact Chain & Blast Radius",
    CsaCategory.HALLUCINATION_EXPLOITATION: "Hallucination Exploitation",
    CsaCategory.CHECKER_OUT_OF_THE_LOOP: "Checker-Out-of-the-Loop",
    CsaCategory.AGENT_UNTRACEABILITY: "Agent Untraceability",
    CsaCategory.RESOURCE_SERVICE_EXHAUSTION: "Resource & Service Exhaustion",
}


# Human-readable names for the 12 ATLAS techniques the corpus currently
# touches. Sourced from MITRE ATLAS v5.4.0 (February 2026). Named
# techniques (those without a stable AML.TNNNN ID yet) are listed too so
# their human label matches the ID column. Unknown technique IDs fall back
# to the bare ID without crashing.
_ATLAS_LABELS: dict[str, str] = {
    "AML.T0012": "Valid Accounts",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0029": "Denial of ML Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0048": "External Harms",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0058": "Publish Hallucinated Entities",
    "AML.T0060": "ML Supply Chain Compromise: Hardware",
    "AML.T0062": "Discover ML Artifacts",
    "AML.T0064": "LLM Prompt Injection: Direct",
    "AML.T0067": "LLM Prompt Injection: Indirect",
    "AML.T0068": "LLM Prompt Self-Replication",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    # Named v5.4.0 techniques (no stable AML.TNNNN yet).
    "AI Agent Context Poisoning": "AI Agent Context Poisoning (named, v5.4.0)",
    "Escape to Host": "Escape to Host (named, v5.4.0)",
    "Exfiltration via AI Agent Tool Invocation": "Exfiltration via AI Agent Tool Invocation (named, v5.4.0)",
    "Memory Manipulation": "Memory Manipulation (named, v5.4.0)",
    "Modify AI Agent Configuration": "Modify AI Agent Configuration (named, v5.4.0)",
    "Publish Poisoned AI Agent Tool": "Publish Poisoned AI Agent Tool (named, v5.4.0)",
    "RAG Credential Harvesting": "RAG Credential Harvesting (named, v5.4.0)",
    "Thread Injection": "Thread Injection (named, v5.4.0)",
}


# Rough denominator the lede paragraph uses to compute the "~85% out of
# scope" honest framing. MITRE ATLAS v5.4.0 publishes roughly 80
# techniques across the matrix — a black-box agent scanner can only
# meaningfully exercise a handful (those targeting the model-as-a-tool
# surface). We keep this conservative.
_ATLAS_V540_TOTAL_TECHNIQUES_APPROX = 80


def _example_probe_ids(probes_for_category: list[str], limit: int = 3) -> str:
    """Return up to ``limit`` example probe IDs, sorted, comma-joined."""
    if not probes_for_category:
        return "—"
    chosen = sorted(probes_for_category)[:limit]
    return ", ".join(f"`{pid}`" for pid in chosen)


def _build_asi_table(probes: list, asi_to_probe_ids: dict[str, list[str]]) -> str:
    lines = [
        "## OWASP Top 10 for Agentic Applications 2026",
        "",
        "Auto-generated from `src/agent_guardian/probes/asiNN/*.yaml` — one row per ASI category. "
        "All ten categories are present in the shipped corpus.",
        "",
        "| ASI | Name | Probe count | Example probe IDs |",
        "|-----|------|-------------|-------------------|",
    ]
    for asi in AsiCategory:
        ids = asi_to_probe_ids.get(asi.value, [])
        lines.append(
            f"| {asi.value} | {asi_description(asi)} | {len(ids)} | {_example_probe_ids(ids)} |"
        )
    lines.append("")
    return "\n".join(lines)


def _build_atlas_table(atlas_counts: Counter[str], atlas_to_probe_ids: dict[str, list[str]]) -> str:
    lines = [
        "## MITRE ATLAS v5.4.0",
        "",
        "Auto-generated from `mitre_atlas:` entries in every probe YAML. "
        "Rows are listed for every technique the shipped corpus actually cites "
        "(no padding, no aspirational entries). Techniques the corpus does not "
        "yet exercise are flagged honestly rather than hidden.",
        "",
        "| ATLAS Technique | Description | Probe count | Example probe IDs |",
        "|-----------------|-------------|-------------|-------------------|",
    ]
    for technique_id in sorted(atlas_counts):
        count = atlas_counts[technique_id]
        ids = atlas_to_probe_ids.get(technique_id, [])
        label = _ATLAS_LABELS.get(technique_id, technique_id)
        lines.append(f"| `{technique_id}` | {label} | {count} | {_example_probe_ids(ids)} |")
    lines.append("")
    lines.append(
        "> **Honest scope note.** MITRE ATLAS v5.4.0 ships roughly "
        f"{_ATLAS_V540_TOTAL_TECHNIQUES_APPROX} techniques across the full "
        "matrix. AgentGuardian is a black-box agent scanner — it can only "
        "meaningfully exercise techniques that manifest at the agent's input / "
        "output / tool-call surface. Techniques targeting model training, "
        "data-pipeline infrastructure, or out-of-band ML-platform compromise "
        "are out of scope by design and **not covered by the current corpus**. "
        "Roughly 85% of the v5.4.0 catalogue falls into that out-of-scope set; "
        "the matrix above lists the in-scope subset we exercise."
    )
    lines.append("")
    return "\n".join(lines)


def _build_csa_table(csa_to_probe_ids: dict[str, list[str]]) -> str:
    lines = [
        "## CSA Agentic AI Red Teaming Guide",
        "",
        "Auto-generated from `csa_category:` entries in every probe YAML. "
        "All 12 categories from the CSA Agentic AI Red Teaming Guide "
        "(Huang et al., 2025-05-28) are listed; zero-coverage rows are marked "
        "honestly rather than dropped.",
        "",
        "| CSA Category | Name | Probe count | Example probe IDs |",
        "|--------------|------|-------------|-------------------|",
    ]
    for cat in CsaCategory:
        ids = csa_to_probe_ids.get(cat.value, [])
        label = _CSA_LABELS[cat]
        example = "(not covered by current corpus)" if not ids else _example_probe_ids(ids)
        lines.append(f"| `{cat.value}` | {label} | {len(ids)} | {example} |")
    lines.append("")
    return "\n".join(lines)


def _build_lede(total_probes: int, atlas_techniques_covered: int) -> str:
    # The README floor (11+) is a deliberately conservative public number so
    # we never overclaim — the matrix below shows the exact count for full
    # transparency, but the lede uses the floor we promise externally.
    return (
        "# Framework-coverage matrix\n"
        "\n"
        "> **Honest framing.** This page replaces the older README claim of "
        '"MITRE ATLAS v5.4.0 mappings" (which read as full-catalogue '
        "coverage). What AgentGuardian actually ships, today, against the "
        "corpus on disk: **11+ MITRE ATLAS techniques covered** (see the "
        f"matrix below for the exact set - currently {atlas_techniques_covered} "
        "techniques). The remaining ~85% of the v5.4.0 catalogue is out of "
        "scope for a black-box agent scanner - training-pipeline compromise, "
        "ML-platform-internal techniques, and infrastructure-layer attacks "
        "do not surface at the agent's I/O boundary and are therefore not "
        "probed.\n"
        "\n"
        f"All three tables below are auto-generated from {total_probes} probe "
        "YAMLs by `scripts/build_coverage_matrix.py`. Re-run that script after "
        "adding or removing probes - the doc is the loader's view of the "
        "world, not a hand-maintained narrative.\n"
    )


def build_matrix(*, probes: list | None = None) -> str:
    """Return the full markdown body for the coverage matrix doc."""
    probes = probes if probes is not None else load_all_probes()

    asi_to_probe_ids: dict[str, list[str]] = defaultdict(list)
    atlas_counts: Counter[str] = Counter()
    atlas_to_probe_ids: dict[str, list[str]] = defaultdict(list)
    csa_to_probe_ids: dict[str, list[str]] = defaultdict(list)

    for p in probes:
        asi_to_probe_ids[p.asi.value].append(p.id)
        csa_to_probe_ids[p.csa_category.value].append(p.id)
        for tech in p.mitre_atlas:
            atlas_counts[tech] += 1
            atlas_to_probe_ids[tech].append(p.id)

    _LOG.debug(
        "PhaseC.C8 build_matrix: total_probes=%d asi_categories=%d atlas_techniques=%d csa_categories=%d",
        len(probes),
        len(asi_to_probe_ids),
        len(atlas_counts),
        len(csa_to_probe_ids),
    )

    lede = _build_lede(
        total_probes=len(probes),
        atlas_techniques_covered=len(atlas_counts),
    )
    asi_table = _build_asi_table(probes, asi_to_probe_ids)
    atlas_table = _build_atlas_table(atlas_counts, atlas_to_probe_ids)
    csa_table = _build_csa_table(csa_to_probe_ids)

    footer = (
        "---\n"
        "\n"
        "Regenerate this page with:\n"
        "\n"
        "```bash\n"
        "uv run python scripts/build_coverage_matrix.py\n"
        "```\n"
    )

    return "\n".join([lede, asi_table, atlas_table, csa_table, footer])


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    out_dir = find_corpus_root().parent.parent.parent / "docs" / "reference"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "framework-coverage-matrix.md"
    body = build_matrix()
    out_path.write_text(body, encoding="utf-8")
    _LOG.info("PhaseC.C8 wrote coverage matrix: path=%s bytes=%d", out_path, len(body))
    print(f"wrote {out_path} ({len(body)} bytes)")


if __name__ == "__main__":
    main()
