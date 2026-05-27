"""One-off runner: scan a target with full swarm-event visibility.

Used to validate end-to-end Gemini-driven AgentGuardian behavior. Prints every
SwarmEvent (recon_start, agent_start, finding, checkpoint, ...) plus DEBUG-level
logs from the swarm + memory + agents to stderr. Writes the same JSON report
the CLI produces.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Load .env BEFORE importing anything that needs the key
from dotenv import load_dotenv

_HERE = Path(__file__).resolve().parent
PROJECT_ROOT = _HERE.parent
load_dotenv(PROJECT_ROOT / ".env")

# Python prepends the script's directory to sys.path[0] when running a script
# directly, which makes our local ``examples/langgraph/`` namespace shadow the
# real PyPI ``langgraph`` package. Strip our own dir, then add the project root.
sys.path = [p for p in sys.path if Path(p).resolve() != _HERE]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Wire logging to stderr at INFO (DEBUG is too noisy; let users bump via env)
LOG_LEVEL = os.environ.get("AG_RUNNER_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    stream=sys.stderr,
    format="%(asctime)s.%(msecs)03d %(levelname)-5s %(name)-44s %(message)s",
    datefmt="%H:%M:%S",
)

# NOTE: deliberately imported AFTER sys.path/dotenv setup above. E402 silenced
# because these imports depend on the .env-loaded GEMINI_API_KEY and on
# project_root being on sys.path before our local examples/langgraph/ would
# shadow the PyPI langgraph package.
from agent_guardian.adapters.code import CodeAdapter  # noqa: E402
from agent_guardian.cli import build_llm  # noqa: E402
from agent_guardian.core.memory import SharedMemory  # noqa: E402
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig, SwarmEvent  # noqa: E402
from agent_guardian.models.tier import Tier  # noqa: E402
from agent_guardian.reports.json_report import write_json  # noqa: E402


def make_observer():
    """Print every SwarmEvent to stderr in a compact human format."""
    counts = {
        "recon_start": 0,
        "recon_done": 0,
        "agent_start": 0,
        "agent_done": 0,
        "agent_skipped": 0,
        "agent_progress": 0,
        "finding": 0,
        "checkpoint": 0,
        "scan_done": 0,
    }

    def observe(event: SwarmEvent) -> None:
        counts[event.kind] = counts.get(event.kind, 0) + 1
        ts = event.timestamp.strftime("%H:%M:%S")
        parts = [f"{ts} EVENT {event.kind}"]
        if event.agent:
            parts.append(f"agent={event.agent}")
        if event.asi:
            parts.append(f"asi={event.asi.value}")
        if event.provisional_aivss is not None:
            parts.append(f"aivss={event.provisional_aivss}")
        if event.decision:
            parts.append(f"decision={event.decision.value}")
        if event.payload:
            # Trim large payloads
            payload_str = json.dumps(event.payload)[:120]
            parts.append(f"payload={payload_str}")
        print(" ".join(parts), file=sys.stderr)

    return observe, counts


async def main() -> int:
    target_path = sys.argv[1] if len(sys.argv) > 1 else "examples.langgraph.simple_chatbot:run"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "examples/reports/langgraph_t4_simple.json"
    model = sys.argv[3] if len(sys.argv) > 3 else "gemini-3.5-flash"
    tier_str = sys.argv[4] if len(sys.argv) > 4 else "T4"

    tier_map = {
        "T1": Tier.T1_CRITICAL,
        "T2": Tier.T2_HIGH,
        "T3": Tier.T3_STANDARD,
        "T4": Tier.T4_LOW,
    }
    tier = tier_map[tier_str]

    print(f"\n{'=' * 70}", file=sys.stderr)
    print(f"  SCAN: {target_path}", file=sys.stderr)
    print(f"  MODEL: {model} (all three roles)", file=sys.stderr)
    print(f"  TIER: {tier_str}", file=sys.stderr)
    print(f"  REPORT: {output_path}", file=sys.stderr)
    print(f"{'=' * 70}\n", file=sys.stderr)

    started = datetime.now(timezone.utc)

    adapter = CodeAdapter(target_path)
    attacker = build_llm(model, role="attacker")
    evaluator = build_llm(model, role="evaluator")
    commander = build_llm(model, role="commander")

    scan_id = f"runner-{started.strftime('%H%M%S')}"
    memory = SharedMemory(scan_id)

    config = SwarmConfig(
        scan_id=scan_id,
        commander_model=model,
        attacker_model=model,
        evaluator_model=model,
        tier_override=tier,
        recon_wall_seconds=90.0,
        overall_wall_seconds=900.0,
        checkpoint_interval_seconds=5.0,
    )

    observer, counts = make_observer()
    swarm = SwarmCommander(
        config=config,
        target=adapter,
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        commander_llm=commander,
        memory=memory,
        observer=observer,
        rng_seed=0,
    )

    scan = await swarm.run()
    finished = datetime.now(timezone.utc)

    print(f"\n{'=' * 70}", file=sys.stderr)
    print("  RESULT", file=sys.stderr)
    print(f"{'=' * 70}", file=sys.stderr)
    print(f"  Wall time:      {(finished - started).total_seconds():.1f}s", file=sys.stderr)
    print(f"  AIVSS:          {scan.aivss}", file=sys.stderr)
    print(f"  Band:           {scan.band.value}", file=sys.stderr)
    print(f"  Findings:       {scan.findings_summary()}", file=sys.stderr)
    print(f"  Event counts:   {counts}", file=sys.stderr)
    print(f"  Memory file:    ~/.agentguardian/scans/{scan_id}/memory.jsonl", file=sys.stderr)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    write_json(scan, Path(output_path))
    print(f"  Wrote report:   {output_path}", file=sys.stderr)

    await adapter.aclose()
    await attacker.aclose()
    await evaluator.aclose()
    if commander is not attacker:
        await commander.aclose()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
