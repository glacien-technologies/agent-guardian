# AIVSS regression fixtures

Each `*.json` file in this directory locks the AIVSS formula's output for a
specific input. The shape is:

```json
{
  "_doc": "Free-form description of what this fixture exercises.",
  "tier": "T1" | "T2" | "T3" | "T4",
  "probes": [ {Probe schema, see src/agent_guardian/models/probe.py} ],
  "findings": [ {Finding schema, see src/agent_guardian/models/finding.py} ],
  "expected_aivss": <int 0..100>,
  "expected_band": "EXCELLENT" | "GOOD" | "WARNING" | "POOR" | "CRITICAL"
}
```

## How to add a fixture

1. Author the input (`tier`, `probes`, `findings`) in a new JSON file.
2. Run `compute_aivss` against the fixture data (e.g. via a one-off REPL or by
   temporarily printing the result inside the test runner).
3. Paste the actual `score` and `band` into `expected_aivss` / `expected_band`.
4. Commit. The fixture is now a regression net for the formula: any change to
   the formula that alters the result will fail this fixture's test.

These files are **not** theoretical targets — they are byte-deterministic
snapshots of the implementation's output.
