"""Judge-evaluation probes (Phase A.A4).

These probes target the JUDGE rather than the agent under test: they
exercise judge-injection robustness, paraphrase consistency, cross-family
self-preference, and a calibration ground-truth set. They are discovered
by the bundled corpus loader (which uses :func:`pathlib.Path.rglob`).

Use prefix ``JDG-`` for all probe IDs so a downstream filter can route
them through a judge-evaluation harness rather than the standard
ASI-attack pipeline.
"""

# Constant exposed for log-tagged loader counts in :mod:`probes.loader`.
JUDGES_PROBE_SUBDIR = "judges"
