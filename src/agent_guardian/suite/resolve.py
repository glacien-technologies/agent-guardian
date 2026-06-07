"""Resolve a parsed suite into concrete per-workload knob-sets.

Merges suite-level ``defaults`` under each ``workloads[]`` entry (workload wins),
fills each workload's ``formats`` from the suite default when unset, and enforces
the cross-field invariant the schema cannot: exactly one target mode per workload
*after* the merge.
"""

from __future__ import annotations

from agent_guardian.suite.errors import SuiteConfigError
from agent_guardian.suite.schema import SuiteFile, WorkloadFields

# The five mutually-exclusive ways to point a scan at a target. ``framework_ref``
# is an adjunct to ``framework``, not a mode on its own.
_TARGET_MODES = ("target", "endpoint", "system_prompt", "framework", "contract")


def _merge(defaults: WorkloadFields, workload: WorkloadFields) -> WorkloadFields:
    base = defaults.model_dump(exclude_unset=True)
    over = workload.model_dump(exclude_unset=True)
    base.update(over)
    return WorkloadFields.model_validate(base)


def resolve_workloads(suite_file: SuiteFile) -> list[WorkloadFields]:
    """Return one fully-merged, validated :class:`WorkloadFields` per workload."""
    resolved: list[WorkloadFields] = []
    for wl in suite_file.workloads:
        merged = _merge(suite_file.defaults, wl)

        present = [m for m in _TARGET_MODES if getattr(merged, m) is not None]
        if len(present) != 1:
            raise SuiteConfigError(
                f"workload '{merged.name}' must resolve to exactly one target mode "
                f"({', '.join(_TARGET_MODES)}); found {present or 'none'}"
            )
        if merged.framework_ref is not None and merged.framework is None:
            raise SuiteConfigError(f"workload '{merged.name}' sets framework_ref without framework")

        if merged.formats is None:
            merged = merged.model_copy(update={"formats": list(suite_file.suite.formats)})
        resolved.append(merged)
    return resolved
