"""Suite runner error types."""

from __future__ import annotations


class SuiteConfigError(ValueError):
    """A suite YAML is structurally valid but semantically wrong.

    Raised for cross-field problems the per-field schema cannot express — e.g. a
    workload that resolves to zero or two target modes after defaults are merged.
    """
