"""Phase C C9: confirm ``agent_guardian.strategies.evasion`` emits a
``DeprecationWarning`` on import.

The static evasion corpus is superseded by the Phase B mutation engine
(:mod:`agent_guardian.strategies.mutator`); the module stays importable for one
release window so existing consumers (notably
:mod:`agent_guardian.agents.detection_evasion_agent`) can migrate.
"""

from __future__ import annotations

import importlib
import sys
import warnings

import pytest


def _force_fresh_reimport() -> None:
    # Module-level ``warnings.warn`` only fires on the first import in a Python
    # process; later test runs (or test order shuffling) would otherwise see a
    # cached module and the warning would silently no-op. Drop the cached
    # module so :func:`importlib.import_module` re-executes the top-level body.
    sys.modules.pop("agent_guardian.strategies.evasion", None)


def test_import_emits_deprecation_warning() -> None:
    _force_fresh_reimport()
    with pytest.warns(DeprecationWarning, match="Phase C"):
        importlib.import_module("agent_guardian.strategies.evasion")


def test_deprecation_warning_points_at_mutator_supersession() -> None:
    _force_fresh_reimport()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        importlib.import_module("agent_guardian.strategies.evasion")
    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecations, "expected at least one DeprecationWarning on import"
    message = str(deprecations[0].message)
    assert "agent_guardian.strategies.mutator" in message
    assert "v2.0" in message


def test_module_still_exports_public_api_after_deprecation() -> None:
    # One-release migration window: the deprecation does NOT yank the public
    # API out from under existing consumers (e.g. detection_evasion_agent).
    _force_fresh_reimport()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        module = importlib.import_module("agent_guardian.strategies.evasion")
    for symbol in ("EVASION_TECHNIQUES", "EvasionGenerator", "EvasionResult"):
        assert hasattr(module, symbol), f"public API symbol {symbol!r} disappeared"
