"""Issue #108: the presidio path must request only entities presidio knows.

The credential/secret entity types in ``PiiRedactor._SECRET_ENTITIES`` have no
presidio recognizer (they are masked by the regex bank). Passing them into
``analyze()`` produces nothing but a flood of one "no recognizer" WARNING per
type per call. This test pins the fix without needing presidio installed by
injecting a fake analyzer and asserting the secret types never reach it.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from agent_guardian.core.redact import PiiRedactor


def test_presidio_analyze_excludes_unrecognized_secret_entities() -> None:
    r = PiiRedactor()
    analyzer = MagicMock()
    analyzer.analyze.return_value = []
    # Force the presidio branch with a fake analyzer (presidio need not be
    # installed for this unit test).
    r._analyzer = analyzer
    r._using_presidio = True

    r._redact_with_presidio("nothing sensitive here")

    analyzer.analyze.assert_called_once()
    passed = set(analyzer.analyze.call_args.kwargs["entities"])
    leaked = passed & PiiRedactor._SECRET_ENTITIES
    assert not leaked, f"secret entities leaked into presidio analyze(): {sorted(leaked)}"
    # The PII entities presidio DOES recognize must still be requested.
    assert passed, "expected presidio-recognized entities to still be requested"
