"""Issue #212 — ``scan --output`` accepts multiple formats.

Pre-fix, ``scan --output sarif --output pdf --output json`` wrote ONLY
report.json (Typer single-valued ``str`` => last-write-wins on repeated
flags). The rc35 deep-review H2 finding: this contradicts the suite-
runner "multi-format from one scan" contract and forces CI consumers
to re-run the entire LLM-spend scan once per format.

The fix: declare ``output`` as ``list[str]`` (default ``["json"]``)
so Typer accumulates repeated flags. The emit loop then writes one
report per requested format.

This test exercises the Typer surface (the CLI command's signature)
to lock the multi-output contract. The downstream emit loop is
already list-based; only the flag declaration changes.
"""

from __future__ import annotations

import inspect

from agent_guardian import cli


def test_scan_output_flag_is_list_typed() -> None:
    """Lock the Typer annotation. A future regression that drops
    ``output: list[str]`` back to ``str`` would silently revert to
    last-write-wins on repeated flags."""
    sig = inspect.signature(cli.scan)
    output_param = sig.parameters.get("output")
    assert output_param is not None, "scan() must accept --output"
    annotation = output_param.annotation
    # Accept either ``list[str]`` or ``List[str]`` (typing alias) or the
    # parametrised generic.
    annotation_str = str(annotation)
    assert "list" in annotation_str.lower() and "str" in annotation_str, (
        f"scan() --output annotation is {annotation!r}; expected list[str] "
        f"so repeated --output flags accumulate (#212)."
    )


def test_scan_output_flag_default_is_json_list() -> None:
    """Back-compat: the no-flag invocation still produces a single JSON
    report. The default must be a list containing exactly 'json'."""
    sig = inspect.signature(cli.scan)
    output_param = sig.parameters.get("output")
    assert output_param is not None
    default_value = output_param.default
    # Typer Option-wrapped defaults expose .default at the Typer level.
    # Read it via the Typer info object.
    actual_default = default_value.default if hasattr(default_value, "default") else default_value
    # Accept either ["json"] (list-typed default) or "json" (the
    # back-compat string default if Typer auto-promotes).
    if isinstance(actual_default, list):
        assert actual_default == ["json"], (
            f"scan() --output default is {actual_default!r}; "
            f"expected ['json'] to match the pre-fix behaviour."
        )
    else:
        assert actual_default == "json", (
            f"scan() --output default is {actual_default!r}; "
            f"expected 'json' (or ['json'] when list-typed) for back-compat."
        )
