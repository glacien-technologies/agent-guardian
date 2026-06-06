#!/usr/bin/env python3
from __future__ import annotations

import json
from contextlib import suppress

from agent_guardian.adapters.http import _extract_tool_calls
from agent_guardian.adapters.http_shapes import get_shape, list_shapes
from agent_guardian.adapters.http_shapes.generic_shape import extract_response_text, walk_jsonpath


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="ignore")
    if len(text) > 8192:
        text = text[:8192]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return

    for path in ("$", "$.output.text", "$.choices[0].message.content", "$.content[0].text"):
        with suppress(ValueError):
            walk_jsonpath(payload, path)

    if isinstance(payload, dict):
        with suppress(ValueError):
            extract_response_text(payload)
        for shape_name in list_shapes():
            shape = get_shape(shape_name)
            with suppress(ValueError):
                shape.extract_response_text(payload)
            _extract_tool_calls(payload, shape_name=shape_name)


def main() -> None:
    import sys

    import atheris

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
