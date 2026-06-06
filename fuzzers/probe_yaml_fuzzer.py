#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from agent_guardian.models.probe import ProbeValidationError, load_probe


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="ignore")
    if len(text) > 8192:
        text = text[:8192]
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.yaml"
        path.write_text(text, encoding="utf-8")
        try:
            load_probe(path)
        except (FileNotFoundError, OSError, ProbeValidationError):
            return


def main() -> None:
    import sys

    import atheris

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
