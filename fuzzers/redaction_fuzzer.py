#!/usr/bin/env python3
from __future__ import annotations

from agent_guardian.core.redact import PiiRedactor, redact_finding


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="ignore")
    if len(text) > 8192:
        text = text[:8192]
    redactor = PiiRedactor()
    redactor.redact(text)
    redact_finding(
        {
            "summary": text,
            "trigger_prompt": text,
            "trigger_response": text,
            "transcript_ref": text,
            "evidence": text,
        },
        enabled=True,
    )


def main() -> None:
    import sys

    import atheris

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
