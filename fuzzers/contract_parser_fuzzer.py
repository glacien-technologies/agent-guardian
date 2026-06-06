#!/usr/bin/env python3
from __future__ import annotations

import yaml

from agent_guardian.contract import (
    ContractValidationError,
    MigrationNeeded,
    UnsupportedContractVersion,
    parse_contract,
)


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="ignore")
    if len(text) > 16384:
        text = text[:16384]
    try:
        parsed = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError:
        return
    if not isinstance(parsed, dict):
        return
    try:
        parse_contract(parsed)
    except (ContractValidationError, MigrationNeeded, UnsupportedContractVersion, ValueError):
        return


def main() -> None:
    import sys

    import atheris

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
