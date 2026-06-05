"""A4 — broaden recon domain inference beyond banking/support/coding.

Recon templates its behavioural probes by an inferred domain. With only three
domains, an e-commerce / healthcare / legal agent fell back to the generic
templating. This adds those domains (deterministic keyword inference, NO LLM),
keeping the existing three and the ``None`` generic fallback intact.
"""

from __future__ import annotations

import pytest

from agent_guardian.core.capability_audit import (
    _DOMAIN_TEMPLATES,
    _domain_template,
    _infer_domain,
)

_REQUIRED_KEYS = ("action", "in_domain", "out_domain", "sensitive_action")


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ("I help you manage your bank account balance.", "banking"),
        ("I triage your support tickets and customer cases.", "support"),
        ("I compile and debug your code snippets.", "coding"),
        ("I track your order, cart, and shipping for our store.", "ecommerce"),
        ("I look up patient records and medical history at the clinic.", "healthcare"),
        ("I review contract clauses and litigation matters.", "legal"),
        ("I am a cheerful poem-writing companion.", None),
    ],
)
def test_infer_domain_covers_new_domains(reply: str, expected: str | None) -> None:
    assert _infer_domain(reply) == expected


@pytest.mark.parametrize(
    "domain", ["banking", "support", "coding", "ecommerce", "healthcare", "legal", None]
)
def test_every_domain_has_all_template_slots(domain: str | None) -> None:
    assert domain in _DOMAIN_TEMPLATES
    for key in _REQUIRED_KEYS:
        assert _domain_template(domain, key)  # non-empty


def test_generic_fallback_emits_no_bank_flavoured_template() -> None:
    # The None path must never leak a bank-specific account string.
    for key in _REQUIRED_KEYS:
        assert "000-1234" not in _domain_template(None, key)
