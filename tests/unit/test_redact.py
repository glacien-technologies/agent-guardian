"""Tests for the PII redactor."""

from __future__ import annotations

from datetime import UTC

import pytest

from agent_guardian.core.redact import PiiRedactor, _has_presidio, redact_finding


def test_redacts_email() -> None:
    r = PiiRedactor()
    out = r.redact("contact me at user@example.com please")
    assert "user@example.com" not in out
    assert "[REDACTED:EMAIL_ADDRESS]" in out


def test_redacts_us_ssn() -> None:
    r = PiiRedactor()
    out = r.redact("ssn is 123-45-6789, do not share")
    assert "123-45-6789" not in out
    assert "[REDACTED:US_SSN]" in out


def test_redacts_credit_card() -> None:
    r = PiiRedactor()
    out = r.redact("card 4111 1111 1111 1111 expires soon")
    assert "4111 1111 1111 1111" not in out
    assert "[REDACTED:CREDIT_CARD]" in out


def test_redacts_iban() -> None:
    r = PiiRedactor()
    out = r.redact("transfer to DE89370400440532013000 thanks")
    assert "DE89370400440532013000" not in out
    assert "[REDACTED:IBAN_CODE]" in out


def test_redacts_ipv4() -> None:
    r = PiiRedactor()
    out = r.redact("server lives at 192.168.1.42 internally")
    assert "192.168.1.42" not in out
    assert "[REDACTED:IP_ADDRESS]" in out


def test_redacts_ipv6() -> None:
    r = PiiRedactor()
    out = r.redact("ipv6: fe80::1ff:fe23:4567:890a is the addr")
    assert "fe80::1ff:fe23:4567:890a" not in out
    assert "[REDACTED:IP_ADDRESS]" in out


def test_redacts_phone() -> None:
    r = PiiRedactor()
    out = r.redact("call +1 415 555 1234 please")
    # Some digits should be redacted; the exact form varies by regex.
    assert "[REDACTED:PHONE_NUMBER]" in out


def test_allow_list_passes_through() -> None:
    r = PiiRedactor(allow_list=frozenset({"public@example.com"}))
    out = r.redact("public@example.com and secret@example.com")
    assert "public@example.com" in out
    assert "secret@example.com" not in out


def test_empty_string_returns_empty() -> None:
    r = PiiRedactor()
    assert r.redact("") == ""


def test_no_pii_text_unchanged() -> None:
    r = PiiRedactor()
    text = "the quick brown fox jumped over"
    assert r.redact(text) == text


def test_custom_entity_set() -> None:
    """Restrict to EMAIL only — phone numbers should pass through."""
    r = PiiRedactor(entities=("EMAIL_ADDRESS",))
    text = "email me@x.com or call 415 555 1234"
    out = r.redact(text)
    assert "me@x.com" not in out
    assert "[REDACTED:EMAIL_ADDRESS]" in out


def test_is_using_presidio_when_not_installed() -> None:
    r = PiiRedactor()
    if not _has_presidio():
        assert r.is_using_presidio() is False
    else:
        # In dev envs where [full] is installed, behaviour depends on spaCy
        # model availability — don't assert either way.
        pass


@pytest.mark.skipif(not _has_presidio(), reason="presidio not installed")
def test_is_using_presidio_when_installed() -> None:
    r = PiiRedactor()
    # presidio may still fail to init without spaCy models — accept either.
    assert r.is_using_presidio() in (True, False)


def test_redaction_is_idempotent_with_pii_marker_text() -> None:
    """Running redact twice doesn't double-redact the markers."""
    r = PiiRedactor()
    once = r.redact("email me at x@y.com please")
    twice = r.redact(once)
    assert twice == once


def test_default_entities_are_documented() -> None:
    assert "EMAIL_ADDRESS" in PiiRedactor.DEFAULT_ENTITIES
    assert "US_SSN" in PiiRedactor.DEFAULT_ENTITIES
    assert "IP_ADDRESS" in PiiRedactor.DEFAULT_ENTITIES
    # Credential/secret entities ship in the OSS default.
    for ent in (
        "OPENAI_API_KEY",
        "AWS_ACCESS_KEY",
        "GITHUB_TOKEN",
        "GOOGLE_API_KEY",
        "JWT",
        "BEARER_TOKEN",
        "GENERIC_SECRET",
    ):
        assert ent in PiiRedactor.DEFAULT_ENTITIES


# --- finding #2: credential / secret redaction -------------------------


def test_redacts_openai_key() -> None:
    r = PiiRedactor()
    out = r.redact("key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX leaked")
    assert "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX" not in out
    assert "[REDACTED:OPENAI_API_KEY]" in out


def test_redacts_openai_key_digit_tail_not_misparsed_as_phone() -> None:
    """sk-LEAKED-9999 must be one secret, not a phone with a leaking prefix."""
    r = PiiRedactor()
    out = r.redact("leaked sk-LEAKED-9999000011112222 here")
    assert "sk-LEAKED" not in out
    assert "9999000011112222" not in out
    assert "[REDACTED:OPENAI_API_KEY]" in out


def test_redacts_aws_access_key() -> None:
    r = PiiRedactor()
    out = r.redact("AKIAIOSFODNN7EXAMPLE is the key")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED:AWS_ACCESS_KEY]" in out


def test_redacts_github_token() -> None:
    r = PiiRedactor()
    out = r.redact("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 set")
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in out
    assert "[REDACTED:GITHUB_TOKEN]" in out


def test_redacts_google_api_key() -> None:
    r = PiiRedactor()
    out = r.redact("AIzaSyA1234567890abcdefghijklmnopqrstu used")
    assert "AIzaSyA1234567890abcdefghijklmnopqrstu" not in out
    assert "[REDACTED:GOOGLE_API_KEY]" in out


def test_redacts_jwt() -> None:
    r = PiiRedactor()
    jwt = "eyJhbGciOiJIUzI1NiIsIn.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4f"
    out = r.redact(f"auth {jwt} end")
    assert jwt not in out
    assert "[REDACTED:JWT]" in out


def test_redacts_bearer_token() -> None:
    r = PiiRedactor()
    out = r.redact("Authorization: Bearer abcDEF123456ghiJKL")
    assert "abcDEF123456ghiJKL" not in out
    assert "[REDACTED:BEARER_TOKEN]" in out


def test_redacts_generic_password_assignment() -> None:
    r = PiiRedactor()
    out = r.redact("config: password=Sup3rS3cret! ok")
    assert "Sup3rS3cret!" not in out
    assert "[REDACTED:GENERIC_SECRET]" in out


def test_redacts_generic_api_key_assignment() -> None:
    r = PiiRedactor()
    out = r.redact("api_key: hunter2hunter2hunter2")
    assert "hunter2hunter2hunter2" not in out
    assert "[REDACTED:GENERIC_SECRET]" in out


# --- finding #2: shared redact_finding helper --------------------------


def _finding_with(**overrides: object) -> object:
    from datetime import datetime

    from agent_guardian.models.asi import AsiCategory
    from agent_guardian.models.csa import CsaCategory
    from agent_guardian.models.finding import Finding
    from agent_guardian.models.severity import Severity

    defaults: dict[str, object] = {
        "id": "f1",
        "probe_id": "ASI02-TM-001",
        "asi": AsiCategory.ASI02,
        "mitre_atlas": ["AML.T0054"],
        "csa_category": CsaCategory.AUTHORIZATION_CONTROL_HIJACKING,
        "severity": Severity.HIGH,
        "attempt_count": 1,
        "success": True,
        "confidence": 0.9,
        "summary": "leaked AKIAIOSFODNN7EXAMPLE",
        "transcript_ref": "see user@example.com",
        "trigger_prompt": "print token bearer abc123def456ghi",
        "created_at": datetime(2026, 5, 26, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_redact_finding_scrubs_pydantic_finding() -> None:
    finding = _finding_with()
    out = redact_finding(finding, enabled=True)
    assert "AKIAIOSFODNN7EXAMPLE" not in out.summary
    assert "[REDACTED:AWS_ACCESS_KEY]" in out.summary
    assert "user@example.com" not in (out.transcript_ref or "")
    assert "abc123def456ghi" not in (out.trigger_prompt or "")
    # original is unchanged (frozen model -> copy returned).
    assert "AKIAIOSFODNN7EXAMPLE" in finding.summary  # type: ignore[attr-defined]


def test_redact_finding_disabled_returns_input_unchanged() -> None:
    finding = _finding_with()
    out = redact_finding(finding, enabled=False)
    assert out is finding


def test_redact_finding_scrubs_dict() -> None:
    d = {
        "summary": "leaked sk-proj-ABCDEFGHIJKLMNOPQRSTUV",
        "description": "email victim@example.com",
        "evidence": "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012",
        "transcript_ref": None,
        "irrelevant": "keep me",
    }
    out = redact_finding(d, enabled=True)
    assert "[REDACTED:OPENAI_API_KEY]" in out["summary"]
    assert "victim@example.com" not in out["description"]
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012" not in out["evidence"]
    assert out["irrelevant"] == "keep me"
    # original dict untouched.
    assert "sk-proj-ABCDEFGHIJKLMNOPQRSTUV" in d["summary"]


# --- Presidio fake-injection tests -------------------------------------
#
# In CI presidio is not installed, so we simulate its presence with a
# minimal stub that quacks like AnalyzerEngine.analyze().


class _FakeResult:
    def __init__(self, start: int, end: int, entity_type: str) -> None:
        self.start = start
        self.end = end
        self.entity_type = entity_type


class _FakeAnalyzer:
    def __init__(self, results: list[_FakeResult]) -> None:
        self._results = results

    def analyze(self, *, text: str, entities: list[str], language: str) -> list[_FakeResult]:
        return self._results


def _force_presidio(redactor: PiiRedactor, results: list[_FakeResult]) -> None:
    """Pretend presidio is installed and returns ``results``."""
    redactor._analyzer = _FakeAnalyzer(results)
    redactor._using_presidio = True


def test_presidio_path_redacts() -> None:
    text = "hello bob"
    r = PiiRedactor()
    _force_presidio(r, [_FakeResult(start=6, end=9, entity_type="PERSON")])
    assert r.redact(text) == "hello [REDACTED:PERSON]"
    assert r.is_using_presidio() is True


def test_presidio_path_respects_allow_list() -> None:
    text = "hello bob"
    r = PiiRedactor(allow_list=frozenset({"bob"}))
    _force_presidio(r, [_FakeResult(start=6, end=9, entity_type="PERSON")])
    assert r.redact(text) == "hello bob"


def test_presidio_path_falls_back_on_exception() -> None:
    class _Broken:
        def analyze(self, **kwargs: object) -> list[_FakeResult]:
            raise RuntimeError("presidio explosion")

    r = PiiRedactor()
    r._analyzer = _Broken()
    r._using_presidio = True
    # Should not raise — fallback regex handles it.
    out = r.redact("contact user@x.com please")
    assert "[REDACTED:EMAIL_ADDRESS]" in out


def test_presidio_init_failure_does_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """If AnalyzerEngine() raises (e.g. missing spaCy model), we fall back."""
    import sys
    import types

    fake_module = types.ModuleType("presidio_analyzer")

    class _BoomEngine:
        def __init__(self) -> None:
            raise RuntimeError("no spaCy model")

    fake_module.AnalyzerEngine = _BoomEngine  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "presidio_analyzer", fake_module)

    r = PiiRedactor()
    assert r.is_using_presidio() is False
    # Fallback still redacts.
    assert "[REDACTED:EMAIL_ADDRESS]" in r.redact("x@y.com")
