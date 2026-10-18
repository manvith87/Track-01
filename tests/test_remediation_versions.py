"""PEP 440 version and constraint evaluation tests (Phase 5)."""

from __future__ import annotations

from packaging.version import Version

from app.remediation.versions import (
    SCHEME_ANY,
    SCHEME_PEP440,
    SCHEME_POETRY,
    evaluate_constraint,
    looks_like_poetry,
    parse_version,
    version_sort_key,
)


def test_parse_version_accepts_valid_and_rejects_garbage() -> None:
    assert parse_version("2.32.0") == Version("2.32.0")
    assert parse_version(" 1.0 ") == Version("1.0")
    assert parse_version("not-a-version") is None
    assert parse_version(None) is None
    assert parse_version("   ") is None


def test_version_sort_key_orders_numerically_then_lexically() -> None:
    keys = sorted(["10.0.0", "2.0.0", "zz-git", "1.9.9"], key=version_sort_key)
    assert keys == ["1.9.9", "2.0.0", "10.0.0", "zz-git"]


def test_no_recorded_constraint_is_satisfied() -> None:
    satisfied, _scheme, detail = evaluate_constraint(None, None, "2.32.1")
    assert satisfied is True
    assert "no version restriction" in detail
    satisfied, _scheme, _detail = evaluate_constraint("", "pep440", "2.32.1")
    assert satisfied is True


def test_any_scheme_places_no_restriction() -> None:
    satisfied, scheme, _detail = evaluate_constraint("anything", SCHEME_ANY, "2.32.1")
    assert satisfied is True
    assert scheme == SCHEME_ANY


def test_pep440_constraints_are_evaluated() -> None:
    satisfied, scheme, detail = evaluate_constraint(">=2.32,<3", "pep440", "2.32.1")
    assert satisfied is True
    assert scheme == SCHEME_PEP440
    assert "satisfies" in detail

    satisfied, _scheme, detail = evaluate_constraint(">=2.32,<3", "pep440", "3.0.0")
    assert satisfied is False
    assert "violates" in detail


def test_exact_pin_rejects_a_different_version() -> None:
    satisfied, _scheme, _detail = evaluate_constraint("==2.32.0", "pep440", "2.32.1")
    assert satisfied is False


def test_wildcard_constraints_are_evaluated() -> None:
    assert evaluate_constraint("2.*", "pep440", "2.32.1")[0] is True
    assert evaluate_constraint("2.*", "pep440", "3.0.0")[0] is False
    assert evaluate_constraint("2.3.*", "pep440", "2.3.9")[0] is True
    assert evaluate_constraint("2.3.*", "pep440", "2.4.0")[0] is False
    assert evaluate_constraint("*", "pep440", "99.0")[0] is True
    assert evaluate_constraint("==2.*", None, "2.0.0")[0] is True
    assert evaluate_constraint("!=2.*", None, "2.0.0")[0] is False
    assert evaluate_constraint("!=2.*", None, "3.0.0")[0] is True


def test_poetry_constraints_are_never_guessed() -> None:
    satisfied, scheme, detail = evaluate_constraint("^2.32", "poetry", "2.32.1")
    assert satisfied is None
    assert scheme == SCHEME_POETRY
    assert "cannot be evaluated" in detail


def test_poetry_syntax_is_detected_without_the_scheme_flag() -> None:
    assert evaluate_constraint("^2.32", None, "2.32.1")[0] is None
    assert evaluate_constraint("2.0 || 3.0", None, "3.0")[0] is None
    assert evaluate_constraint("~2.32", None, "2.32.1")[0] is None
    # ~= is a valid PEP 440 compatible-release specifier, not poetry syntax.
    assert evaluate_constraint("~=2.32", None, "2.32.1")[0] is True


def test_invalid_specifier_is_unknown() -> None:
    satisfied, _scheme, detail = evaluate_constraint(">>>2.0", "pep440", "2.32.1")
    assert satisfied is None
    assert "not a PEP 440 specifier set" in detail


def test_unparsable_proposed_version_is_unknown() -> None:
    satisfied, _scheme, detail = evaluate_constraint(">=2.32", "pep440", "zz-git")
    assert satisfied is None
    assert "not a PEP 440 version" in detail


def test_looks_like_poetry_recognizes_operators() -> None:
    assert looks_like_poetry("^1.2.3")
    assert looks_like_poetry(">=1.0 || <2.0")
    assert looks_like_poetry("~1.2")
    assert not looks_like_poetry("~=1.2")
    assert not looks_like_poetry(">=1.2,<2.0")
