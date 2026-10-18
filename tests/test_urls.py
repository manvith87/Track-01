"""URL and reference validation tests (hostile input is the default assumption)."""

from __future__ import annotations

import pytest

from app.core.errors import (
    EmbeddedCredentialsError,
    InvalidReferenceError,
    InvalidRepositoryUrlError,
    UnsupportedHostError,
)
from app.ingestion.urls import parse_repository_url, validate_reference
from app.models.common import ReferenceType


# ---------------------------------------------------------------------------
# Repository URLs that must be accepted
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/psf/requests",
        "https://github.com/psf/requests/",
        "https://github.com/psf/requests.git",
        "https://www.github.com/psf/requests",
        "https://github.com/psf/requests?tab=readme-ov-file",
        "https://github.com/psf/requests#readme",
        "  https://github.com/psf/requests  ",
        "https://github.com:443/psf/requests",
    ],
)
def test_valid_repository_urls_are_normalised(settings, url: str) -> None:
    parsed = parse_repository_url(url, settings=settings)
    identity = parsed.identity
    assert identity.host == "github.com"
    assert identity.owner == "psf"
    assert identity.name == "requests"
    assert identity.canonical_id == "github.com/psf/requests"
    assert identity.clone_url == "https://github.com/psf/requests.git"
    assert identity.api_url.endswith("/repos/psf/requests")


def test_query_parameters_are_ignored_but_reported(settings) -> None:
    parsed = parse_repository_url("https://github.com/psf/requests?tab=readme-ov-file", settings=settings)
    assert parsed.ignored_query is True
    assert parse_repository_url("https://github.com/psf/requests", settings=settings).ignored_query is False


def test_reference_embedded_in_url_is_extracted(settings) -> None:
    tree = parse_repository_url("https://github.com/psf/requests/tree/v2.32.3", settings=settings)
    assert tree.derived_ref is not None
    assert tree.derived_ref.name == "v2.32.3"

    nested = parse_repository_url("https://github.com/psf/requests/tree/release/2.32.x", settings=settings)
    assert nested.derived_ref is not None
    assert nested.derived_ref.name == "release/2.32.x"

    commit = parse_repository_url(f"https://github.com/psf/requests/commit/{'a' * 40}", settings=settings)
    assert commit.derived_ref is not None
    assert commit.derived_ref.is_full_sha is True
    assert commit.derived_ref.ref_type_hint is ReferenceType.COMMIT


def test_owner_and_repository_case_is_preserved_but_id_is_canonical(settings) -> None:
    parsed = parse_repository_url("https://github.com/PSF/Requests", settings=settings)
    assert parsed.identity.owner == "PSF"
    assert parsed.identity.canonical_id == "github.com/psf/requests"
    assert parsed.identity.canonical_url == "https://github.com/PSF/Requests"


# ---------------------------------------------------------------------------
# Repository URLs that must be rejected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "github.com/psf/requests",
        "http://github.com/psf/requests",
        "git://github.com/psf/requests.git",
        "ssh://git@github.com/psf/requests.git",
        "ftp://github.com/psf/requests",
        "git@github.com:psf/requests.git",
        "file:///C:/repos/requests",
        "C:/repos/requests",
        "C:\\repos\\requests",
        "https://gitlab.com/psf/requests",
        "https://raw.githubusercontent.com/psf/requests/main/README.md",
        "https://github.com/psf",
        "https://github.com/",
        "https://github.com/psf/requests/blob/main/requirements.txt",
        "https://github.com/psf/requests/issues/1",
        "https://github.com/psf/requests/tree/",
        "https://github.com/-bad/requests",
        "https://github.com/psf/..",
        "https://github.com:8443/psf/requests",
        "https://github.com/psf/requ\x00ests",
        "https://github.com/p s/requests",
    ],
)
def test_invalid_repository_urls_are_rejected(settings, url: str) -> None:
    with pytest.raises((InvalidRepositoryUrlError, UnsupportedHostError)):
        parse_repository_url(url, settings=settings)


def test_non_string_url_is_rejected(settings) -> None:
    with pytest.raises(InvalidRepositoryUrlError):
        parse_repository_url(None, settings=settings)  # type: ignore[arg-type]


def test_embedded_credentials_are_rejected(settings) -> None:
    with pytest.raises(EmbeddedCredentialsError):
        parse_repository_url("https://user:secret@github.com/psf/requests", settings=settings)
    with pytest.raises(EmbeddedCredentialsError):
        parse_repository_url("https://github.com/psf/requests?access_token=abcdef", settings=settings)
    with pytest.raises(EmbeddedCredentialsError):
        parse_repository_url("https://github.com/psf/requests?token=abcdef", settings=settings)


def test_unsupported_host_is_reported_as_such(settings) -> None:
    with pytest.raises(UnsupportedHostError):
        parse_repository_url("https://example.com/psf/requests", settings=settings)


def test_overlong_url_is_rejected(settings) -> None:
    with pytest.raises(InvalidRepositoryUrlError):
        parse_repository_url("https://github.com/psf/" + "a" * 2100, settings=settings)


# ---------------------------------------------------------------------------
# Reference validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "expected_name"),
    [
        ("main", "main"),
        ("v2.32.3", "v2.32.3"),
        ("release/2.32", "release/2.32"),
        ("refs/heads/main", "main"),
        ("refs/tags/v1.0.0", "v1.0.0"),
        ("feature/UPPER_case", "feature/UPPER_case"),
        ("deadbee", "deadbee"),
    ],
)
def test_valid_references(raw: str, expected_name: str) -> None:
    reference = validate_reference(raw)
    assert reference.name == expected_name
    assert reference.is_full_sha is False


def test_full_sha_reference_is_classified_as_commit() -> None:
    reference = validate_reference("A" * 40)
    assert reference.is_full_sha is True
    assert reference.ref_type_hint is ReferenceType.COMMIT
    assert reference.name == "a" * 40  # lower-cased
    assert reference.raw == "A" * 40  # original preserved


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        None,
        "-x",
        "--upload-pack=evil",
        "a b",
        "a~b",
        "a^b",
        "a:b",
        "a?b",
        "a*b",
        "a[b]",
        "a\\b",
        "a//b",
        "a/../b",
        "/main",
        "main/",
        "main.lock",
        "main.",
        "main@{1}",
        "a" * 300,
    ],
)
def test_invalid_references_are_rejected(raw: str | None) -> None:
    with pytest.raises(InvalidReferenceError):
        validate_reference(raw)  # type: ignore[arg-type]
