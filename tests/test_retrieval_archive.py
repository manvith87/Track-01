"""Archive retrieval tests.

The codeload download is served by an ``httpx.MockTransport``: no socket is
ever opened.  Low-level archive hardening is covered by ``test_safety.py``;
these tests pin down the retriever's own contract - URL construction, byte
caps, HTTP error mapping, report fields and disk hygiene.
"""

from __future__ import annotations

import httpx
import pytest

from app.core.errors import (
    DownloadTimeoutError,
    NetworkFailureError,
    RateLimitExceededError,
    ReferenceNotFoundError,
    RepositoryAccessDeniedError,
    RepositoryTooLargeError,
    RetrievalError,
    UnsafeRepositoryContentError,
)
from app.ingestion.retrieval import ArchiveRetriever
from app.ingestion.urls import parse_repository_url
from app.models.common import ReferenceType, RetrievalStrategy, Severity
from tests.support import FAKE_SHA, make_settings, make_tar_gz, make_tar_gz_members, file_member, symlink_member

IDENTITY = parse_repository_url("https://github.com/psf/requests").identity
WRAPPER = f"requests-{FAKE_SHA[:12]}"
ARCHIVE_URL_PATH = f"/psf/requests/tar.gz/{FAKE_SHA}"


def retrieve(tmp_path, handler, *, settings=None, archive_url_path: str = ARCHIVE_URL_PATH):
    settings = settings or make_settings()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    retriever = ArchiveRetriever(settings, client=client)
    return retriever.retrieve(
        identity=IDENTITY,
        commit_sha=FAKE_SHA,
        reference=None,
        reference_type=ReferenceType.DEFAULT_BRANCH,
        workdir=tmp_path,
    )


def serving(payload: bytes, *, status: int = 200, headers: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == ARCHIVE_URL_PATH
        return httpx.Response(status, content=payload, headers=headers, request=request)

    return handler


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_archive_is_downloaded_from_codeload_for_the_exact_sha(tmp_path) -> None:
    archive = make_tar_gz({"requirements.txt": "requests>=2.31\n", "README.md": "# hi\n"}, wrapper=WRAPPER)
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        return httpx.Response(200, content=archive, request=request)

    report = retrieve(tmp_path, handler)

    assert seen["method"] == "GET"
    assert seen["url"] == f"{make_settings().github_codeload_base_url}{ARCHIVE_URL_PATH}"
    assert report.strategy is RetrievalStrategy.ARCHIVE
    assert report.commit_sha == FAKE_SHA
    assert report.commit_sha_verified is True
    assert report.repository_root == tmp_path / "repo"
    assert report.stripped_root == WRAPPER
    assert report.files_written == 2
    assert report.warnings == ()
    assert (tmp_path / "repo" / "requirements.txt").read_text(encoding="utf-8") == "requests>=2.31\n"
    assert (tmp_path / "repo" / "README.md").read_text(encoding="utf-8") == "# hi\n"
    # The downloaded tarball never survives the retrieval.
    assert not (tmp_path / "repository.tar.gz").exists()


def test_archive_url_is_built_from_settings_and_identity() -> None:
    settings = make_settings(github_codeload_base_url="https://codeload.example.test")
    retriever = ArchiveRetriever(settings, client=httpx.Client(transport=httpx.MockTransport(serving(b"x"))))
    assert retriever.archive_url(IDENTITY, FAKE_SHA) == f"https://codeload.example.test/psf/requests/tar.gz/{FAKE_SHA}"


def test_archive_without_a_wrapper_directory_extracts_in_place(tmp_path) -> None:
    archive = make_tar_gz({"requirements.txt": "requests\n"})
    report = retrieve(tmp_path, serving(archive))
    assert report.stripped_root is None
    assert (tmp_path / "repo" / "requirements.txt").exists()
    assert report.warnings == ()


def test_an_archive_root_that_does_not_match_the_sha_is_flagged(tmp_path) -> None:
    archive = make_tar_gz({"requirements.txt": "requests\n"}, wrapper="requests-deadbeef123")
    report = retrieve(tmp_path, serving(archive))

    assert len(report.warnings) == 1
    warning = report.warnings[0]
    assert warning.code.value == "archive_root_dir_unexpected"
    assert warning.severity is Severity.INFO
    assert warning.details == {"archive_root": "requests-deadbeef123", "commit_sha": FAKE_SHA}
    # The content is still extracted; only provenance is flagged.
    assert (tmp_path / "repo" / "requirements.txt").exists()


def test_extract_through_the_retriever_never_materialises_links(tmp_path) -> None:
    archive = make_tar_gz_members(
        [
            file_member(f"{WRAPPER}/requirements.txt", b"requests\n"),
            symlink_member(f"{WRAPPER}/docs/link.md", "target.md"),
        ]
    )
    report = retrieve(tmp_path, serving(archive))
    assert report.symlinks_skipped == 1
    assert (tmp_path / "repo" / "requirements.txt").exists()
    import os

    assert os.path.lexists(tmp_path / "repo" / "docs" / "link.md") is False


# ---------------------------------------------------------------------------
# Download failures
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (404, None, ReferenceNotFoundError),
        (403, None, RepositoryAccessDeniedError),
        (401, None, RepositoryAccessDeniedError),
        (403, {"x-ratelimit-remaining": "0"}, RateLimitExceededError),
        (429, None, RateLimitExceededError),
        (500, None, RetrievalError),
        (503, None, RetrievalError),
    ],
)
def test_http_failures_map_to_typed_errors(tmp_path, status, headers, expected) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=b"oops", headers=headers, request=request)

    with pytest.raises(expected) as excinfo:
        retrieve(tmp_path, handler)
    assert excinfo.value.details["repository"] == IDENTITY.canonical_id
    assert excinfo.value.details["status_code"] == status
    if status >= 500:
        assert excinfo.value.retryable is True
    if status == 429:
        assert excinfo.value.retryable is True


def test_timeout_and_network_errors_are_retryable(tmp_path) -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(DownloadTimeoutError) as excinfo:
        retrieve(tmp_path, timeout_handler)
    assert excinfo.value.retryable is True

    def broken_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(NetworkFailureError) as excinfo:
        retrieve(tmp_path, broken_handler)
    assert excinfo.value.retryable is True


def test_empty_download_is_rejected(tmp_path) -> None:
    with pytest.raises(UnsafeRepositoryContentError, match="empty"):
        retrieve(tmp_path, serving(b""))


def test_corrupt_archive_is_rejected_with_a_clear_error(tmp_path) -> None:
    with pytest.raises(UnsafeRepositoryContentError, match="readable tar archive"):
        retrieve(tmp_path, serving(b"this is definitely not a gzip stream"))


# ---------------------------------------------------------------------------
# Size caps
# ---------------------------------------------------------------------------
def test_declared_content_length_over_the_limit_is_rejected_before_download(tmp_path) -> None:
    archive = make_tar_gz({"requirements.txt": "requests>=2.31\n"})
    settings = make_settings(max_download_bytes=16)
    with pytest.raises(RepositoryTooLargeError) as excinfo:
        retrieve(tmp_path, serving(archive), settings=settings)
    assert excinfo.value.details["content_length"] == len(archive)
    assert excinfo.value.details["max_download_bytes"] == 16


def test_streamed_body_over_the_limit_is_rejected_mid_download(tmp_path) -> None:
    body = b"x" * 4096

    def handler(request: httpx.Request) -> httpx.Response:
        # The server lies in the header; the streamed body is what must be capped.
        return httpx.Response(200, content=body, headers={"content-length": "8"}, request=request)

    settings = make_settings(max_download_bytes=512)
    with pytest.raises(RepositoryTooLargeError) as excinfo:
        retrieve(tmp_path, handler, settings=settings)
    assert excinfo.value.details.get("content_length") in (None, 8)
    assert excinfo.value.details.get("max_download_bytes") == 512


def test_archive_member_limit_is_enforced(tmp_path) -> None:
    archive = make_tar_gz(
        {f"{WRAPPER}/f{i}.txt": "x" for i in range(5)},
    )
    settings = make_settings(max_archive_members=3)
    with pytest.raises(RepositoryTooLargeError) as excinfo:
        retrieve(tmp_path, serving(archive), settings=settings)
    assert excinfo.value.details == {"members": 5, "max_members": 3}


def test_extracted_size_limit_is_enforced(tmp_path) -> None:
    archive = make_tar_gz(
        {
            f"{WRAPPER}/a.bin": b"a" * 100,
            f"{WRAPPER}/b.bin": b"b" * 100,
        }
    )
    settings = make_settings(max_extracted_bytes=150)
    with pytest.raises(RepositoryTooLargeError) as excinfo:
        retrieve(tmp_path, serving(archive), settings=settings)
    assert excinfo.value.details == {"max_total_bytes": 150}


def test_escaping_archive_aborts_through_the_retriever(tmp_path) -> None:
    archive = make_tar_gz_members(
        [
            file_member(f"{WRAPPER}/../evil.txt", b"owned\n"),
        ]
    )
    with pytest.raises(UnsafeRepositoryContentError, match="escapes the repository root"):
        retrieve(tmp_path, serving(archive))
    assert not (tmp_path / "evil.txt").exists()
