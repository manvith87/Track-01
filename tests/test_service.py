"""End-to-end ingestion service tests.

Everything here runs offline: retrieval is a fake that materialises files on
disk and the GitHub API is a stub.  The tests pin down the orchestration rules:
what is validated before any work happens, what is recorded, how degradation is
reported, and that temporary directories are always cleaned up.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.errors import (
    EmbeddedCredentialsError,
    IngestionTimeoutError,
    InputValidationError,
    InvalidReferenceError,
    RateLimitExceededError,
    RepositoryAccessDeniedError,
    RepositoryNotFoundError,
    RepositoryTooLargeError,
    UnsupportedHostError,
)
from app.ingestion import service as service_module
from app.ingestion.github_api import RepositoryMetadataSnapshot
from app.ingestion.retrieval import GitRetrievalError, RetrievalReport
from app.ingestion.service import ingest_repository
from app.models.common import (
    IngestionStatus,
    ManifestParseStatus,
    ReferenceType,
    RetrievalStrategy,
    Severity,
    WarningCode,
)
from tests.support import (
    BROKEN_REPOSITORY,
    CLEAN_REPOSITORY,
    FAKE_SHA,
    FAKE_SHA_MOVED,
    MESSY_REPOSITORY,
    OVERSIZED_REPOSITORY,
    FakeRetriever,
    StubGitHubClient,
    write_tree,
)


def run_ingest(
    settings,
    files=None,
    *,
    url: str = "https://github.com/example/repo",
    ref: str | None = None,
    retriever=None,
    client=None,
    sha: str = FAKE_SHA,
    verified: bool = True,
):
    if retriever is None:
        retriever = FakeRetriever(files if files is not None else {}, sha=sha, verified=verified)
    if client is None:
        client = StubGitHubClient(sha=sha)
    return ingest_repository(url, ref, settings=settings, retriever=retriever, api_client=client)


def codes(result) -> set[str]:
    return {warning.code.value for warning in result.warnings}


def assert_work_root_clean(settings) -> None:
    root = settings.temp_root
    if root is not None and root.exists():
        assert list(root.iterdir()) == []


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_clean_repository_end_to_end(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    client = StubGitHubClient()
    result = ingest_repository(
        "https://github.com/example/clean",
        settings=settings,
        retriever=retriever,
        api_client=client,
    )

    assert result.status is IngestionStatus.SUCCESS
    assert result.warnings == []
    assert result.errors == []

    assert result.repository.identity.canonical_id == "github.com/example/clean"
    assert result.repository.commit.sha == FAKE_SHA
    assert result.repository.commit.short_sha == FAKE_SHA[:12]
    assert result.repository.commit.message == "test commit"
    assert result.repository.commit.author_name == "Test Author"
    assert result.repository.commit.source == "github_api"
    assert result.repository.metadata_source == "github_api"
    assert result.repository.is_private is False

    reference = result.reference
    assert reference.requested_ref is None
    assert reference.ref_type is ReferenceType.DEFAULT_BRANCH
    assert reference.is_default_branch is True
    assert reference.resolved_via == "github_api"
    assert reference.default_branch == "main"
    assert reference.resolved_commit_sha == FAKE_SHA
    assert reference.sha_verified is True

    summary = result.summary
    assert summary.status is IngestionStatus.SUCCESS
    assert summary.repository_id == "github.com/example/clean"
    assert summary.commit_sha == FAKE_SHA
    assert summary.files_examined == 3
    assert summary.manifests_detected == 2
    assert summary.manifests_parsed == 2
    assert summary.manifests_failed == 0
    assert summary.manifests_skipped == 0
    assert summary.declarations == 4
    assert summary.direct_declarations == 4
    assert summary.resolved_packages == 0
    assert summary.dependency_edges == 0
    assert summary.transitive_packages == 0
    assert summary.warning_count == 0
    assert summary.error_count == 0
    assert summary.unsupported_formats == []
    assert summary.retrieval_strategy == "git"
    assert summary.duration_ms >= 0

    # Without a lockfile nothing may claim a resolved version.
    assert all(declaration.resolved_version is None for declaration in result.declarations)
    assert all(declaration.resolved_from is None for declaration in result.declarations)
    # limits echo the settings; summary.retrieval_strategy echoes what was used.
    assert result.limits.retrieval_strategy == "auto"
    assert result.limits.max_files_scanned == settings.max_files_scanned

    # The retriever was asked for the exact resolved commit.
    assert retriever.calls[0]["commit_sha"] == FAKE_SHA
    assert retriever.calls[0]["reference"] is None
    assert retriever.calls[0]["reference_type"] is ReferenceType.DEFAULT_BRANCH
    assert client.metadata_calls == 1
    assert client.resolution_calls == [None]

    assert_work_root_clean(settings)


def test_requested_ref_is_recorded_and_passed_to_the_retriever(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    client = StubGitHubClient()
    result = ingest_repository(
        "https://github.com/example/clean",
        "main",
        settings=settings,
        retriever=retriever,
        api_client=client,
    )
    assert result.reference.requested_ref == "main"
    assert result.reference.ref_type is ReferenceType.BRANCH
    assert result.reference.is_default_branch is False
    assert result.reference.resolved_via == "github_api"
    assert retriever.calls[0]["reference"] == "main"
    assert retriever.calls[0]["reference_type"] is ReferenceType.BRANCH


def test_reference_in_url_is_extracted_and_used(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    result = ingest_repository(
        "https://github.com/example/repo/tree/release%2F2.0",
        settings=settings,
        retriever=retriever,
        api_client=StubGitHubClient(),
    )
    assert result.reference.requested_ref == "release/2.0"
    assert retriever.calls[0]["reference"] == "release/2.0"


def test_full_sha_reference_is_used_directly(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    client = StubGitHubClient()
    result = ingest_repository(
        "https://github.com/example/clean",
        FAKE_SHA,
        settings=settings,
        retriever=retriever,
        api_client=client,
    )
    assert result.reference.ref_type is ReferenceType.COMMIT
    assert result.reference.resolved_via == "provided_commit_sha"
    assert result.reference.requested_ref == FAKE_SHA
    assert result.repository.commit.source == "request"
    assert retriever.calls[0]["commit_sha"] == FAKE_SHA


# ---------------------------------------------------------------------------
# Repository shapes
# ---------------------------------------------------------------------------
def test_messy_repository_is_fully_described(settings_factory) -> None:
    settings = settings_factory()
    result = run_ingest(settings, MESSY_REPOSITORY)

    assert result.status is IngestionStatus.PARTIAL
    assert codes(result) == {
        WarningCode.UNSUPPORTED_FORMAT.value,
        WarningCode.RELATION_INFERRED.value,
        WarningCode.MULTIPLE_LOCKFILES.value,
        WarningCode.DIRECTNESS_UNKNOWN.value,
        WarningCode.CONFLICTING_EXACT_PINS.value,
        WarningCode.PIN_RESOLVED_MISMATCH.value,
        WarningCode.CONFLICTING_RESOLVED_VERSIONS.value,
    }
    assert len([w for w in result.warnings if w.code is WarningCode.PIN_RESOLVED_MISMATCH]) == 2

    summary = result.summary
    assert summary.files_examined == 9
    assert summary.manifests_detected == 8
    assert summary.manifests_parsed == 6
    assert summary.manifests_failed == 0
    assert summary.manifests_skipped == 2
    # requirements.txt includes requirements-dev.txt, and that file is also a
    # manifest in its own right - both occurrences are reported.
    assert summary.declarations == 10
    assert summary.direct_declarations == 10
    assert summary.dev_declarations == 5
    assert summary.optional_declarations == 1
    assert summary.resolved_packages == 13
    assert summary.dependency_edges == 6
    assert summary.transitive_packages == 5
    assert summary.unknown_relation_packages == 2
    assert summary.conflicting_packages == 3
    assert summary.unsupported_formats == ["Pipfile", "setup.py"]

    # The virtualenv and node_modules were pruned, so their contents are absent.
    assert all(not source.path.startswith((".venv", "node_modules")) for source in result.source_files)

    # Conflict bookkeeping is explained, not just counted.
    exact_pins = next(w for w in result.warnings if w.code is WarningCode.CONFLICTING_EXACT_PINS)
    assert exact_pins.details["package"] == "click"
    resolved_conflict = next(
        w for w in result.warnings if w.code is WarningCode.CONFLICTING_RESOLVED_VERSIONS
    )
    assert resolved_conflict.details["package"] == "rich"
    assert resolved_conflict.details["resolutions"] == {
        "poetry.lock": ["13.6.0", "13.7.1"],
        "uvproj/uv.lock": ["13.7.1"],
    }

    coverage = {entry.format: entry for entry in result.coverage}
    assert coverage["requirements.txt"].detected_files == 2
    assert coverage["pyproject.toml"].detected_files == 2
    assert coverage["poetry.lock"].parsed_files == 1
    assert coverage["uv.lock"].parsed_files == 1
    assert coverage["Pipfile"].support_level.value == "unsupported"
    assert coverage["setup.py"].support_level.value == "unsupported"

    # Dev declarations keep their group evidence.
    dev_declarations = [d for d in result.declarations if d.scope is not None and d.scope.value == "dev"]
    assert {d.normalized_name for d in dev_declarations} == {"click", "pytest"}
    included = next(d for d in dev_declarations if d.provenance.manifest_path == "requirements-dev.txt")
    assert included.group == "requirements-dev"  # the originating group name is preserved


def test_empty_repository_is_reported(settings_factory) -> None:
    settings = settings_factory()
    result = run_ingest(settings, {})
    assert result.status is IngestionStatus.PARTIAL
    assert WarningCode.EMPTY_REPOSITORY.value in codes(result)
    assert result.summary.files_examined == 0
    assert result.summary.manifests_detected == 0
    assert result.summary.declarations == 0


def test_repository_without_manifests_is_reported(settings_factory) -> None:
    settings = settings_factory()
    result = run_ingest(settings, {"README.md": "# just docs\n"})
    assert result.status is IngestionStatus.PARTIAL
    assert WarningCode.NO_MANIFESTS_FOUND.value in codes(result)
    assert result.summary.files_examined == 1
    assert result.summary.manifests_detected == 0


def test_malformed_lockfile_does_not_fail_the_run(settings_factory) -> None:
    settings = settings_factory()
    result = run_ingest(settings, BROKEN_REPOSITORY)
    assert result.status is IngestionStatus.PARTIAL
    assert len(result.errors) == 1
    assert result.errors[0].code.value == "manifest_parse_error"
    assert result.errors[0].manifest_path == "poetry.lock"
    records = {record.path: record for record in result.manifests}
    assert records["poetry.lock"].status is ManifestParseStatus.FAILED
    assert records["requirements.txt"].status is ManifestParseStatus.PARSED
    assert result.summary.manifests_failed == 1
    assert result.summary.manifests_parsed == 1
    assert result.summary.declarations == 1


def test_oversized_manifest_is_skipped_with_a_warning(settings_factory) -> None:
    settings = settings_factory(max_manifest_bytes=64)
    result = run_ingest(settings, OVERSIZED_REPOSITORY)
    assert result.status is IngestionStatus.PARTIAL
    assert WarningCode.MANIFEST_TOO_LARGE.value in codes(result)
    assert result.summary.oversized_files_skipped == 1
    record = result.manifests[0]
    assert record.status is ManifestParseStatus.SKIPPED
    assert record.skipped_reason == "too_large"


def test_source_files_report_is_bounded_but_manifests_first(settings_factory) -> None:
    settings = settings_factory(max_reported_source_files=2)
    result = run_ingest(settings, CLEAN_REPOSITORY)
    assert result.source_files_truncated is True
    assert len(result.source_files) == 2
    assert [source.path for source in result.source_files] == ["pyproject.toml", "requirements.txt"]


# ---------------------------------------------------------------------------
# Commit verification and degraded metadata
# ---------------------------------------------------------------------------
def test_branch_moving_between_resolution_and_retrieval_is_recorded(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY, sha=FAKE_SHA_MOVED)
    client = StubGitHubClient(sha=FAKE_SHA)
    result = ingest_repository(
        "https://github.com/example/clean",
        "main",
        settings=settings,
        retriever=retriever,
        api_client=client,
    )
    # The commit that was actually analysed wins everywhere.
    assert result.reference.resolved_commit_sha == FAKE_SHA_MOVED
    assert result.repository.commit.sha == FAKE_SHA_MOVED
    assert result.summary.commit_sha == FAKE_SHA_MOVED
    assert all(declaration.commit_sha == FAKE_SHA_MOVED for declaration in result.declarations)
    assert result.reference.sha_verified is True
    assert result.status is IngestionStatus.SUCCESS


def test_unverified_commit_sha_is_reported(settings_factory) -> None:
    settings = settings_factory()
    result = run_ingest(settings, CLEAN_REPOSITORY, verified=False)
    assert result.reference.sha_verified is False
    assert WarningCode.COMMIT_SHA_UNVERIFIED.value in codes(result)
    assert result.status is IngestionStatus.PARTIAL


def test_metadata_and_resolution_degrade_to_git_ls_remote(settings_factory, monkeypatch) -> None:
    settings = settings_factory()
    client = StubGitHubClient(
        metadata_error=RateLimitExceededError("api rate limit exhausted"),
        resolution_error=RateLimitExceededError("api rate limit exhausted"),
    )
    resolve_calls: list[dict] = []

    def fake_git_resolve(identity, *, settings, workdir, reference, timeout):
        resolve_calls.append(
            {
                "identity": identity.canonical_id,
                "reference": reference.name if reference is not None else None,
                "timeout": timeout,
            }
        )
        return FAKE_SHA, ReferenceType.DEFAULT_BRANCH, "main"

    monkeypatch.setattr(service_module, "git_binary_available", lambda effective: True)
    monkeypatch.setattr(service_module, "git_resolve_reference", fake_git_resolve)

    result = ingest_repository(
        "https://github.com/example/clean",
        settings=settings,
        retriever=FakeRetriever(CLEAN_REPOSITORY),
        api_client=client,
    )

    assert codes(result) >= {
        WarningCode.METADATA_UNAVAILABLE.value,
        WarningCode.RATE_LIMIT_FALLBACK.value,
        WarningCode.REF_RESOLVED_LOCALLY.value,
    }
    assert result.reference.resolved_via == "git_ls_remote"
    assert result.reference.default_branch == "main"
    assert result.repository.default_branch == "main"
    assert result.repository.metadata_source == "unavailable"
    assert result.repository.commit.source == "git"
    assert result.status is IngestionStatus.PARTIAL  # degradation is reported
    assert resolve_calls == [
        {"identity": "github.com/example/clean", "reference": None, "timeout": min(settings.git_timeout_seconds, 30.0)}
    ]

    # Both the resolution workdir and the ingestion workdir were removed.
    assert_work_root_clean(settings)


def test_full_sha_with_api_failure_is_used_with_a_warning(settings_factory, monkeypatch) -> None:
    settings = settings_factory()
    client = StubGitHubClient(resolution_error=RateLimitExceededError("api rate limit exhausted"))

    def die(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("git must not be consulted for a full SHA")

    monkeypatch.setattr(service_module, "git_binary_available", die)
    result = ingest_repository(
        "https://github.com/example/clean",
        FAKE_SHA,
        settings=settings,
        retriever=FakeRetriever(CLEAN_REPOSITORY),
        api_client=client,
    )
    assert result.reference.resolved_via == "provided_commit_sha"
    assert result.reference.ref_type is ReferenceType.COMMIT
    assert result.repository.commit.source == "request"
    assert codes(result) == {
        WarningCode.RATE_LIMIT_FALLBACK.value,
        WarningCode.COMMIT_SHA_UNVERIFIED.value,
    }


def test_query_parameters_in_url_are_ignored_with_an_info_warning(settings_factory) -> None:
    settings = settings_factory()
    result = run_ingest(settings, CLEAN_REPOSITORY, url="https://github.com/example/clean?tab=readme-ov-file")
    assert result.status is IngestionStatus.SUCCESS  # INFO warnings do not degrade the run
    assert len(result.warnings) == 1
    assert result.warnings[0].code is WarningCode.METADATA_UNAVAILABLE
    assert result.warnings[0].severity is Severity.INFO


def test_git_failure_falls_back_to_archive_in_auto_mode(settings_factory, monkeypatch) -> None:
    settings = settings_factory()  # strategy "auto"
    archive_instances: list = []

    class FakeArchive:
        def __init__(self, effective):
            archive_instances.append(self)
            self.closed = False

        def retrieve(self, **kwargs):
            root = kwargs["workdir"] / "repo"
            write_tree(root, CLEAN_REPOSITORY)
            return RetrievalReport(
                strategy=RetrievalStrategy.ARCHIVE,
                repository_root=root,
                commit_sha=FAKE_SHA,
                commit_sha_verified=True,
                files_written=3,
                bytes_written=64,
                duration_ms=1,
                warnings=(),
            )

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(
        service_module,
        "select_retriever",
        lambda effective: FakeRetriever(CLEAN_REPOSITORY, error=GitRetrievalError("git exploded")),
    )
    monkeypatch.setattr(service_module, "ArchiveRetriever", FakeArchive)

    result = ingest_repository(
        "https://github.com/example/clean",
        settings=settings,
        api_client=StubGitHubClient(),
    )
    assert WarningCode.RETRIEVAL_FALLBACK.value in codes(result)
    assert result.summary.retrieval_strategy == "archive"
    assert result.status is IngestionStatus.PARTIAL
    assert len(archive_instances) == 1
    assert archive_instances[0].closed is True
    assert_work_root_clean(settings)


# ---------------------------------------------------------------------------
# Failures are precise, early and leave no temporary directories behind
# ---------------------------------------------------------------------------
def test_unsupported_host_is_rejected_before_any_work(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    client = StubGitHubClient()
    with pytest.raises(UnsupportedHostError):
        ingest_repository("https://gitlab.com/example/clean", settings=settings, retriever=retriever, api_client=client)
    assert retriever.calls == []
    assert client.metadata_calls == 0
    assert_work_root_clean(settings)


def test_embedded_credentials_are_rejected(settings_factory) -> None:
    settings = settings_factory()
    with pytest.raises(EmbeddedCredentialsError):
        run_ingest(settings, CLEAN_REPOSITORY, url="https://user:token@github.com/example/clean")


def test_invalid_ref_is_rejected_before_any_work(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    client = StubGitHubClient()
    with pytest.raises(InvalidReferenceError):
        ingest_repository(
            "https://github.com/example/clean", "a b", settings=settings, retriever=retriever, api_client=client
        )
    assert retriever.calls == []
    assert client.metadata_calls == 0


def test_url_ref_and_parameter_disagreement_is_rejected(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    client = StubGitHubClient()
    with pytest.raises(InputValidationError) as excinfo:
        ingest_repository(
            "https://github.com/example/clean/tree/main",
            "develop",
            settings=settings,
            retriever=retriever,
            api_client=client,
        )
    assert excinfo.value.details == {"url_ref": "main", "ref": "develop"}
    assert retriever.calls == []
    assert client.metadata_calls == 0


def test_missing_repository_propagates(settings_factory) -> None:
    settings = settings_factory()
    client = StubGitHubClient(metadata_error=RepositoryNotFoundError("not found"))
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    with pytest.raises(RepositoryNotFoundError):
        ingest_repository(
            "https://github.com/example/clean", settings=settings, retriever=retriever, api_client=client
        )
    assert retriever.calls == []


def test_private_repository_is_rejected(settings_factory) -> None:
    settings = settings_factory()
    snapshot = RepositoryMetadataSnapshot(default_branch="main", size_kb=10, is_private=True)
    with pytest.raises(RepositoryAccessDeniedError):
        run_ingest(settings, CLEAN_REPOSITORY, client=StubGitHubClient(snapshot=snapshot))


def test_repository_size_limit_is_enforced_before_retrieval(settings_factory) -> None:
    settings = settings_factory(max_repository_size_kb=100)
    snapshot = RepositoryMetadataSnapshot(default_branch="main", size_kb=101)
    retriever = FakeRetriever(CLEAN_REPOSITORY)
    with pytest.raises(RepositoryTooLargeError):
        ingest_repository(
            "https://github.com/example/clean",
            settings=settings,
            retriever=retriever,
            api_client=StubGitHubClient(snapshot=snapshot),
        )
    assert retriever.calls == []


def test_retrieval_failure_propagates_and_cleans_up(settings_factory) -> None:
    settings = settings_factory()
    retriever = FakeRetriever(CLEAN_REPOSITORY, error=GitRetrievalError("git exploded"))
    with pytest.raises(GitRetrievalError):
        ingest_repository(
            "https://github.com/example/clean",
            settings=settings,
            retriever=retriever,
            api_client=StubGitHubClient(),
        )
    assert_work_root_clean(settings)


def test_ingestion_time_budget_is_enforced(settings_factory) -> None:
    settings = settings_factory(max_ingestion_seconds=0.0)
    with pytest.raises(IngestionTimeoutError) as excinfo:
        run_ingest(settings, CLEAN_REPOSITORY)
    assert excinfo.value.http_status == 504
    assert excinfo.value.details == {"stage": "metadata"}
    assert_work_root_clean(settings)
