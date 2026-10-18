"""Repository ingestion service.

``ingest_repository`` is the single entry point Phase 1 exposes.  It runs the
whole pipeline - validate, retrieve, discover, parse, aggregate - and returns a
fully self-describing :class:`~app.models.ingestion.IngestionResult`.

Guarantees:

* repository code is never executed: only Git plumbing/tarball extraction and
  pure text parsing happen - never ``setup.py``, never a build backend, never an
  import of the analysed project;
* the exact analysed commit SHA is recorded and verified against the retrieved
  working tree whenever the retrieval strategy allows it;
* temporary working directories are always removed, including on failure;
* every run is bounded by configurable timeouts, size and count limits.
"""

from __future__ import annotations

import dataclasses
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Settings, get_settings
from app.core.errors import (
    BlastRadiusError,
    IngestionTimeoutError,
    InputValidationError,
    MetadataRetrievalError,
    NetworkFailureError,
    RateLimitExceededError,
    RepositoryAccessDeniedError,
    RepositoryNotFoundError,
    RepositoryTooLargeError,
    RetrievalToolMissingError,
)
from app.core.logging import get_logger, safe_text
from app.ingestion.aggregation import AggregatedDependencies, aggregate_dependencies
from app.ingestion.discovery import DiscoveryResult, discover_repository_files
from app.ingestion.github_api import GitHubApiClient, ReferenceResolution, RepositoryMetadataSnapshot
from app.ingestion.parsers import ParseOutcome, ParserContext, get_parser
from app.ingestion.parsers.base import FileResolver
from app.ingestion.retrieval import (
    ArchiveRetriever,
    GitRetrievalError,
    RetrievalReport,
    RepositoryRetriever,
    git_binary_available,
    git_resolve_reference,
    select_retriever,
)
from app.ingestion.safety import read_text_file, remove_tree, validate_relative_path
from app.ingestion.urls import ParsedRepositoryUrl, ValidatedReference, parse_repository_url, validate_reference
from app.models.common import (
    ErrorCode,
    IngestionStage,
    IngestionStatus,
    ManifestParseStatus,
    ReferenceType,
    Severity,
    WarningCode,
)
from app.models.ids import short_sha
from app.models.ingestion import (
    IngestionError,
    IngestionLimits,
    IngestionResult,
    IngestionSummary,
    IngestionWarning,
)
from app.models.repository import RepositoryCommit, RepositoryIdentity, RepositoryMetadata, RepositoryReference
from app.models.source import SourceFile

_log = get_logger("ingestion.service")

DEFAULT_SUMMARY_MESSAGE = "Repository ingested successfully"


class RepositoryFileResolver:
    """File resolver restricted to files discovery already found in the tree.

    Used by the ``requirements.txt`` parser to follow local ``-r`` includes
    without ever touching a path that is not part of the analysed revision.
    """

    def __init__(self, root: Path, repository_files: frozenset[str], *, max_bytes: int) -> None:
        self._root = root
        self._files = repository_files
        self._max_bytes = max_bytes

    def exists(self, relative_path: str) -> bool:
        try:
            normalized = validate_relative_path(relative_path)
        except BlastRadiusError:
            return False
        return normalized in self._files

    def read_text(self, relative_path: str) -> str | None:
        try:
            normalized = validate_relative_path(relative_path)
        except BlastRadiusError:
            return None
        if normalized not in self._files:
            return None
        path = self._root.joinpath(*normalized.split("/"))
        read = read_text_file(path, max_bytes=self._max_bytes)
        return read.text


def ingest_repository(
    repository_url: str,
    ref: str | None = None,
    *,
    settings: Settings | None = None,
    retriever: RepositoryRetriever | None = None,
    api_client: GitHubApiClient | None = None,
) -> IngestionResult:
    """Ingest a public GitHub repository revision.

    Args:
        repository_url: HTTPS URL of a public GitHub repository. Local paths,
            other hosts, credentials and non-repository URLs are rejected.
        ref: Optional branch, tag or commit SHA. An unknown reference raises
            instead of silently falling back to the default branch.
        settings: Effective settings; defaults to the process configuration.
        retriever: Retrieval strategy override (test seam / advanced use).
        api_client: GitHub API client override (test seam / advanced use).

    Raises:
        BlastRadiusError: for validation, retrieval and safety failures. The
            exception carries a stable code, an HTTP status and details.
    """
    effective = settings or get_settings()
    started_monotonic = time.monotonic()
    started_at = _utc_now_iso()
    deadline = started_monotonic + effective.max_ingestion_seconds

    validated, reference = _validate_request(repository_url, ref, effective)
    identity = validated.identity

    warnings: list[IngestionWarning] = []
    if validated.ignored_query:
        warnings.append(
            _warning(
                WarningCode.METADATA_UNAVAILABLE,
                "Query parameters in the repository URL were ignored; they never affect which revision is analysed",
                severity=Severity.INFO,
                stage=IngestionStage.VALIDATION,
            )
        )

    _log.info(
        "ingestion started repository=%s requested_ref=%s strategy=%s",
        identity.canonical_id,
        safe_text(validated_ref_label(reference), 80),
        effective.retrieval_strategy,
    )

    owns_client = api_client is None
    client = api_client or GitHubApiClient(effective)
    workdir: Path | None = None
    try:
        snapshot, metadata_warnings = _fetch_metadata(client, identity, effective)
        warnings.extend(metadata_warnings)

        resolution, resolution_warnings = _resolve_reference(
            client,
            identity,
            reference,
            snapshot=snapshot,
            settings=effective,
            deadline=deadline,
        )
        warnings.extend(resolution_warnings)
        _log.info(
            "reference resolved repository=%s ref_type=%s commit=%s via=%s",
            identity.canonical_id,
            resolution.ref_type.value,
            short_sha(resolution.commit_sha),
            resolution.resolved_via,
        )

        workdir = _create_workdir(effective)
        report, retrieval_warnings = _retrieve(
            identity=identity,
            resolution=resolution,
            reference=reference,
            settings=effective,
            retriever=retriever,
            workdir=workdir,
            deadline=deadline,
        )
        warnings.extend(retrieval_warnings)
        _check_deadline(deadline, stage=IngestionStage.DISCOVERY)

        discovery_result = discover_repository_files(report.repository_root, effective)
        warnings.extend(discovery_result.warnings)
        _log.info(
            "discovery finished repository=%s files=%d manifests=%d pruned_dirs=%d symlinks=%d truncated=%s",
            identity.canonical_id,
            discovery_result.files_examined,
            len(discovery_result.manifests),
            discovery_result.directories_pruned,
            discovery_result.symlinks_skipped,
            discovery_result.truncated,
        )

        if discovery_result.files_examined == 0:
            warnings.append(
                _warning(
                    WarningCode.EMPTY_REPOSITORY,
                    "The analysed revision contains no files",
                    stage=IngestionStage.DISCOVERY,
                )
            )
        elif not discovery_result.manifests:
            warnings.append(
                _warning(
                    WarningCode.NO_MANIFESTS_FOUND,
                    "No supported Python dependency manifest or lockfile was found in the repository",
                    stage=IngestionStage.DISCOVERY,
                )
            )

        _check_deadline(deadline, stage=IngestionStage.PARSING)
        outcomes = _parse_manifests(discovery_result, report, effective)

        _check_deadline(deadline, stage=IngestionStage.AGGREGATION)
        aggregated = aggregate_dependencies(
            repository_id=identity.canonical_id,
            commit_sha=report.commit_sha or resolution.commit_sha,
            discovery=discovery_result,
            outcomes=outcomes,
            settings=effective,
        )
        warnings.extend(aggregated.warnings)

        commit_sha = report.commit_sha or resolution.commit_sha
        all_warnings = _deduplicate_warnings([*warnings])
        status = _compute_status(aggregated, discovery_result, all_warnings)
        repository = _build_repository_metadata(
            identity=identity,
            snapshot=snapshot,
            resolution=resolution,
            report=report,
            commit_sha=commit_sha,
            requested_ref=reference.raw if reference else None,
        )
        source_files, truncated = _limit_source_files(discovery_result, effective)

        result = IngestionResult(
            status=status,
            repository=repository,
            reference=RepositoryReference(
                requested_ref=reference.raw if reference else None,
                ref_type=resolution.ref_type,
                resolved_commit_sha=commit_sha,
                default_branch=snapshot.default_branch or resolution.default_branch,
                resolved_via=resolution.resolved_via,
                is_default_branch=resolution.ref_type is ReferenceType.DEFAULT_BRANCH,
                sha_verified=report.commit_sha_verified,
            ),
            source_files=source_files,
            source_files_truncated=truncated,
            manifests=aggregated.manifests,
            declarations=aggregated.declarations,
            resolved_packages=aggregated.resolved_packages,
            dependency_edges=aggregated.edges,
            coverage=aggregated.coverage,
            warnings=all_warnings,
            errors=aggregated.errors,
            summary=_build_summary(
                status=status,
                repository_id=identity.canonical_id,
                commit_sha=commit_sha,
                discovery_result=discovery_result,
                aggregated=aggregated,
                warnings=all_warnings,
                report=report,
                started_at=started_at,
                started_monotonic=started_monotonic,
            ),
            limits=_build_limits(effective),
        )

        _log.info(
            "ingestion finished repository=%s commit=%s status=%s declarations=%d resolved=%d edges=%d warnings=%d "
            "errors=%d duration_ms=%d",
            identity.canonical_id,
            short_sha(commit_sha),
            status.value,
            len(result.declarations),
            len(result.resolved_packages),
            len(result.dependency_edges),
            len(all_warnings),
            len(result.errors),
            result.summary.duration_ms,
        )
        return result
    except BlastRadiusError as exc:
        _log.warning(
            "ingestion failed repository=%s code=%s stage=%s message=%s",
            identity.canonical_id,
            exc.code.value,
            exc.stage.value,
            safe_text(exc.message, 300),
        )
        raise
    finally:
        if workdir is not None:
            _cleanup_workdir(workdir)
        if owns_client:
            client.close()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validated_ref_label(reference: ValidatedReference | None) -> str:
    """Human readable label for the requested reference."""
    return reference.raw if reference else "<default branch>"


def _validate_request(
    repository_url: str,
    ref: str | None,
    settings: Settings,
) -> tuple[ParsedRepositoryUrl, ValidatedReference | None]:
    validated = parse_repository_url(repository_url, settings=settings)
    reference = validate_reference(ref) if ref is not None and str(ref).strip() else None

    if validated.derived_ref is not None:
        if reference is not None and reference.name != validated.derived_ref.name:
            raise InputValidationError(
                "The reference in the URL and the 'ref' parameter disagree; pass only one of them",
                details={"url_ref": validated.derived_ref.name, "ref": reference.name},
            )
        reference = validated.derived_ref
    return validated, reference


# ---------------------------------------------------------------------------
# Metadata and reference resolution
# ---------------------------------------------------------------------------
def _fetch_metadata(
    client: GitHubApiClient,
    identity: RepositoryIdentity,
    settings: Settings,
) -> tuple[RepositoryMetadataSnapshot, list[IngestionWarning]]:
    """Fetch repository metadata, degrading to a warning when it is unavailable."""
    warnings: list[IngestionWarning] = []
    try:
        snapshot = client.get_repository(identity)
    except RepositoryNotFoundError:
        raise
    except (RateLimitExceededError, MetadataRetrievalError, NetworkFailureError) as exc:
        warnings.append(
            _warning(
                WarningCode.METADATA_UNAVAILABLE,
                "Repository metadata could not be retrieved from the GitHub API; retrieval continued without it",
                stage=IngestionStage.METADATA,
                reason=exc.code.value,
                detail=safe_text(exc.message, 200),
            )
        )
        if isinstance(exc, RateLimitExceededError):
            warnings.append(
                _warning(
                    WarningCode.RATE_LIMIT_FALLBACK,
                    "The anonymous GitHub API rate limit was exhausted; Git based resolution is used instead",
                    stage=IngestionStage.METADATA,
                    retryable=True,
                )
            )
        return RepositoryMetadataSnapshot(), warnings

    if snapshot.is_private:
        raise RepositoryAccessDeniedError(
            "Only public GitHub repositories can be ingested; the repository is private",
            details={"repository": identity.canonical_id},
        )
    if snapshot.size_kb is not None and snapshot.size_kb > settings.max_repository_size_kb:
        raise RepositoryTooLargeError(
            "The repository exceeds the configured size limit",
            details={
                "repository": identity.canonical_id,
                "size_kb": snapshot.size_kb,
                "max_repository_size_kb": settings.max_repository_size_kb,
            },
        )
    return snapshot, warnings


def _resolve_reference(
    client: GitHubApiClient,
    identity: RepositoryIdentity,
    reference: ValidatedReference | None,
    *,
    snapshot: RepositoryMetadataSnapshot,
    settings: Settings,
    deadline: float,
) -> tuple[ReferenceResolution, list[IngestionWarning]]:
    """Resolve the requested reference to an exact commit SHA."""
    warnings: list[IngestionWarning] = []
    _check_deadline(deadline, stage=IngestionStage.METADATA)
    api_error: BlastRadiusError | None = None

    try:
        resolution = client.resolve_reference(
            identity,
            reference,
            default_branch=snapshot.default_branch,
        )
    except RepositoryNotFoundError:
        raise
    except (RateLimitExceededError, MetadataRetrievalError, NetworkFailureError) as exc:
        api_error = exc
    else:
        # GitHub's commit endpoint cannot say whether a name was a branch or a
        # tag; a successful tag probe upgrades the label. Nothing is guessed.
        if reference is not None and resolution.ref_type is ReferenceType.BRANCH and client.is_ref_a_tag(identity, reference.name):
            resolution = dataclasses.replace(resolution, ref_type=ReferenceType.TAG)
        return resolution, warnings

    if api_error is not None:
        warnings.append(
            _warning(
                WarningCode.RATE_LIMIT_FALLBACK
                if isinstance(api_error, RateLimitExceededError)
                else WarningCode.METADATA_UNAVAILABLE,
                "The GitHub API could not resolve the reference; falling back to git ls-remote",
                stage=IngestionStage.METADATA,
                reason=api_error.code.value,
            )
        )

    if reference is not None and reference.is_full_sha:
        warnings.append(
            _warning(
                WarningCode.COMMIT_SHA_UNVERIFIED,
                "A full commit SHA was supplied directly and could not be verified against the repository metadata",
                stage=IngestionStage.METADATA,
                commit_sha=reference.name,
            )
        )
        return (
            ReferenceResolution(
                commit_sha=reference.name,
                ref_type=ReferenceType.COMMIT,
                resolved_via="provided_commit_sha",
                default_branch=snapshot.default_branch,
                commit_source="request",
            ),
            warnings,
        )

    if not git_binary_available(settings):
        if api_error is not None:
            raise api_error
        raise RetrievalToolMissingError(
            "Neither the GitHub API nor Git is available to resolve the reference",
            details={"repository": identity.canonical_id},
        )

    workdir = _create_workdir(settings, prefix="blastradius-resolve-")
    try:
        sha, ref_type, default_branch = git_resolve_reference(
            identity,
            settings=settings,
            workdir=workdir,
            reference=reference,
            timeout=max(1.0, min(settings.git_timeout_seconds, deadline - time.monotonic())),
        )
    finally:
        _cleanup_workdir(workdir)

    warnings.append(
        _warning(
            WarningCode.REF_RESOLVED_LOCALLY,
            "The commit SHA was resolved with git ls-remote instead of the GitHub API",
            stage=IngestionStage.METADATA,
            commit_sha=sha,
        )
    )
    return (
        ReferenceResolution(
            commit_sha=sha,
            ref_type=ref_type,
            resolved_via="git_ls_remote",
            default_branch=default_branch or snapshot.default_branch,
            commit_source="git",
        ),
        warnings,
    )


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
def _retrieve(
    *,
    identity: RepositoryIdentity,
    resolution: ReferenceResolution,
    reference: ValidatedReference | None,
    settings: Settings,
    retriever: RepositoryRetriever | None,
    workdir: Path,
    deadline: float,
) -> tuple[RetrievalReport, list[IngestionWarning]]:
    warnings: list[IngestionWarning] = []
    active = retriever or select_retriever(settings)
    try:
        report = active.retrieve(
            identity=identity,
            commit_sha=resolution.commit_sha,
            reference=reference,
            reference_type=resolution.ref_type,
            workdir=workdir,
            deadline=deadline,
        )
    except GitRetrievalError as exc:
        if retriever is not None or settings.retrieval_strategy == "git":
            raise
        warnings.append(
            _warning(
                WarningCode.RETRIEVAL_FALLBACK,
                "The Git retrieval strategy failed; the archive strategy was used instead",
                stage=IngestionStage.RETRIEVAL,
                detail=safe_text(exc.details.get("stderr", exc.message), 200),
            )
        )
        _log.warning(
            "git retrieval failed, falling back to archive repository=%s detail=%s",
            identity.canonical_id,
            safe_text(exc.message, 200),
        )
        fallback = ArchiveRetriever(settings)
        try:
            report = fallback.retrieve(
                identity=identity,
                commit_sha=resolution.commit_sha,
                reference=reference,
                reference_type=resolution.ref_type,
                workdir=workdir,
                deadline=deadline,
            )
        finally:
            fallback.close()

    warnings.extend(report.warnings)
    if not report.commit_sha_verified:
        warnings.append(
            _warning(
                WarningCode.COMMIT_SHA_UNVERIFIED,
                "The analysed commit SHA could not be verified against the retrieved working tree",
                stage=IngestionStage.RETRIEVAL,
                commit_sha=resolution.commit_sha,
            )
        )
    return report, warnings


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def _parse_manifests(
    discovery_result: DiscoveryResult,
    report: RetrievalReport,
    settings: Settings,
) -> dict[str, ParseOutcome | None]:
    """Parse every supported manifest, converting crashes into reported errors."""
    repository_files = frozenset(source.path for source in discovery_result.files)
    resolver: FileResolver = RepositoryFileResolver(
        report.repository_root,
        repository_files,
        max_bytes=settings.max_manifest_bytes,
    )
    outcomes: dict[str, ParseOutcome | None] = {}
    for manifest in discovery_result.manifests:
        if manifest.format is None:
            continue
        if manifest.text is None:
            outcomes[manifest.path] = None
            continue
        context = ParserContext(
            path=manifest.path,
            text=manifest.text,
            settings=settings,
            resolver=resolver,
            repository_files=repository_files,
        )
        try:
            parser = get_parser(manifest.format)
            outcome = parser(context)
        except BlastRadiusError as exc:
            _log.warning(
                "parser rejected manifest path=%s code=%s",
                safe_text(manifest.path, 120),
                exc.code.value,
            )
            outcome = ParseOutcome(status=ManifestParseStatus.FAILED)
            outcome.errors.append(
                IngestionError(
                    code=exc.code,
                    message=f"Parsing failed: {exc.message}",
                    stage=IngestionStage.PARSING,
                    manifest_path=manifest.path,
                    details=dict(exc.details),
                )
            )
        except Exception as exc:  # noqa: BLE001 - untrusted input must never crash the request
            # A parser bug on hostile input is reported as a file-local error and
            # logged with a traceback; it never aborts the whole ingestion and it
            # is never silently swallowed.
            _log.exception("unexpected parser failure path=%s", safe_text(manifest.path, 120))
            outcome = ParseOutcome(status=ManifestParseStatus.FAILED)
            outcome.errors.append(
                IngestionError(
                    code=ErrorCode.INTERNAL_ERROR,
                    message="The parser failed unexpectedly on this file; its dependencies are not reported",
                    stage=IngestionStage.PARSING,
                    manifest_path=manifest.path,
                    details={"exception": type(exc).__name__},
                )
            )
        outcomes[manifest.path] = outcome
        _log.debug(
            "parsed manifest path=%s format=%s status=%s declarations=%d resolved=%d",
            safe_text(manifest.path, 120),
            manifest.format.value,
            outcome.status.value,
            len(outcome.declarations),
            len(outcome.resolved_packages),
        )
    return outcomes


# ---------------------------------------------------------------------------
# Result assembly
# ---------------------------------------------------------------------------
def _compute_status(
    aggregated: AggregatedDependencies,
    discovery_result: DiscoveryResult,
    warnings: list[IngestionWarning],
) -> IngestionStatus:
    if aggregated.errors:
        return IngestionStatus.PARTIAL
    if any(
        record.status in {ManifestParseStatus.FAILED, ManifestParseStatus.PARTIAL} for record in aggregated.manifests
    ):
        return IngestionStatus.PARTIAL
    if discovery_result.truncated:
        return IngestionStatus.PARTIAL
    if any(warning.severity in {Severity.WARNING, Severity.ERROR} for warning in warnings):
        return IngestionStatus.PARTIAL
    return IngestionStatus.SUCCESS


def _build_repository_metadata(
    *,
    identity: RepositoryIdentity,
    snapshot: RepositoryMetadataSnapshot,
    resolution: ReferenceResolution,
    report: RetrievalReport,
    commit_sha: str,
    requested_ref: str | None,
) -> RepositoryMetadata:
    commit = RepositoryCommit(
        sha=commit_sha,
        short_sha=short_sha(commit_sha),
        message=resolution.commit_message or report.commit_message,
        author_name=resolution.commit_author or report.commit_author,
        committed_at=resolution.committed_at,
        source=resolution.commit_source,
    )
    return RepositoryMetadata(
        identity=identity,
        commit=commit,
        reference=RepositoryReference(
            requested_ref=requested_ref,
            ref_type=resolution.ref_type,
            resolved_commit_sha=commit_sha,
            default_branch=snapshot.default_branch or resolution.default_branch,
            resolved_via=resolution.resolved_via,
            is_default_branch=resolution.ref_type is ReferenceType.DEFAULT_BRANCH,
            sha_verified=report.commit_sha_verified,
        ),
        description=snapshot.description,
        default_branch=snapshot.default_branch or resolution.default_branch,
        is_private=False,
        is_archived=snapshot.is_archived,
        is_fork=snapshot.is_fork,
        stars=snapshot.stars,
        forks=snapshot.forks,
        open_issues=snapshot.open_issues,
        size_kb=snapshot.size_kb,
        license_spdx_id=snapshot.license_spdx_id,
        primary_language=snapshot.primary_language,
        pushed_at=snapshot.pushed_at,
        created_at=snapshot.created_at,
        metadata_source="github_api" if snapshot.default_branch is not None or snapshot.size_kb is not None else "unavailable",
    )


def _build_summary(
    *,
    status: IngestionStatus,
    repository_id: str,
    commit_sha: str,
    discovery_result: DiscoveryResult,
    aggregated: AggregatedDependencies,
    warnings: list[IngestionWarning],
    report: RetrievalReport,
    started_at: str,
    started_monotonic: float,
) -> IngestionSummary:
    parsed = sum(1 for record in aggregated.manifests if record.status is ManifestParseStatus.PARSED)
    partial = sum(1 for record in aggregated.manifests if record.status is ManifestParseStatus.PARTIAL)
    failed = sum(1 for record in aggregated.manifests if record.status is ManifestParseStatus.FAILED)
    skipped = sum(1 for record in aggregated.manifests if record.status is ManifestParseStatus.SKIPPED)
    unsupported = sorted(
        {record.unsupported_format.value for record in aggregated.manifests if record.unsupported_format is not None}
    )
    return IngestionSummary(
        status=status,
        repository_id=repository_id,
        commit_sha=commit_sha,
        files_examined=discovery_result.files_examined,
        directories_pruned=discovery_result.directories_pruned,
        symlinks_skipped=discovery_result.symlinks_skipped,
        oversized_files_skipped=discovery_result.oversized_manifests_skipped,
        manifests_detected=len(aggregated.manifests),
        manifests_parsed=parsed + partial,
        manifests_failed=failed,
        manifests_skipped=skipped,
        declarations=len(aggregated.declarations),
        resolved_packages=len(aggregated.resolved_packages),
        dependency_edges=len(aggregated.edges),
        direct_declarations=aggregated.direct_declarations,
        transitive_packages=aggregated.transitive_packages,
        unknown_relation_packages=aggregated.unknown_relation_packages,
        dev_declarations=aggregated.dev_declarations,
        optional_declarations=aggregated.optional_declarations,
        conflicting_packages=len(aggregated.conflicting_packages),
        warning_count=len(warnings),
        error_count=len(aggregated.errors),
        unsupported_formats=unsupported,
        retrieval_strategy=report.strategy.value,
        started_at=started_at,
        finished_at=_utc_now_iso(),
        duration_ms=int((time.monotonic() - started_monotonic) * 1000),
    )


def _build_limits(settings: Settings) -> IngestionLimits:
    return IngestionLimits(
        retrieval_strategy=settings.retrieval_strategy,
        download_timeout_seconds=settings.download_timeout_seconds,
        git_timeout_seconds=settings.git_timeout_seconds,
        max_ingestion_seconds=settings.max_ingestion_seconds,
        max_download_bytes=settings.max_download_bytes,
        max_extracted_bytes=settings.max_extracted_bytes,
        max_archive_members=settings.max_archive_members,
        max_repository_size_kb=settings.max_repository_size_kb,
        max_files_scanned=settings.max_files_scanned,
        max_directory_entries=settings.max_directory_entries,
        max_manifest_bytes=settings.max_manifest_bytes,
        max_manifests=settings.max_manifests,
        max_dependencies=settings.max_dependencies,
    )


def _limit_source_files(
    discovery_result: DiscoveryResult,
    settings: Settings,
) -> tuple[list[SourceFile], bool]:
    """Keep the reported file list bounded, manifests first."""
    files = discovery_result.files
    limit = settings.max_reported_source_files
    if len(files) <= limit:
        return files, False
    manifests = [source for source in files if source.manifest_format or source.unsupported_format]
    others = [source for source in files if not (source.manifest_format or source.unsupported_format)]
    return (manifests + others)[:limit], True


# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------
def _create_workdir(settings: Settings, *, prefix: str = "blastradius-ingest-") -> Path:
    if settings.temp_root is not None:
        settings.temp_root.mkdir(parents=True, exist_ok=True)
    directory = tempfile.mkdtemp(prefix=prefix, dir=str(settings.temp_root) if settings.temp_root else None)
    _log.debug("created temporary working directory %s", safe_text(directory, 200))
    return Path(directory)


def _cleanup_workdir(workdir: Path) -> None:
    """Remove a temporary working directory, never raising on failure."""
    remove_tree(workdir)
    if workdir.exists():  # pragma: no cover - platform specific
        _log.warning("temporary working directory could not be removed path=%s", safe_text(workdir, 200))


def _check_deadline(deadline: float, *, stage: IngestionStage) -> None:
    if time.monotonic() >= deadline:
        raise IngestionTimeoutError(
            "Ingestion exceeded the configured time budget",
            details={"stage": stage.value},
        )


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _warning(code: WarningCode, message: str, *, severity: Severity = Severity.WARNING, stage: IngestionStage, **details: object) -> IngestionWarning:
    return IngestionWarning(code=code, message=message, severity=severity, stage=stage, details=dict(details))


def _deduplicate_warnings(warnings: list[IngestionWarning]) -> list[IngestionWarning]:
    seen: set[tuple[str, str | None, int | None, str]] = set()
    unique: list[IngestionWarning] = []
    for warning in warnings:
        key = (warning.code.value, warning.manifest_path, warning.line_number, warning.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(warning)
    return unique


__all__ = ["RepositoryFileResolver", "ingest_repository"]
