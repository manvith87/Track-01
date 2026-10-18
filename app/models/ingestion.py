"""Ingestion level models: warnings, errors, coverage, summary and result."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.common import (
    ErrorCode,
    IngestionStage,
    IngestionStatus,
    Severity,
    SupportLevel,
    WarningCode,
)
from app.models.dependencies import (
    DependencyDeclaration,
    DependencyManifestRecord,
    ResolvedDependencyEdge,
    ResolvedPackage,
)
from app.models.repository import RepositoryMetadata, RepositoryReference
from app.models.source import SourceFile


class IngestionWarning(BaseModel):
    """A non-fatal problem, ambiguity or limitation encountered during ingestion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: WarningCode
    message: str
    severity: Severity = Severity.WARNING
    stage: IngestionStage = IngestionStage.UNKNOWN
    manifest_path: str | None = None
    line_number: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IngestionError(BaseModel):
    """A fatal or file-local error record.

    File-local errors (for example a malformed ``poetry.lock``) are reported
    here and downgrade the run to ``partial`` instead of failing it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: ErrorCode
    message: str
    stage: IngestionStage = IngestionStage.UNKNOWN
    manifest_path: str | None = None
    line_number: int | None = None
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class FormatCoverage(BaseModel):
    """Per-format coverage: what was detected versus what was actually parsed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    format: str
    support_level: SupportLevel
    detected_files: int = Field(default=0, ge=0)
    parsed_files: int = Field(default=0, ge=0)
    failed_files: int = Field(default=0, ge=0)
    notes: str | None = None


class IngestionLimits(BaseModel):
    """Effective safety limits applied to the run (useful for auditing)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    retrieval_strategy: str
    download_timeout_seconds: float
    git_timeout_seconds: float
    max_ingestion_seconds: float
    max_download_bytes: int
    max_extracted_bytes: int
    max_archive_members: int
    max_repository_size_kb: int
    max_files_scanned: int
    max_directory_entries: int
    max_manifest_bytes: int
    max_manifests: int
    max_dependencies: int


class IngestionSummary(BaseModel):
    """Counts and timings that summarise an ingestion run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: IngestionStatus
    repository_id: str | None = None
    commit_sha: str | None = None

    files_examined: int = Field(default=0, ge=0)
    directories_pruned: int = Field(default=0, ge=0)
    symlinks_skipped: int = Field(default=0, ge=0)
    oversized_files_skipped: int = Field(default=0, ge=0)

    manifests_detected: int = Field(default=0, ge=0)
    manifests_parsed: int = Field(default=0, ge=0)
    manifests_failed: int = Field(default=0, ge=0)
    manifests_skipped: int = Field(default=0, ge=0)

    declarations: int = Field(default=0, ge=0)
    resolved_packages: int = Field(default=0, ge=0)
    dependency_edges: int = Field(default=0, ge=0)

    direct_declarations: int = Field(default=0, ge=0)
    transitive_packages: int = Field(default=0, ge=0)
    unknown_relation_packages: int = Field(default=0, ge=0)
    dev_declarations: int = Field(default=0, ge=0)
    optional_declarations: int = Field(default=0, ge=0)
    conflicting_packages: int = Field(default=0, ge=0)

    warning_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)
    unsupported_formats: list[str] = Field(default_factory=list)

    retrieval_strategy: str | None = None
    started_at: str | None = Field(default=None, description="ISO-8601 UTC timestamp.")
    finished_at: str | None = None
    duration_ms: int = Field(default=0, ge=0)


class IngestionResult(BaseModel):
    """Complete, self-contained result of ingesting one repository revision.

    Phase 2 consumes this object directly: ``repository.identity.canonical_id``
    and ``reference.resolved_commit_sha`` are the keys that associate every
    nested record with a repository analysis.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: IngestionStatus
    repository: RepositoryMetadata | None = None
    reference: RepositoryReference

    source_files: list[SourceFile] = Field(default_factory=list)
    source_files_truncated: bool = False

    manifests: list[DependencyManifestRecord] = Field(default_factory=list)
    declarations: list[DependencyDeclaration] = Field(default_factory=list)
    resolved_packages: list[ResolvedPackage] = Field(default_factory=list)
    dependency_edges: list[ResolvedDependencyEdge] = Field(default_factory=list)

    coverage: list[FormatCoverage] = Field(default_factory=list)
    warnings: list[IngestionWarning] = Field(default_factory=list)
    errors: list[IngestionError] = Field(default_factory=list)
    summary: IngestionSummary
    limits: IngestionLimits


__all__ = [
    "FormatCoverage",
    "IngestionError",
    "IngestionLimits",
    "IngestionResult",
    "IngestionSummary",
    "IngestionWarning",
]
