"""Request and response models for the HTTP API.

The ingestion *domain* models (``app.models``) are reused as payloads so the
two layers cannot drift, while the request/response envelopes, truncation
metadata and error shape live here - the API contract is explicit and separate
from the parsing logic.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.config import Settings
from app.ingestion.parsers import FORMAT_CAPABILITIES, SUPPORTED_FORMATS
from app.models.common import IngestionStatus, SupportLevel
from app.models.dependencies import (
    DependencyDeclaration,
    DependencyManifestRecord,
    ResolvedDependencyEdge,
    ResolvedPackage,
)
from app.models.ingestion import (
    FormatCoverage,
    IngestionError,
    IngestionLimits,
    IngestionResult,
    IngestionSummary,
    IngestionWarning,
)
from app.models.repository import RepositoryMetadata, RepositoryReference
from app.models.source import SourceFile


class RepositoryIngestRequest(BaseModel):
    """Request body for ``POST /api/v1/repositories/ingest``."""

    model_config = ConfigDict(extra="forbid")

    repository_url: str = Field(
        min_length=1,
        max_length=2048,
        description="HTTPS URL of a public GitHub repository, e.g. https://github.com/psf/requests",
        examples=["https://github.com/psf/requests"],
    )
    ref: str | None = Field(
        default=None,
        max_length=255,
        description="Optional branch, tag or commit SHA. An unknown reference is rejected, never silently replaced.",
        examples=["v2.32.3"],
    )


class ResponseTruncation(BaseModel):
    """Which collections were truncated to keep the response bounded."""

    model_config = ConfigDict(extra="forbid")

    declarations: bool = False
    resolved_packages: bool = False
    dependency_edges: bool = False
    warnings: bool = False
    errors: bool = False
    manifests: bool = False
    source_files: bool = False


class SupportedFormatInfo(BaseModel):
    """A dependency format and how completely it is supported."""

    model_config = ConfigDict(extra="forbid")

    format: str
    support_level: SupportLevel
    is_lockfile: bool
    capabilities: str


class RepositoryIngestResponse(BaseModel):
    """Structured ingestion result."""

    model_config = ConfigDict(extra="forbid")

    status: IngestionStatus = Field(description="success, partial (data missing) or failed.")
    repository: RepositoryMetadata | None = Field(
        default=None, description="Repository identity, analysed commit and host metadata."
    )
    reference: RepositoryReference
    summary: IngestionSummary
    limits: IngestionLimits
    coverage: list[FormatCoverage] = Field(default_factory=list, description="Detected vs parsed files per format.")
    manifests: list[DependencyManifestRecord] = Field(default_factory=list)
    declarations: list[DependencyDeclaration] = Field(default_factory=list)
    resolved_packages: list[ResolvedPackage] = Field(default_factory=list)
    dependency_edges: list[ResolvedDependencyEdge] = Field(default_factory=list)
    warnings: list[IngestionWarning] = Field(default_factory=list)
    errors: list[IngestionError] = Field(default_factory=list)
    source_files: list[SourceFile] = Field(default_factory=list, description="Examined files (bounded, manifests first).")
    truncated: ResponseTruncation = Field(default_factory=ResponseTruncation)
    supported_formats: list[SupportedFormatInfo] = Field(
        default_factory=list, description="Dependency formats this build actually parses."
    )
    analysis_id: str | None = Field(
        default=None,
        description=(
            "Graph analysis identifier that persisting this result will use "
            "(the exact id of POST /analyses/{analysis_id}/graph). None when no "
            "resolved commit is available, so the result cannot be persisted."
        ),
    )

    @classmethod
    def from_result(cls, result: IngestionResult, settings: Settings) -> "RepositoryIngestResponse":
        """Map a domain result to the API contract, bounding payload sizes."""
        limit = settings.max_api_records
        return cls(
            analysis_id=_analysis_id_for(result),
            status=result.status,
            repository=result.repository,
            reference=result.reference,
            summary=result.summary,
            limits=result.limits,
            coverage=result.coverage,
            manifests=result.manifests[:limit],
            declarations=result.declarations[:limit],
            resolved_packages=result.resolved_packages[:limit],
            dependency_edges=result.dependency_edges[: limit * 2],
            warnings=result.warnings[:limit],
            errors=result.errors[:limit],
            source_files=result.source_files,
            truncated=ResponseTruncation(
                declarations=len(result.declarations) > limit,
                resolved_packages=len(result.resolved_packages) > limit,
                dependency_edges=len(result.dependency_edges) > limit * 2,
                warnings=len(result.warnings) > limit,
                errors=len(result.errors) > limit,
                manifests=len(result.manifests) > limit,
                source_files=result.source_files_truncated,
            ),
            supported_formats=supported_formats(),
        )

    def to_ingestion_result(self) -> IngestionResult:
        """Rebuild the Phase 1 domain result this response was projected from.

        The projection is lossless apart from the collections bounded by
        ``BLASTRADIUS_MAX_API_RECORDS`` (the ``truncated`` flags record that).
        Mapping the presentation-only fields (``truncated``,
        ``supported_formats``, ``analysis_id``) back to their domain
        equivalents lets an API client hand the response it was just given
        straight back to the graph persistence endpoint.
        """
        return IngestionResult(
            status=self.status,
            repository=self.repository,
            reference=self.reference,
            source_files=self.source_files,
            source_files_truncated=self.truncated.source_files,
            manifests=self.manifests,
            declarations=self.declarations,
            resolved_packages=self.resolved_packages,
            dependency_edges=self.dependency_edges,
            coverage=self.coverage,
            warnings=self.warnings,
            errors=self.errors,
            summary=self.summary,
            limits=self.limits,
        )


def _analysis_id_for(result: IngestionResult) -> str | None:
    """The graph identifier that persisting ``result`` will use.

    Derived with the graph layer's own function (single source of truth for the
    id scheme) through a local import, so the Phase 1 API module stays usable
    without importing the graph client stack.
    """
    if result.repository is None or not result.reference.resolved_commit_sha:
        return None
    from app.graph.service import GraphService

    return GraphService.analysis_id(
        result.repository.identity.canonical_id, result.reference.resolved_commit_sha
    )


def coerce_ingestion_result(payload: dict[str, Any]) -> IngestionResult:
    """Rebuild the Phase 1 domain result from a serialised JSON payload.

    Two shapes are accepted: the domain ``IngestionResult`` shape (as produced
    by the ingestion pipeline) and the public ``RepositoryIngestResponse``
    shape returned by ``POST /api/v1/repositories/ingest``.  The two are
    mutually exclusive (both forbid unknown fields), so the public shape is
    only attempted when the domain shape does not validate.
    """
    try:
        return IngestionResult.model_validate(payload)
    except ValidationError:
        return RepositoryIngestResponse.model_validate(payload).to_ingestion_result()


def supported_formats() -> list[SupportedFormatInfo]:
    """The dependency formats this build parses, with their capabilities."""
    return [
        SupportedFormatInfo(
            format=manifest_format.value,
            support_level=SupportLevel.SUPPORTED,
            is_lockfile=manifest_format.is_lockfile,
            capabilities=FORMAT_CAPABILITIES.get(manifest_format, ""),
        )
        for manifest_format in SUPPORTED_FORMATS
    ]


class ErrorDetail(BaseModel):
    """Machine readable error payload."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    stage: str
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Consistent error envelope for every failure."""

    model_config = ConfigDict(extra="forbid")

    error: ErrorDetail


__all__ = [
    "ErrorDetail",
    "ErrorResponse",
    "RepositoryIngestRequest",
    "RepositoryIngestResponse",
    "ResponseTruncation",
    "SupportedFormatInfo",
    "coerce_ingestion_result",
    "supported_formats",
]
