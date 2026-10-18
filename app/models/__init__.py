"""Typed domain models for BlastRadius.

The models in this package are deliberately independent from the FastAPI
response models (see :mod:`app.api.v1.schemas`).  They form the *contract*
between the ingestion engine and later phases: Phase 2 persists these records
in FalkorDB without needing to re-parse anything.
"""

from app.models.common import (
    ConstraintScheme,
    DependencyRelation,
    DependencyScope,
    Ecosystem,
    ErrorCode,
    IngestionStage,
    IngestionStatus,
    ManifestFormat,
    ManifestParseStatus,
    ReferenceType,
    RetrievalStrategy,
    Severity,
    SourceKind,
    SupportLevel,
    UnsupportedManifestFormat,
    WarningCode,
)
from app.models.dependencies import (
    DependencyDeclaration,
    DependencyManifestRecord,
    DependencyProvenance,
    ResolvedDependencyEdge,
    ResolvedPackage,
)
from app.models.ids import short_sha, stable_id
from app.models.ingestion import (
    FormatCoverage,
    IngestionError,
    IngestionLimits,
    IngestionResult,
    IngestionSummary,
    IngestionWarning,
)
from app.models.repository import (
    RepositoryCommit,
    RepositoryIdentity,
    RepositoryMetadata,
    RepositoryReference,
)
from app.models.source import SourceFile

__all__ = [
    "ConstraintScheme",
    "DependencyDeclaration",
    "DependencyManifestRecord",
    "DependencyProvenance",
    "DependencyRelation",
    "DependencyScope",
    "Ecosystem",
    "ErrorCode",
    "FormatCoverage",
    "IngestionError",
    "IngestionLimits",
    "IngestionResult",
    "IngestionStage",
    "IngestionStatus",
    "IngestionSummary",
    "IngestionWarning",
    "ManifestFormat",
    "ManifestParseStatus",
    "ReferenceType",
    "RepositoryCommit",
    "RepositoryIdentity",
    "RepositoryMetadata",
    "RepositoryReference",
    "ResolvedDependencyEdge",
    "ResolvedPackage",
    "RetrievalStrategy",
    "Severity",
    "SourceFile",
    "SourceKind",
    "SupportLevel",
    "UnsupportedManifestFormat",
    "WarningCode",
    "short_sha",
    "stable_id",
]
