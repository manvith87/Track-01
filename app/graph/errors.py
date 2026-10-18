"""Graph-specific errors for BlastRadius Phase 2.

Every exception carries a stable machine-readable code, a pipeline stage and an
HTTP status so that the API layer can translate failures into the documented
error envelope without guessing.  Graph failures never cause the Phase 1
ingestion endpoint to fail: graph persistence is opt-in and degraded gracefully.
"""

from __future__ import annotations

from typing import Any

from app.core.errors import BlastRadiusError
from app.models.common import ErrorCode, IngestionStage


class GraphError(BlastRadiusError):
    """Base class for every expected graph storage failure."""

    code: ErrorCode = ErrorCode.INTERNAL_ERROR
    http_status: int = 502
    stage: IngestionStage = IngestionStage.UNKNOWN
    retryable: bool = False
    default_message: str = "Graph storage error"


class GraphUnavailableError(GraphError):
    """FalkorDB cannot be reached (connection refused / DNS failure)."""

    code = ErrorCode.NETWORK_FAILURE
    http_status = 502
    retryable = True
    default_message = "FalkorDB graph database is unavailable"


class GraphAuthenticationError(GraphError):
    """The configured graph credentials are rejected."""

    code = ErrorCode.REPOSITORY_ACCESS_DENIED
    http_status = 403
    default_message = "Graph database authentication failed"


class GraphTimeoutError(GraphError):
    """A graph operation exceeded its timeout."""

    code = ErrorCode.INGESTION_TIMEOUT
    http_status = 504
    retryable = True
    default_message = "Graph database operation timed out"


class GraphQueryError(GraphError):
    """A Cypher query failed (syntax, constraint, or server error)."""

    code = ErrorCode.RETRIEVAL_FAILED
    http_status = 502
    retryable = False
    default_message = "Graph query failed"


class GraphRecordNotFoundError(GraphError):
    """A requested graph record (repository / analysis / package) does not exist."""

    code = ErrorCode.REPOSITORY_NOT_FOUND
    http_status = 404
    default_message = "The requested graph record was not found"


__all__ = [
    "GraphAuthenticationError",
    "GraphError",
    "GraphQueryError",
    "GraphRecordNotFoundError",
    "GraphTimeoutError",
    "GraphUnavailableError",
]
