"""Graph API endpoints for BlastRadius Phase 2.

Graph persistence is opt-in and independent of Phase 1 ingestion.  When
FalkorDB is unavailable, graph endpoints return an explicit error (or
``connected: false`` for the health probe) instead of falling back to fake or
in-memory data.

Routes are mounted under ``/api/v1`` by the version-one router:

* ``GET /api/v1/graph/health`` - FalkorDB connectivity probe
* ``POST /api/v1/analyses/{analysis_id}/graph`` - persist an ingestion result
* ``GET /api/v1/analyses/{analysis_id}/graph`` - bounded graph for one analysis
* ``GET /api/v1/analyses/{analysis_id}/graph/statistics`` - graph statistics
* ``GET /api/v1/analyses/{analysis_id}/packages`` - packages and resolved versions
* ``GET /api/v1/analyses/{analysis_id}/dependency-edges`` - dependency edges
* ``GET /api/v1/analyses/{analysis_id}/graph/status`` - analysis status
* ``GET /api/v1/packages/{package_id}/neighborhood`` - bounded package neighbourhood
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from app.api.deps import get_graph_service, get_graph_settings
from app.api.v1.schemas import coerce_ingestion_result
from app.core.config import Settings
from app.core.logging import get_logger
from app.graph.client import GraphClient
from app.graph.errors import GraphError, GraphRecordNotFoundError
from app.graph.schemas import (
    GraphAnalysisStatus,
    GraphHealth,
    GraphIngestRequest,
    GraphIngestResponse,
    GraphNeighborhood,
    GraphRecord,
    GraphStatistics,
)
from app.graph.service import GraphService

_log = get_logger("api.graph")

router = APIRouter(tags=["graph"])


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get(
    "/graph/health",
    response_model=GraphHealth,
    summary="Report FalkorDB connectivity",
)
def graph_health(
    settings: Settings = Depends(get_graph_settings),
) -> GraphHealth:
    """Return whether the configured FalkorDB graph is reachable.

    This probe never raises: when the graph is unavailable it reports
    ``connected: false`` so that callers can degrade gracefully.
    """
    client = GraphClient(settings)
    try:
        connected = client.ping()
    except GraphError as exc:
        connected = False
        message = exc.message
    except Exception as exc:  # noqa: BLE001 - never let a probe crash the request
        connected = False
        message = f"{type(exc).__name__}: {exc}"
    else:
        message = None
    finally:
        client.close()
    return GraphHealth(
        connected=connected,
        graph_name=settings.graph_name,
        connection=settings.connection_label,
        error=message,
    )


# ---------------------------------------------------------------------------
# Persist an ingestion result
# ---------------------------------------------------------------------------

@router.post(
    "/analyses/{analysis_id}/graph",
    response_model=GraphIngestResponse,
    summary="Persist a Phase 1 ingestion result into the graph",
    responses={
        400: {"description": "Invalid ingestion result"},
        404: {"description": "Analysis record not found"},
        502: {"description": "Graph database unavailable"},
        504: {"description": "Graph operation timed out"},
    },
)
def ingest_result_into_graph_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier (stable id)."),
    payload: GraphIngestRequest | None = None,
    service: GraphService = Depends(get_graph_service),
) -> GraphIngestResponse:
    """Persist a Phase 1 :class:`~app.models.ingestion.IngestionResult` into FalkorDB.

    The request body must contain the serialised ingestion result under the
    ``result`` key: either the domain ``IngestionResult`` shape or the public
    ``RepositoryIngestResponse`` shape returned by
    ``POST /api/v1/repositories/ingest``, which converts losslessly.  The
    write is idempotent: re-ingesting the same repository at the same commit
    upserts instead of duplicating nodes or relationships.
    """
    if payload is None or payload.result is None:
        raise HTTPException(status_code=400, detail="Request body must include a 'result' object")

    try:
        result = coerce_ingestion_result(payload.result)
    except Exception as exc:  # noqa: BLE001 - invalid payload is a client error
        raise HTTPException(status_code=400, detail=f"Invalid ingestion result: {exc}") from exc

    try:
        summary = service.ingest_result_into_graph(result)
    except GraphError:
        raise
    except Exception as exc:  # noqa: BLE001 - translate unexpected failures into the envelope
        _log.exception("graph ingestion failed analysis_id=%s", analysis_id)
        raise GraphError(
            f"Graph ingestion failed: {exc}",
            details={"analysis_id": analysis_id, "exception": type(exc).__name__},
        ) from exc

    return GraphIngestResponse(
        repository_id=summary.repository_id,
        analysis_id=summary.analysis_id,
        status=summary.status,
        created=summary.created,
        updated=summary.updated,
        unchanged=summary.unchanged,
        rejected=summary.rejected,
        nodes_created=summary.nodes_created,
        relationships_created=summary.relationships_created,
        records_ingested=summary.records_ingested,
        details=summary.details,
    )


# ---------------------------------------------------------------------------
# Read queries
# ---------------------------------------------------------------------------

@router.get(
    "/analyses/{analysis_id}/graph",
    response_model=GraphRecord,
    summary="Return the bounded graph for one analysis",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def get_repository_graph_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    skip: int = Query(default=0, ge=0, description="Number of records to skip."),
    limit: int = Query(default=200, ge=1, le=1000, description="Maximum records to return."),
    service: GraphService = Depends(get_graph_service),
) -> GraphRecord:
    """Return a bounded graph representation of the selected repository analysis."""
    try:
        data = service.get_repository_graph(analysis_id, skip=skip, limit=limit)
    except GraphRecordNotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    return GraphRecord(columns=data["columns"], rows=data["rows"], count=data["count"], run_time_ms=data["run_time_ms"])


@router.get(
    "/analyses/{analysis_id}/graph/statistics",
    response_model=GraphStatistics,
    summary="Return graph statistics for one analysis",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def get_graph_statistics_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    service: GraphService = Depends(get_graph_service),
) -> GraphStatistics:
    """Return actual counts of nodes and relationships for one analysis."""
    try:
        stats = service.get_graph_statistics(analysis_id)
    except GraphRecordNotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    return GraphStatistics(**stats)


@router.get(
    "/analyses/{analysis_id}/packages",
    response_model=GraphRecord,
    summary="Return package declarations and resolved versions",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def get_repository_packages_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    skip: int = Query(default=0, ge=0, description="Number of records to skip."),
    limit: int = Query(default=200, ge=1, le=1000, description="Maximum records to return."),
    service: GraphService = Depends(get_graph_service),
) -> GraphRecord:
    """Return actual package declarations and any known resolved versions."""
    try:
        data = service.get_repository_packages(analysis_id, skip=skip, limit=limit)
    except GraphRecordNotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    return GraphRecord(columns=data["columns"], rows=data["rows"], count=data["count"], run_time_ms=data["run_time_ms"])


@router.get(
    "/analyses/{analysis_id}/dependency-edges",
    response_model=GraphRecord,
    summary="Return dependency edges established by the ingestion data",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def get_dependency_edges_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    skip: int = Query(default=0, ge=0, description="Number of records to skip."),
    limit: int = Query(default=200, ge=1, le=1000, description="Maximum records to return."),
    service: GraphService = Depends(get_graph_service),
) -> GraphRecord:
    """Return only dependency edges established by the supplied ingestion data."""
    try:
        data = service.get_dependency_edges(analysis_id, skip=skip, limit=limit)
    except GraphRecordNotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    return GraphRecord(columns=data["columns"], rows=data["rows"], count=data["count"], run_time_ms=data["run_time_ms"])


@router.get(
    "/analyses/{analysis_id}/graph/status",
    response_model=GraphAnalysisStatus,
    summary="Return graph ingestion status for an analysis",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def get_analysis_graph_status_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    service: GraphService = Depends(get_graph_service),
) -> GraphAnalysisStatus:
    """Return graph ingestion status and incomplete-data indicators."""
    status = service.get_analysis_graph_status(analysis_id)
    return GraphAnalysisStatus(
        analysis_id=analysis_id,
        repository_id=status.get("repository_id", ""),
        commit_sha=status.get("commit_sha", ""),
        status=status.get("status", ""),
        created_at=status.get("created_at"),
        updated_at=status.get("updated_at"),
    )


#: Neighbourhood query for a package (exposed for completeness; bounded depth).
@router.get(
    "/packages/{package_id}/neighborhood",
    response_model=GraphNeighborhood,
    summary="Return a bounded DEPENDS_ON neighbourhood of a package",
    responses={404: {"description": "Package not found in the graph"}},
)
def get_dependency_neighborhood_endpoint(
    package_id: str = Path(..., description="Stable package identifier."),
    depth: int = Query(default=1, ge=1, le=5, description="Traversal depth (max 5)."),
    service: GraphService = Depends(get_graph_service),
) -> GraphNeighborhood:
    """Return a bounded neighbourhood of the requested package."""
    data = service.get_dependency_neighborhood(package_id, depth=depth)
    return GraphNeighborhood(
        package_id=package_id,
        depth=depth,
        edges=[row.get("edges", []) for row in data["rows"] if isinstance(row.get("edges"), list)],
    )


__all__ = ["router"]
