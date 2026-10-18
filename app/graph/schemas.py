"""Request and response models for the graph API (Phase 2).

These models describe graph queries and summaries.  They reuse the Phase 1
domain identifiers (``repository_id`` / ``analysis_id`` / ``package_id``) so
that graph clients can be scoped to the exact analysis that produced them.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GraphHealth(BaseModel):
    """Graph connectivity status."""

    model_config = ConfigDict(extra="forbid")

    connected: bool = Field(description="Whether a round-trip to FalkorDB succeeded.")
    graph_name: str = Field(description="Configured graph name.")
    connection: str = Field(description="Host:port/database label (credentials redacted).")
    error: str | None = Field(default=None, description="Failure message when not connected.")


class GraphIngestRequest(BaseModel):
    """Request to persist an ingestion result into the graph."""

    model_config = ConfigDict(extra="forbid")

    #: The Phase 1 IngestionResult, serialised as a JSON object.
    result: dict[str, Any] | None = Field(
        default=None, description="Serialised IngestionResult to persist."
    )


class GraphIngestResponse(BaseModel):
    """Outcome of persisting an ingestion result into the graph."""

    model_config = ConfigDict(extra="forbid")

    repository_id: str
    analysis_id: str
    status: str
    created: int = Field(ge=0)
    updated: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    rejected: int = Field(ge=0)
    nodes_created: int = Field(ge=0)
    relationships_created: int = Field(ge=0)
    records_ingested: int = Field(ge=0)
    details: dict[str, Any] = Field(default_factory=dict)


class GraphRecord(BaseModel):
    """A single row returned by a graph query."""

    model_config = ConfigDict(extra="forbid")

    columns: list[str]
    rows: list[dict[str, Any]]
    count: int
    run_time_ms: float | None = None


class GraphStatistics(BaseModel):
    """Actual counts of graph records for one analysis."""

    model_config = ConfigDict(extra="forbid")

    repositories: int = Field(ge=0)
    files: int = Field(ge=0)
    manifests: int = Field(ge=0)
    declarations: int = Field(ge=0)
    packages: int = Field(ge=0)
    dependency_edges: int = Field(ge=0)
    resolved_packages: int = Field(ge=0)
    #: Phase 3: AFFECTED_BY edges reachable from this analysis's packages.
    vulnerability_edges: int = Field(default=0, ge=0)


class GraphAnalysisStatus(BaseModel):
    """Status of a graph-persisted analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    repository_id: str
    commit_sha: str
    status: str
    created_at: str | None = None
    updated_at: str | None = None


class GraphNeighborhood(BaseModel):
    """Bounded DEPENDS_ON neighbourhood of a package."""

    model_config = ConfigDict(extra="forbid")

    package_id: str
    depth: int
    edges: list[dict[str, Any]] = Field(default_factory=list)


__all__ = [
    "GraphAnalysisStatus",
    "GraphHealth",
    "GraphIngestRequest",
    "GraphIngestResponse",
    "GraphNeighborhood",
    "GraphRecord",
    "GraphStatistics",
]
