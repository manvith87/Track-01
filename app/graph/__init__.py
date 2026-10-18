"""Graph storage package for BlastRadius Phase 2.

Provides a FalkorDB-backed knowledge graph that persists Phase 1 ingestion
results.  The graph is optional: the Phase 1 ingestion endpoint works
independently of FalkorDB.
"""

from app.graph.config import GraphSettings, get_graph_settings, reset_graph_settings_cache
from app.graph.client import GraphClient
from app.graph.errors import (
    GraphAuthenticationError,
    GraphError,
    GraphQueryError,
    GraphRecordNotFoundError,
    GraphTimeoutError,
    GraphUnavailableError,
)
from app.graph.service import GraphIngestionSummary, GraphService

__all__ = [
    "GraphAuthenticationError",
    "GraphClient",
    "GraphError",
    "GraphIngestionSummary",
    "GraphQueryError",
    "GraphRecordNotFoundError",
    "GraphSettings",
    "GraphService",
    "GraphTimeoutError",
    "GraphUnavailableError",
    "get_graph_settings",
    "reset_graph_settings_cache",
]
