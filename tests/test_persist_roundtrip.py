"""API round-trip tests for the ingest -> graph-persistence sequence.

The frontend contract is that ``POST /repositories/ingest`` returns a payload
that ``POST /analyses/{analysis_id}/graph`` accepts unchanged:

1. the ingest response carries the graph ``analysis_id`` that persisting the
   result will use (derived by the same function the graph layer uses);
2. the public ``RepositoryIngestResponse`` shape is accepted by the graph
   persistence endpoint and converted losslessly back to the domain
   ``IngestionResult`` it was projected from.

Both services are stubbed through FastAPI dependency overrides, so these tests
pin the wire contract without any network, GitHub or FalkorDB access.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

import pytest

from app.api.deps import get_app_settings, get_graph_service, get_ingestion_service
from app.api.v1.schemas import RepositoryIngestResponse
from app.graph.service import GraphIngestionSummary, GraphService
from app.main import create_app
from app.models.ingestion import IngestionResult
from tests.support import make_settings

INGEST_PATH = "/api/v1/repositories/ingest"


class StubGraphService:
    """Captures the domain result the graph endpoint reconstructs."""

    def __init__(self) -> None:
        self.ingested: list[IngestionResult] = []

    def ingest_result_into_graph(self, result: IngestionResult) -> GraphIngestionSummary:
        self.ingested.append(result)
        return GraphIngestionSummary(
            repository_id=result.repository.identity.canonical_id,
            analysis_id=GraphService.analysis_id(
                result.repository.identity.canonical_id,
                result.reference.resolved_commit_sha or "",
            ),
            status=result.status.value,
            created=7,
            records_ingested=7,
        )


@pytest.fixture
def client_and_graph(canned_ingestion_result: IngestionResult):
    """TestClient with stubbed ingestion and graph services."""
    graph = StubGraphService()

    def service(url: str, ref: str | None, *, settings: Any) -> IngestionResult:
        return canned_ingestion_result

    settings = make_settings(log_level="ERROR")
    app = create_app(settings)
    app.dependency_overrides[get_ingestion_service] = lambda: service
    app.dependency_overrides[get_app_settings] = lambda: settings
    app.dependency_overrides[get_graph_service] = lambda: graph
    with TestClient(app) as test_client:
        yield test_client, graph


def _ingest(client: TestClient) -> dict[str, Any]:
    response = client.post(INGEST_PATH, json={"repository_url": "https://github.com/example/clean"})
    assert response.status_code == 200
    return response.json()


# ---------------------------------------------------------------------------
# analysis_id exposure
# ---------------------------------------------------------------------------

def test_ingest_response_exposes_the_analysis_id_the_graph_will_use(client_and_graph) -> None:
    client, _graph = client_and_graph
    body = _ingest(client)

    expected = GraphService.analysis_id(body["summary"]["repository_id"], body["summary"]["commit_sha"])
    assert body["analysis_id"] == expected
    assert body["analysis_id"].startswith("analysis_")


def test_analysis_id_is_none_when_the_result_cannot_be_persisted(canned_ingestion_result) -> None:
    settings = make_settings(log_level="ERROR")

    without_repository = canned_ingestion_result.model_copy(update={"repository": None})
    assert RepositoryIngestResponse.from_result(without_repository, settings).analysis_id is None

    without_commit = canned_ingestion_result.model_copy(
        update={"reference": canned_ingestion_result.reference.model_copy(update={"resolved_commit_sha": None})}
    )
    assert RepositoryIngestResponse.from_result(without_commit, settings).analysis_id is None


# ---------------------------------------------------------------------------
# Payload round trip
# ---------------------------------------------------------------------------

def test_persist_accepts_the_ingest_response_unchanged(client_and_graph, canned_ingestion_result) -> None:
    client, graph = client_and_graph
    body = _ingest(client)

    response = client.post(
        f"/api/v1/analyses/{body['analysis_id']}/graph",
        json={"result": body},
    )

    assert response.status_code == 200, response.text
    assert response.json()["analysis_id"] == body["analysis_id"]
    assert len(graph.ingested) == 1
    # The untruncated canned result survives the projection round trip exactly.
    assert graph.ingested[0] == canned_ingestion_result


def test_persist_accepts_the_domain_payload_too(client_and_graph, canned_ingestion_result) -> None:
    client, graph = client_and_graph

    response = client.post(
        "/api/v1/analyses/analysis_any/graph",
        json={"result": canned_ingestion_result.model_dump(mode="python")},
    )

    assert response.status_code == 200, response.text
    assert len(graph.ingested) == 1
    assert graph.ingested[0] == canned_ingestion_result


def test_persist_still_rejects_arbitrary_json(client_and_graph) -> None:
    client, _graph = client_and_graph
    response = client.post("/api/v1/analyses/analysis_x/graph", json={"result": {"not": "ingestion"}})
    assert response.status_code == 400


def test_response_round_trip_preserves_source_file_truncation(canned_ingestion_result) -> None:
    settings = make_settings(log_level="ERROR")
    truncated = canned_ingestion_result.model_copy(update={"source_files_truncated": True})

    response = RepositoryIngestResponse.from_result(truncated, settings)
    assert response.truncated.source_files is True

    restored = response.to_ingestion_result()
    assert restored.source_files_truncated is True
    assert restored == truncated
