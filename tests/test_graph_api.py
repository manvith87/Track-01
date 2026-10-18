"""Graph API tests.

The graph service is replaced with a stub through FastAPI's dependency
override seam, so these tests exercise the real routes, request models and
error mapping without any database.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

import pytest

from app.api.deps import get_graph_service
from app.api.v1.graph import router as graph_router
from app.core.config import Settings
from app.graph.service import GraphIngestionSummary
from app.main import create_app
from app.models.ingestion import IngestionResult
from tests.support import FAKE_SHA, FakeRetriever, MESSY_REPOSITORY, StubGitHubClient, make_settings


@pytest.fixture
def ingested_result(tmp_path) -> IngestionResult:
    """A real Phase 1 ingestion result (offline, via fakes) to persist in tests."""
    settings = make_settings(temp_root=tmp_path / "work")
    from app.ingestion.service import ingest_repository

    return ingest_repository(
        "https://github.com/example/clean",
        settings=settings,
        retriever=FakeRetriever(MESSY_REPOSITORY),
        api_client=StubGitHubClient(),
    )


class StubGraphService:
    """Deterministic stand-in for GraphService."""

    def __init__(self) -> None:
        self.ingested: list[IngestionResult] = []
        self.statistics = {
            "repositories": 1,
            "files": 3,
            "manifests": 2,
            "declarations": 4,
            "packages": 0,
            "dependency_edges": 0,
            "resolved_packages": 0,
        }
        self.status = {
            "repository_id": "github.com/example/clean",
            "commit_sha": FAKE_SHA,
            "status": "success",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": None,
        }

    def ingest_result_into_graph(self, result: IngestionResult) -> GraphIngestionSummary:
        self.ingested.append(result)
        return GraphIngestionSummary(
            repository_id=result.repository.identity.canonical_id,
            analysis_id="analysis_" + FAKE_SHA,
            status=result.status.value,
            created=5,
            updated=0,
            unchanged=0,
            rejected=0,
            nodes_created=5,
            relationships_created=2,
            records_ingested=5,
            details={"repository": {"created": 1, "updated": 0}},
        )

    def get_repository_graph(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict:
        return {"columns": [], "rows": [], "count": 0, "run_time_ms": 1.0}

    def get_graph_statistics(self, analysis_id: str) -> dict:
        return dict(self.statistics)

    def get_repository_packages(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict:
        return {"columns": [], "rows": [], "count": 0, "run_time_ms": 1.0}

    def get_dependency_edges(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict:
        return {"columns": [], "rows": [], "count": 0, "run_time_ms": 1.0}

    def get_analysis_graph_status(self, analysis_id: str) -> dict:
        return dict(self.status)


def make_client(stub: StubGraphService | None = None) -> TestClient:
    stub = stub or StubGraphService()
    app = create_app(Settings(log_level="ERROR"))
    app.dependency_overrides[get_graph_service] = lambda: stub
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_graph_health_reports_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeClient:
        def __init__(self, settings):  # noqa: ARG001
            pass

        def ping(self) -> bool:
            return True

        def close(self) -> None:
            pass

    monkeypatch.setattr("app.api.v1.graph.GraphClient", FakeClient)
    client = make_client()
    response = client.get("/api/v1/graph/health")
    assert response.status_code == 200
    body = response.json()
    assert body["connected"] is True
    assert body["graph_name"] == "blastradius"


def test_graph_health_reports_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeClient:
        def __init__(self, settings):  # noqa: ARG001
            pass

        def ping(self) -> bool:
            return False

        def close(self) -> None:
            pass

    monkeypatch.setattr("app.api.v1.graph.GraphClient", FakeClient)
    client = make_client()
    response = client.get("/api/v1/graph/health")
    assert response.status_code == 200
    body = response.json()
    assert body["connected"] is False


# ---------------------------------------------------------------------------
# Persist an ingestion result
# ---------------------------------------------------------------------------

def test_ingest_result_endpoint_persists_and_returns_summary(ingested_result) -> None:
    stub = StubGraphService()
    client = make_client(stub)

    payload = {"result": ingested_result.model_dump(mode="python")}
    response = client.post("/api/v1/analyses/analysis_x/graph", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["repository_id"] == ingested_result.repository.identity.canonical_id
    assert body["analysis_id"] == "analysis_" + FAKE_SHA
    assert body["status"] == ingested_result.status.value
    assert body["created"] == 5
    assert body["updated"] == 0
    assert body["records_ingested"] == 5
    assert len(stub.ingested) == 1
    assert stub.ingested[0] == ingested_result


def test_ingest_result_endpoint_rejects_missing_body() -> None:
    client = make_client()
    response = client.post("/api/v1/analyses/analysis_x/graph", json={"result": None})
    assert response.status_code == 400


def test_ingest_result_endpoint_rejects_invalid_result() -> None:
    client = make_client()
    response = client.post(
        "/api/v1/analyses/analysis_x/graph", json={"result": {"not": "an ingestion result"}}
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Read queries
# ---------------------------------------------------------------------------

def test_graph_statistics_endpoint() -> None:
    stub = StubGraphService()
    client = make_client(stub)
    response = client.get("/api/v1/analyses/analysis_x/graph/statistics")
    assert response.status_code == 200
    body = response.json()
    assert body["repositories"] == 1
    assert body["declarations"] == 4
    assert body["packages"] == 0


def test_graph_endpoint_returns_bounded_rows() -> None:
    stub = StubGraphService()
    client = make_client(stub)
    response = client.get("/api/v1/analyses/analysis_x/graph?skip=0&limit=10")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 0
    assert body["columns"] == []


def test_packages_and_edges_endpoints() -> None:
    stub = StubGraphService()
    client = make_client(stub)

    packages = client.get("/api/v1/analyses/analysis_x/packages")
    assert packages.status_code == 200
    assert packages.json()["count"] == 0

    edges = client.get("/api/v1/analyses/analysis_x/dependency-edges")
    assert edges.status_code == 200
    assert edges.json()["count"] == 0


def test_analysis_status_endpoint() -> None:
    stub = StubGraphService()
    client = make_client(stub)
    response = client.get("/api/v1/analyses/analysis_x/graph/status")
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == "analysis_x"
    assert body["commit_sha"] == FAKE_SHA
    assert body["status"] == "success"


def test_missing_graph_record_returns_404() -> None:
    class MissingService(StubGraphService):
        def get_analysis_graph_status(self, analysis_id: str) -> dict:
            from app.graph.errors import GraphRecordNotFoundError

            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} is not persisted in the graph",
                details={"analysis_id": analysis_id},
            )

    client = make_client(MissingService())
    response = client.get("/api/v1/analyses/unknown/graph/status")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "repository_not_found"


def test_graph_unavailable_returns_502() -> None:
    class FailingService(StubGraphService):
        def get_graph_statistics(self, analysis_id: str) -> dict:
            from app.graph.errors import GraphError

            raise GraphError("database is on fire")

    client = make_client(FailingService())
    response = client.get("/api/v1/analyses/analysis_x/graph/statistics")
    assert response.status_code == 502


def test_graph_endpoint_returns_serialisable_rows_for_real_node_values() -> None:
    """End-to-end check: a real service over canned driver values -> JSON 200.

    The stub-service tests above never exercised whole Node/Edge values, which
    the real ``GET /analyses/{id}/graph`` query returns.  FastAPI cannot
    serialise driver objects, so this pins the serialised row contract.
    """
    from falkordb.edge import Edge
    from falkordb.node import Node

    from app.graph.queries import GET_ANALYSIS, GET_GRAPH
    from app.graph.service import GraphService as RealGraphService
    from tests.support import FakeGraphClient, FakeQueryResult

    package = Node(
        node_id=7,
        labels=["Package"],
        properties={"id": "pkg_1", "normalized_name": "requests", "version": "2.31.0"},
    )
    edge = Edge(package, "DEPENDS_ON", package, edge_id=11, properties={"constraint": ">=2"})

    fake = FakeGraphClient()
    fake.connect()
    fake.canned[GET_ANALYSIS] = FakeQueryResult(
        header=["id", "repository_id", "commit_sha", "status"],
        rows=[["analysis_x", "github.com/example/clean", FAKE_SHA, "success"]],
    )
    fake.canned[GET_GRAPH] = FakeQueryResult(
        header=["r", "f", "m", "d", "p", "rp", "rt", "e", "t"],
        rows=[[None, None, None, None, package, None, None, edge, None]],
    )

    app = create_app(Settings(log_level="ERROR"))
    app.dependency_overrides[get_graph_service] = lambda: RealGraphService(fake)
    client = TestClient(app)

    response = client.get("/api/v1/analyses/analysis_x/graph")
    assert response.status_code == 200
    body = response.json()
    assert body["rows"][0]["p"]["labels"] == ["Package"]
    assert body["rows"][0]["p"]["properties"]["normalized_name"] == "requests"
    assert body["rows"][0]["e"]["type"] == "DEPENDS_ON"
