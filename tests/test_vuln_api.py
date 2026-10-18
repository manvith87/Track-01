"""Vulnerability API endpoint tests (offline; dependency overrides only).

No OSV network and no FalkorDB: the three providers are replaced with
deterministic stubs, plus a real ``OsvService`` wired to the scriptable fake
client for validation-only paths.  The tests verify the HTTP contracts:
404s, the error envelope, cap enforcement and that only version-confirmed
matches are handed to the graph writer.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_graph_service, get_osv_service, get_vulnerability_service
from app.core.config import Settings
from app.graph.errors import GraphRecordNotFoundError
from app.graph.vulnerability import VulnerabilitySyncSummary
from app.main import create_app
from app.osv.models import OsvVulnerability
from app.osv.service import (
    OsvConfirmedMatch,
    OsvPackageItem,
    OsvService,
    OsvSyncReport,
)
from tests.support import FakeOsvClient, make_osv_settings, raw_osv_record

REPO = "github.com/example/demo"
SHA = "a" * 40
ANALYSIS = "analysis_demo"


# ---------------------------------------------------------------------------
# stubs
# ---------------------------------------------------------------------------
class StubGraphService:
    """Deterministic stand-in for GraphService."""

    def __init__(self, packages: list[dict[str, Any]] | None = None, missing: bool = False) -> None:
        self.packages = packages if packages is not None else [
            {
                "id": "pkg_1",
                "original_name": "requests",
                "normalized_name": "requests",
                "ecosystem": "pypi",
                "version": "2.3.0",
            },
            {
                "id": "pkg_2",
                "original_name": "undecided-thing",
                "normalized_name": "undecided-thing",
                "ecosystem": "pypi",
                "version": None,
            },
        ]
        self.missing = missing

    def get_analysis_graph_status(self, analysis_id: str) -> dict[str, Any]:
        if self.missing:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} is not persisted in the graph",
                details={"analysis_id": analysis_id},
            )
        return {
            "analysis_id": analysis_id,
            "repository_id": REPO,
            "commit_sha": SHA,
            "status": "success",
        }

    def get_repository_packages(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
        return {"columns": ["id"], "rows": list(self.packages), "count": len(self.packages), "run_time_ms": 1.0}


class StubVulnerabilityGraphService:
    """Records edge payloads handed over by the API layer."""

    def __init__(self) -> None:
        self.node_payloads: list[list[OsvVulnerability]] = []
        self.edge_payloads: list[list[dict[str, Any]]] = []
        self.scopes: list[tuple[str, str]] = []

    def record_vulnerabilities(
        self,
        vulnerabilities: list[OsvVulnerability],
        edge_matches: list[dict[str, Any]],
        *,
        repository_id: str,
        commit_sha: str,
    ) -> VulnerabilitySyncSummary:
        self.node_payloads.append(list(vulnerabilities))
        self.edge_payloads.append(list(edge_matches))
        self.scopes.append((repository_id, commit_sha))
        return VulnerabilitySyncSummary(
            repository_id=repository_id,
            commit_sha=commit_sha,
            vulnerabilities_created=len(vulnerabilities),
            edges_created=len(edge_matches),
        )

    def get_last_sync(self, analysis_id: str) -> dict[str, Any]:
        return {"vulnerability_edges": len(self.edge_payloads), "last_synced_at": "2026-01-01T00:00:00+00:00"}

    def get_analysis_scope(self, analysis_id: str) -> dict[str, Any]:
        return {"repository_id": REPO, "commit_sha": SHA}


class StubOsvService:
    """OsvService duck-typed double replaying a scripted report."""

    def __init__(self, report: OsvSyncReport, settings: Any | None = None) -> None:
        self.last_items: list[OsvPackageItem] = []
        self._scripted = report
        self._settings = settings or make_osv_settings()

    @property
    def settings(self) -> Any:  # noqa: D401 - matches real service surface
        return self._settings

    def sync(self, items: list[OsvPackageItem]) -> OsvSyncReport:
        self.last_items = list(items)
        return self._scripted


def confirmed_report(*matches: OsvConfirmedMatch) -> OsvSyncReport:
    unique_ids = {m.vulnerability_id for m in matches}
    vulnerabilities = tuple(
        OsvVulnerability.model_validate(
            {
                "id": osv_id,
                "modified": "2024-05-01T00:00:00Z",
                "affected": [],
            }
        )
        for osv_id in sorted(unique_ids)
    )
    return OsvSyncReport(
        items_scanned=1,
        items_with_matches=len(matches),
        items_without_matches=0,
        matches=tuple(matches),
        vulnerabilities=vulnerabilities,
        outcomes=(),
        errors=(),
    )


def confirmed_match(**overrides: Any) -> OsvConfirmedMatch:
    values: dict[str, Any] = {
        "vulnerability_id": "GHSA-v1",
        "ecosystem": "pypi",
        "upstream_ecosystem": "PyPI",
        "package_name": "requests",
        "package_version": "2.3.0",
        "match_type": "version",
        "fixed_versions": ("2.20.0",),
        "ranges_json": "[]",
        "osv_modified": "2024-05-01T00:00:00Z",
    }
    values.update(overrides)
    return OsvConfirmedMatch(**values)


def make_client(
    graph: StubGraphService | None = None,
    osv_service: OsvService | None = None,
    vuln_stub: StubVulnerabilityGraphService | None = None,
) -> TestClient:
    app = create_app(Settings(log_level="ERROR"))
    app.dependency_overrides[get_graph_service] = lambda: graph or StubGraphService()
    app.dependency_overrides[get_osv_service] = lambda: osv_service or StubOsvService(confirmed_report())
    app.dependency_overrides[get_vulnerability_service] = lambda: vuln_stub or StubVulnerabilityGraphService()
    return TestClient(app)


def real_osv_service(client_double: FakeOsvClient | None = None) -> OsvService:
    return OsvService(client_double or FakeOsvClient(), make_osv_settings())


# ---------------------------------------------------------------------------
# live OSV lookup endpoint (read-only)
# ---------------------------------------------------------------------------
def test_lookup_returns_confirmed_results() -> None:
    fake = FakeOsvClient(
        query_responses={
            ("PyPI", "requests", "2.3.0"): {
                "vulns": [raw_osv_record("GHSA-v1", fixed="2.20.0", aliases=["CVE-2023-0001"])]
            },
        }
    )
    client = make_client(osv_service=real_osv_service(fake))
    response = client.get(
        "/api/v1/osv/vulnerabilities",
        params={"name": "requests", "ecosystem": "pypi", "version": "2.3.0"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["match_type"] == "version"
    assert body["confirmed"] is True
    assert body["count"] == 1
    assert body["upstream_ecosystem"] == "PyPI"
    record = body["vulnerabilities"][0]
    assert record["id"] == "GHSA-v1"
    assert record["aliases"] == ["CVE-2023-0001"]
    assert record["affected_packages"] == ["PyPI:requests"]


def test_lookup_without_version_is_marked_unconfirmed() -> None:
    fake = FakeOsvClient(
        query_responses={("PyPI", "requests", None): {"vulns": [raw_osv_record("GHSA-v1")]}},
    )
    client = make_client(osv_service=real_osv_service(fake))
    response = client.get("/api/v1/osv/vulnerabilities", params={"name": "requests"})
    assert response.status_code == 200
    body = response.json()
    assert body["match_type"] == "name"
    assert body["confirmed"] is False
    assert body["version"] is None


def test_lookup_rejects_unknown_ecosystem_with_error_envelope() -> None:
    # Use the REAL service: OsvService.upstream_ecosystem raises before any network call.
    app = create_app(Settings(log_level="ERROR"))
    app.dependency_overrides[get_osv_service] = lambda: real_osv_service()
    client = TestClient(app)
    response = client.get("/api/v1/osv/vulnerabilities", params={"name": "left-pad", "ecosystem": "npm"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_input"


def test_lookup_upstream_failure_maps_to_502_envelope() -> None:
    from app.osv.errors import OsvUnavailableError

    class UnreachableOsv:
        settings = make_osv_settings()

        def lookup(self, ecosystem: str, name: str, version: str | None) -> Any:
            raise OsvUnavailableError("api.osv.dev unreachable", details={"attempts": 3})

    app = create_app(Settings(log_level="ERROR"))
    app.dependency_overrides[get_osv_service] = lambda: UnreachableOsv()
    client = TestClient(app)
    response = client.get(
        "/api/v1/osv/vulnerabilities",
        params={"name": "requests", "version": "2.3.0"},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "network_failure"
    assert body["error"]["retryable"] is True


# ---------------------------------------------------------------------------
# targeted ingestion endpoint
# ---------------------------------------------------------------------------
def test_ingest_scans_only_resolved_packages_and_scopes_edges() -> None:
    report = confirmed_report(confirmed_match())
    osv_stub = StubOsvService(report)
    vuln_stub = StubVulnerabilityGraphService()
    graph = StubGraphService()
    client = make_client(graph, osv_stub, vuln_stub)

    response = client.post(f"/api/v1/analyses/{ANALYSIS}/vulnerabilities")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["packages_scanned"] == 1  # unresolved package excluded
    assert body["vulnerabilities_found"] == 1
    assert body["vulnerabilities_created"] == 1
    assert body["edges_created"] == 1
    assert body["last_synced_at"] == "2026-01-01T00:00:00+00:00"

    # Only the resolved package reached the OSV layer.
    assert [item.package_name for item in osv_stub.last_items] == ["requests"]
    assert osv_stub.last_items[0].version == "2.3.0"
    assert osv_stub.last_items[0].original_name == "requests"

    # Edge payload carries the scope and evidence for the graph writer.
    payload = vuln_stub.edge_payloads[0][0]
    assert payload["repository_id"] == REPO
    assert payload["commit_sha"] == SHA
    assert payload["vulnerability_id"] == "GHSA-v1"
    assert payload["package_version"] == "2.3.0"
    assert payload["fixed_versions"] == ["2.20.0"]
    assert vuln_stub.scopes == [(REPO, SHA)]


def test_ingest_report_errors_surface_in_response() -> None:
    from app.osv.service import OsvItemOutcome, OsvSyncError

    report = OsvSyncReport(
        items_scanned=1,
        items_with_matches=0,
        items_without_matches=1,
        matches=(),
        vulnerabilities=(),
        outcomes=(
            OsvItemOutcome(
                ecosystem="pypi", package_name="requests", version="2.3.0",
                status="no_matches",
            ),
        ),
        errors=(
            OsvSyncError(kind="name_only", message="unconfirmed name match not ingested"),
        ),
    )
    client = make_client(osv_service=StubOsvService(report))
    response = client.post(f"/api/v1/analyses/{ANALYSIS}/vulnerabilities")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed_with_errors"
    assert body["errors"][0]["kind"] == "name_only"
    assert body["edges_created"] == 0


def test_ingest_missing_analysis_returns_404_envelope() -> None:
    client = make_client(graph=StubGraphService(missing=True))
    response = client.post("/api/v1/analyses/unknown/vulnerabilities")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "repository_not_found"


def test_ingest_enforces_package_cap_with_invalid_input() -> None:
    too_many = [
        {
            "id": f"pkg_{i}",
            "original_name": f"pkg{i}",
            "normalized_name": f"pkg{i}",
            "ecosystem": "pypi",
            "version": "1.0.0",
        }
        for i in range(2)
    ]
    osv_stub = StubOsvService(confirmed_report(), settings=make_osv_settings(max_packages_per_ingest=1))
    client = make_client(StubGraphService(packages=too_many), osv_stub)
    response = client.post(f"/api/v1/analyses/{ANALYSIS}/vulnerabilities")
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "invalid_input"
    assert "BLASTRADIUS_OSV_MAX_PACKAGES_PER_INGEST" in body["error"]["message"]


def test_ingest_total_upstream_failure_maps_to_502() -> None:
    from app.osv.errors import OsvUnavailableError

    class BrokenOsv(StubOsvService):
        def sync(self, items: list[OsvPackageItem]) -> OsvSyncReport:
            raise OsvUnavailableError("api.osv.dev unreachable", details={"attempts": 3})

    client = make_client(osv_service=BrokenOsv(confirmed_report()))
    response = client.post(f"/api/v1/analyses/{ANALYSIS}/vulnerabilities")
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "network_failure"
    assert body["error"]["retryable"] is True


# ---------------------------------------------------------------------------
# graph-backed reads
# ---------------------------------------------------------------------------
def make_read_stub(rows: list[dict[str, Any]], paths: list[dict[str, Any]] | None = None) -> StubVulnerabilityGraphService:
    class ReadingStub(StubVulnerabilityGraphService):
        def get_analysis_vulnerabilities(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
            return {"columns": ["vulnerability_id"], "rows": rows, "count": len(rows), "run_time_ms": 1.0}

        def get_impact_paths(self, analysis_id: str, *, vulnerability_id: str | None = None, depth: int = 3, skip: int = 0, limit: int = 200) -> dict[str, Any]:
            self.requested_depth = depth
            self.requested_vuln_id = vulnerability_id
            return {"columns": ["vulnerability_id"], "rows": paths or [], "count": len(paths or []), "run_time_ms": 1.0}

        def get_vulnerability(self, vulnerability_id: str) -> dict[str, Any]:
            if vulnerability_id == "GHSA-canned":
                return {
                    "id": "GHSA-canned",
                    "summary": "bad thing",
                    "severities": ["CVSS_V3 CVSS:3.1/AV:N"],
                    "references": ["WEB https://example.test/x"],
                    "aliases": ["CVE-2024-1"],
                    "affected_packages": ["PyPI:requests"],
                }
            raise GraphRecordNotFoundError("not stored", details={"vulnerability_id": vulnerability_id})

        def get_vulnerability_components(self, vulnerability_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
            return {
                "columns": ["package_id"],
                "rows": [
                    {
                        "package_id": "pkg_1",
                        "package_name": "requests",
                        "package_version": "2.3.0",
                        "ecosystem": "pypi",
                        "repository_id": REPO,
                        "commit_sha": SHA,
                        "match_type": "version",
                        "fixed_versions": ["2.20.0"],
                        "last_synced_at": "2026-01-01T00:00:00+00:00",
                    }
                ],
                "count": 1,
                "run_time_ms": 1.0,
            }

    return ReadingStub()


def test_list_analysis_vulnerabilities_maps_rows() -> None:
    stub = make_read_stub(
        [
            {
                "vulnerability_id": "GHSA-v1",
                "summary": "bad",
                "package_id": "pkg_1",
                "package_name": "requests",
                "package_version": "2.3.0",
                "ecosystem": "pypi",
                "match_type": "version",
                "fixed_versions": ["2.20.0"],
                "aliases": ["CVE-2024-1"],
                "severities": ["CVSS_V3 CVSS:3.1/AV:N"],
                "published": "2024-01-01T00:00:00Z",
                "modified": "2024-02-01T00:00:00Z",
                "last_synced_at": "2026-01-01T00:00:00+00:00",
            }
        ]
    )
    client = make_client(vuln_stub=stub)
    response = client.get(f"/api/v1/analyses/{ANALYSIS}/vulnerabilities")
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == ANALYSIS
    assert body["repository_id"] == REPO
    assert body["count"] == 1
    item = body["items"][0]
    assert item["vulnerability_id"] == "GHSA-v1"
    assert item["fixed_versions"] == ["2.20.0"]
    assert item["severities"] == [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]
    assert item["last_synced_at"] == "2026-01-01T00:00:00+00:00"


def test_vulnerability_blast_radius_maps_paths() -> None:
    stub = make_read_stub(
        rows=[],
        paths=[
            {
                "vulnerability_id": "GHSA-v1",
                "vulnerability_summary": "bad",
                "affected_package_id": "pkg_1",
                "affected_package_name": "requests",
                "affected_package_version": "2.3.0",
                "downstream_chain": ["requests", "web-app"],
                "hop_count": 1,
                "match_type": "version",
                "fixed_versions": ["2.20.0"],
            },
            {
                "vulnerability_id": "GHSA-v1",
                "affected_package_id": "pkg_1",
                "affected_package_name": "requests",
                "affected_package_version": "2.3.0",
                "downstream_chain": ["requests"],
                "hop_count": 0,
                "fixed_versions": [],
            },
        ],
    )
    client = make_client(vuln_stub=stub)
    response = client.get(
        f"/api/v1/analyses/{ANALYSIS}/vulnerabilities/blast-radius",
        params={"depth": 2},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["depth"] == 2
    assert body["count"] == 2
    assert body["paths"][0]["downstream_chain"] == ["requests", "web-app"]
    assert body["paths"][0]["hop_count"] == 1
    # Explicitly absent stored match_type maps to None, not an invented value.
    assert body["paths"][1]["match_type"] is None
    assert body["paths"][0]["match_type"] == "version"


def test_vulnerability_detail_includes_components() -> None:
    client = make_client(vuln_stub=make_read_stub([]))
    response = client.get("/api/v1/vulnerabilities/GHSA-canned")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "GHSA-canned"
    assert body["severities"] == [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]
    assert body["references"] == [{"type": "WEB", "url": "https://example.test/x"}]
    assert body["affected_component_count"] == 1
    assert body["affected_components"][0]["repository_id"] == REPO


def test_vulnerability_detail_missing_returns_404() -> None:
    client = make_client(vuln_stub=make_read_stub([]))
    response = client.get("/api/v1/vulnerabilities/GHSA-nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "repository_not_found"
