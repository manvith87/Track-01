"""Offline MCP server tests (no network, no FalkorDB).

Uses ``FakeGraphClient`` and ``FakeOsvClient`` injected through the
``_graph_services`` / ``_osv_service`` seams exposed by ``app.mcp.tools``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from mcp import MCPError

from app.graph.config import GraphSettings
from app.graph.errors import GraphRecordNotFoundError
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.mcp.tools import (
    analysis_blast_radius,
    analysis_dependency_edges,
    analysis_packages,
    analysis_statistics,
    analysis_status,
    analysis_vulnerabilities,
    graph_health,
    osv_lookup,
    package_neighborhood,
    vulnerability_components,
    vulnerability_get,
)
from app.osv.service import OsvService
from tests.support import FakeGraphClient, FakeOsvClient, FakeQueryResult, make_osv_settings, raw_osv_record


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_graph_services(client: FakeGraphClient) -> tuple[GraphService, VulnerabilityGraphService]:
    graph_service = GraphService(client)
    vuln_service = VulnerabilityGraphService(client, graph_service)
    return graph_service, vuln_service


def _make_osv_service(client: FakeOsvClient) -> OsvService:
    return OsvService(client, make_osv_settings())


def _patch(monkeypatch: pytest.MonkeyPatch, client: FakeGraphClient, osv_client: FakeOsvClient) -> None:
    monkeypatch.setattr(
        "app.mcp.tools._graph_services",
        lambda: _make_graph_services(client),
    )
    monkeypatch.setattr(
        "app.mcp.tools.get_osv_service",
        lambda: _make_osv_service(osv_client),
    )


def _analysis_canned(client: FakeGraphClient) -> None:
    """Canne GET_ANALYSIS so that get_analysis_graph_status succeeds."""
    from app.graph.queries import GET_ANALYSIS
    client.canned[GET_ANALYSIS] = FakeQueryResult(
        ["id", "repository_id", "commit_sha", "status"],
        [["analysis_1", "github.com/example/demo", "a" * 40, "success"]],
    )


def _run(coro: Any) -> Any:
    """Run an async tool function in a sync test."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# graph.health
# ---------------------------------------------------------------------------

def test_graph_health_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGraphClient(GraphSettings(graph_name="blastradius_health_test"))
    client.connect()
    _patch(monkeypatch, client, FakeOsvClient())
    result = _run(graph_health())
    assert result["connected"] is True
    assert result["error"] is None
    # The probe reports the graph of the injected services, not process env.
    assert result["graph_name"] == "blastradius_health_test"


def test_graph_health_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    # A connected client whose ping fails must still report connected: false.
    client = FakeGraphClient()
    client.connect()
    monkeypatch.setattr(client, "ping", lambda: False)
    _patch(monkeypatch, client, FakeOsvClient())
    result = _run(graph_health())
    assert result["connected"] is False
    assert result["error"] is None


# ---------------------------------------------------------------------------
# analysis.status
# ---------------------------------------------------------------------------

def test_analysis_status_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGraphClient()
    client.connect()
    _analysis_canned(client)
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(analysis_status("analysis_1"))
    assert result["id"] == "analysis_1"
    assert result["status"] == "success"


def test_analysis_status_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGraphClient()
    client.connect()
    from app.graph.queries import GET_ANALYSIS
    client.canned[GET_ANALYSIS] = FakeQueryResult(["id"], [])
    _patch(monkeypatch, client, FakeOsvClient())

    with pytest.raises(MCPError):
        _run(analysis_status("analysis_missing"))


def test_analysis_status_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGraphClient()
    client.connect()
    _patch(monkeypatch, client, FakeOsvClient())

    with pytest.raises(MCPError):
        _run(analysis_status(""))


# ---------------------------------------------------------------------------
# analysis.statistics
# ---------------------------------------------------------------------------

def test_analysis_statistics_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import GET_STATISTICS

    client = FakeGraphClient()
    client.connect()
    _analysis_canned(client)
    client.canned[GET_STATISTICS] = FakeQueryResult(
        ["repositories", "packages", "dependency_edges", "vulnerability_edges"],
        [[1, 2, 1, 0]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(analysis_statistics("analysis_1"))
    assert result["repositories"] == 1
    assert result["packages"] == 2
    assert result["dependency_edges"] == 1
    assert result["vulnerability_edges"] == 0


# ---------------------------------------------------------------------------
# analysis.packages
# ---------------------------------------------------------------------------

def test_analysis_packages_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import GET_PACKAGES

    client = FakeGraphClient()
    client.connect()
    _analysis_canned(client)
    client.canned[GET_PACKAGES] = FakeQueryResult(
        ["package_id", "package_name", "package_version", "ecosystem"],
        [["pkg_1", "requests", "2.3.0", "pypi"]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(analysis_packages("analysis_1"))
    assert result["count"] == 1
    assert result["rows"][0]["package_name"] == "requests"


def test_analysis_packages_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGraphClient()
    client.connect()
    _patch(monkeypatch, client, FakeOsvClient())

    with pytest.raises(MCPError):
        _run(analysis_packages("analysis_1", limit=9999))


# ---------------------------------------------------------------------------
# analysis.dependency_edges
# ---------------------------------------------------------------------------

def test_analysis_dependency_edges_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import GET_EDGES

    client = FakeGraphClient()
    client.connect()
    _analysis_canned(client)
    client.canned[GET_EDGES] = FakeQueryResult(
        ["from_name", "to_name", "to_version"],
        [["requests", "urllib3", "2.2.1"]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(analysis_dependency_edges("analysis_1"))
    assert result["count"] == 1


# ---------------------------------------------------------------------------
# package.neighborhood
# ---------------------------------------------------------------------------

def test_package_neighborhood_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import neighborhood_template

    client = FakeGraphClient()
    client.connect()
    client.canned[neighborhood_template(1)] = FakeQueryResult(
        ["package_id", "edges"],
        [["pkg_1", [["requests", "urllib3"]]]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(package_neighborhood("pkg_1"))
    assert result["count"] == 1
    assert result["rows"][0]["package_id"] == "pkg_1"


def test_package_neighborhood_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGraphClient()
    client.connect()
    _patch(monkeypatch, client, FakeOsvClient())

    with pytest.raises(MCPError):
        _run(package_neighborhood("pkg_1", depth=9))


# ---------------------------------------------------------------------------
# analysis.vulnerabilities
# ---------------------------------------------------------------------------

def test_analysis_vulnerabilities_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import GET_VULNERABILITIES

    client = FakeGraphClient()
    client.connect()
    _analysis_canned(client)
    client.canned[GET_VULNERABILITIES] = FakeQueryResult(
        ["vulnerability_id", "package_name"],
        [["GHSA-v1", "requests"]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(analysis_vulnerabilities("analysis_1"))
    assert result["count"] == 1


# ---------------------------------------------------------------------------
# analysis.blast_radius
# ---------------------------------------------------------------------------

def test_analysis_blast_radius_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import impact_paths_template

    client = FakeGraphClient()
    client.connect()
    _analysis_canned(client)
    template = impact_paths_template(2)
    client.canned[template] = FakeQueryResult(
        ["vulnerability_id", "affected_package_name", "hop_count"],
        [["GHSA-v1", "requests", 0]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(analysis_blast_radius("analysis_1", depth=2))
    assert result["count"] == 1


def test_analysis_blast_radius_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGraphClient()
    client.connect()
    _patch(monkeypatch, client, FakeOsvClient())

    with pytest.raises(MCPError):
        _run(analysis_blast_radius("analysis_1", depth=9))


# ---------------------------------------------------------------------------
# vulnerability.get
# ---------------------------------------------------------------------------

def test_vulnerability_get_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import GET_VULNERABILITY

    client = FakeGraphClient()
    client.connect()
    client.canned[GET_VULNERABILITY] = FakeQueryResult(
        ["id", "summary", "aliases"],
        [["GHSA-v1", "bad widget", ["CVE-1"]]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(vulnerability_get("GHSA-v1"))
    assert result["id"] == "GHSA-v1"
    assert result["summary"] == "bad widget"


def test_vulnerability_get_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import GET_VULNERABILITY

    client = FakeGraphClient()
    client.connect()
    client.canned[GET_VULNERABILITY] = FakeQueryResult(["id"], [])
    _patch(monkeypatch, client, FakeOsvClient())

    with pytest.raises(MCPError):
        _run(vulnerability_get("GHSA-missing"))


# ---------------------------------------------------------------------------
# vulnerability.components
# ---------------------------------------------------------------------------

def test_vulnerability_components_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.graph.queries import GET_VULNERABILITY_COMPONENTS

    client = FakeGraphClient()
    client.connect()
    client.canned[GET_VULNERABILITY_COMPONENTS] = FakeQueryResult(
        ["package_id", "package_name"],
        [["pkg_1", "requests"]],
    )
    _patch(monkeypatch, client, FakeOsvClient())

    result = _run(vulnerability_components("GHSA-v1"))
    assert result["count"] == 1


# ---------------------------------------------------------------------------
# osv.lookup
# ---------------------------------------------------------------------------

def test_osv_lookup_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    osv_client = FakeOsvClient(
        query_responses={
            ("PyPI", "requests", "2.3.0"): {
                "vulns": [raw_osv_record("GHSA-v1", fixed="2.20.0")]
            }
        },
        records={
            "GHSA-v1": raw_osv_record("GHSA-v1", fixed="2.20.0", modified="2024-05-01T00:00:00Z")
        },
    )
    _patch(monkeypatch, FakeGraphClient(), osv_client)

    result = _run(osv_lookup("requests", ecosystem="pypi", version="2.3.0"))
    assert result["match_type"] == "version"
    assert result["confirmed"] is True
    assert result["count"] >= 1
    assert result["package_name"] == "requests"


def test_osv_lookup_name_only(monkeypatch: pytest.MonkeyPatch) -> None:
    osv_client = FakeOsvClient(
        query_responses={("PyPI", "requests", None): {"vulns": []}},
    )
    _patch(monkeypatch, FakeGraphClient(), osv_client)

    result = _run(osv_lookup("requests"))
    assert result["match_type"] == "name"
    assert result["confirmed"] is False
    assert result["count"] == 0


def test_osv_lookup_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, FakeGraphClient(), FakeOsvClient())

    with pytest.raises(MCPError):
        _run(osv_lookup(""))


def test_osv_lookup_unknown_ecosystem(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, FakeGraphClient(), FakeOsvClient())

    with pytest.raises(MCPError):
        _run(osv_lookup("left-pad", ecosystem="npm"))


# ---------------------------------------------------------------------------
# read-only: tools never call write methods
# ---------------------------------------------------------------------------

def test_tools_are_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify no tool invokes graph-write or OSV-ingest methods."""
    client = FakeGraphClient()
    client.connect()
    _analysis_canned(client)
    osv_client = FakeOsvClient()
    _patch(monkeypatch, client, osv_client)

    _run(analysis_status("analysis_1"))

    # No batch/query/hydrate calls should have been made to OSV.
    assert osv_client.batch_calls == []
    assert osv_client.get_calls == []
