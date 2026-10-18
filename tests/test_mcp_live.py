"""Opt-in live MCP server tests against real FalkorDB and OSV.dev.

These tests are skipped unless both env vars are set::

    BLASTRADIUS_GRAPH_LIVE_TESTS=1
    BLASTRADIUS_OSV_LIVE_TESTS=1

They call the MCP tool functions directly with real GraphService /
VulnerabilityGraphService / OsvService instances backed by FalkorDB and OSV.dev.
All graph data lives in a dedicated test graph (``blastradius_mcp_livetest``)
so the default ``blastradius`` graph is never touched, and no containers or
volumes are deleted.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from app.graph.client import GraphClient
from app.graph.config import GraphSettings
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

OSV_LIVE = os.environ.get("BLASTRADIUS_OSV_LIVE_TESTS") == "1"
GRAPH_LIVE = os.environ.get("BLASTRADIUS_GRAPH_LIVE_TESTS") == "1"

skip_without_osv_and_graph = pytest.mark.skipif(
    not (OSV_LIVE and GRAPH_LIVE),
    reason="live MCP test: set BLASTRADIUS_OSV_LIVE_TESTS=1 and BLASTRADIUS_GRAPH_LIVE_TESTS=1",
)

LIVE_TEST_REPOSITORY_ID = "github.com/blastradius-mcp/demo"
LIVE_TEST_COMMIT_SHA = "m" * 40


def _patch_graph_services(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[GraphClient, GraphService, VulnerabilityGraphService]:
    client = GraphClient(GraphSettings(graph_name="blastradius_mcp_livetest"))
    client.connect()
    graph_service = GraphService(client)
    vuln_service = VulnerabilityGraphService(client, graph_service)

    def fake_graph_services() -> tuple[GraphService, VulnerabilityGraphService]:
        return graph_service, vuln_service

    monkeypatch.setattr("app.mcp.tools._graph_services", fake_graph_services)
    return client, graph_service, vuln_service


def _run(coro) -> object:
    return asyncio.run(coro)


@skip_without_osv_and_graph
def test_mcp_graph_health_live() -> None:
    """graph.health works against a real FalkorDB (dedicated graph)."""
    monkeypatch = pytest.MonkeyPatch()
    client, _, _ = _patch_graph_services(monkeypatch)
    try:
        result = _run(graph_health())
        assert result["graph_name"] == "blastradius_mcp_livetest"
        assert "connected" in result
    finally:
        client.close()
        monkeypatch.undo()


@skip_without_osv_and_graph
def test_mcp_osv_lookup_live() -> None:
    """osv_lookup works against real OSV.dev (read-only, no graph writes)."""
    monkeypatch = pytest.MonkeyPatch()
    _patch_graph_services(monkeypatch)
    try:
        result = _run(osv_lookup("requests", ecosystem="pypi", version="2.3.0"))
        assert result["match_type"] == "version"
        assert result["package_name"] == "requests"
        assert result["count"] >= 1
    finally:
        monkeypatch.undo()


@skip_without_osv_and_graph
def test_mcp_full_flow_live() -> None:
    """End-to-end: ingest scenario data, then read via MCP tools."""
    from app.models.common import (
        DependencyRelation,
        DependencyScope,
        Ecosystem,
        IngestionStatus,
        ManifestFormat,
        ManifestParseStatus,
        ReferenceType,
    )
    from app.models.dependencies import (
        DependencyDeclaration,
        DependencyManifestRecord,
        DependencyProvenance,
        ResolvedDependencyEdge,
        ResolvedPackage,
    )
    from app.models.ingestion import IngestionResult, IngestionLimits, IngestionSummary
    from app.models.repository import (
        RepositoryCommit,
        RepositoryIdentity,
        RepositoryMetadata,
        RepositoryReference,
    )
    from app.models.source import SourceFile
    from datetime import datetime, timezone

    monkeypatch = pytest.MonkeyPatch()
    graph_client, graph_service, vuln_service = _patch_graph_services(monkeypatch)

    try:
        sha = LIVE_TEST_COMMIT_SHA
        identity = RepositoryIdentity(
            host="github.com",
            owner="blastradius-mcp",
            name="demo",
            canonical_id=LIVE_TEST_REPOSITORY_ID,
            canonical_url=f"https://{LIVE_TEST_REPOSITORY_ID}",
            clone_url=f"https://{LIVE_TEST_REPOSITORY_ID}.git",
            api_url=f"https://api.github.com/repos/{LIVE_TEST_REPOSITORY_ID}",
        )
        reference = RepositoryReference(
            requested_ref=None,
            ref_type=ReferenceType.DEFAULT_BRANCH,
            resolved_commit_sha=sha,
            default_branch="main",
            resolved_via="github_api",
            is_default_branch=True,
            sha_verified=True,
        )
        commit = RepositoryCommit(
            sha=sha,
            short_sha=sha[:12],
            message="mcp live test commit",
            author_name="MCP Live Test",
            committed_at=datetime.now(tz=timezone.utc).isoformat(),
            source="github_api",
        )
        provenance = DependencyProvenance(
            manifest_path="poetry.lock",
            manifest_format="requirements.txt",
            section=None,
            line_number=1,
            snippet=None,
            evidence="declared in poetry.lock",
        )

        def _limits() -> IngestionLimits:
            return IngestionLimits(
                retrieval_strategy="git",
                download_timeout_seconds=60.0,
                git_timeout_seconds=120.0,
                max_ingestion_seconds=300.0,
                max_download_bytes=200 * 1024 * 1024,
                max_extracted_bytes=500 * 1024 * 1024,
                max_archive_members=200000,
                max_repository_size_kb=512000,
                max_files_scanned=20000,
                max_directory_entries=2000,
                max_manifest_bytes=5 * 1024 * 1024,
                max_manifests=200,
                max_dependencies=20000,
            )

        def _summary(status: IngestionStatus, declarations: int, resolved: int, edges: int) -> IngestionSummary:
            return IngestionSummary(
                status=status,
                repository_id=LIVE_TEST_REPOSITORY_ID,
                commit_sha=sha,
                files_examined=1,
                manifests_detected=1,
                manifests_parsed=1,
                declarations=declarations,
                resolved_packages=resolved,
                dependency_edges=edges,
                direct_declarations=declarations,
                warning_count=0,
                error_count=0,
                started_at=datetime.now(tz=timezone.utc).isoformat(),
                finished_at=datetime.now(tz=timezone.utc).isoformat(),
                duration_ms=100,
            )

        resolved = [
            ResolvedPackage(
                id="pkg_requests_2_31_0",
                repository_id=LIVE_TEST_REPOSITORY_ID,
                commit_sha=sha,
                original_name="requests",
                normalized_name="requests",
                version="2.31.0",
                ecosystem=Ecosystem.PYPI,
                relation=DependencyRelation.DIRECT,
                is_dev=False,
                is_optional=False,
                is_root_project=False,
                groups=(),
                marker=None,
                requires_python=None,
                source_kind="registry",
                source_reference=None,
                dependency_count=2,
                source_manifest="poetry.lock",
                provenance=provenance,
            ),
        ]
        edges = [
            ResolvedDependencyEdge(
                id="edge_requests_urllib3",
                repository_id=LIVE_TEST_REPOSITORY_ID,
                commit_sha=sha,
                from_name="requests",
                from_version="2.31.0",
                to_name="urllib3",
                to_version_constraint=">=1.21.1,<3",
                to_resolved_version="2.2.1",
                marker=None,
                extras=(),
                optional=False,
                dev=False,
                source_manifest="poetry.lock",
                provenance=provenance,
            )
        ]
        declarations = [
            DependencyDeclaration(
                id="decl_requests",
                repository_id=LIVE_TEST_REPOSITORY_ID,
                commit_sha=sha,
                original_name="requests",
                normalized_name="requests",
                ecosystem=Ecosystem.PYPI,
                version_constraint=">=2.31,<3",
                constraint_scheme="pep440",
                is_exact_pin=False,
                resolved_version="2.31.0",
                resolved_from="poetry.lock",
                referenced_version=None,
                scope=DependencyScope.RUNTIME,
                relation=DependencyRelation.DIRECT,
                extras=(),
                marker=None,
                requires_python=None,
                source_kind="registry",
                source_reference=None,
                is_direct_url_reference=False,
                group=None,
                provenance=provenance,
            )
        ]
        result = IngestionResult(
            status=IngestionStatus.SUCCESS,
            repository=RepositoryMetadata(
                identity=identity,
                commit=commit,
                reference=reference,
            ),
            reference=reference,
            source_files=[
                SourceFile(
                    path="poetry.lock",
                    size_bytes=100,
                    sha256="y" * 64,
                    manifest_format=ManifestFormat.POETRY_LOCK,
                    support_level="supported",
                )
            ],
            manifests=[
                DependencyManifestRecord(
                    id="manifest_poetry_lock",
                    repository_id=LIVE_TEST_REPOSITORY_ID,
                    commit_sha=sha,
                    path="poetry.lock",
                    directory=".",
                    format=ManifestFormat.POETRY_LOCK,
                    support_level="supported",
                    is_lockfile=True,
                    size_bytes=100,
                    sha256="y" * 64,
                    status=ManifestParseStatus.PARSED,
                    declaration_count=1,
                    resolved_count=1,
                    edge_count=1,
                )
            ],
            declarations=declarations,
            resolved_packages=resolved,
            dependency_edges=edges,
            coverage=[],
            warnings=[],
            errors=[],
            summary=_summary(IngestionStatus.SUCCESS, declarations=1, resolved=1, edges=1),
            limits=_limits(),
        )

        summary = graph_service.ingest_result_into_graph(result)
        analysis_id = summary.analysis_id

        status = _run(analysis_status(analysis_id))
        assert status["status"] == "success"

        stats = _run(analysis_statistics(analysis_id))
        assert stats["packages"] >= 1
        assert stats["dependency_edges"] == 1

        packages = _run(analysis_packages(analysis_id))
        assert packages["count"] >= 1
        package_names = {row["normalized_name"] for row in packages["rows"]}
        assert "requests" in package_names

        dep_edges = _run(analysis_dependency_edges(analysis_id))
        assert dep_edges["count"] == 1

        nb = _run(
            package_neighborhood(
                GraphService.package_id(LIVE_TEST_REPOSITORY_ID, sha, "requests", "2.31.0"),
                depth=1,
            )
        )
        assert nb["count"] >= 1
        assert nb["rows"][0]["package_id"] == GraphService.package_id(
            LIVE_TEST_REPOSITORY_ID, sha, "requests", "2.31.0"
        )

        lookup = _run(osv_lookup("requests", ecosystem="pypi", version="2.31.0"))
        assert lookup["match_type"] == "version"
        assert lookup["count"] >= 1

    finally:
        graph_client.graph.query("MATCH (n) DETACH DELETE n")
        graph_client.close()
        monkeypatch.undo()
