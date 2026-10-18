"""Opt-in live integration tests: real OSV.dev and (optionally) real FalkorDB.

These tests are skipped unless::

    BLASTRADIUS_OSV_LIVE_TESTS=1                     # OSV-only lookups
    BLASTRADIUS_OSV_LIVE_TESTS=1 + BLASTRADIUS_GRAPH_LIVE_TESTS=1
                                                     # full sync into FalkorDB

Live upstream data changes over time, so assertions are tolerant of content
while being strict about shape and semantics: exact resolved versions must
yield version-confirmed matches, scope must never leak, re-running must not
duplicate anything, and every read must name the vulnerability ids behind it.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from app.graph.client import GraphClient
from app.graph.config import GraphSettings
from app.graph.errors import GraphError
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.osv.client import OsvApiClient
from app.osv.config import OsvSettings
from app.osv.service import OsvPackageItem, OsvService

OSV_LIVE = os.environ.get("BLASTRADIUS_OSV_LIVE_TESTS") == "1"
GRAPH_LIVE = os.environ.get("BLASTRADIUS_GRAPH_LIVE_TESTS") == "1"

skip_without_osv = pytest.mark.skipif(
    not OSV_LIVE,
    reason="live OSV test: set BLASTRADIUS_OSV_LIVE_TESTS=1",
)
skip_without_osv_and_graph = pytest.mark.skipif(
    not (OSV_LIVE and GRAPH_LIVE),
    reason="live end-to-end test: set BLASTRADIUS_OSV_LIVE_TESTS=1 and BLASTRADIUS_GRAPH_LIVE_TESTS=1",
)

#: Dedicated graph used by the live OSV end-to-end test.  A separate graph name
#: means cleanup is scoped to this graph and can never delete user or demo data
#: stored in the default "blastradius" graph.
OSV_LIVE_GRAPH_NAME = "blastradius_osv_livetest"

#: Repository/commit used for the live test's own data.  Distinct from the
#: demo ids ("a"*40 / "b"*40) used elsewhere so test data never collides with
#: existing graph contents.
LIVE_TEST_REPOSITORY_ID = "github.com/blastradius-livetest/demo"
LIVE_TEST_COMMIT_SHA = "l" * 40


def _try_graph_client() -> GraphClient | None:
    try:
        client = GraphClient(GraphSettings(graph_name=OSV_LIVE_GRAPH_NAME))
        client.connect()
        if client.ping():
            return client
        client.close()
    except GraphError:
        return None
    return None


# ---------------------------------------------------------------------------
# OSV-only (no graph)
# ---------------------------------------------------------------------------
@skip_without_osv
def test_live_osv_lookup_requests_version_confirmed() -> None:
    """requests 2.3.0 is known-vulnerable; OSV must confirm it with >=1 record."""
    settings = OsvSettings()
    with OsvApiClient(settings) as client:
        service = OsvService(client, settings)
        result = service.lookup("pypi", "requests", "2.3.0")

    assert result.match_type == "version"
    assert result.upstream_ecosystem == "PyPI"
    assert result.count >= 1, "requests 2.3.0 must have at least one OSV record"
    for vuln in result.vulnerabilities:
        assert vuln.id, "every record must carry an OSV id"
        # Defence in depth held: each record really declares the package.
        assert vuln.affected_entry_for("requests", "PyPI") is not None


@skip_without_osv
def test_live_osv_lookup_unknown_version_reports_no_matches_gracefully() -> None:
    """A version that cannot exist yields zero matches, not an error."""
    settings = OsvSettings()
    with OsvApiClient(settings) as client:
        service = OsvService(client, settings)
        result = service.lookup("pypi", "requests", "99998.0.0")
    assert result.count == 0
    assert result.errors == () or all("does not declare" not in e for e in result.errors)


# ---------------------------------------------------------------------------
# End-to-end: ingest scenario into the graph, then OSV sync into FalkorDB
# ---------------------------------------------------------------------------


def _livetest_scenario() -> Any:
    """Build a tiny ``IngestionResult`` with unique, scoped test data.

    Uses ``LIVE_TEST_REPOSITORY_ID`` / ``LIVE_TEST_COMMIT_SHA`` so the data
    never collides with demo or user data already in the graph.
    """
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

    sha = LIVE_TEST_COMMIT_SHA
    identity = RepositoryIdentity(
        host="github.com",
        owner="blastradius-livetest",
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
        message="livetest commit",
        author_name="Live Test",
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
        ResolvedPackage(
            id="pkg_urllib3_2_2_1",
            repository_id=LIVE_TEST_REPOSITORY_ID,
            commit_sha=sha,
            original_name="urllib3",
            normalized_name="urllib3",
            version="2.2.1",
            ecosystem=Ecosystem.PYPI,
            relation=DependencyRelation.TRANSITIVE,
            is_dev=False,
            is_optional=False,
            is_root_project=False,
            groups=(),
            marker=None,
            requires_python=None,
            source_kind="registry",
            source_reference=None,
            dependency_count=0,
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
    return IngestionResult(
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
                resolved_count=2,
                edge_count=1,
            )
        ],
        declarations=declarations,
        resolved_packages=resolved,
        dependency_edges=edges,
        coverage=[],
        warnings=[],
        errors=[],
        summary=_summary(IngestionStatus.SUCCESS, declarations=1, resolved=2, edges=1),
        limits=_limits(),
    )


@skip_without_osv_and_graph
def test_live_full_vulnerability_sync_and_reads() -> None:
    graph = _try_graph_client()
    if graph is None:
        pytest.skip("FalkorDB is not reachable")
    try:
        # Dedicated graph: no whole-graph cleanup that could reach other data.
        result = _livetest_scenario()
        graph_service = GraphService(graph)
        summary = graph_service.ingest_result_into_graph(result)
        analysis_id = summary.analysis_id

        osv_settings = OsvSettings()
        with OsvApiClient(osv_settings) as client:
            osv_service = OsvService(client, osv_settings)

            item = OsvPackageItem(
                ecosystem="pypi",
                package_name="requests",
                original_name="requests",
                version="2.31.0",
            )
            report = osv_service.sync([item])

        # Live data tolerance: requests 2.31.0 should have known records, but the
        # exact ids are upstream's to change.  Semantics must hold either way.
        for match in report.matches:
            assert match.match_type == "version"
            assert match.package_name == "requests"
            assert match.upstream_ecosystem == "PyPI"

        vuln_service = VulnerabilityGraphService(graph, graph_service)
        graph_summary = vuln_service.record_vulnerabilities(
            list(report.vulnerabilities),
            [
                {
                    **m.model_dump(),
                    "repository_id": LIVE_TEST_REPOSITORY_ID,
                    "commit_sha": LIVE_TEST_COMMIT_SHA,
                }
                for m in report.matches
            ],
            repository_id=LIVE_TEST_REPOSITORY_ID,
            commit_sha=LIVE_TEST_COMMIT_SHA,
        )
        assert graph_summary.vulnerabilities_created + graph_summary.vulnerabilities_updated == len(
            report.vulnerabilities
        )
        assert graph_summary.edges_created + graph_summary.edges_updated == len(report.matches)

        # Idempotency: a second identical run creates nothing new.
        second = vuln_service.record_vulnerabilities(
            list(report.vulnerabilities),
            [
                {
                    **m.model_dump(),
                    "repository_id": LIVE_TEST_REPOSITORY_ID,
                    "commit_sha": LIVE_TEST_COMMIT_SHA,
                }
                for m in report.matches
            ],
            repository_id=LIVE_TEST_REPOSITORY_ID,
            commit_sha=LIVE_TEST_COMMIT_SHA,
        )
        assert second.vulnerabilities_created == 0
        assert second.edges_created == 0
        assert second.vulnerabilities_updated == len(report.vulnerabilities)
        assert second.edges_updated == len(report.matches)

        if report.matches:
            listing = vuln_service.get_analysis_vulnerabilities(analysis_id)
            assert listing["count"] == len(report.matches)
            names = {row["package_name"] for row in listing["rows"]}
            assert "requests" in names

            paths = vuln_service.get_impact_paths(analysis_id, depth=2)
            hop_zero = [p for p in paths["rows"] if p["hop_count"] == 0]
            assert hop_zero, "directly affected package (requests) must be listed"

            detail = vuln_service.get_vulnerability(report.matches[0].vulnerability_id)
            assert detail["id"] == report.matches[0].vulnerability_id
            assert detail["source"] == "osv"
    finally:
        # Teardown: wipe the dedicated test graph entirely.  Because it is a
        # separate graph name, this cannot delete user or demo data stored in
        # the default "blastradius" graph.  Wiping (rather than scoped delete)
        # also removes the shared :Vulnerability nodes, which carry no
        # repository_id/commit_sha and would otherwise persist across runs.
        graph.graph.query("MATCH (n) DETACH DELETE n")
        graph.close()