"""Graph integration tests against a real FalkorDB instance.

These tests are opt-in: they are skipped unless
``BLASTRADIUS_GRAPH_LIVE_TESTS=1`` is set *and* a FalkorDB server is reachable
on the configured host/port.  They are not run as part of the offline suite.

Start a local FalkorDB (see docs/GRAPH_SCHEMA.md) before running::

    $env:BLASTRADIUS_GRAPH_LIVE_TESTS = "1"
    python -m pytest tests/test_graph_integration.py -m graph -s
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from app.graph.client import GraphClient
from app.graph.config import GraphSettings
from app.graph.errors import GraphError, GraphRecordNotFoundError
from app.graph.service import GraphService
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

LIVE = os.environ.get("BLASTRADIUS_GRAPH_LIVE_TESTS") == "1"
skip_without_falkordb = pytest.mark.skipif(
    not LIVE,
    reason="graph integration test: set BLASTRADIUS_GRAPH_LIVE_TESTS=1 and run FalkorDB",
)

#: Dedicated graph used by the live integration tests.  A separate graph name
#: means cleanup (DETACH DELETE) is scoped to this graph and can never delete
#: user or demo data stored in the default "blastradius" graph.
LIVE_GRAPH_NAME = "blastradius_livetest"


def _try_connect(graph_name: str = LIVE_GRAPH_NAME) -> GraphClient | None:
    """Return a connected graph client, or None when FalkorDB is unavailable."""
    try:
        settings = GraphSettings(graph_name=graph_name)
        client = GraphClient(settings)
        client.connect()
        if client.ping():
            return client
        client.close()
    except GraphError:
        return None
    return None


@pytest.fixture
def graph_client() -> GraphClient:
    client = _try_connect()
    if client is None:
        pytest.skip("FalkorDB is not reachable on localhost:6379")
    # The dedicated test graph is wiped before AND after each test.  Because it
    # is a separate graph name, this cannot delete data in any other graph.
    client.graph.query("MATCH (n) DETACH DELETE n")
    yield client
    try:
        client.graph.query("MATCH (n) DETACH DELETE n")
    finally:
        client.close()


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _base_identity() -> RepositoryIdentity:
    return RepositoryIdentity(
        host="github.com",
        owner="example",
        name="demo",
        canonical_id="github.com/example/demo",
        canonical_url="https://github.com/example/demo",
        clone_url="https://github.com/example/demo.git",
        api_url="https://api.github.com/repos/example/demo",
    )


def _base_reference(sha: str) -> RepositoryReference:
    return RepositoryReference(
        requested_ref=None,
        ref_type=ReferenceType.DEFAULT_BRANCH,
        resolved_commit_sha=sha,
        default_branch="main",
        resolved_via="github_api",
        is_default_branch=True,
        sha_verified=True,
    )


def _base_commit(sha: str) -> RepositoryCommit:
    return RepositoryCommit(
        sha=sha,
        short_sha=sha[:12],
        message="demo commit",
        author_name="Demo Author",
        committed_at=_utc_now(),
        source="github_api",
    )


def _provenance(path: str, line: int = 1) -> DependencyProvenance:
    return DependencyProvenance(
        manifest_path=path,
        manifest_format="requirements.txt",
        section=None,
        line_number=line,
        snippet=None,
        evidence="declared in requirements.txt",
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


def _summary(status: IngestionStatus, sha: str, declarations: int, resolved: int, edges: int) -> IngestionSummary:
    return IngestionSummary(
        status=status,
        repository_id="github.com/example/demo",
        commit_sha=sha,
        files_examined=2,
        manifests_detected=1,
        manifests_parsed=1,
        declarations=declarations,
        resolved_packages=resolved,
        dependency_edges=edges,
        direct_declarations=declarations,
        warning_count=0,
        error_count=0,
        started_at=_utc_now(),
        finished_at=_utc_now(),
        duration_ms=100,
    )


def scenario_a_no_lockfile() -> IngestionResult:
    """Repository with declarations but no lockfile: unresolved, no edges."""
    sha = "a" * 40
    identity = _base_identity()
    reference = _base_reference(sha)
    result = IngestionResult(
        status=IngestionStatus.SUCCESS,
        repository=RepositoryMetadata(
            identity=identity,
            commit=_base_commit(sha),
            reference=reference,
        ),
        reference=reference,
        source_files=[
            SourceFile(
                path="requirements.txt",
                size_bytes=40,
                sha256="x" * 64,
                manifest_format=ManifestFormat.REQUIREMENTS_TXT,
                support_level="supported",
            )
        ],
        manifests=[
            DependencyManifestRecord(
                id="manifest_requirements",
                repository_id="github.com/example/demo",
                commit_sha=sha,
                path="requirements.txt",
                directory=".",
                format=ManifestFormat.REQUIREMENTS_TXT,
                support_level="supported",
                is_lockfile=False,
                size_bytes=40,
                sha256="x" * 64,
                status=ManifestParseStatus.PARSED,
                declaration_count=2,
                resolved_count=0,
                edge_count=0,
            )
        ],
        declarations=[
            DependencyDeclaration(
                id="decl_requests",
                repository_id="github.com/example/demo",
                commit_sha=sha,
                original_name="requests",
                normalized_name="requests",
                ecosystem=Ecosystem.PYPI,
                version_constraint=">=2.31,<3",
                constraint_scheme="pep440",
                is_exact_pin=False,
                resolved_version=None,
                resolved_from=None,
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
                provenance=_provenance("requirements.txt"),
            ),
            DependencyDeclaration(
                id="decl_click",
                repository_id="github.com/example/demo",
                commit_sha=sha,
                original_name="click",
                normalized_name="click",
                ecosystem=Ecosystem.PYPI,
                version_constraint="==8.1.7",
                constraint_scheme="pep440",
                is_exact_pin=True,
                resolved_version=None,
                resolved_from=None,
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
                provenance=_provenance("requirements.txt"),
            ),
        ],
        resolved_packages=[],
        dependency_edges=[],
        coverage=[],
        warnings=[],
        errors=[],
        summary=_summary(IngestionStatus.SUCCESS, sha, declarations=2, resolved=0, edges=0),
        limits=_limits(),
    )
    return result


def scenario_b_with_lockfile() -> IngestionResult:
    """Repository with declarations + lockfile: resolved versions + edges."""
    sha = "b" * 40
    identity = _base_identity()
    reference = _base_reference(sha)

    resolved = [
        ResolvedPackage(
            id="pkg_requests_2_31_0",
            repository_id="github.com/example/demo",
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
            provenance=_provenance("poetry.lock"),
        ),
        ResolvedPackage(
            id="pkg_urllib3_2_2_1",
            repository_id="github.com/example/demo",
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
            provenance=_provenance("poetry.lock"),
        ),
    ]

    edges = [
        ResolvedDependencyEdge(
            id="edge_requests_urllib3",
            repository_id="github.com/example/demo",
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
            provenance=_provenance("poetry.lock"),
        )
    ]

    declarations = [
        DependencyDeclaration(
            id="decl_requests",
            repository_id="github.com/example/demo",
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
            provenance=_provenance("poetry.lock"),
        )
    ]

    result = IngestionResult(
        status=IngestionStatus.SUCCESS,
        repository=RepositoryMetadata(
            identity=identity,
            commit=_base_commit(sha),
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
                repository_id="github.com/example/demo",
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
        summary=_summary(IngestionStatus.SUCCESS, sha, declarations=1, resolved=2, edges=1),
        limits=_limits(),
    )
    return result


@skip_without_falkordb
def test_scenario_a_no_lockfile_keeps_versions_unresolved(graph_client: GraphClient) -> None:
    service = GraphService(graph_client)
    result = scenario_a_no_lockfile()
    canonical_id = result.repository.identity.canonical_id
    commit_sha = result.reference.resolved_commit_sha
    analysis_id = GraphService.analysis_id(canonical_id, commit_sha)

    summary = service.ingest_result_into_graph(result)

    assert summary.records_ingested > 0
    assert summary.created > 0

    # Declarations stored with unresolved versions.
    declarations = service.get_declarations(analysis_id)
    assert declarations["count"] == 2
    for row in declarations["rows"]:
        assert row["resolved_version"] is None

    # No resolved packages, no dependency edges fabricated.
    packages = service.get_repository_packages(analysis_id)
    assert packages["count"] == 0
    edges = service.get_dependency_edges(analysis_id)
    assert edges["count"] == 0

    # Statistics reflect the incomplete state.
    stats = service.get_graph_statistics(analysis_id)
    assert stats["declarations"] == 2
    assert stats["packages"] == 0
    assert stats["dependency_edges"] == 0
    assert stats["resolved_packages"] == 0


@skip_without_falkordb
def test_scenario_b_with_lockfile_persists_resolved_and_edges(graph_client: GraphClient) -> None:
    service = GraphService(graph_client)
    result = scenario_b_with_lockfile()
    canonical_id = result.repository.identity.canonical_id
    commit_sha = result.reference.resolved_commit_sha
    analysis_id = GraphService.analysis_id(canonical_id, commit_sha)

    summary = service.ingest_result_into_graph(result)
    assert summary.records_ingested > 0

    # Resolved packages carry concrete versions.
    packages = service.get_repository_packages(analysis_id)
    assert packages["count"] == 2
    versions = {row["version"] for row in packages["rows"]}
    assert versions == {"2.31.0", "2.2.1"}

    # Dependency edge persisted.
    edges = service.get_dependency_edges(analysis_id)
    assert edges["count"] == 1
    edge_row = edges["rows"][0]
    assert edge_row["from_name"] == "requests"
    assert edge_row["to_name"] == "urllib3"
    assert edge_row["to_version"] == "2.2.1"

    # Declaration resolves to the resolved package.
    declarations = service.get_declarations(analysis_id)
    assert declarations["count"] == 1

    stats = service.get_graph_statistics(analysis_id)
    assert stats["resolved_packages"] == 1
    assert stats["dependency_edges"] == 1


@skip_without_falkordb
def test_re_ingestion_does_not_duplicate(graph_client: GraphClient) -> None:
    service = GraphService(graph_client)
    result = scenario_b_with_lockfile()
    canonical_id = result.repository.identity.canonical_id
    commit_sha = result.reference.resolved_commit_sha
    analysis_id = GraphService.analysis_id(canonical_id, commit_sha)

    first = service.ingest_result_into_graph(result)
    second = service.ingest_result_into_graph(result)

    assert second.created == 0
    assert second.updated == first.created
    stats = service.get_graph_statistics(analysis_id)
    assert stats["packages"] == 2  # still 2, not 4
    assert stats["dependency_edges"] == 1  # still 1, not 2


@skip_without_falkordb
def test_missing_analysis_is_404(graph_client: GraphClient) -> None:
    service = GraphService(graph_client)
    with pytest.raises(GraphRecordNotFoundError):
        service.get_analysis_graph_status("does-not-exist")
