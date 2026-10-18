"""Graph service tests (offline; a stateful fake stands in for FalkorDB).

These tests exercise :class:`~app.graph.service.GraphService` independently of
FastAPI and of any real database, using the :class:`tests.support.FakeGraphClient`
test double.
"""

from __future__ import annotations

import json

import pytest

from app.core.errors import BlastRadiusError
from app.graph.client import GraphClient
from app.graph.errors import GraphError
from app.graph.service import GraphService
from app.ingestion.service import ingest_repository
from app.models.common import DependencyScope, Ecosystem, IngestionStatus, ReferenceType, RetrievalStrategy
from app.models.ingestion import IngestionResult
from tests.support import (
    CLEAN_REPOSITORY,
    FAKE_SHA,
    FakeGraphClient,
    FakeQueryResult,
    FakeRetriever,
    MESSY_REPOSITORY,
    StubGitHubClient,
    make_settings,
)


def _ingest_clean(tmp_path) -> IngestionResult:
    settings = make_settings(temp_root=tmp_path / "work")
    return ingest_repository(
        "https://github.com/example/clean",
        settings=settings,
        retriever=FakeRetriever(CLEAN_REPOSITORY),
        api_client=StubGitHubClient(),
    )


def _ingest_messy(tmp_path) -> IngestionResult:
    settings = make_settings(temp_root=tmp_path / "work")
    return ingest_repository(
        "https://github.com/example/messy",
        settings=settings,
        retriever=FakeRetriever(MESSY_REPOSITORY),
        api_client=StubGitHubClient(),
    )


def _service(client: FakeGraphClient | None = None) -> GraphService:
    return GraphService(client or FakeGraphClient())


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def test_ingest_creates_all_node_types(tmp_path) -> None:
    result = _ingest_clean(tmp_path)
    client = FakeGraphClient()
    summary = _service(client).ingest_result_into_graph(result)

    identity = result.repository.identity
    canonical_id = identity.canonical_id
    commit_sha = result.reference.resolved_commit_sha
    analysis_id = GraphService.analysis_id(canonical_id, commit_sha)

    assert summary.repository_id == canonical_id
    assert summary.analysis_id == analysis_id
    assert summary.created > 0
    assert summary.updated == 0
    assert summary.rejected == 0
    assert summary.records_ingested == summary.created

    # Core nodes exist.
    assert client.nodes["Repository"][canonical_id]
    assert client.nodes["Commit"][commit_sha]
    assert client.nodes["Analysis"][analysis_id]

    # Source files were persisted.
    assert len(client.nodes["SourceFile"]) >= 1
    # Manifests were persisted.
    assert len(client.nodes["DependencyManifest"]) >= 1
    # Declarations were persisted.
    assert len(client.nodes["DependencyDeclaration"]) == len(result.declarations)

    # No lockfile in the clean repo → declaration-target packages exist
    # (version None) but no resolved packages and no edges.  Multiple
    # declarations may target the same normalised package name.
    unique_packages = {declaration.normalized_name for declaration in result.declarations}
    assert len(client.nodes["Package"]) == len(unique_packages)
    for node in client.nodes["Package"].values():
        assert node.get("version") in (None, "")


def test_ingest_messy_persists_resolved_packages_and_edges(tmp_path) -> None:
    result = _ingest_messy(tmp_path)
    client = FakeGraphClient()
    summary = _service(client).ingest_result_into_graph(result)

    canonical_id = result.repository.identity.canonical_id
    commit_sha = result.reference.resolved_commit_sha

    # Resolved packages carry concrete versions.  Packages sharing the same
    # normalised name and version (e.g. rich 13.7.1 in both lockfiles) map to
    # one stable id, so the stored count can be <= the summary count.
    resolved_nodes = [
        node for node in client.nodes["Package"].values() if node.get("version")
    ]
    assert len(resolved_nodes) >= 1
    assert len(resolved_nodes) <= result.summary.resolved_packages
    for node in resolved_nodes:
        assert node["repository_id"] == canonical_id
        assert node["commit_sha"] == commit_sha
        assert node["version"] is not None and node["version"] != ""

    # Dependency edges were persisted.
    if result.summary.dependency_edges > 0:
        assert len(result.dependency_edges) > 0
        # Every edge is between packages that exist in this analysis.
        for edge in result.dependency_edges:
            from_id = GraphService.package_id(
                canonical_id, commit_sha, edge.from_name, edge.from_version
            )
            to_id = GraphService.package_id(
                canonical_id, commit_sha, edge.to_name, edge.to_resolved_version
            )
            assert from_id in client.nodes["Package"]
            assert to_id in client.nodes["Package"]


def test_declaration_without_resolved_version_has_no_resolves_to(tmp_path) -> None:
    result = _ingest_clean(tmp_path)
    client = FakeGraphClient()
    _service(client).ingest_result_into_graph(result)

    # Count TARGETS vs RESOLVES_TO relationships issued to the fake.
    targets = [q for q, _ in client.queries if "TARGETS" in q and "MERGE" in q]
    resolves_to = [q for q, _ in client.queries if "RESOLVES_TO" in q and "MERGE" in q]
    assert len(targets) == len(result.declarations)
    assert len(resolves_to) == 0  # clean repo has no lockfile → nothing resolved


def test_repository_node_carries_its_write_identity(tmp_path) -> None:
    """Regression: the Repository node must keep the identity fields.

    Live trigger: only top-level metadata fields were stored (the identity
    fields live on a nested model), so ``owner``/``name``/``host`` were null and
    the Phase 6 preview endpoint answered ``action_repository_invalid`` for
    every analysis because it could not resolve a canonical GitHub target.
    """
    result = _ingest_clean(tmp_path)
    client = FakeGraphClient()
    _service(client).ingest_result_into_graph(result)

    identity = result.repository.identity
    node = client.nodes["Repository"][identity.canonical_id]
    assert node["owner"] == identity.owner
    assert node["name"] == identity.name
    assert node["host"] == identity.host
    assert node["canonical_id"] == identity.canonical_id
    assert node["canonical_url"] == identity.canonical_url
    assert node["clone_url"] == identity.clone_url
    assert node["api_url"] == identity.api_url
    assert node["commit_sha"] == result.reference.resolved_commit_sha


def test_manifest_and_declaration_nodes_are_scoped_to_the_analysis(tmp_path) -> None:
    """Regression: shared manifest paths must not merge two analyses' nodes.

    Live trigger: pypa/sampleproject and python-poetry/poetry both contain a
    root ``pyproject.toml``.  Parser ids are only path-scoped, so using them as
    graph node ids linked both repositories (and both sets of declarations) to
    one manifest node — cross-analysis contamination.
    """
    client = FakeGraphClient()
    service = _service(client)
    clean = _ingest_clean(tmp_path)
    messy = _ingest_messy(tmp_path)
    service.ingest_result_into_graph(clean)
    service.ingest_result_into_graph(messy)

    results = (clean, messy)
    shared_paths = {m.path for m in clean.manifests} & {m.path for m in messy.manifests}
    assert shared_paths, "fixtures must share a manifest path for this regression test"

    for result in results:
        canonical = result.repository.identity.canonical_id
        commit = result.reference.resolved_commit_sha
        for path in shared_paths:
            manifest_node_id = service.manifest_id(canonical, commit, path)
            assert manifest_node_id in client.nodes["DependencyManifest"]

    for path in shared_paths:
        clean_mid = service.manifest_id(
            clean.repository.identity.canonical_id, clean.reference.resolved_commit_sha, path
        )
        messy_mid = service.manifest_id(
            messy.repository.identity.canonical_id, messy.reference.resolved_commit_sha, path
        )
        assert clean_mid != messy_mid

    # The parser-produced ids are not graph node identities any more.
    parser_manifest_ids = {m.id for result in results for m in result.manifests if m.id}
    assert parser_manifest_ids.isdisjoint(client.nodes["DependencyManifest"])

    for result in results:
        canonical = result.repository.identity.canonical_id
        commit = result.reference.resolved_commit_sha
        scoped = {service.declaration_id(canonical, commit, d) for d in result.declarations}
        # Phase 1 can emit duplicate records with the same parser id (an
        # included requirements file that is also discovered standalone); the
        # graph collapses identical ids into one node, so compare unique ids.
        assert len(scoped) == len({d.id for d in result.declarations})
        assert scoped <= set(client.nodes["DependencyDeclaration"])
        assert {d.id for d in result.declarations}.isdisjoint(client.nodes["DependencyDeclaration"])


def test_conditional_dependency_variants_are_kept_separate(tmp_path) -> None:
    """Regression: same package pair, different markers -> two relationships.

    Live trigger: python-poetry/poetry 1.1.0's ``poetry.lock`` records
    ``pytest 4.6.11 -> more-itertools`` twice (``python_version <= "2.7"`` and
    ``> "2.7"``).  Merging relationships on the endpoint pair alone dropped one
    of the two recorded edges.
    """
    base = _ingest_messy(tmp_path)
    assert base.dependency_edges, "fixture must produce dependency edges for this test"
    edge = base.dependency_edges[0]
    variant = edge.model_copy(
        update={
            "id": f"{edge.id}_variant",
            "marker": 'python_version > "2.7"',
            "to_version_constraint": ">=1.0,<2.0",
        }
    )
    assert variant.marker != edge.marker
    result = base.model_copy(update={"dependency_edges": [*base.dependency_edges, variant]})

    client = FakeGraphClient()
    service = _service(client)
    service.ingest_result_into_graph(result)

    canonical = result.repository.identity.canonical_id
    commit = result.reference.resolved_commit_sha
    from_pid = service.package_id(canonical, commit, edge.from_name, edge.from_version)
    to_pid = service.package_id(canonical, commit, edge.to_name, edge.to_resolved_version)

    depends = {
        key: props for key, props in client.relationships.items() if key[0] == "DEPENDS_ON"
    }
    assert len(depends) == len(result.dependency_edges)
    pair_keys = [key for key in depends if key[1] == from_pid and key[2] == to_pid]
    assert len(pair_keys) == 2, "both conditional variants must persist"
    assert {depends[key].get("marker") for key in pair_keys} == {edge.marker, variant.marker}

    # Re-persisting the same result updates the same relationships (idempotent).
    before = len(client.relationships)
    service.ingest_result_into_graph(result)
    assert len(client.relationships) == before


def test_re_ingestion_is_idempotent_no_duplicates(tmp_path) -> None:
    result = _ingest_clean(tmp_path)
    client = FakeGraphClient()
    service = _service(client)

    summary1 = service.ingest_result_into_graph(result)
    nodes_after_first = {
        label: len(nodes) for label, nodes in client.nodes.items()
    }
    created_first = summary1.created

    # Re-ingest the same result: same stable ids → upserts, no duplicates.
    summary2 = service.ingest_result_into_graph(result)
    nodes_after_second = {
        label: len(nodes) for label, nodes in client.nodes.items()
    }

    assert summary2.created == 0, f"expected no new nodes on re-ingest, got {summary2.created}"
    assert summary2.updated == created_first, "every node should be updated on re-ingest"
    assert nodes_after_second == nodes_after_first, "no duplicate logical nodes"
    assert summary2.records_ingested == created_first


def test_empty_result_persists_core_nodes_only(tmp_path) -> None:
    from app.models.common import IngestionStatus, ReferenceType, RetrievalStrategy
    from app.models.repository import (
        RepositoryCommit,
        RepositoryIdentity,
        RepositoryMetadata,
        RepositoryReference,
    )
    from app.models.source import SourceFile
    from app.models.ingestion import IngestionSummary, IngestionLimits

    identity = RepositoryIdentity(
        host="github.com",
        owner="example",
        name="empty",
        canonical_id="github.com/example/empty",
        canonical_url="https://github.com/example/empty",
        clone_url="https://github.com/example/empty.git",
        api_url="https://api.github.com/repos/example/empty",
    )
    reference = RepositoryReference(
        requested_ref=None,
        ref_type=ReferenceType.DEFAULT_BRANCH,
        resolved_commit_sha=FAKE_SHA,
        resolved_via="github_api",
        is_default_branch=True,
        sha_verified=True,
    )
    result = IngestionResult(
        status=IngestionStatus.SUCCESS,
        repository=RepositoryMetadata(
            identity=identity,
            commit=RepositoryCommit(
                sha=FAKE_SHA,
                short_sha=FAKE_SHA[:12],
                source="github_api",
            ),
            reference=reference,
        ),
        reference=reference,
        source_files=[],
        manifests=[],
        declarations=[],
        resolved_packages=[],
        dependency_edges=[],
        coverage=[],
        warnings=[],
        errors=[],
        summary=IngestionSummary(
            status=IngestionStatus.SUCCESS,
            repository_id="github.com/example/empty",
            commit_sha=FAKE_SHA,
        ),
        limits=IngestionLimits(
            retrieval_strategy=RetrievalStrategy.GIT.value,
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
        ),
    )

    client = FakeGraphClient()
    summary = _service(client).ingest_result_into_graph(result)

    assert summary.created == 3  # repository, commit, analysis
    assert summary.updated == 0
    assert len(client.nodes.get("SourceFile", {})) == 0
    assert len(client.nodes.get("Package", {})) == 0


def test_missing_repository_or_commit_raises() -> None:
    from app.models.ingestion import IngestionLimits, IngestionSummary
    from app.models.repository import RepositoryReference

    service = _service()
    result = IngestionResult(
        status=IngestionStatus.SUCCESS,
        repository=None,
        reference=RepositoryReference(
            requested_ref=None,
            ref_type=ReferenceType.COMMIT,
            resolved_commit_sha=FAKE_SHA,
            resolved_via="provided_commit_sha",
            is_default_branch=False,
            sha_verified=True,
        ),
        source_files=[],
        manifests=[],
        declarations=[],
        resolved_packages=[],
        dependency_edges=[],
        coverage=[],
        warnings=[],
        errors=[],
        summary=IngestionSummary(
            status=IngestionStatus.SUCCESS,
            repository_id="github.com/example/empty",
            commit_sha=FAKE_SHA,
        ),
        limits=IngestionLimits(
            retrieval_strategy=RetrievalStrategy.GIT.value,
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
        ),
    )
    with pytest.raises(ValueError, match="no repository"):
        service.ingest_result_into_graph(result)


def test_graph_failure_propagates_and_is_not_reported_success(tmp_path) -> None:
    result = _ingest_clean(tmp_path)

    class FailingClient(GraphClient):
        def __init__(self):
            self.connected = True

        @property
        def is_connected(self):
            return self.connected

        def query(self, cypher, *, params=None, timeout=None, read_only=False):
            raise GraphError("database is on fire")

        def close(self):
            pass

    service = GraphService(FailingClient())
    with pytest.raises(GraphError):
        service.ingest_result_into_graph(result)


# ---------------------------------------------------------------------------
# Lazy connection of the graph read path
# ---------------------------------------------------------------------------

def test_get_repository_graph_connects_a_not_yet_connected_client() -> None:
    """Regression: the read guard must connect lazily, not raise NameError.

    The production dependency hands ``GraphService`` a fresh ``GraphClient``
    that has not connected yet.  ``GET /analyses/{id}/graph`` must connect it
    and then answer from the result set.
    """
    from app.graph.queries import GET_ANALYSIS, GET_GRAPH

    client = FakeGraphClient()
    assert client.is_connected is False
    client.canned[GET_ANALYSIS] = FakeQueryResult(
        header=["id", "repository_id", "commit_sha", "status"],
        rows=[["analysis_1", "github.com/example/clean", FAKE_SHA, "success"]],
    )
    client.canned[GET_GRAPH] = FakeQueryResult(
        header=["r", "f", "m", "d", "p", "rp", "rt", "e", "t"],
        rows=[["repository", None, None, None, None, None, None, None, None]],
    )

    data = _service(client).get_repository_graph("analysis_1", skip=0, limit=10)

    assert client.is_connected is True
    assert data["columns"][0] == "r"
    assert data["count"] == 1


def test_get_repository_graph_surfaces_typed_connection_failures() -> None:
    """A client that cannot connect yields a typed graph error, not a NameError."""
    from app.graph.errors import GraphUnavailableError

    class RefusingClient(FakeGraphClient):
        def connect(self) -> None:
            raise GraphUnavailableError("FalkorDB is unavailable")

    with pytest.raises(GraphUnavailableError):
        _service(RefusingClient()).get_repository_graph("analysis_1")


def test_graph_read_serialises_driver_nodes_and_edges() -> None:
    """Regression: driver Node/Edge values must become JSON-safe row values.

    ``GET /analyses/{id}/graph`` returns whole nodes and edges; the API's row
    contract is JSON, so the service must expose stable plain dicts instead of
    raw driver objects (which FastAPI cannot serialise).
    """
    from falkordb.edge import Edge
    from falkordb.node import Node

    from app.graph.queries import GET_ANALYSIS, GET_GRAPH

    package = Node(
        node_id=7,
        labels=["Package"],
        properties={"id": "pkg_1", "normalized_name": "requests", "version": "2.31.0"},
    )
    edge = Edge(package, "DEPENDS_ON", package, edge_id=11, properties={"constraint": ">=2"})

    client = FakeGraphClient()
    client.connect()
    client.canned[GET_ANALYSIS] = FakeQueryResult(
        header=["id", "repository_id", "commit_sha", "status"],
        rows=[["analysis_1", "github.com/example/clean", FAKE_SHA, "success"]],
    )
    client.canned[GET_GRAPH] = FakeQueryResult(header=["p", "e"], rows=[[package, edge]])

    data = _service(client).get_repository_graph("analysis_1")

    json.dumps(data)  # the whole payload must be JSON-serialisable
    node = data["rows"][0]["p"]
    assert node["id"] == 7
    assert node["labels"] == ["Package"]
    assert node["properties"]["normalized_name"] == "requests"
    relation = data["rows"][0]["e"]
    assert relation["id"] == 11
    assert relation["type"] == "DEPENDS_ON"
    assert relation["src"] == 7
    assert relation["dst"] == 7
    assert relation["properties"] == {"constraint": ">=2"}
