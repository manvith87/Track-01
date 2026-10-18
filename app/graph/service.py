"""Graph ingestion and query service for BlastRadius Phase 2.

The service consumes a Phase 1 :class:`~app.models.ingestion.IngestionResult`
and persists it into FalkorDB as a provenance-aware knowledge graph.  It is
independent of FastAPI and can be instantiated and tested directly.

Core guarantees:

* **Idempotent** - every node and relationship is keyed by a stable, deterministic
  identifier, so re-ingesting the same result upserts instead of duplicating.
* **No fabricated data** - a declaration is linked to a resolved package only
  when the source result actually states a resolved version; dependency edges
  are persisted only when supplied by the ingestion result; unresolved versions
  remain unresolved.
* **Repository isolation** - every node carries ``repository_id`` and
  ``commit_sha`` so graphs for different repositories (or commits) can never be
  accidentally merged, even when they share package names.
* **Fail loud** - if any part of the graph write fails, the exception
  propagates and ingestion is not reported as successful.  Retrying is safe
  because all writes are idempotent upserts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from app.core.logging import get_logger
from app.graph.client import GraphClient
from app.graph.errors import GraphError, GraphRecordNotFoundError, GraphUnavailableError
from app.graph.queries import (
    NODE_LABELS,
    _validate_label,
    _validate_rel_type,
    GET_ANALYSIS,
    GET_COMMIT,
    GET_DECLARATIONS,
    GET_EDGES,
    GET_FILES,
    GET_GRAPH,
    GET_MANIFESTS,
    GET_PACKAGES,
    GET_REPOSITORY,
    GET_STATISTICS,
    neighborhood_template,
)
from app.models.common import DependencyRelation, DependencyScope, Ecosystem
from app.models.dependencies import (
    DependencyDeclaration,
    ResolvedDependencyEdge,
    ResolvedPackage,
)
from app.models.ingestion import IngestionResult
from app.models.ids import stable_id
from app.models.repository import RepositoryIdentity

_log = get_logger("graph.service")


# ---------------------------------------------------------------------------
# Result summary
# ---------------------------------------------------------------------------

class GraphIngestionSummary(BaseModel):
    """Summary of a graph ingestion run.

    ``created`` / ``updated`` are measured by checking whether each node
    identifier already existed before the upsert.  ``unchanged`` is reported as
    ``0`` because every re-ingestion refreshes node properties; a precise
    unchanged count would require per-node property comparison and is not
    meaningful for an idempotent upsert.  ``rejected`` counts records that
    failed validation and were skipped.
    """

    model_config = ConfigDict(extra="forbid")

    repository_id: str
    analysis_id: str
    status: str
    created: int = Field(default=0, ge=0)
    updated: int = Field(default=0, ge=0)
    unchanged: int = Field(default=0, ge=0)
    rejected: int = Field(default=0, ge=0)
    nodes_created: int = Field(default=0, ge=0)
    relationships_created: int = Field(default=0, ge=0)
    records_ingested: int = Field(default=0, ge=0)
    details: dict[str, dict[str, int]] = Field(default_factory=dict)

    @property
    def total_nodes(self) -> int:
        return self.created + self.updated + self.unchanged


#: Properties (besides the stable ``id``) that may be stored on each node label.
#: Only these field names are ever interpolated into Cypher; they come from the
#: code, never from repository content.  Values are always bound as parameters.
NODE_PROPERTIES: Final[dict[str, tuple[str, ...]]] = {
    "Repository": (
        "canonical_id",
        "owner",
        "name",
        "host",
        "canonical_url",
        "clone_url",
        "api_url",
        "description",
        "default_branch",
        "is_private",
        "is_archived",
        "is_fork",
        "stars",
        "forks",
        "open_issues",
        "size_kb",
        "license_spdx_id",
        "primary_language",
        "pushed_at",
        "metadata_source",
        "commit_sha",
    ),
    "Commit": (
        "sha",
        "short_sha",
        "message",
        "author_name",
        "committed_at",
        "source",
    ),
    "Analysis": (
        "repository_id",
        "commit_sha",
        "status",
        "started_at",
        "finished_at",
        "duration_ms",
        "retrieval_strategy",
        "warning_count",
        "error_count",
        "files_examined",
        "manifests_detected",
        "declarations",
        "resolved_packages",
        "dependency_edges",
        "unknown_relation_packages",
        "dev_declarations",
        "optional_declarations",
        "conflicting_packages",
        "unsupported_formats",
    ),
    "SourceFile": (
        "path",
        "size_bytes",
        "sha256",
        "manifest_format",
        "support_level",
        "skipped_reason",
    ),
    "DependencyManifest": (
        "path",
        "directory",
        "format",
        "support_level",
        "is_lockfile",
        "size_bytes",
        "sha256",
        "status",
        "declaration_count",
        "resolved_count",
        "edge_count",
        "requires_python",
        "companion_manifest",
        "warning_codes",
        "error_codes",
    ),
    "DependencyDeclaration": (
        "repository_id",
        "commit_sha",
        "original_name",
        "normalized_name",
        "ecosystem",
        "version_constraint",
        "constraint_scheme",
        "is_exact_pin",
        "resolved_version",
        "resolved_from",
        "referenced_version",
        "scope",
        "relation",
        "extras",
        "marker",
        "requires_python",
        "source_kind",
        "source_reference",
        "is_direct_url_reference",
        "group",
        "line_number",
        "section",
        "evidence",
    ),
    "Package": (
        "repository_id",
        "commit_sha",
        "original_name",
        "normalized_name",
        "ecosystem",
        "version",
        "relation",
        "is_dev",
        "is_optional",
        "is_root_project",
        "groups",
        "marker",
        "requires_python",
        "source_kind",
        "source_reference",
        "dependency_count",
        "source_manifest",
    ),
    # OSV-sourced record (keyed by the OSV vulnerability id, shared across
    # analyses).  Structured nested data is stored flattened (lists of
    # scalars); ranges currently applying to a specific package ride on the
    # AFFECTED_BY relationship instead of the node.
    "Vulnerability": (
        "summary",
        "details",
        "aliases",
        "related",
        "published",
        "modified",
        "withdrawn",
        "severities",
        "references",
        "affected_packages",
        "schema_version",
        "source",
    ),
}


def _iso(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _clean(value: Any) -> Any:
    """Convert a Pydantic model value into a primitive FalkorDB can store."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):  # type: ignore[name-defined]  (Enum imported below)
        return value.value
    if isinstance(value, (list, tuple, set)):
        return [_clean(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()}
    return str(value)


def _node_reference(node: Any) -> int | str | None:
    """A stable reference to a node value returned by the driver."""
    if node is None:
        return None
    if isinstance(node, int):
        return node
    node_id = getattr(node, "id", None)
    if node_id is not None:
        return node_id
    return str(node)


def _json_safe_value(value: Any) -> Any:
    """Convert one query result value into JSON-serialisable primitives.

    FalkorDB returns graph *nodes* and *edges* as driver objects, which FastAPI
    cannot serialise for the API's ``rows: list[dict]`` contract.  Nodes become
    ``{"id", "labels", "properties"}`` and edges ``{"id", "type", "src", "dst",
    "properties"}`` (``src``/``dst`` reference the nodes' ``id`` values within
    the same response), so graph reads stay JSON-safe and stable regardless of
    driver internals.  Scalars, lists and maps are returned unchanged.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe_value(item) for item in value]
    relation = getattr(value, "relation", None)
    src = getattr(value, "src_node", None)
    dst = getattr(value, "dest_node", None)
    if relation is not None and (src is not None or dst is not None):
        return {
            "id": getattr(value, "id", None),
            "type": str(relation),
            "src": _node_reference(src),
            "dst": _node_reference(dst),
            "properties": _json_safe_value(getattr(value, "properties", None) or {}),
        }
    labels = getattr(value, "labels", None)
    if labels is not None and hasattr(value, "properties"):
        return {
            "id": getattr(value, "id", None),
            "labels": [str(label) for label in labels],
            "properties": _json_safe_value(getattr(value, "properties", None) or {}),
        }
    return str(value)


def _properties(model: Any, *, include: tuple[str, ...]) -> dict[str, Any]:
    """Return the allowed properties of a Pydantic model as clean primitives.

    ``None`` values are omitted so that FalkorDB never stores an explicit null
    property.  Only ``include`` keys (from :data:`NODE_PROPERTIES`) are kept.
    """
    raw = model.model_dump(mode="python")
    cleaned: dict[str, Any] = {}
    for key in include:
        if key in raw:
            value = _clean(raw[key])
            if value is not None:
                cleaned[key] = value
    return cleaned


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


#: Relationship property keys for :DEPENDS_ON (fixed field names, code-defined).
DEPENDS_ON_PROPERTIES: Final[tuple[str, ...]] = (
    "constraint",
    "to_resolved_version",
    "marker",
    "extras",
    "optional",
    "dev",
    "source_manifest",
    "variant_key",
)

#: Relationship property keys for :AFFECTED_BY (vulnerability evidence scoped
#: to the analyzed repository snapshot via the originating :Package node).
AFFECTED_BY_PROPERTIES: Final[tuple[str, ...]] = (
    "repository_id",
    "commit_sha",
    "package_name",
    "package_version",
    "ecosystem",
    "match_type",
    "fixed_versions",
    "ranges_json",
    "osv_modified",
)

#: Per relationship-type property allowlists (code-defined names only).
RELATIONSHIP_PROPERTIES: Final[dict[str, tuple[str, ...]]] = {
    "AFFECTED_BY": AFFECTED_BY_PROPERTIES,
    "DEPENDS_ON": DEPENDS_ON_PROPERTIES,
}


class GraphService:
    """Persist and query ingestion results in FalkorDB."""

    def __init__(self, client: GraphClient) -> None:
        self._client = client

    @property
    def client(self) -> GraphClient:
        """The underlying graph client (exposed for health probes)."""
        return self._client

    # ------------------------------------------------------------------ #
    # identifiers
    # ------------------------------------------------------------------ #
    @staticmethod
    def analysis_id(canonical_id: str, commit_sha: str) -> str:
        return stable_id("analysis", canonical_id, commit_sha)

    @staticmethod
    def file_id(canonical_id: str, commit_sha: str, path: str) -> str:
        return stable_id("file", canonical_id, commit_sha, path)

    @staticmethod
    def manifest_id(canonical_id: str, commit_sha: str, path: str) -> str:
        return stable_id("manifest", canonical_id, commit_sha, path)

    @staticmethod
    def package_id(canonical_id: str, commit_sha: str, normalized_name: str, version: str | None) -> str:
        return stable_id("pkg", canonical_id, commit_sha, normalized_name, version or "")

    @staticmethod
    def declaration_id(canonical_id: str, commit_sha: str, declaration: DependencyDeclaration) -> str:
        """Return the graph-scoped id for one dependency declaration.

        Phase 1 declaration ids are only scoped to a manifest path and source
        location, so two repositories (or two commits) that share a path can
        produce the same id.  Graph nodes must be unique per analysis, so the
        parser id — which already distinguishes repeated declarations — is
        re-scoped with the repository and commit.
        """
        return stable_id("decl", canonical_id, commit_sha, declaration.id)

    # ------------------------------------------------------------------ #
    # low level upserts
    # ------------------------------------------------------------------ #
    def _existing_ids(self, label: str, ids: list[str]) -> set[str]:
        """Return the subset of ``ids`` that already exist as nodes of ``label``."""
        _validate_label(label)
        if not ids:
            return set()
        cypher = f"MATCH (n:{label}) WHERE n.id IN $ids RETURN n.id AS id"
        result = self._client.query(cypher, params={"ids": ids}, read_only=True)
        return {str(row[0]) for row in result.result_set}

    def _upsert_node(self, label: str, properties: dict[str, Any], *, now: str) -> str:
        """Upsert one node, returning its id.

        ``properties`` must contain ``id`` plus any subset of the label's
        allowed properties.  ``None`` values are omitted.
        """
        _validate_label(label)
        node_id = str(properties["id"])
        allowed = NODE_PROPERTIES[label]
        prop_keys = [key for key in allowed if key in properties and properties[key] is not None and key != "id"]
        create_bits = ["n.created_at = $created_at", "n.id = $id"]
        create_bits.extend(f"n.{key} = ${key}" for key in prop_keys)
        match_bits = ["n.updated_at = $updated_at"]
        match_bits.extend(f"n.{key} = ${key}" for key in prop_keys)
        cypher = f"""
        MERGE (n:{label} {{id: $id}})
        ON CREATE SET {', '.join(create_bits)}
        ON MATCH SET {', '.join(match_bits)}
        RETURN n.id AS id
        """
        params: dict[str, Any] = {"id": node_id, "created_at": now, "updated_at": now}
        for key in prop_keys:
            params[key] = properties[key]
        result = self._client.query(cypher, params=params, read_only=False)
        return str(result.result_set[0][0])

    def _upsert_relationship(
        self,
        rel_type: str,
        from_label: str,
        from_id: str,
        to_label: str,
        to_id: str,
        *,
        properties: dict[str, Any] | None = None,
        variant_key: str | None = None,
        now: str,
    ) -> None:
        _validate_rel_type(rel_type)
        _validate_label(from_label)
        _validate_label(to_label)
        allowed = RELATIONSHIP_PROPERTIES.get(rel_type, DEPENDS_ON_PROPERTIES)
        prop_keys = [key for key in allowed if properties and key in properties and properties[key] is not None]
        create_bits = ["rel.created_at = $created_at"]
        match_bits = ["rel.updated_at = $updated_at"]
        create_bits.extend(f"rel.{key} = ${key}" for key in prop_keys)
        match_bits.extend(f"rel.{key} = ${key}" for key in prop_keys)
        # Keep parallel relationship variants distinct: two records can describe
        # the same package pair (e.g. conditional variants that differ only by
        # environment marker).  Including the variant key in the MERGE pattern
        # keeps them as separate relationships while re-persisting the same
        # record still updates its relationship instead of duplicating it.
        pattern = f"(from)-[rel:{rel_type}"
        if variant_key is not None:
            pattern += " {variant_key: $variant_key}"
            create_bits.append("rel.variant_key = $variant_key")
            match_bits.append("rel.variant_key = $variant_key")
        pattern += "]->(to)"
        cypher = f"""
        MATCH (from:{from_label} {{id: $from_id}})
        MATCH (to:{to_label} {{id: $to_id}})
        MERGE {pattern}
        ON CREATE SET {', '.join(create_bits)}
        ON MATCH SET {', '.join(match_bits)}
        RETURN rel
        """
        params: dict[str, Any] = {
            "from_id": from_id,
            "to_id": to_id,
            "created_at": now,
            "updated_at": now,
        }
        if variant_key is not None:
            params["variant_key"] = variant_key
        if properties:
            for key in prop_keys:
                params[key] = properties[key]
        self._client.query(cypher, params=params, read_only=False)

    # ------------------------------------------------------------------ #
    # ingestion
    # ------------------------------------------------------------------ #
    def ingest_result_into_graph(self, result: IngestionResult) -> GraphIngestionSummary:
        """Persist an :class:`IngestionResult` into the graph (idempotent).

        Raises:
            GraphError: if any graph write fails.  The ingestion is *not*
                reported as successful in that case; retrying is safe because
                every write is an idempotent upsert.
        """
        if result is None:
            raise ValueError("ingestion result must not be None")
        repository = result.repository
        if repository is None:
            raise ValueError("ingestion result has no repository; nothing to persist")
        identity: RepositoryIdentity = repository.identity
        canonical_id = identity.canonical_id
        reference = result.reference
        commit_sha = reference.resolved_commit_sha
        if not commit_sha:
            raise ValueError("ingestion result has no resolved commit SHA; nothing to persist")

        now = _now_iso()
        analysis_id = self.analysis_id(canonical_id, commit_sha)
        summary = GraphIngestionSummary(
            repository_id=canonical_id,
            analysis_id=analysis_id,
            status=result.status.value,
        )

        # ------------------------------------------------------------------ #
        # 1. collect nodes to upsert
        # ------------------------------------------------------------------ #
        now = _now_iso()

        repository_props = {"id": canonical_id}
        # Identity fields (owner/name/host/urls/canonical_id) live on the nested
        # ``identity`` model while the metadata fields live on the top-level
        # model; both must be merged or the node would lack its write target.
        repository_props.update(
            _properties(repository.identity, include=NODE_PROPERTIES["Repository"])
        )
        repository_props.update(_properties(repository, include=NODE_PROPERTIES["Repository"]))
        repository_props["commit_sha"] = commit_sha

        commit = repository.commit
        commit_props = {
            "id": commit_sha,
            "sha": commit_sha,
            "short_sha": commit.short_sha or commit_sha[:12],
            "message": commit.message,
            "author_name": commit.author_name,
            "committed_at": _iso(commit.committed_at),
            "source": commit.source,
        }

        summary_props = {
            "id": analysis_id,
            "repository_id": canonical_id,
            "commit_sha": commit_sha,
            "status": result.status.value,
            "started_at": result.summary.started_at,
            "finished_at": result.summary.finished_at,
            "duration_ms": result.summary.duration_ms,
            "retrieval_strategy": result.summary.retrieval_strategy,
            "warning_count": result.summary.warning_count,
            "error_count": result.summary.error_count,
            "files_examined": result.summary.files_examined,
            "manifests_detected": result.summary.manifests_detected,
            "declarations": result.summary.declarations,
            "resolved_packages": result.summary.resolved_packages,
            "dependency_edges": result.summary.dependency_edges,
            "unknown_relation_packages": result.summary.unknown_relation_packages,
            "dev_declarations": result.summary.dev_declarations,
            "optional_declarations": result.summary.optional_declarations,
            "conflicting_packages": result.summary.conflicting_packages,
            "unsupported_formats": result.summary.unsupported_formats,
        }

        file_nodes = [
            {
                "id": self.file_id(canonical_id, commit_sha, source.path),
                "path": source.path,
                "size_bytes": source.size_bytes,
                "sha256": source.sha256,
                "manifest_format": source.manifest_format.value if source.manifest_format else None,
                "support_level": source.support_level.value if source.support_level else None,
                "skipped_reason": source.skipped_reason,
            }
            for source in result.source_files
        ]

        manifest_nodes = []
        for manifest in result.manifests:
            manifest_nodes.append(
                {
                    "id": self.manifest_id(canonical_id, commit_sha, manifest.path),
                    "path": manifest.path,
                    "directory": manifest.directory,
                    "format": manifest.format.value if manifest.format else None,
                    "support_level": manifest.support_level.value,
                    "is_lockfile": manifest.is_lockfile,
                    "size_bytes": manifest.size_bytes,
                    "sha256": manifest.sha256,
                    "status": manifest.status.value,
                    "declaration_count": manifest.declaration_count,
                    "resolved_count": manifest.resolved_count,
                    "edge_count": manifest.edge_count,
                    "requires_python": manifest.requires_python,
                    "companion_manifest": manifest.companion_manifest,
                    "warning_codes": list(manifest.warning_codes),
                    "error_codes": list(manifest.error_codes),
                }
            )

        declaration_nodes = []
        for declaration in result.declarations:
            declaration_nodes.append(
                {
                    "id": self.declaration_id(canonical_id, commit_sha, declaration),
                    "repository_id": declaration.repository_id or canonical_id,
                    "commit_sha": declaration.commit_sha or commit_sha,
                    "original_name": declaration.original_name,
                    "normalized_name": declaration.normalized_name,
                    "ecosystem": declaration.ecosystem.value,
                    "version_constraint": declaration.version_constraint,
                    "constraint_scheme": declaration.constraint_scheme.value,
                    "is_exact_pin": declaration.is_exact_pin,
                    "resolved_version": declaration.resolved_version,
                    "resolved_from": declaration.resolved_from,
                    "referenced_version": declaration.referenced_version,
                    "scope": declaration.scope.value,
                    "relation": declaration.relation.value,
                    "extras": list(declaration.extras),
                    "marker": declaration.marker,
                    "requires_python": declaration.requires_python,
                    "source_kind": declaration.source_kind.value,
                    "source_reference": declaration.source_reference,
                    "is_direct_url_reference": declaration.is_direct_url_reference,
                    "group": declaration.group,
                    "line_number": declaration.provenance.line_number,
                    "section": declaration.provenance.section,
                    "evidence": declaration.provenance.evidence,
                }
            )

        package_nodes: dict[str, dict[str, Any]] = {}
        # Resolved packages first (they carry concrete versions).
        for package in result.resolved_packages:
            pid = self.package_id(
                canonical_id, commit_sha, package.normalized_name, package.version
            )
            package_nodes[pid] = {
                "id": pid,
                "repository_id": package.repository_id or canonical_id,
                "commit_sha": package.commit_sha or commit_sha,
                "original_name": package.original_name,
                "normalized_name": package.normalized_name,
                "ecosystem": package.ecosystem.value,
                "version": package.version,
                "relation": package.relation.value,
                "is_dev": package.is_dev,
                "is_optional": package.is_optional,
                "is_root_project": package.is_root_project,
                "groups": list(package.groups),
                "marker": package.marker,
                "requires_python": package.requires_python,
                "source_kind": package.source_kind.value,
                "source_reference": package.source_reference,
                "dependency_count": package.dependency_count,
                "source_manifest": package.source_manifest,
            }
        # Declaration targets without a resolved version (version = "").
        for declaration in result.declarations:
            pid = self.package_id(canonical_id, commit_sha, declaration.normalized_name, None)
            if pid not in package_nodes:
                package_nodes[pid] = {
                    "id": pid,
                    "repository_id": declaration.repository_id or canonical_id,
                    "commit_sha": declaration.commit_sha or commit_sha,
                    "original_name": declaration.original_name,
                    "normalized_name": declaration.normalized_name,
                    "ecosystem": declaration.ecosystem.value,
                    "version": None,
                    "relation": declaration.relation.value,
                    "is_dev": declaration.scope is DependencyScope.DEV,
                    "is_optional": declaration.scope is DependencyScope.OPTIONAL,
                    "is_root_project": False,
                    "groups": [declaration.group] if declaration.group else [],
                    "marker": declaration.marker,
                    "requires_python": declaration.requires_python,
                    "source_kind": declaration.source_kind.value,
                    "source_reference": declaration.source_reference,
                    "dependency_count": 0,
                    "source_manifest": declaration.provenance.manifest_path,
                }
        # Edge endpoints.
        for edge in result.dependency_edges:
            for name, version in (
                (edge.from_name, edge.from_version),
                (edge.to_name, edge.to_resolved_version),
            ):
                pid = self.package_id(canonical_id, commit_sha, name, version)
                if pid not in package_nodes:
                    package_nodes[pid] = {
                        "id": pid,
                        "repository_id": canonical_id,
                        "commit_sha": commit_sha,
                        "original_name": name,
                        "normalized_name": name,
                        "ecosystem": Ecosystem.PYPI.value,
                        "version": version,
                        "relation": DependencyRelation.UNKNOWN.value,
                        "is_dev": False,
                        "is_optional": False,
                        "is_root_project": False,
                        "groups": [],
                        "marker": None,
                        "requires_python": None,
                        "source_kind": "unknown",
                        "source_reference": None,
                        "dependency_count": 0,
                        "source_manifest": edge.source_manifest,
                    }

        # ------------------------------------------------------------------ #
        # 2. pre-check which nodes already exist (for accurate counts)
        # ------------------------------------------------------------------ #
        def existing_for(label: str, nodes: list[dict[str, Any]]) -> set[str]:
            return self._existing_ids(label, [node["id"] for node in nodes])

        now = _now_iso()
        existing_repository = existing_for("Repository", [repository_props])
        existing_commit = existing_for("Commit", [commit_props])
        existing_analysis = existing_for("Analysis", [summary_props])
        existing_files = existing_for("SourceFile", file_nodes)
        existing_manifests = existing_for("DependencyManifest", manifest_nodes)
        existing_declarations = existing_for("DependencyDeclaration", declaration_nodes)
        existing_packages = existing_for("Package", list(package_nodes.values()))

        def upsert_many(label: str, nodes: list[dict[str, Any]], existing: set[str]) -> tuple[int, int]:
            created = 0
            updated = 0
            for node in nodes:
                self._upsert_node(label, node, now=now)
                if node["id"] in existing:
                    updated += 1
                else:
                    created += 1
            return created, updated

        # ------------------------------------------------------------------ #
        # 3. upsert core nodes
        # ------------------------------------------------------------------ #
        self._upsert_node("Repository", repository_props, now=now)
        self._upsert_node("Commit", commit_props, now=now)
        self._upsert_node("Analysis", summary_props, now=now)

        repo_created = 0 if canonical_id in existing_repository else 1
        repo_updated = 1 if canonical_id in existing_repository else 0
        commit_created = 0 if commit_sha in existing_commit else 1
        commit_updated = 1 if commit_sha in existing_commit else 0
        analysis_created = 0 if analysis_id in existing_analysis else 1
        analysis_updated = 1 if analysis_id in existing_analysis else 0

        files_created, files_updated = upsert_many("SourceFile", file_nodes, existing_files)
        manifests_created, manifests_updated = upsert_many(
            "DependencyManifest", manifest_nodes, existing_manifests
        )
        declarations_created, declarations_updated = upsert_many(
            "DependencyDeclaration", declaration_nodes, existing_declarations
        )
        packages_created, packages_updated = upsert_many(
            "Package", list(package_nodes.values()), existing_packages
        )

        summary.created = (
            repo_created + commit_created + analysis_created + files_created + manifests_created
            + declarations_created + packages_created
        )
        summary.updated = (
            repo_updated + commit_updated + analysis_updated + files_updated + manifests_updated
            + declarations_updated + packages_updated
        )
        summary.nodes_created = summary.created
        summary.records_ingested = summary.created + summary.updated

        # ------------------------------------------------------------------ #
        # 4. upsert relationships
        # ------------------------------------------------------------------ #
        now = _now_iso()
        relationships_created = 0

        def relate(rel_type: str, from_label: str, from_id: str, to_label: str, to_id: str,
                   properties: dict[str, Any] | None = None,
                   variant_key: str | None = None) -> None:
            nonlocal relationships_created
            self._upsert_relationship(
                rel_type, from_label, from_id, to_label, to_id,
                properties=properties, variant_key=variant_key, now=now,
            )
            relationships_created += 1

        relate("ANALYZES", "Analysis", analysis_id, "Repository", canonical_id)
        relate("AT_COMMIT", "Analysis", analysis_id, "Commit", commit_sha)
        relate("HAS_COMMIT", "Repository", canonical_id, "Commit", commit_sha)

        for source in result.source_files:
            relate("CONTAINS", "Repository", canonical_id, "SourceFile",
                   self.file_id(canonical_id, commit_sha, source.path))
        for manifest in result.manifests:
            mid = self.manifest_id(canonical_id, commit_sha, manifest.path)
            relate("HAS_MANIFEST", "Repository", canonical_id, "DependencyManifest", mid)

        # Resolved-package lookup for RESOLVES_TO edges.
        resolved_by_name_version = {
            (package.normalized_name, package.version): package
            for package in result.resolved_packages
        }

        for declaration in result.declarations:
            did = self.declaration_id(canonical_id, commit_sha, declaration)
            mid = self.manifest_id(canonical_id, commit_sha, declaration.provenance.manifest_path)
            relate("DECLARES", "DependencyManifest", mid, "DependencyDeclaration", did)
            # TARGETS: declaration -> package by name (version may be None).
            target_pid = self.package_id(canonical_id, commit_sha, declaration.normalized_name, None)
            relate("TARGETS", "DependencyDeclaration", did, "Package", target_pid)
            # RESOLVES_TO: only when the source result states a resolved version
            # AND an actual resolved package with that version exists.
            resolved_version = declaration.resolved_version
            if resolved_version and (declaration.normalized_name, resolved_version) in resolved_by_name_version:
                resolve_pid = self.package_id(canonical_id, commit_sha, declaration.normalized_name, resolved_version)
                relate("RESOLVES_TO", "DependencyDeclaration", did, "Package", resolve_pid)

        for edge in result.dependency_edges:
            from_pid = self.package_id(canonical_id, commit_sha, edge.from_name, edge.from_version)
            to_pid = self.package_id(canonical_id, commit_sha, edge.to_name, edge.to_resolved_version)
            # One relationship per recorded dependency edge: variants that share
            # the package pair but differ in constraint, marker, extras,
            # optionality, dev scope or source manifest stay separate.
            variant_key = stable_id(
                "edge",
                canonical_id,
                commit_sha,
                edge.source_manifest,
                edge.from_name,
                edge.from_version,
                edge.to_name,
                edge.to_resolved_version,
                edge.to_version_constraint,
                edge.marker,
                tuple(sorted(edge.extras)),
                edge.optional,
                edge.dev,
            )
            relate(
                "DEPENDS_ON",
                "Package",
                from_pid,
                "Package",
                to_pid,
                properties={
                    "constraint": edge.to_version_constraint,
                    "to_resolved_version": edge.to_resolved_version,
                    "marker": edge.marker,
                    "extras": list(edge.extras),
                    "optional": edge.optional,
                    "dev": edge.dev,
                    "source_manifest": edge.source_manifest,
                },
                variant_key=variant_key,
            )

        summary.relationships_created = relationships_created
        summary.details = {
            "repository": {"created": repo_created, "updated": repo_updated},
            "commit": {"created": commit_created, "updated": commit_updated},
            "analysis": {"created": analysis_created, "updated": analysis_updated},
            "files": {"created": files_created, "updated": files_updated},
            "manifests": {"created": manifests_created, "updated": manifests_updated},
            "declarations": {"created": declarations_created, "updated": declarations_updated},
            "packages": {"created": packages_created, "updated": packages_updated},
            "relationships": {"created": relationships_created},
        }

        _log.info(
            "graph ingested repository=%s analysis=%s created=%d updated=%d rejected=%d relationships=%d",
            canonical_id,
            analysis_id,
            summary.created,
            summary.updated,
            summary.rejected,
            relationships_created,
        )
        return summary

    # ------------------------------------------------------------------ #
    # queries
    # ------------------------------------------------------------------ #
    def get_repository_graph(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
        """Return a bounded graph representation of one analysis."""
        self._require_connected()
        analysis = self.get_analysis_graph_status(analysis_id)
        repository_id = analysis.get("repository_id")
        result = self._client.query(
            GET_GRAPH,
            params={"analysis_id": analysis_id, "skip": skip, "limit": limit},
            read_only=True,
        )
        return self._graph_result_to_dict(result)

    def get_repository_packages(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
        """Return package declarations and known resolved versions."""
        analysis = self.get_analysis_graph_status(analysis_id)
        repository_id = analysis.get("repository_id")
        commit_sha = analysis.get("commit_sha")
        if not repository_id or not commit_sha:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} has no associated repository/commit",
                details={"analysis_id": analysis_id},
            )
        result = self._client.query(
            GET_PACKAGES,
            params={
                "repository_id": repository_id,
                "analysis_id": analysis_id,
                "commit_sha": commit_sha,
                "skip": skip,
                "limit": limit,
            },
            read_only=True,
        )
        return self._graph_result_to_dict(result)

    def get_dependency_edges(self, analysis_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
        """Return dependency edges established by the ingestion data."""
        analysis = self.get_analysis_graph_status(analysis_id)
        repository_id = analysis.get("repository_id")
        commit_sha = analysis.get("commit_sha")
        if not repository_id or not commit_sha:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} has no associated repository/commit",
                details={"analysis_id": analysis_id},
            )
        result = self._client.query(
            GET_EDGES,
            params={
                "repository_id": repository_id,
                "analysis_id": analysis_id,
                "commit_sha": commit_sha,
                "skip": skip,
                "limit": limit,
            },
            read_only=True,
        )
        return self._graph_result_to_dict(result)

    def get_graph_statistics(self, analysis_id: str) -> dict[str, Any]:
        """Return actual counts of nodes and relationships for one analysis."""
        analysis = self.get_analysis_graph_status(analysis_id)
        repository_id = analysis.get("repository_id")
        commit_sha = analysis.get("commit_sha")
        if not repository_id or not commit_sha:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} has no associated repository/commit",
                details={"analysis_id": analysis_id},
            )
        result = self._client.query(
            GET_STATISTICS,
            params={"repository_id": repository_id, "analysis_id": analysis_id, "commit_sha": commit_sha},
            read_only=True,
        )
        rows = result.result_set
        if not rows:
            return {
                "repositories": 0, "files": 0, "manifests": 0, "declarations": 0,
                "packages": 0, "dependency_edges": 0, "resolved_packages": 0,
                "vulnerability_edges": 0,
            }
        header = result.header
        row = rows[0]
        stats = {}
        for index, column in enumerate(header):
            name = GraphService._column_name(column)
            stats[name] = row[index]
        return {
            "repositories": int(stats.get("repositories", 0) or 0),
            "files": int(stats.get("files", 0) or 0),
            "manifests": int(stats.get("manifests", 0) or 0),
            "declarations": int(stats.get("declarations", 0) or 0),
            "packages": int(stats.get("packages", 0) or 0),
            "dependency_edges": int(stats.get("dependency_edges", 0) or 0),
            "resolved_packages": int(stats.get("resolved_packages", 0) or 0),
            "vulnerability_edges": int(stats.get("vulnerability_edges", 0) or 0),
        }

    def get_analysis_graph_status(self, analysis_id: str) -> dict[str, Any]:
        """Return graph ingestion status and incomplete-data indicators."""
        result = self._client.query(
            GET_ANALYSIS,
            params={"analysis_id": analysis_id},
            read_only=True,
        )
        if not result.result_set:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} is not persisted in the graph",
                details={"analysis_id": analysis_id},
            )
        return self._row_to_dict(GET_ANALYSIS, result)

    def get_repository(self, repository_id: str) -> dict[str, Any]:
        result = self._client.query(
            GET_REPOSITORY,
            params={"repository_id": repository_id},
            read_only=True,
        )
        if not result.result_set:
            raise GraphRecordNotFoundError(
                f"Repository {repository_id!r} is not persisted in the graph",
                details={"repository": repository_id},
            )
        return self._row_to_dict(GET_REPOSITORY, result)

    def get_commit(self, commit_sha: str) -> dict[str, Any]:
        result = self._client.query(
            GET_COMMIT,
            params={"commit_sha": commit_sha},
            read_only=True,
        )
        if not result.result_set:
            raise GraphRecordNotFoundError(
                f"Commit {commit_sha!r} is not persisted in the graph",
                details={"commit_sha": commit_sha},
            )
        return self._row_to_dict(GET_COMMIT, result)

    def get_dependency_neighborhood(self, package_id: str, depth: int = 1) -> dict[str, Any]:
        """Return a bounded neighborhood of a package via DEPENDS_ON edges."""
        if depth < 1:
            depth = 1
        if depth > 5:
            depth = 5
        result = self._client.query(
            neighborhood_template(depth),
            params={"package_id": package_id},
            read_only=True,
        )
        return self._graph_result_to_dict(result)

    def get_files(self, repository_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
        result = self._client.query(
            GET_FILES,
            params={"repository_id": repository_id, "skip": skip, "limit": limit},
            read_only=True,
        )
        return self._graph_result_to_dict(result)

    def get_manifests(self, repository_id: str, *, skip: int = 0, limit: int = 200) -> dict[str, Any]:
        result = self._client.query(
            GET_MANIFESTS,
            params={"repository_id": repository_id, "skip": skip, "limit": limit},
            read_only=True,
        )
        return self._graph_result_to_dict(result)

    def get_declarations(self, analysis_id: str, *,
                         skip: int = 0, limit: int = 200) -> dict[str, Any]:
        analysis = self.get_analysis_graph_status(analysis_id)
        repository_id = analysis.get("repository_id")
        commit_sha = analysis.get("commit_sha")
        if not repository_id or not commit_sha:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} has no associated repository/commit",
                details={"analysis_id": analysis_id},
            )
        result = self._client.query(
            GET_DECLARATIONS,
            params={
                "repository_id": repository_id,
                "analysis_id": analysis_id,
                "commit_sha": commit_sha,
                "skip": skip,
                "limit": limit,
            },
            read_only=True,
        )
        return self._graph_result_to_dict(result)

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _require_connected(self) -> None:
        """Ensure the graph client has an open connection.

        The client connects lazily, so a not-yet-connected client is connected
        here; connection failures surface as typed
        :class:`~app.graph.errors.GraphError` subclasses raised by ``connect``.
        """
        if not self._client.is_connected:
            self._client.connect()
        if not self._client.is_connected:
            raise GraphUnavailableError(
                "Graph client is not connected",
                details={"operation": "query"},
            )

    def get_analysis_status(self, analysis_id: str) -> dict[str, Any] | None:
        try:
            return self.get_analysis_graph_status(analysis_id)
        except GraphRecordNotFoundError:
            return None

    @staticmethod
    def _column_name(column: Any) -> str:
        """Extract the column name from a FalkorDB header entry.

        FalkorDB returns column headers as ``[1, 'column_name']`` lists/tuples
        rather than plain strings.  Handle both formats robustly.
        """
        if isinstance(column, (list, tuple)) and len(column) >= 2:
            return str(column[1])
        return str(column).split(":")[0]

    @staticmethod
    def _row_to_dict(query: str, result: Any) -> dict[str, Any]:
        if not result.result_set:
            return {}
        header = result.header
        row = result.result_set[0]
        record: dict[str, Any] = {}
        for index, column in enumerate(header):
            name = GraphService._column_name(column)
            record[name] = _json_safe_value(row[index])
        return record

    @staticmethod
    def _graph_result_to_dict(result: Any) -> dict[str, Any]:
        header = result.header
        columns = [GraphService._column_name(column) for column in header]
        rows: list[dict[str, Any]] = []
        for record in result.result_set:
            rows.append(
                {columns[index]: _json_safe_value(value) for index, value in enumerate(record)}
            )
        return {
            "columns": columns,
            "rows": rows,
            "count": len(rows),
            "run_time_ms": result.run_time_ms,
        }


__all__ = [
    "GraphIngestionSummary",
    "GraphService",
]
