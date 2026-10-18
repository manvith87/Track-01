"""Cypher queries and schema allowlists for the BlastRadius graph.

All Cypher strings are static templates: untrusted repository content is never
interpolated into a query.  Dynamic labels and relationship types are validated
against the fixed allowlists below before use.

Schema (documented in docs/GRAPH_SCHEMA.md):

Nodes
-----
(:Repository {id, canonical_id, owner, name, host, canonical_url, clone_url,
             api_url, description, default_branch, is_private, is_archived,
             is_fork, stars, forks, open_issues, size_kb, license_spdx_id,
             primary_language, pushed_at, created_at, metadata_source,
             commit_sha, updated_at})
(:Commit {id, sha, short_sha, message, author_name, committed_at, source,
          updated_at})
(:Analysis {id, repository_id, commit_sha, status, started_at, finished_at,
            duration_ms, retrieval_strategy, warning_count, error_count,
            files_examined, manifests_detected, declarations, resolved_packages,
            dependency_edges, unknown_relation_packages, dev_declarations,
            optional_declarations, conflicting_packages, unsupported_formats,
            created_at, updated_at})
(:SourceFile {id, path, size_bytes, sha256, manifest_format, support_level,
              skipped_reason, updated_at})
(:DependencyManifest {id, path, directory, format, support_level, is_lockfile,
                      size_bytes, sha256, status, declaration_count,
                      resolved_count, edge_count, requires_python,
                      companion_manifest, warning_codes, error_codes, updated_at})
(:DependencyDeclaration {id, repository_id, commit_sha, original_name,
                         normalized_name, ecosystem, version_constraint,
                         constraint_scheme, is_exact_pin, resolved_version,
                         resolved_from, referenced_version, scope, relation,
                         extras, marker, requires_python, source_kind,
                         source_reference, is_direct_url_reference, group,
                         line_number, section, evidence, updated_at})
(:Package {id, repository_id, commit_sha, original_name, normalized_name,
           ecosystem, version, relation, is_dev, is_optional, is_root_project,
           groups, marker, requires_python, source_kind, source_reference,
           dependency_count, source_manifest, updated_at})

Relationships
-------------
(:Repository)-[:CONTAINS]->(:SourceFile)
(:Repository)-[:HAS_MANIFEST]->(:DependencyManifest)
(:Analysis)-[:ANALYZES]->(:Repository)
(:Analysis)-[:AT_COMMIT]->(:Commit)
(:Repository)-[:HAS_COMMIT]->(:Commit)
(:DependencyManifest)-[:DECLARES]->(:DependencyDeclaration)
(:DependencyDeclaration)-[:TARGETS]->(:Package)
(:DependencyDeclaration)-[:RESOLVES_TO]->(:Package)   (only when resolved)
(:Package)-[:DEPENDS_ON {constraint, to_resolved_version, marker, extras,
                         optional, dev, source_manifest}]->(:Package)
"""

from __future__ import annotations

from typing import Final

#: Node labels permitted in dynamically built queries.
NODE_LABELS: Final[tuple[str, ...]] = (
    "Repository",
    "Commit",
    "Analysis",
    "SourceFile",
    "DependencyManifest",
    "DependencyDeclaration",
    "Package",
    "Vulnerability",
)

#: Relationship types permitted in dynamically built queries.
RELATIONSHIP_TYPES: Final[tuple[str, ...]] = (
    "CONTAINS",
    "HAS_MANIFEST",
    "ANALYZES",
    "AT_COMMIT",
    "HAS_COMMIT",
    "DECLARES",
    "TARGETS",
    "RESOLVES_TO",
    "DEPENDS_ON",
    "AFFECTED_BY",
)


def _validate_label(label: str, *, context: str = "label") -> str:
    if label not in NODE_LABELS:
        raise ValueError(f"Unsupported {context}: {label!r} (allowed: {', '.join(NODE_LABELS)})")
    return label


def _validate_rel_type(rel_type: str, *, context: str = "relationship type") -> str:
    if rel_type not in RELATIONSHIP_TYPES:
        raise ValueError(f"Unsupported {context}: {rel_type!r} (allowed: {', '.join(RELATIONSHIP_TYPES)})")
    return rel_type


def _set_clause(prefix: str, keys: list[str], *, on_create: bool = False) -> str:
    """Build a Cypher SET clause with parameterised values.

    ``keys`` are fixed model field names from this module (not user input), so
    interpolating them into the query string is safe.  Every value is bound as a
    parameter.
    """
    op = "ON CREATE SET" if on_create else "ON MATCH SET"
    assignments = [f"{prefix}.{key} = ${key}" for key in keys]
    return f"{op} {', '.join(assignments)}"


# ---------------------------------------------------------------------------
# Read queries
# ---------------------------------------------------------------------------

GET_ANALYSIS = """
MATCH (a:Analysis {id: $analysis_id})
RETURN a.id AS id, a.repository_id AS repository_id, a.commit_sha AS commit_sha,
       a.status AS status, a.started_at AS started_at, a.finished_at AS finished_at,
       a.duration_ms AS duration_ms, a.retrieval_strategy AS retrieval_strategy,
       a.warning_count AS warning_count, a.error_count AS error_count,
       a.files_examined AS files_examined, a.manifests_detected AS manifests_detected,
       a.declarations AS declarations, a.resolved_packages AS resolved_packages,
       a.dependency_edges AS dependency_edges,
       a.unknown_relation_packages AS unknown_relation_packages,
       a.dev_declarations AS dev_declarations,
       a.optional_declarations AS optional_declarations,
       a.conflicting_packages AS conflicting_packages,
       a.unsupported_formats AS unsupported_formats, a.created_at AS created_at,
       a.updated_at AS updated_at
"""

GET_REPOSITORY = """
MATCH (r:Repository {id: $repository_id})
RETURN r.id AS id, r.canonical_id AS canonical_id, r.owner AS owner, r.name AS name,
       r.host AS host, r.canonical_url AS canonical_url, r.clone_url AS clone_url,
       r.api_url AS api_url, r.description AS description,
       r.default_branch AS default_branch, r.is_private AS is_private,
       r.is_archived AS is_archived, r.is_fork AS is_fork, r.stars AS stars,
       r.forks AS forks, r.open_issues AS open_issues, r.size_kb AS size_kb,
       r.license_spdx_id AS license_spdx_id, r.primary_language AS primary_language,
       r.pushed_at AS pushed_at, r.created_at AS created_at,
       r.metadata_source AS metadata_source, r.commit_sha AS commit_sha,
       r.updated_at AS updated_at
"""

GET_COMMIT = """
MATCH (c:Commit {id: $commit_sha})
RETURN c.id AS id, c.sha AS sha, c.short_sha AS short_sha, c.message AS message,
       c.author_name AS author_name, c.committed_at AS committed_at,
       c.source AS source, c.updated_at AS updated_at
"""

GET_FILES = """
MATCH (r:Repository {id: $repository_id})-[:CONTAINS]->(f:SourceFile)
RETURN f.id AS id, f.path AS path, f.size_bytes AS size_bytes,
       f.sha256 AS sha256, f.manifest_format AS manifest_format,
       f.support_level AS support_level, f.skipped_reason AS skipped_reason
SKIP $skip LIMIT $limit
"""

GET_MANIFESTS = """
MATCH (r:Repository {id: $repository_id})-[:HAS_MANIFEST]->(m:DependencyManifest)
RETURN m.id AS id, m.path AS path, m.directory AS directory, m.format AS format,
       m.support_level AS support_level, m.is_lockfile AS is_lockfile,
       m.size_bytes AS size_bytes, m.sha256 AS sha256, m.status AS status,
       m.declaration_count AS declaration_count, m.resolved_count AS resolved_count,
       m.edge_count AS edge_count, m.requires_python AS requires_python,
       m.companion_manifest AS companion_manifest, m.warning_codes AS warning_codes,
       m.error_codes AS error_codes
SKIP $skip LIMIT $limit
"""

GET_DECLARATIONS = """
MATCH (a:Analysis {id: $analysis_id})-[:ANALYZES]->(r:Repository {id: $repository_id})
MATCH (m:DependencyManifest)-[:DECLARES]->(d:DependencyDeclaration)
WHERE d.repository_id = $repository_id AND d.commit_sha = $commit_sha
RETURN d.id AS id, d.original_name AS original_name, d.normalized_name AS normalized_name,
       d.ecosystem AS ecosystem, d.version_constraint AS version_constraint,
       d.constraint_scheme AS constraint_scheme, d.is_exact_pin AS is_exact_pin,
       d.resolved_version AS resolved_version, d.resolved_from AS resolved_from,
       d.referenced_version AS referenced_version, d.scope AS scope,
       d.relation AS relation, d.extras AS extras, d.marker AS marker,
       d.requires_python AS requires_python, d.source_kind AS source_kind,
       d.source_reference AS source_reference,
       d.is_direct_url_reference AS is_direct_url_reference, d.group AS group,
       d.line_number AS line_number, d.section AS section, d.evidence AS evidence,
       m.path AS manifest_path
SKIP $skip LIMIT $limit
"""

GET_PACKAGES = """
MATCH (a:Analysis {id: $analysis_id})-[:AT_COMMIT]->(:Commit {sha: $commit_sha})
MATCH (p:Package {repository_id: $repository_id, commit_sha: $commit_sha})
WHERE p.version IS NOT NULL
RETURN p.id AS id, p.original_name AS original_name,
       p.normalized_name AS normalized_name, p.ecosystem AS ecosystem,
       p.version AS version, p.relation AS relation, p.is_dev AS is_dev,
       p.is_optional AS is_optional, p.is_root_project AS is_root_project,
       p.groups AS groups, p.marker AS marker, p.requires_python AS requires_python,
       p.source_kind AS source_kind, p.source_reference AS source_reference,
       p.dependency_count AS dependency_count, p.source_manifest AS source_manifest
SKIP $skip LIMIT $limit
"""

GET_EDGES = """
MATCH (a:Analysis {id: $analysis_id})-[:AT_COMMIT]->(:Commit {sha: $commit_sha})
MATCH (from:Package {repository_id: $repository_id, commit_sha: $commit_sha})
      -[rel:DEPENDS_ON]->(to:Package {repository_id: $repository_id, commit_sha: $commit_sha})
RETURN from.id AS from_id, from.normalized_name AS from_name, from.version AS from_version,
       to.id AS to_id, to.normalized_name AS to_name, to.version AS to_version,
       rel.constraint AS constraint, rel.to_resolved_version AS to_resolved_version,
       rel.marker AS marker, rel.extras AS extras, rel.optional AS optional,
       rel.dev AS dev, rel.source_manifest AS source_manifest
SKIP $skip LIMIT $limit
"""

GET_GRAPH = """
MATCH (a:Analysis {id: $analysis_id})-[:ANALYZES]->(r:Repository)
OPTIONAL MATCH (r)-[:CONTAINS]->(f:SourceFile)
OPTIONAL MATCH (r)-[:HAS_MANIFEST]->(m:DependencyManifest)
OPTIONAL MATCH (m)-[:DECLARES]->(d:DependencyDeclaration)
OPTIONAL MATCH (d)-[:TARGETS]->(p:Package)
OPTIONAL MATCH (d)-[rt:RESOLVES_TO]->(rp:Package)
OPTIONAL MATCH (p)-[e:DEPENDS_ON]->(t:Package)
RETURN r, f, m, d, p, rp, rt, e, t
SKIP $skip LIMIT $limit
"""

GET_STATISTICS = """
MATCH (a:Analysis {id: $analysis_id})-[:ANALYZES]->(r:Repository {id: $repository_id})
OPTIONAL MATCH (r)-[:CONTAINS]->(f:SourceFile)
WITH r, count(DISTINCT f) AS files
OPTIONAL MATCH (r)-[:HAS_MANIFEST]->(m:DependencyManifest)
WITH r, files, count(DISTINCT m) AS manifests
OPTIONAL MATCH (r)-[:HAS_MANIFEST]->(:DependencyManifest)-[:DECLARES]->(d:DependencyDeclaration)
WITH r, files, manifests, count(DISTINCT d) AS declarations
OPTIONAL MATCH (p:Package {repository_id: $repository_id, commit_sha: $commit_sha})
WITH r, files, manifests, declarations,
     count(DISTINCT CASE WHEN p.version IS NOT NULL THEN p END) AS packages
OPTIONAL MATCH (p1:Package {repository_id: $repository_id, commit_sha: $commit_sha})-[e:DEPENDS_ON]->(:Package {repository_id: $repository_id, commit_sha: $commit_sha})
WITH r, files, manifests, declarations, packages, count(DISTINCT e) AS dependency_edges
OPTIONAL MATCH (p2:Package {repository_id: $repository_id, commit_sha: $commit_sha})-[ve:AFFECTED_BY]->(:Vulnerability)
WITH r, files, manifests, declarations, packages, dependency_edges, count(DISTINCT ve) AS vulnerability_edges
OPTIONAL MATCH (:DependencyDeclaration)-[:RESOLVES_TO]->(p3:Package {repository_id: $repository_id, commit_sha: $commit_sha})
WITH r, files, manifests, declarations, packages, dependency_edges, vulnerability_edges,
     count(DISTINCT p3) AS resolved_packages
RETURN count(DISTINCT r) AS repositories,
       files, manifests, declarations, packages, dependency_edges,
       vulnerability_edges, resolved_packages
"""

def neighborhood_template(depth: int) -> str:
    """Build the neighbourhood query with the traversal depth inlined.

    FalkorDB does not accept a parameter for a variable-length relationship
    bound (``*1..$depth``), so the depth must be an inlined integer literal.
    Untrusted input never reaches this function: the depth is coerced and
    strict-bounded here, and only this one integer is interpolated — every
    other value stays parameterized.
    """
    try:
        bounded = int(depth)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"neighbourhood depth must be an integer, got {depth!r}") from exc
    if not 1 <= bounded <= 5:
        raise ValueError(f"neighbourhood depth must be in [1, 5], got {bounded}")
    return f"""
MATCH (p:Package {{id: $package_id}})
MATCH (p)-[rel:DEPENDS_ON*1..{bounded}]->(neighbor:Package)
RETURN p.id AS package_id, collect(DISTINCT {{
    from: p.normalized_name,
    to: neighbor.normalized_name,
    constraint: rel.constraint,
    to_resolved_version: rel.to_resolved_version
}}) AS edges
"""

# ---------------------------------------------------------------------------
# Vulnerability intelligence (Phase 3)
#
# :Vulnerability nodes are keyed by their OSV record id and are therefore
# shared across analyses.  All AFFECTED_BY links start from :Package nodes,
# which already carry repository_id and commit_sha, so repository findings can
# never leak across repositories.  Edge writes additionally stamp the scope.
# ---------------------------------------------------------------------------

GET_VULNERABILITIES = """
MATCH (a:Analysis {id: $analysis_id})-[:AT_COMMIT]->(:Commit {sha: $commit_sha})
MATCH (p:Package {repository_id: $repository_id, commit_sha: $commit_sha})-[rel:AFFECTED_BY]->(v:Vulnerability)
RETURN p.id AS package_id, p.normalized_name AS package_name, p.version AS package_version,
       p.ecosystem AS ecosystem, p.relation AS package_relation, p.is_dev AS is_dev,
       p.is_optional AS is_optional, p.is_root_project AS is_root_project,
       p.groups AS groups, p.marker AS package_marker, p.source_manifest AS source_manifest,
       v.id AS vulnerability_id, v.summary AS summary,
       v.aliases AS aliases, v.severities AS severities, v.references AS references,
       v.withdrawn AS withdrawn, v.published AS published,
       v.modified AS modified, rel.fixed_versions AS fixed_versions,
       rel.ranges_json AS ranges_json, rel.osv_modified AS osv_modified,
       rel.match_type AS match_type, rel.repository_id AS repository_id,
       rel.commit_sha AS commit_sha, rel.updated_at AS last_synced_at
ORDER BY v.id, p.normalized_name, p.version
SKIP $skip LIMIT $limit
"""

GET_VULNERABILITY = """
MATCH (v:Vulnerability {id: $vulnerability_id})
RETURN v.id AS id, v.summary AS summary, v.details AS details, v.aliases AS aliases,
       v.related AS related, v.published AS published, v.modified AS modified,
       v.withdrawn AS withdrawn, v.severities AS severities, v.references AS references,
       v.affected_packages AS affected_packages, v.schema_version AS schema_version,
       v.source AS source, v.created_at AS created_at, v.updated_at AS updated_at
"""

GET_VULNERABILITY_COMPONENTS = """
MATCH (v:Vulnerability {id: $vulnerability_id})-[rel:AFFECTED_BY]-(p:Package)
RETURN p.id AS package_id, p.normalized_name AS package_name, p.version AS package_version,
       p.ecosystem AS ecosystem, p.repository_id AS repository_id, p.commit_sha AS commit_sha,
       rel.match_type AS match_type, rel.fixed_versions AS fixed_versions,
       rel.updated_at AS last_synced_at
ORDER BY p.repository_id, p.commit_sha, p.normalized_name, p.version
SKIP $skip LIMIT $limit
"""

# Explainable impact paths: packages downstream of a directly affected package
# ( hop_count = 0 is the affected package itself ).
#: Hard ceiling for the impact-path traversal; the API layer bounds depth to
#: 0..5, this guards non-API callers too.
MAX_IMPACT_DEPTH: Final[int] = 5


def _bounded_traversal_depth(depth: int, *, minimum: int, label: str) -> int:
    """Coerce and bound a variable-length traversal depth for inlining.

    FalkorDB does not accept a parameter for a variable-length relationship
    bound (``*1..$depth``), so the depth must be an inlined integer literal.
    Untrusted input never reaches the template builders: the depth is coerced
    and strict-bounded here, and only this one integer is interpolated —
    every other value stays parameterized.
    """
    try:
        bounded = int(depth)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} depth must be an integer, got {depth!r}") from exc
    if not minimum <= bounded <= MAX_IMPACT_DEPTH:
        raise ValueError(
            f"{label} depth must be in [{minimum}, {MAX_IMPACT_DEPTH}], got {bounded}"
        )
    return bounded


def impact_paths_template(depth: int, *, for_vulnerability: bool = False) -> str:
    """Build the impact-path query with the traversal depth inlined.

    FalkorDB does not accept a parameter for a variable-length relationship
    bound (``*0..$depth``), so the depth must be an inlined integer literal.
    Untrusted input never reaches this function: the depth is coerced and
    strict-bounded here, and only this one integer is interpolated — every
    other value stays parameterized.

    ``hop_count == 0`` rows are the affected packages themselves;
    ``for_vulnerability=True`` restricts paths to one vulnerability id.
    """
    try:
        bounded = int(depth)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"impact-path depth must be an integer, got {depth!r}") from exc
    if not 0 <= bounded <= MAX_IMPACT_DEPTH:
        raise ValueError(f"impact-path depth must be in [0, {MAX_IMPACT_DEPTH}], got {bounded}")
    anchor = (
        "MATCH (src)-[rel:AFFECTED_BY]->(v:Vulnerability {id: $vulnerability_id})"
        if for_vulnerability
        else "MATCH (src)-[rel:AFFECTED_BY]->(v:Vulnerability)"
    )
    order = "ORDER BY vulnerability_id, hop_count, downstream_chain" if not for_vulnerability else "ORDER BY hop_count, downstream_chain"
    return f"""
MATCH (a:Analysis {{id: $analysis_id}})-[:AT_COMMIT]->(:Commit {{sha: $commit_sha}})
MATCH (down:Package {{repository_id: $repository_id, commit_sha: $commit_sha}})-[deps:DEPENDS_ON*0..{bounded}]->(src:Package {{repository_id: $repository_id, commit_sha: $commit_sha}})
{anchor}
RETURN v.id AS vulnerability_id, v.summary AS vulnerability_summary,
       src.id AS affected_package_id, src.normalized_name AS affected_package_name,
       src.version AS affected_package_version,
       [n IN nodes(deps) | n.normalized_name] AS downstream_chain,
       length(deps) AS hop_count,
       rel.fixed_versions AS fixed_versions, rel.match_type AS match_type
{order}
SKIP $skip LIMIT $limit
"""

GET_VULNERABILITY_LAST_SYNC = """
MATCH (a:Analysis {id: $analysis_id})-[:AT_COMMIT]->(:Commit {sha: $commit_sha})
MATCH (p:Package {repository_id: $repository_id, commit_sha: $commit_sha})-[rel:AFFECTED_BY]->(v:Vulnerability)
RETURN count(rel) AS vulnerability_edges, max(rel.updated_at) AS last_synced_at
"""

# ---------------------------------------------------------------------------
# Phase 5: deterministic prioritization / remediation inputs
#
# Both queries are analysis-scoped aggregations over the same graph facts the
# Phase 3 reads expose (AFFECTED_BY, DEPENDS_ON); they return one row per
# package instead of per path so callers never depend on path ordering:
#
# * ``modeled_entry_paths_template``  - which direct (or root-project)
#   packages have a modeled DEPENDS_ON path to an affected package, and the
#   shortest path length.
# * ``dependency_impact_summary_template`` - how many distinct packages
#   (transitively) depend on an affected package.
# ---------------------------------------------------------------------------


def modeled_entry_paths_template(depth: int) -> str:
    """Entry-point reachability aggregation bounded at ``depth`` hops.

    An *entry* is a package that a manifest declares directly
    (``relation = 'direct'``) or the lockfile's root project
    (``is_root_project = true``).  Only affected packages are returned, and
    rows stay scoped to one analysis's repository + commit.  The traversal is
    bounded: dependency chains longer than ``depth`` hops are not modelled.
    """
    bounded = _bounded_traversal_depth(depth, minimum=1, label="entry-path")
    return f"""
MATCH (a:Analysis {{id: $analysis_id}})-[:AT_COMMIT]->(:Commit {{sha: $commit_sha}})
MATCH (entry:Package {{repository_id: $repository_id, commit_sha: $commit_sha}})
WHERE entry.relation = 'direct' OR entry.is_root_project = true
MATCH (entry)-[chain:DEPENDS_ON*1..{bounded}]->(target:Package {{repository_id: $repository_id, commit_sha: $commit_sha}})-[:AFFECTED_BY]->(:Vulnerability)
RETURN target.id AS package_id, collect(DISTINCT entry.normalized_name) AS entry_points,
       min(length(chain)) AS min_hops, count(DISTINCT entry) AS entry_count
"""


def dependency_impact_summary_template(depth: int) -> str:
    """Per-affected-package dependent aggregation bounded at ``depth`` hops.

    Counts the distinct packages that (transitively) depend on an affected
    package through :DEPENDS_ON chains, together with the shortest chain
    length.  Counts are computed in the database from the same relationship
    facts the Phase 3 impact-path query traverses; no ordering of path
    internals is relied upon.
    """
    bounded = _bounded_traversal_depth(depth, minimum=1, label="impact-summary")
    return f"""
MATCH (a:Analysis {{id: $analysis_id}})-[:AT_COMMIT]->(:Commit {{sha: $commit_sha}})
MATCH (src:Package {{repository_id: $repository_id, commit_sha: $commit_sha}})-[:AFFECTED_BY]->(:Vulnerability)
MATCH (down:Package {{repository_id: $repository_id, commit_sha: $commit_sha}})-[deps:DEPENDS_ON*1..{bounded}]->(src)
RETURN src.id AS package_id, count(DISTINCT down.id) AS dependent_count,
       collect(DISTINCT down.normalized_name) AS dependents, min(length(deps)) AS min_hops
"""

UPSERT_VULNERABILITY = """
MERGE (n:Vulnerability {id: $id})
ON CREATE SET
    n.summary = COALESCE($summary, n.summary),
    n.details = COALESCE($details, n.details),
    n.aliases = COALESCE($aliases, n.aliases),
    n.related = COALESCE($related, n.related),
    n.published = COALESCE($published, n.published),
    n.modified = COALESCE($modified, n.modified),
    n.withdrawn = COALESCE($withdrawn, n.withdrawn),
    n.severities = COALESCE($severities, n.severities),
    n.references = COALESCE($references, n.references),
    n.affected_packages = COALESCE($affected_packages, n.affected_packages),
    n.schema_version = COALESCE($schema_version, n.schema_version),
    n.source = COALESCE($source, n.source),
    n.created_at = $now
ON MATCH SET
    n.summary = COALESCE($summary, n.summary),
    n.details = COALESCE($details, n.details),
    n.aliases = COALESCE($aliases, n.aliases),
    n.related = COALESCE($related, n.related),
    n.published = COALESCE($published, n.published),
    n.modified = COALESCE($modified, n.modified),
    n.withdrawn = COALESCE($withdrawn, n.withdrawn),
    n.severities = COALESCE($severities, n.severities),
    n.references = COALESCE($references, n.references),
    n.affected_packages = COALESCE($affected_packages, n.affected_packages),
    n.schema_version = COALESCE($schema_version, n.schema_version),
    n.source = COALESCE($source, n.source),
    n.updated_at = $now
RETURN n.id AS id
"""

UPSERT_AFFECTED_BY = """
MATCH (p:Package {id: $package_id})
MATCH (n:Vulnerability {id: $vulnerability_id})
MERGE (p)-[rel:AFFECTED_BY]->(n)
ON CREATE SET
    rel.repository_id = $repository_id,
    rel.commit_sha = $commit_sha,
    rel.package_name = $package_name,
    rel.package_version = $package_version,
    rel.ecosystem = $ecosystem,
    rel.match_type = $match_type,
    rel.fixed_versions = $fixed_versions,
    rel.ranges_json = $ranges_json,
    rel.osv_modified = $osv_modified,
    rel.created_at = $now,
    rel.updated_at = $now
ON MATCH SET
    rel.repository_id = $repository_id,
    rel.commit_sha = $commit_sha,
    rel.package_name = $package_name,
    rel.package_version = $package_version,
    rel.ecosystem = $ecosystem,
    rel.match_type = $match_type,
    rel.fixed_versions = $fixed_versions,
    rel.ranges_json = $ranges_json,
    rel.osv_modified = $osv_modified,
    rel.updated_at = $now
RETURN p.id AS package_id, n.id AS vulnerability_id
"""

# ---------------------------------------------------------------------------
# Administrative
# ---------------------------------------------------------------------------

DELETE_ANALYSIS = """
MATCH (a:Analysis {id: $analysis_id})
DETACH DELETE a
"""

GRAPH_EXISTS = """
RETURN EXISTS { MATCH (:Analysis {id: $analysis_id}) } AS exists
"""


__all__ = [
    "NODE_LABELS",
    "RELATIONSHIP_TYPES",
    "_validate_label",
    "_validate_rel_type",
    "_set_clause",
    "GET_ANALYSIS",
    "GET_REPOSITORY",
    "GET_COMMIT",
    "GET_FILES",
    "GET_MANIFESTS",
    "GET_DECLARATIONS",
    "GET_PACKAGES",
    "GET_EDGES",
    "GET_GRAPH",
    "GET_STATISTICS",
    "neighborhood_template",
    "GET_VULNERABILITIES",
    "GET_VULNERABILITY",
    "GET_VULNERABILITY_COMPONENTS",
    "MAX_IMPACT_DEPTH",
    "impact_paths_template",
    "modeled_entry_paths_template",
    "dependency_impact_summary_template",
    "GET_VULNERABILITY_LAST_SYNC",
    "UPSERT_VULNERABILITY",
    "UPSERT_AFFECTED_BY",
    "DELETE_ANALYSIS",
    "GRAPH_EXISTS",
]
