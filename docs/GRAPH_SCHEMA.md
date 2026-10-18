# BlastRadius Graph Schema (Phase 2)

This document describes the FalkorDB knowledge graph produced by Phase 2 from a
Phase 1 `IngestionResult`.

## Design principles

* **Provenance-aware**: every record carries its repository identity, commit SHA,
  manifest path, line number and evidence, so findings trace back to source.
* **No fabricated data**: a dependency declaration is linked to a resolved
  package only when the lockfile actually states a resolved version.  An exact
  `==` pin in a manifest stays a constraint — it is never turned into a
  resolved version.  Transitive `DEPENDS_ON` edges exist only when supplied by
  a lockfile.
* **Repository isolation**: every node carries `repository_id` and `commit_sha`,
  so graphs for different repositories (or commits) never merge, even when they
  share package names.
* **Idempotent**: re-ingesting the same repository at the same commit upserts
  instead of duplicating nodes or relationships.

## Stable identifiers

Every node uses `stable_id(prefix, *parts)` (`app/models/ids.py`): a SHA-256
digest truncated to 16 hex chars with a typed prefix.  Identifiers are
deterministic for a given repository + commit + record key.

| Node | Id parts |
|------|----------|
| `Repository` | `canonical_id` (e.g. `github.com/psf/requests`) |
| `Commit` | full commit SHA |
| `Analysis` | `canonical_id | commit_sha` |
| `SourceFile` | `canonical_id | commit_sha | path` |
| `DependencyManifest` | `canonical_id | commit_sha | path` |
| `DependencyDeclaration` | `canonical_id | commit_sha | declaration.id` (parser id re-scoped to the analysis) |
| `Package` | `canonical_id | commit_sha | normalized_name | version` |

The `DependencyManifest` and `DependencyDeclaration` ids are derived by the
graph writer, not taken from the ingestion records: Phase 1 ids are relative to
a repository path only, so the same manifest path in two repositories (or two
commits) would otherwise share one node and leak declarations across
analyses.  Re-scoping keeps node identity unique per analysis and idempotent
for repeated persists of the same analysis.

Packages with `version = ""` (no resolved version) are declaration targets that
remain unresolved — they are distinct from resolved packages with the same name
but a concrete version.

## Node types

### Repository
| Property | Source |
|----------|--------|
| `id` | `canonical_id` |
| `canonical_id`, `owner`, `name`, `host` | `RepositoryIdentity` |
| `canonical_url`, `clone_url`, `api_url` | `RepositoryIdentity` |
| `description`, `default_branch`, `is_private`, `is_archived`, `is_fork` | `RepositoryMetadata` |
| `stars`, `forks`, `open_issues`, `size_kb` | `RepositoryMetadata` |
| `license_spdx_id`, `primary_language` | `RepositoryMetadata` |
| `pushed_at`, `created_at` | `RepositoryMetadata` |
| `metadata_source` | `github_api` or `unavailable` |
| `commit_sha` | `reference.resolved_commit_sha` |
| `created_at`, `updated_at` | ingestion timestamps |

### Commit
| Property | Source |
|----------|--------|
| `id`, `sha` | `reference.resolved_commit_sha` |
| `short_sha` | first 12 chars |
| `message`, `author_name`, `committed_at`, `source` | `RepositoryCommit` |

### Analysis
| Property | Source |
|----------|--------|
| `id` | `stable_id("analysis", canonical_id, commit_sha)` |
| `repository_id`, `commit_sha` | from ingestion result |
| `status`, `started_at`, `finished_at`, `duration_ms` | `IngestionSummary` |
| `retrieval_strategy`, `warning_count`, `error_count` | `IngestionSummary` |
| `files_examined`, `manifests_detected`, `declarations`, `resolved_packages`, `dependency_edges` | `IngestionSummary` |
| `unknown_relation_packages`, `dev_declarations`, `optional_declarations`, `conflicting_packages` | `IngestionSummary` |
| `unsupported_formats` | `IngestionSummary.unsupported_formats` |

### SourceFile
| Property | Source |
|----------|--------|
| `id` | `stable_id("file", canonical_id, commit_sha, path)` |
| `path`, `size_bytes`, `sha256`, `manifest_format`, `support_level`, `skipped_reason` | `SourceFile` |

### DependencyManifest
| Property | Source |
|----------|--------|
| `id` | `DependencyManifestRecord.id` or `stable_id("manifest", canonical_id, commit_sha, path)` |
| `path`, `directory`, `format`, `support_level`, `is_lockfile` | `DependencyManifestRecord` |
| `size_bytes`, `sha256`, `status`, `declaration_count`, `resolved_count`, `edge_count` | `DependencyManifestRecord` |
| `requires_python`, `companion_manifest`, `warning_codes`, `error_codes` | `DependencyManifestRecord` |

### DependencyDeclaration
| Property | Source |
|----------|--------|
| `id` | `DependencyDeclaration.id` |
| `repository_id`, `commit_sha` | stamped by the service |
| `original_name`, `normalized_name`, `ecosystem` | declaration |
| `version_constraint`, `constraint_scheme`, `is_exact_pin` | declaration |
| `resolved_version`, `resolved_from` | declaration (None when no lockfile resolution) |
| `referenced_version`, `scope`, `relation`, `extras`, `marker`, `requires_python` | declaration |
| `source_kind`, `source_reference`, `is_direct_url_reference`, `group` | declaration |
| `line_number`, `section`, `evidence` | `DependencyProvenance` |

### Package
| Property | Source |
|----------|--------|
| `id` | `stable_id("pkg", canonical_id, commit_sha, normalized_name, version)` |
| `repository_id`, `commit_sha` | stamped by the service |
| `original_name`, `normalized_name`, `ecosystem`, `version` | `ResolvedPackage` |
| `relation`, `is_dev`, `is_optional`, `is_root_project`, `groups`, `marker`, `requires_python` | `ResolvedPackage` |
| `source_kind`, `source_reference`, `dependency_count`, `source_manifest` | `ResolvedPackage` |

## Relationship types

| Relationship | Meaning | When created |
|--------------|---------|--------------|
| `Repository -[:CONTAINS]-> SourceFile` | file is part of the repository | always for each source file |
| `Repository -[:HAS_MANIFEST]-> DependencyManifest` | manifest detected | always for each manifest |
| `Analysis -[:ANALYZES]-> Repository` | analysis covers repository | always |
| `Analysis -[:AT_COMMIT]-> Commit` | analysis is at a commit | always |
| `Repository -[:HAS_COMMIT]-> Commit` | repository has commit | always |
| `DependencyManifest -[:DECLARES]-> DependencyDeclaration` | manifest declares dependency | always for each declaration |
| `DependencyDeclaration -[:TARGETS]-> Package` | declaration names a package | always (version may be None → unresolved) |
| `DependencyDeclaration -[:RESOLVES_TO]-> Package` | declaration resolves to a concrete version | **only** when `resolved_version` is set and a matching resolved package exists |
| `Package -[:DEPENDS_ON {constraint, to_resolved_version, marker, extras, optional, dev, source_manifest, variant_key}]-> Package` | lockfile dependency edge | only when the lockfile supplies real edges |
| `Package -[:AFFECTED_BY {repository_id, commit_sha, package_name, package_version, ecosystem, match_type, fixed_versions, ranges_json, osv_modified}]-> Vulnerability` | OSV-confirmed vulnerability for the exact resolved version | Phase 3 targeted OSV ingestion (`match_type="version"` only) |

`DEPENDS_ON` relationships carry a `variant_key` derived from the analysis,
source manifest and the edge's own fields (constraint, marker, extras,
optionality, dev scope).  Two recorded edges between the same package pair —
for example conditional variants that differ only by environment marker — are
stored as two relationships instead of collapsing into one, and re-persisting
the same analysis updates the same relationships (idempotent).

## Cypher query examples

```cypher
// All resolved packages and versions for an analysis
MATCH (a:Analysis {id: $analysis_id})-[:AT_COMMIT]->(:Commit {sha: $commit_sha})
MATCH (p:Package {repository_id: $repository_id, commit_sha: $commit_sha})
WHERE p.version IS NOT NULL
RETURN p.normalized_name, p.version

// Dependency edges for an analysis
MATCH (a:Analysis {id: $analysis_id})-[:AT_COMMIT]->(:Commit {sha: $commit_sha})
MATCH (from:Package {repository_id: $repository_id, commit_sha: $commit_sha})
      -[e:DEPENDS_ON]->(to:Package {repository_id: $repository_id, commit_sha: $commit_sha})
RETURN from.normalized_name AS from, to.normalized_name AS to, e.constraint

// Declarations that remain unresolved (no lockfile resolution)
MATCH (d:DependencyDeclaration {repository_id: $repository_id, commit_sha: $commit_sha})
WHERE d.resolved_version IS NULL
RETURN d.original_name, d.version_constraint, d.provenance.section

// Bounded neighbourhood of a package (depth-limited)
MATCH (p:Package {id: $package_id})
MATCH (p)-[e:DEPENDS_ON*1..3]->(neighbor:Package)
RETURN p.normalized_name, collect(neighbor.normalized_name)
```

## Incomplete-data semantics

| Situation | Graph representation |
|-----------|----------------------|
| No lockfile | declarations stored, `TARGETS` to version-less packages, no `RESOLVES_TO`, no `DEPENDS_ON` edges |
| Exact `==` pin only (no lockfile) | stored as `version_constraint` on the declaration; `is_exact_pin=true`; **no** resolved version node created |
| Lockfile present | `Package` nodes with concrete `version`; `RESOLVES_TO` from matching declarations; `DEPENDS_ON` edges |
| Partial/truncated ingestion | `Analysis.status = "partial"`; `warning_count`/`error_count` reflect what was missing; stored data is what was actually extracted |

## Vulnerability intelligence (Phase 3)

Phase 3 attaches OSV.dev vulnerability data to resolved packages.  Access to
OSV is read-only and credential-free, and it is deliberately bounded: no
full-database ingestion, only targeted lookups.

### Design principles

* **Global `:Vulnerability` nodes, repo-scoped edges**: vulnerabilities are
  keyed by their OSV record id and are shared/deduplicated across analyses.
  Every `AFFECTED_BY` relationship starts from a `:Package` node, which
  already carries `repository_id`/`commit_sha`, so repository findings never
  leak across repositories.  The edge also stamps the scope explicitly.
* **Only version-backed claims**: only packages with a *resolved version*
  produce `AFFECTED_BY` edges, and only when OSV itself confirmed that exact
  version is affected (`match_type="version"`).  Name-level (unresolved
  version) lookups are reported as `match_type="name"` and are **never
  written**.
* **No fabricated data**: summaries, severities, references, ranges, aliases
  and timestamps are stored exactly as OSV returned them (after decoding).
  Missing metadata stays absent/unknown — nothing is invented, and a repeated
  sync that receives fewer fields never overwrites stored values with
  missing ones (re-upserts use `COALESCE`).
* **Idempotent**: re-running an ingestion refreshes existing nodes and edges
  instead of duplicating them (`MERGE` keyed by stable ids).

### Node: Vulnerability

Keyed by OSV id (no synthetic id — the OSV record id *is* the stable id).

| Property | Source |
|----------|--------|
| `id` | OSV record id (e.g. `GHSA-...`, `CVE-...`, `PYSEC-...`) |
| `summary`, `details`, `aliases`, `related` | OSV record (text truncated to `BLASTRADIUS_OSV_MAX_DETAILS_LENGTH`; missing = absent) |
| `published`, `modified`, `withdrawn` | OSV timestamps (missing = absent) |
| `severities` | flattened `TYPE score` strings (e.g. `CVSS_V3 CVSS:3.1/AV:N`); never computed by BlastRadius |
| `references` | flattened `TYPE url` strings (capped at `BLASTRADIUS_OSV_MAX_REFERENCES_PER_VULNERABILITY`) |
| `affected_packages` | flattened `ECOSYSTEM:name` keys of the record's OSV `affected` entries |
| `schema_version`, `source` | OSV schema version; always `"osv"` |
| `created_at`, `updated_at` | stamped by the service |

### Relationship: AFFECTED_BY

Dependencies: `(p:Package)-[:AFFECTED_BY]->(v:Vulnerability)`; `p` is a
resolved package (p.version IS NOT NULL) and `match_type="version"` means OSV
was queried with the exact resolved version.

| Property | Source |
|----------|--------|
| `repository_id`, `commit_sha` | scope stamps (mirroring the Package node) |
| `package_name`, `package_version`, `ecosystem` | the resolved package (normalized name + exact version) |
| `match_type` | always `"version"` for stored edges |
| `fixed_versions` | de-duplicated `fixed` versions of the matched OSV affected entry's ranges |
| `ranges_json` | JSON string of the matched OSV affected entry's ranges (evidence trail) |
| `osv_modified` | the record's `modified` timestamp at discovery time |
| `created_at`, `updated_at` | stamped by the service |

### How a targeted ingestion run works

1. The analysis must be persisted; ingestion reads its resolved packages
   (`GET /api/v1/analyses/{id}/packages`).  Packages without a resolved
   version are listed as unresolved and never queried.
2. Discovery uses one batched `POST /v1/querybatch` per `batch_size` chunk
   (followed by per-item pagination through `POST /v1/query` when a chunk
   result carries a `next_page_token`).
3. Full records are hydrated via `GET /v1/vulns/{id}`; ids are deduplicated
   per run and bounded by `BLASTRADIUS_OSV_MAX_VULNERABILITIES_PER_INGEST`.
4. Each hydrated record is re-verified to declare the matched package before
   it may become an edge (defence in depth against upstream drift).
5. Failures never abort the run silently: per-item errors are surfaced as
   typed entries (`kind = discovery | hydrate | decode | package_mismatch |
   name_only`) in the response/cap totals.  A run where *every* discovery
   chunk fails re-raises the upstream error envelope (502/429/504).

### Endpoints (mounted under /api/v1)

| Endpoint | Purpose |
|----------|---------|
| `GET /osv/vulnerabilities?name=&ecosystem=&version=` | live OSV lookup, no graph writes (`confirmed=false` without version) |
| `POST /analyses/{analysis_id}/vulnerabilities` | targeted ingestion; idempotent; returns counts + per-item errors |
| `GET /analyses/{analysis_id}/vulnerabilities` | graph-backed view of affected packages/vulnerabilities |
| `GET /analyses/{analysis_id}/vulnerabilities/blast-radius?depth=&vulnerability_id=` | explainable impact paths (`hop_count=0` = affected package itself) |
| `GET /vulnerabilities/{vulnerability_id}` | stored record details + affected graph components |

### Scope note: vulnerability detail is cross-repository by design

`GET /vulnerabilities/{vulnerability_id}` returns the stored OSV record plus
*every* graph component linked to it through `AFFECTED_BY`, regardless of
which repository or commit the edge was recorded under.  The query is
intentionally undirected and unscoped (`(v)-[rel:AFFECTED_BY]-(p)`): a
vulnerability is a global OSV record shared across analyses, and a consumer
may want to see all affected components everywhere.

Each component row carries its own `repository_id` and `commit_sha`.  Callers
that need an analysis-scoped view should filter those rows by
`repository_id`/`commit_sha`, or use
`GET /analyses/{analysis_id}/vulnerabilities` / `.../blast-radius`, which are
scoped to a single analysis's repository and commit.

### Blast-radius semantics

Impact paths follow `DEPENDS_ON*0..depth` *downstream*: a vulnerable
`(src)` package impacts `(down)` packages that (transitively) depend on it.
Every row carries `vulnerability_id` (the supporting evidence), the hop
chain as preserved package names, and `match_type`/`fixed_versions` from the
edge.  No risk score or severity ranking is computed — only graph facts.

### Configuration defaults

| Variable | Default | Meaning |
|----------|---------|---------|
| `BLASTRADIUS_OSV_BASE_URL` | `https://api.osv.dev` | API base URL (`http://` only for local test doubles) |
| `BLASTRADIUS_OSV_TIMEOUT_SECONDS` / `_CONNECT_TIMEOUT_SECONDS` | `20` / `5` | request/connect timeouts |
| `BLASTRADIUS_OSV_MAX_RETRIES` / `_RETRY_BACKOFF_SECONDS` | `3` / `0.5` | bounded retries for 429/5xx/transport/timeouts; exponential backoff + jitter; `Retry-After` respected |
| `BLASTRADIUS_OSV_BATCH_SIZE` | `50` | `querybatch` chunk size |
| `BLASTRADIUS_OSV_MAX_PAGES_PER_QUERY` | `5` | page-token cap per package query |
| `BLASTRADIUS_OSV_MAX_VULNERABILITIES_PER_INGEST` | `200` | hydrated uniqueness cap (refuses, never truncates) |
| `BLASTRADIUS_OSV_MAX_PACKAGES_PER_INGEST` | `200` | resolved-package scan cap (refuses, never truncates) |
| `BLASTRADIUS_OSV_MAX_DETAILS_LENGTH` | `4000` | text truncation while decoding |
| `BLASTRADIUS_OSV_MAX_REFERENCES_PER_VULNERABILITY` | `50` | reference cap while decoding |

### PyPI name spelling note

BlastRadius normalizes package names (PEP 503).  For PyPI lookups the
normalized name is queried first; when a versioned query finds nothing and
the ingestion knows the *declared* spelling of the package (e.g.
`typing_extensions` vs. `typing-extensions`), exactly one retry is made with
the declared spelling.  Undecodable/paginated records never create invented
versions, and GIT range events (commit SHAs) are never mistaken for fixed
versions.

