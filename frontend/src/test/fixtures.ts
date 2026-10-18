/**
 * Recorded response shapes used by the component tests.
 *
 * Values mirror the real payloads observed from the running backend
 * (analysis_9ea623c6550a26c0, github.com/example/demo) so the UI is exercised
 * against realistic contracts, not invented structures.
 */

const COMMIT_SHA = "b".repeat(40);
export const ANALYSIS_ID = "analysis_9ea623c6550a26c0";
const REPOSITORY_ID = "github.com/example/demo";
export const VULN_ID = "GHSA-aaaa-bbbb-cccc";

export const repositoryTarget = {
  host: "github.com",
  owner: "example",
  name: "demo",
  full_name: "example/demo",
  canonical_id: REPOSITORY_ID,
  canonical_url: "https://github.com/example/demo",
};

export const graphStatus = {
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  status: "persisted",
  created_at: "2026-01-02T03:04:05Z",
  updated_at: "2026-01-02T03:04:06Z",
};

export const graphHealth = {
  connected: true,
  connection: "falkordb://127.0.0.1:6379",
  graph: "blastradius",
  error: null,
};

export const graphStatistics = {
  repositories: 1,
  files: 12,
  manifests: 2,
  declarations: 3,
  packages: 4,
  dependency_edges: 5,
  resolved_packages: 4,
  vulnerability_edges: 1,
};

// A single graph row is a full path: repository → file → manifest →
// declaration → package → (resolved package | dependency target).
export const graphRow = {
  r: {
    id: 1,
    labels: ["Repository"],
    properties: {
      id: REPOSITORY_ID,
      canonical_url: "https://github.com/example/demo",
      commit_sha: COMMIT_SHA,
      metadata_source: "github_api",
    },
  },
  f: {
    id: 2,
    labels: ["SourceFile"],
    properties: {
      id: "file_1",
      path: "requirements.txt",
      size_bytes: 120,
      manifest_format: "requirements.txt",
      support_level: "supported",
    },
  },
  m: {
    id: 3,
    labels: ["DependencyManifest"],
    properties: {
      id: "manifest_1",
      path: "requirements.txt",
      format: "requirements.txt",
      status: "parsed",
      declaration_count: 3,
      is_lockfile: false,
    },
  },
  d: {
    id: 4,
    labels: ["DependencyDeclaration"],
    properties: {
      id: "decl_1",
      original_name: "requests",
      normalized_name: "requests",
      version_constraint: ">=2.31",
      constraint_scheme: "pep440",
      line_number: 1,
      section: null,
      evidence: "requests>=2.31",
    },
  },
  p: {
    id: 5,
    labels: ["Package"],
    properties: { id: "pkg_1", normalized_name: "requests", version: "2.31.0", relation: "direct" },
  },
  rp: {
    id: 6,
    labels: ["Package"],
    properties: { id: "pkg_2", normalized_name: "urllib3", version: "2.0.7" },
  },
  rt: { id: 7, type: "RESOLVES_TO", src: 5, dst: 6, properties: {} },
  e: { id: 8, type: "DEPENDS_ON", src: 5, dst: 9, properties: { constraint: ">=1.26" } },
  t: {
    id: 9,
    labels: ["Package"],
    properties: { id: "pkg_3", normalized_name: "certifi", version: "2024.2.2" },
  },
};

export const graphRecord = {
  columns: ["r", "f", "m", "d", "p", "rp", "rt", "e", "t"],
  rows: [graphRow],
  count: 1,
  run_time_ms: 12.5,
};

export const emptyGraphRecord = { columns: ["r"], rows: [], count: 0, run_time_ms: 3.0 };

export const vulnerabilitiesResponse = {
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  count: 1,
  last_synced_at: "2026-01-04T00:00:00Z",
  items: [
    {
      vulnerability_id: VULN_ID,
      summary: "Proxy header leak in requests",
      package_id: "pkg_1",
      package_name: "requests",
      package_version: "2.31.0",
      ecosystem: "PyPI",
      match_type: "version",
      fixed_versions: ["2.32.0"],
      aliases: ["CVE-2024-0001"],
      severities: [{ type: "CVSS_V3", score: "9.8" }],
      published: "2024-01-01T00:00:00Z",
      modified: "2026-01-03T00:00:00Z",
      last_synced_at: "2026-01-04T00:00:00Z",
    },
  ],
};

export const blastRadiusResponse = {
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  depth: 2,
  count: 1,
  paths: [
    {
      vulnerability_id: VULN_ID,
      vulnerability_summary: "Proxy header leak in requests",
      affected_package_id: "pkg_1",
      affected_package_name: "requests",
      affected_package_version: "2.31.0",
      downstream_chain: ["certifi"],
      hop_count: 2,
      match_type: "version",
      fixed_versions: ["2.32.0"],
    },
  ],
};

const analysisContext = {
  analysis_status: "partial",
  complete: false,
  warning_count: 1,
  error_count: 0,
  resolved_packages: 4,
  dependency_edges: 5,
  vulnerability_edges: 1,
  declaration_targets_without_version: 1,
  notes: ["One declaration could not be matched against a resolved version."],
};

const finding = {
  finding_id: "finding_1",
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  vulnerability_id: VULN_ID,
  vulnerability_summary: "Proxy header leak in requests",
  aliases: ["CVE-2024-0001"],
  advisory_references: ["WEB https://osv.dev/GHSA-aaaa-bbbb-cccc"],
  advisory_withdrawn: false,
  package: {
    package_id: "pkg_1",
    package_name: "requests",
    package_version: "2.31.0",
    ecosystem: "PyPI",
    dependency_role: "direct",
    is_dev: false,
    is_optional: false,
    is_root_project: false,
    source_manifest: "poetry.lock",
  },
  match_type: "version",
  fixed_versions: ["2.32.0"],
  osv_modified: "2026-01-03T00:00:00Z",
  last_synced_at: "2026-01-04T00:00:00Z",
  priority: {
    score: 8.5,
    formula_version: "priority-v1",
    rank: 1,
    factors: [
      {
        name: "advisory_severity",
        weight: 0.4,
        normalized: 0.9,
        contribution: 0.36,
        raw: { numeric_score: 9.8 },
        notes: [],
      },
      {
        name: "reachability",
        weight: 0.35,
        normalized: 1,
        contribution: 0.35,
        raw: { status: "direct" },
      },
    ],
    severity: {
      source: "OSV",
      quantified: true,
      numeric_score: 9.8,
      score_type: "CVSS_V3",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      entries: ["CVSS_V3 9.8"],
      note: null,
    },
    reachability: {
      status: "direct",
      entry_points: ["pkg_1"],
      min_hops: 0,
      dependent_component_count: 3,
      dependent_components: ["urllib3", "certifi"],
      dependent_components_truncated: false,
      scope_exposure: "runtime",
      evidence_available: true,
      notes: [],
    },
    remediation_available: true,
    remediation_note: null,
  },
  confidence: "verified",
  confidence_reasons: ["Version-matched from the lockfile."],
  limitations: [],
};

export const findingsResponse = {
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  total: 2,
  count: 2,
  skip: 0,
  limit: 50,
  analysis_context: analysisContext,
  findings: [
    finding,
    {
      ...finding,
      finding_id: "finding_2",
      vulnerability_id: "GHSA-dddd-eeee-ffff",
      aliases: [],
      advisory_withdrawn: true,
      package: { ...finding.package, package_name: "flask", package_version: "2.0.0" },
      priority: {
        ...finding.priority,
        score: 3.25,
        rank: 2,
        remediation_available: false,
        severity: {
          source: "OSV",
          quantified: false,
          numeric_score: null,
          score_type: null,
          vector: null,
          entries: ["MODERATE"],
          note: null,
        },
        reachability: {
          status: "unavailable",
          entry_points: [],
          min_hops: null,
          dependent_component_count: 0,
          dependent_components: [],
          dependent_components_truncated: false,
          scope_exposure: null,
          evidence_available: false,
          notes: ["Reachability could not be modeled from the stored graph."],
        },
      },
    },
  ],
  limitations: [],
};

const candidate = {
  package_id: "pkg_1",
  package_name: "requests",
  ecosystem: "PyPI",
  current_version: "2.31.0",
  proposed_version: "2.32.0",
  origin: "osv_fixed",
  dependency_role: "direct",
  selected: true,
  resolves: [
    {
      vulnerability_id: VULN_ID,
      status: "resolves",
      detail: "2.32.0 is at or above the advisory fixed version.",
      fixed_versions: ["2.32.0"],
      affected_intervals_reconstructed: 1,
    },
  ],
  resolved_finding_ids: ["finding_1"],
  unknown_finding_ids: [],
  unresolved_finding_ids: [],
  constraint_checks: [
    {
      source: "requirements.txt",
      origin: "declaration",
      constraint: ">=2.31",
      scheme: "pep440",
      satisfied: true,
      detail: "2.32.0 satisfies >=2.31.",
    },
  ],
  compatibility: "constraints_satisfied",
  compatibility_detail: "All declared ranges accept 2.32.0 (no resolver was executed).",
  resolver_executed: false,
  limitations: [],
};

export const findingDetailResponse = {
  finding,
  remediation: {
    package_id: "pkg_1",
    package_name: "requests",
    current_version: "2.31.0",
    ecosystem: "PyPI",
    dependency_role: "direct",
    finding_ids: ["finding_1"],
    candidates: [candidate],
    no_candidate_reason: null,
    unresolved_relationships: [],
    migration_concerns: [],
    limitations: [],
  },
  limitations: [],
};

export const fixGroup = {
  group_id: "group_1",
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  package_id: "pkg_1",
  package_name: "requests",
  ecosystem: "PyPI",
  current_version: "2.31.0",
  proposed_version: "2.32.0",
  dependency_role: "direct",
  coverage: "confirmed_advisory",
  verified_resolved_finding_ids: ["finding_1"],
  potential_resolved_finding_ids: [],
  unresolved_finding_ids: ["finding_2"],
  resolved_findings: [finding],
  advisory_evidence: [
    {
      vulnerability_id: VULN_ID,
      summary: "Proxy header leak in requests",
      fixed_versions: ["2.32.0"],
      match_type: "version",
      osv_modified: "2026-01-03T00:00:00Z",
    },
  ],
  affected_components: ["pkg_1", "pkg_2"],
  affected_components_truncated: false,
  entry_points: ["pkg_1"],
  compatibility: "constraints_satisfied",
  constraint_checks: candidate.constraint_checks,
  unresolved_relationships: [],
  migration_concerns: [],
  limitations: [],
  candidates: [candidate],
  ranking: {
    rank: 1,
    verified_resolved_count: 1,
    verified_resolved_priority_sum: 8.5,
    reachable_resolved_count: 1,
    compatibility_tier: 2,
    compatibility_tier_label: "constraints satisfied",
    highest_finding_priority: 8.5,
  },
};

export const fixGroupsResponse = {
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  count: 1,
  total: 1,
  skip: 0,
  limit: 25,
  analysis_context: analysisContext,
  groups: [fixGroup],
  unresolved_findings: [
    {
      finding_id: "finding_2",
      vulnerability_id: "GHSA-dddd-eeee-ffff",
      package_name: "flask",
      package_version: "2.0.0",
      reason: "The advisory carries no fixed version, so no candidate exists.",
    },
  ],
  unresolved_findings_truncated: false,
  limitations: [],
};

export const fixGroupDetailResponse = { group: fixGroup, limitations: [] };

export const remediationCandidatesResponse = {
  analysis_id: ANALYSIS_ID,
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  count: 1,
  total: 1,
  skip: 0,
  limit: 25,
  analysis_context: analysisContext,
  plans: [
    {
      package_id: "pkg_1",
      package_name: "requests",
      current_version: "2.31.0",
      ecosystem: "PyPI",
      dependency_role: "direct",
      finding_ids: ["finding_1"],
      candidates: [candidate],
      no_candidate_reason: null,
      unresolved_relationships: [],
      migration_concerns: [],
      limitations: [],
    },
  ],
  limitations: [],
};

export const agentResponse = {
  analysis_id: ANALYSIS_ID,
  answer: "requests 2.31.0 is affected by GHSA-aaaa-bbbb-cccc and has a modeled path from the root project.",
  grounded: true,
  incomplete: false,
  rounds_used: 2,
  tool_calls: [
    {
      round_index: 1,
      name: "get_blast_radius",
      status: "ok",
      reason: null,
      result_chars: 120,
      arguments: { analysis_id: ANALYSIS_ID, depth: 2 },
    },
  ],
  evidence: [
    {
      round_index: 1,
      tool: "get_blast_radius",
      sequence: 1,
      excerpt: "requests 2.31.0 -> certifi (2 hops)",
      result_chars: 28,
    },
  ],
  limitations: ["Paths are bounded by the relationships stored in the graph."],
  repository_id: REPOSITORY_ID,
  commit_sha: COMMIT_SHA,
  advisory_links: [VULN_ID],
};

export const issuePreview = {
  action_id: "action_1a2b3c",
  state: "PREVIEWED",
  template_version: "issue-template-v1",
  created_at: "2026-01-04T10:00:00Z",
  expires_at: "2026-01-04T10:15:00Z",
  payload_digest: "d".repeat(64),
  repository: repositoryTarget,
  commit_sha: COMMIT_SHA,
  analysis_id: ANALYSIS_ID,
  selection: { group_id: "group_1", finding_id: null },
  title: "[BlastRadius] Upgrade requests 2.31.0 → 2.32.0 (1 advisory-confirmed finding)",
  body: "## Summary\n\nThis issue was prepared by BlastRadius from analysis_9ea623c6550a26c0.\n\n- Advisory: GHSA-aaaa-bbbb-cccc\n- Package: requests 2.31.0 → 2.32.0\n",
  coverage: "confirmed_advisory",
  compatibility: "constraints_satisfied",
  verified_finding_count: 1,
  potential_finding_count: 0,
  limitations: ["Constraint checks are declarative; no resolver was executed."],
  notes: ["Preview only — no request has been sent to GitHub."],
};

export const issueConfirm = {
  action_id: "action_1a2b3c",
  state: "SUCCEEDED",
  repository: repositoryTarget,
  analysis_id: ANALYSIS_ID,
  commit_sha: COMMIT_SHA,
  title: issuePreview.title,
  issue_number: 42,
  issue_url: "https://github.com/example/demo/issues/42",
  created: true,
  reconciled: false,
  executed_at: "2026-01-04T10:05:00Z",
};

export const ingestResponse = {
  analysis_id: ANALYSIS_ID,
  status: "partial",
  repository_url: "https://github.com/example/demo",
  repository: {
    identity: {
      host: "github.com",
      owner: "example",
      name: "demo",
      canonical_id: REPOSITORY_ID,
      canonical_url: "https://github.com/example/demo",
      clone_url: "https://github.com/example/demo.git",
      api_url: "https://api.github.com/repos/example/demo",
    },
    commit: {
      sha: COMMIT_SHA,
      short_sha: "bbbbbbbbbbbb",
      message: "Initial import",
      author_name: "Dev",
      committed_at: "2026-01-02T03:04:05Z",
      source: "github_api",
    },
    reference: {
      requested_ref: null,
      ref_type: "default_branch",
      resolved_commit_sha: COMMIT_SHA,
      is_default_branch: true,
      resolved_via: "github_api",
      sha_verified: true,
    },
    metadata_source: "github_api",
    primary_language: "Python",
    license_spdx_id: "MIT",
    is_archived: false,
  },
  reference: {
    requested_ref: null,
    ref_type: "default_branch",
    resolved_commit_sha: COMMIT_SHA,
    is_default_branch: true,
    resolved_via: "github_api",
    sha_verified: true,
  },
  summary: {
    repository_id: REPOSITORY_ID,
    files_examined: 12,
    manifests_detected: 2,
    manifests_parsed: 2,
    declarations: 3,
    resolved_packages: 4,
    dependency_edges: 5,
    warning_count: 1,
    error_count: 0,
    duration_ms: 1234,
    started_at: "2026-01-02T03:04:05Z",
    retrieval_strategy: "archive",
    direct_declarations: 2,
    transitive_packages: 2,
    unknown_relation_packages: 0,
    dev_declarations: 1,
    optional_declarations: 0,
    conflicting_packages: 0,
    symlinks_skipped: 0,
    oversized_files_skipped: 0,
  },
  limits: {
    retrieval_strategy: "archive",
    download_timeout_seconds: 60,
    git_timeout_seconds: 60,
    max_ingestion_seconds: 300,
    max_download_bytes: 104857600,
    max_extracted_bytes: 104857600,
    max_archive_members: 50000,
    max_repository_size_kb: 102400,
    max_files_scanned: 20000,
    max_directory_entries: 50000,
    max_manifest_bytes: 1048576,
    max_manifests: 200,
    max_dependencies: 5000,
  },
  coverage: [
    {
      format: "requirements.txt",
      support_level: "supported",
      detected_files: 1,
      parsed_files: 1,
      failed_files: 0,
      notes: null,
    },
  ],
  manifests: [
    {
      id: "manifest_1",
      path: "requirements.txt",
      format: "requirements.txt",
      support_level: "supported",
      status: "parsed",
      is_lockfile: false,
      declaration_count: 3,
      resolved_count: 0,
      edge_count: 0,
      companion_manifest: null,
      warning_codes: ["unresolved_version"],
      error_codes: [],
    },
  ],
  declarations: [
    {
      normalized_name: "requests",
      original_name: "requests",
      ecosystem: "PyPI",
      version_constraint: ">=2.31",
      constraint_scheme: "pep440",
      is_exact_pin: false,
      resolved_version: null,
      referenced_version: null,
      resolved_from: null,
      scope: "runtime",
      relation: "direct",
      is_dev: false,
      is_optional: false,
      provenance: {
        manifest_path: "requirements.txt",
        line_number: 1,
        section: null,
        evidence: "requests>=2.31",
        snippet: null,
      },
    },
  ],
  resolved_packages: [
    {
      id: "pkg_1",
      normalized_name: "requests",
      original_name: "requests",
      ecosystem: "PyPI",
      version: "2.31.0",
      relation: "direct",
      is_dev: false,
      is_optional: false,
      is_root_project: false,
      source_manifest: "poetry.lock",
      provenance: {
        manifest_path: "poetry.lock",
        line_number: 10,
        section: null,
        evidence: 'name = "requests"',
        snippet: null,
      },
    },
  ],
  dependency_edges: [],
  warnings: [
    {
      code: "unresolved_version",
      message: "requests>=2.31 has no resolved version.",
      severity: "warning",
      stage: "parsing",
      manifest_path: "requirements.txt",
      line_number: 1,
    },
  ],
  errors: [],
  supported_formats: [
    {
      format: "requirements.txt",
      support_level: "supported",
      capabilities: "declarations, constraints",
      is_lockfile: false,
    },
  ],
  truncated: {
    declarations: true,
    resolved_packages: false,
    dependency_edges: false,
    warnings: false,
    errors: false,
    manifests: false,
    source_files: false,
  },
};

export const graphIngestResponse = {
  analysis_id: ANALYSIS_ID,
  status: "success",
  created: 12,
  updated: 3,
  unchanged: 1,
  rejected: 0,
  duration_ms: 250,
  nodes_created: 20,
  relationships_created: 24,
  details: {},
};

export const osvSyncResponse = {
  analysis_id: ANALYSIS_ID,
  status: "completed",
  packages_scanned: 4,
  items_with_matches: 1,
  items_without_matches: 3,
  vulnerabilities_found: 1,
  vulnerabilities_created: 1,
  vulnerabilities_updated: 0,
  edges_created: 1,
  edges_updated: 0,
  skipped_edges: 0,
  last_synced_at: "2026-01-04T00:00:00Z",
  errors: [],
};
