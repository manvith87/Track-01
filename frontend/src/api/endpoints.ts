/**
 * Typed bindings for every BlastRadius endpoint the UI uses.
 *
 * Types come from `generated.ts`, which is produced from the backend's own
 * OpenAPI document (`npm run api:types`) — the server remains the source of
 * truth. Nothing in this module invents fields, defaults or endpoints.
 */

import {
  AGENT_TIMEOUT_MS,
  apiRequest,
  DEFAULT_TIMEOUT_MS,
  LONG_OPERATION_TIMEOUT_MS,
  withQuery,
} from "./client";
import type {
  AgentAskResponse,
  AnalysisVulnerabilitiesResponse,
  FindingDetailResponse,
  FixGroupResponse,
  FixGroupsResponse,
  GraphAnalysisStatus,
  GraphHealth,
  GraphIngestResponse,
  GraphNeighborhood,
  GraphRecord,
  GraphStatistics,
  IssueConfirmOut,
  IssuePreviewOut,
  PrioritizedFindingsResponse,
  RemediationCandidatesResponse,
  RepositoryIngestResponse,
  SupportedFormatInfo,
  VulnerabilityBlastRadiusResponse,
  VulnerabilityDetailResponse,
  VulnerabilityIngestResponse,
} from "./generated";

export interface PageParams {
  skip?: number;
  limit?: number;
}

// ---------------------------------------------------------------------------
// Health and formats
// ---------------------------------------------------------------------------

export function getAppHealth(signal?: AbortSignal): Promise<Record<string, unknown>> {
  return apiRequest("/health", { signal, timeoutMs: 5_000 });
}

export function getGraphHealth(signal?: AbortSignal): Promise<GraphHealth> {
  return apiRequest("/api/v1/graph/health", { signal, timeoutMs: 5_000 });
}

export function listSupportedFormats(signal?: AbortSignal): Promise<SupportedFormatInfo[]> {
  return apiRequest("/api/v1/repositories/formats", { signal });
}

// ---------------------------------------------------------------------------
// Screen A — repository ingestion and graph persistence
// ---------------------------------------------------------------------------

export function ingestRepository(
  input: { repository_url: string; ref?: string | null },
  signal?: AbortSignal,
): Promise<RepositoryIngestResponse> {
  return apiRequest("/api/v1/repositories/ingest", {
    method: "POST",
    body: { repository_url: input.repository_url, ref: input.ref || null },
    signal,
    timeoutMs: LONG_OPERATION_TIMEOUT_MS,
  });
}

/**
 * Persist an ingest response into the graph.
 *
 * The backend accepts the `RepositoryIngestResponse` shape unchanged under
 * `result` (converted losslessly server-side), so the UI never reconstructs
 * domain objects and never guesses the analysis id.
 */
export function persistAnalysis(
  analysisId: string,
  result: RepositoryIngestResponse,
  signal?: AbortSignal,
): Promise<GraphIngestResponse> {
  return apiRequest(`/api/v1/analyses/${encodeURIComponent(analysisId)}/graph`, {
    method: "POST",
    body: { result },
    signal,
    timeoutMs: LONG_OPERATION_TIMEOUT_MS,
  });
}

// ---------------------------------------------------------------------------
// Screen C — graph reads
// ---------------------------------------------------------------------------

export function getGraphRecord(
  analysisId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<GraphRecord> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/graph`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getGraphStatistics(analysisId: string, signal?: AbortSignal): Promise<GraphStatistics> {
  return apiRequest(`/api/v1/analyses/${encodeURIComponent(analysisId)}/graph/statistics`, { signal });
}

export function getGraphStatus(analysisId: string, signal?: AbortSignal): Promise<GraphAnalysisStatus> {
  return apiRequest(`/api/v1/analyses/${encodeURIComponent(analysisId)}/graph/status`, { signal });
}

export function getPackages(
  analysisId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<GraphRecord> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/packages`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getDependencyEdges(
  analysisId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<GraphRecord> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/dependency-edges`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getPackageNeighborhood(
  packageId: string,
  depth: number,
  signal?: AbortSignal,
): Promise<GraphNeighborhood> {
  return apiRequest(withQuery(`/api/v1/packages/${encodeURIComponent(packageId)}/neighborhood`, { depth }), {
    signal,
  });
}

// ---------------------------------------------------------------------------
// Vulnerabilities (Screen C overlay, Screen A sync)
// ---------------------------------------------------------------------------

export function syncVulnerabilities(
  analysisId: string,
  signal?: AbortSignal,
): Promise<VulnerabilityIngestResponse> {
  return apiRequest(`/api/v1/analyses/${encodeURIComponent(analysisId)}/vulnerabilities`, {
    method: "POST",
    signal,
    timeoutMs: LONG_OPERATION_TIMEOUT_MS,
  });
}

export function getAnalysisVulnerabilities(
  analysisId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<AnalysisVulnerabilitiesResponse> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/vulnerabilities`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getBlastRadius(
  analysisId: string,
  params: PageParams & { depth?: number; vulnerability_id?: string } = {},
  signal?: AbortSignal,
): Promise<VulnerabilityBlastRadiusResponse> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/vulnerabilities/blast-radius`, {
      depth: params.depth,
      vulnerability_id: params.vulnerability_id,
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getVulnerabilityDetail(
  vulnerabilityId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<VulnerabilityDetailResponse> {
  return apiRequest(
    withQuery(`/api/v1/vulnerabilities/${encodeURIComponent(vulnerabilityId)}`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

// ---------------------------------------------------------------------------
// Screen B / E — findings, candidates, groups
// ---------------------------------------------------------------------------

export function getFindings(
  analysisId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<PrioritizedFindingsResponse> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/findings`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getFindingDetail(
  analysisId: string,
  findingId: string,
  signal?: AbortSignal,
): Promise<FindingDetailResponse> {
  return apiRequest(
    `/api/v1/analyses/${encodeURIComponent(analysisId)}/findings/${encodeURIComponent(findingId)}`,
    { signal },
  );
}

export function getRemediationCandidates(
  analysisId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<RemediationCandidatesResponse> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/remediation/candidates`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getFixGroups(
  analysisId: string,
  params: PageParams = {},
  signal?: AbortSignal,
): Promise<FixGroupsResponse> {
  return apiRequest(
    withQuery(`/api/v1/analyses/${encodeURIComponent(analysisId)}/remediation/groups`, {
      skip: params.skip,
      limit: params.limit,
    }),
    { signal },
  );
}

export function getFixGroup(
  analysisId: string,
  groupId: string,
  signal?: AbortSignal,
): Promise<FixGroupResponse> {
  return apiRequest(
    `/api/v1/analyses/${encodeURIComponent(analysisId)}/remediation/groups/${encodeURIComponent(groupId)}`,
    { signal },
  );
}

// ---------------------------------------------------------------------------
// Screen D — evidence-grounded analyst
// ---------------------------------------------------------------------------

export function askAgent(
  analysisId: string,
  input: { question: string; max_rounds?: number },
  signal?: AbortSignal,
): Promise<AgentAskResponse> {
  return apiRequest(`/api/v1/analyses/${encodeURIComponent(analysisId)}/ask`, {
    method: "POST",
    body: input,
    signal,
    timeoutMs: AGENT_TIMEOUT_MS,
  });
}

// ---------------------------------------------------------------------------
// Screen F — approved GitHub issue actions
// ---------------------------------------------------------------------------

export function previewIssue(
  analysisId: string,
  selection: { group_id?: string; finding_id?: string },
  signal?: AbortSignal,
): Promise<IssuePreviewOut> {
  return apiRequest(`/api/v1/analyses/${encodeURIComponent(analysisId)}/remediation/github-issue/preview`, {
    method: "POST",
    body: selection,
    signal,
    timeoutMs: DEFAULT_TIMEOUT_MS,
  });
}

/**
 * Confirm the one authorized GitHub write.
 *
 * The approval secret is supplied by the operator for this single request and
 * is never stored (not in component state beyond the input, not in storage).
 */
export function confirmIssue(
  input: { action_id: string; payload_digest: string; approvalSecret: string },
  signal?: AbortSignal,
): Promise<IssueConfirmOut> {
  return apiRequest("/api/v1/actions/github-issue/confirm", {
    method: "POST",
    body: { action_id: input.action_id, payload_digest: input.payload_digest },
    headers: { "X-BlastRadius-Approval": input.approvalSecret },
    signal,
  });
}
