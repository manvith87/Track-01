/**
 * Query keys and read hooks for every screen.
 *
 * Keys always include the analysis id, so switching analyses can never mix
 * results from two different analyses in a component (stale responses land in
 * the cache entry of the analysis they belong to).
 */

import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import {
  getAnalysisVulnerabilities,
  getBlastRadius,
  getDependencyEdges,
  getFindingDetail,
  getFindings,
  getFixGroup,
  getFixGroups,
  getGraphHealth,
  getGraphRecord,
  getGraphStatistics,
  getGraphStatus,
  getPackageNeighborhood,
  getPackages,
  getRemediationCandidates,
} from "../api/endpoints";
import type {
  AnalysisVulnerabilitiesResponse,
  FindingDetailResponse,
  FixGroupResponse,
  FixGroupsResponse,
  GraphAnalysisStatus,
  GraphHealth,
  GraphNeighborhood,
  GraphRecord,
  GraphStatistics,
  PrioritizedFindingsResponse,
  RemediationCandidatesResponse,
  VulnerabilityBlastRadiusResponse,
} from "../api/generated";

export const queryKeys = {
  graphHealth: () => ["graph-health"] as const,
  graphStatus: (analysisId: string) => ["analysis", analysisId, "graph-status"] as const,
  graphRecord: (analysisId: string, limit: number) => ["analysis", analysisId, "graph", limit] as const,
  statistics: (analysisId: string) => ["analysis", analysisId, "statistics"] as const,
  packages: (analysisId: string, skip: number, limit: number) =>
    ["analysis", analysisId, "packages", skip, limit] as const,
  dependencyEdges: (analysisId: string) => ["analysis", analysisId, "dependency-edges"] as const,
  vulnerabilities: (analysisId: string, limit: number) =>
    ["analysis", analysisId, "vulnerabilities", limit] as const,
  blastRadius: (analysisId: string, depth: number) =>
    ["analysis", analysisId, "blast-radius", depth] as const,
  neighborhood: (packageId: string, depth: number) => ["package", packageId, "neighborhood", depth] as const,
  findings: (analysisId: string, skip: number, limit: number) =>
    ["analysis", analysisId, "findings", skip, limit] as const,
  findingDetail: (analysisId: string, findingId: string) =>
    ["analysis", analysisId, "finding", findingId] as const,
  candidates: (analysisId: string, skip: number, limit: number) =>
    ["analysis", analysisId, "candidates", skip, limit] as const,
  fixGroups: (analysisId: string, skip: number, limit: number) =>
    ["analysis", analysisId, "fix-groups", skip, limit] as const,
  fixGroupDetail: (analysisId: string, groupId: string) =>
    ["analysis", analysisId, "fix-group", groupId] as const,
};

export function useGraphHealth(): UseQueryResult<GraphHealth> {
  return useQuery({ queryKey: queryKeys.graphHealth(), queryFn: ({ signal }) => getGraphHealth(signal) });
}

export function useGraphStatus(analysisId: string): UseQueryResult<GraphAnalysisStatus> {
  return useQuery({
    queryKey: queryKeys.graphStatus(analysisId),
    queryFn: ({ signal }) => getGraphStatus(analysisId, signal),
    enabled: analysisId.length > 0,
  });
}

export function useGraphStatistics(analysisId: string): UseQueryResult<GraphStatistics> {
  return useQuery({
    queryKey: queryKeys.statistics(analysisId),
    queryFn: ({ signal }) => getGraphStatistics(analysisId, signal),
    enabled: analysisId.length > 0,
  });
}

export function useGraphRecord(analysisId: string, limit: number): UseQueryResult<GraphRecord> {
  return useQuery({
    queryKey: queryKeys.graphRecord(analysisId, limit),
    queryFn: ({ signal }) => getGraphRecord(analysisId, { limit }, signal),
    enabled: analysisId.length > 0,
  });
}

export function usePackages(analysisId: string, skip: number, limit: number): UseQueryResult<GraphRecord> {
  return useQuery({
    queryKey: queryKeys.packages(analysisId, skip, limit),
    queryFn: ({ signal }) => getPackages(analysisId, { skip, limit }, signal),
    enabled: analysisId.length > 0,
  });
}

export function useDependencyEdges(analysisId: string): UseQueryResult<GraphRecord> {
  return useQuery({
    queryKey: queryKeys.dependencyEdges(analysisId),
    queryFn: ({ signal }) => getDependencyEdges(analysisId, { limit: 500 }, signal),
    enabled: analysisId.length > 0,
  });
}

export function useAnalysisVulnerabilities(
  analysisId: string,
  limit: number,
): UseQueryResult<AnalysisVulnerabilitiesResponse> {
  return useQuery({
    queryKey: queryKeys.vulnerabilities(analysisId, limit),
    queryFn: ({ signal }) => getAnalysisVulnerabilities(analysisId, { limit }, signal),
    enabled: analysisId.length > 0,
  });
}

export function useBlastRadius(
  analysisId: string,
  depth: number,
): UseQueryResult<VulnerabilityBlastRadiusResponse> {
  return useQuery({
    queryKey: queryKeys.blastRadius(analysisId, depth),
    queryFn: ({ signal }) => getBlastRadius(analysisId, { depth, limit: 200 }, signal),
    enabled: analysisId.length > 0,
  });
}

export function useNeighborhood(packageId: string | null, depth: number): UseQueryResult<GraphNeighborhood> {
  return useQuery({
    queryKey: queryKeys.neighborhood(packageId ?? "", depth),
    queryFn: ({ signal }) => getPackageNeighborhood(packageId ?? "", depth, signal),
    enabled: Boolean(packageId),
  });
}

export function useFindings(
  analysisId: string,
  skip: number,
  limit: number,
): UseQueryResult<PrioritizedFindingsResponse> {
  return useQuery({
    queryKey: queryKeys.findings(analysisId, skip, limit),
    queryFn: ({ signal }) => getFindings(analysisId, { skip, limit }, signal),
    enabled: analysisId.length > 0,
  });
}

export function useFindingDetail(
  analysisId: string,
  findingId: string | null,
): UseQueryResult<FindingDetailResponse> {
  return useQuery({
    queryKey: queryKeys.findingDetail(analysisId, findingId ?? ""),
    queryFn: ({ signal }) => getFindingDetail(analysisId, findingId ?? "", signal),
    enabled: analysisId.length > 0 && Boolean(findingId),
  });
}

export function useRemediationCandidates(
  analysisId: string,
  skip: number,
  limit: number,
): UseQueryResult<RemediationCandidatesResponse> {
  return useQuery({
    queryKey: queryKeys.candidates(analysisId, skip, limit),
    queryFn: ({ signal }) => getRemediationCandidates(analysisId, { skip, limit }, signal),
    enabled: analysisId.length > 0,
  });
}

export function useFixGroups(
  analysisId: string,
  skip: number,
  limit: number,
): UseQueryResult<FixGroupsResponse> {
  return useQuery({
    queryKey: queryKeys.fixGroups(analysisId, skip, limit),
    queryFn: ({ signal }) => getFixGroups(analysisId, { skip, limit }, signal),
    enabled: analysisId.length > 0,
  });
}

export function useFixGroupDetail(
  analysisId: string,
  groupId: string | null,
): UseQueryResult<FixGroupResponse> {
  return useQuery({
    queryKey: queryKeys.fixGroupDetail(analysisId, groupId ?? ""),
    queryFn: ({ signal }) => getFixGroup(analysisId, groupId ?? "", signal),
    enabled: analysisId.length > 0 && Boolean(groupId),
  });
}
