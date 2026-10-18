import { useMemo, type ReactNode } from "react";
import { AnalysisContext, type AnalysisContextValue } from "./analysis-context";
import { useGraphStatus } from "../hooks/queries";

/**
 * Provides the selected analysis to every screen.
 *
 * The route parameter is the single source of truth for the selection, and the
 * persisted record is loaded from the backend (never carried between analyses
 * in client state).
 */
export function AnalysisProvider({ analysisId, children }: { analysisId: string; children: ReactNode }) {
  const statusQuery = useGraphStatus(analysisId);
  const { refetch } = statusQuery;

  const value = useMemo<AnalysisContextValue>(
    () => ({
      analysisId,
      status: statusQuery.data,
      statusLoading: statusQuery.isPending && statusQuery.fetchStatus !== "idle",
      statusError: statusQuery.error,
      repositoryId: statusQuery.data?.repository_id ?? null,
      commitSha: statusQuery.data?.commit_sha ?? null,
      refetchStatus: () => {
        void refetch();
      },
    }),
    [
      analysisId,
      statusQuery.data,
      statusQuery.error,
      statusQuery.isPending,
      statusQuery.fetchStatus,
      refetch,
    ],
  );

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>;
}
