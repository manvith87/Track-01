import { createContext, useContext } from "react";
import type { GraphAnalysisStatus } from "../api/generated";

export interface AnalysisContextValue {
  /** Analysis id taken from the route; every query is keyed by it. */
  analysisId: string;
  /** Persisted analysis record from GET /analyses/{id}/graph/status. */
  status: GraphAnalysisStatus | undefined;
  statusLoading: boolean;
  statusError: unknown;
  repositoryId: string | null;
  commitSha: string | null;
  refetchStatus: () => void;
}

export const AnalysisContext = createContext<AnalysisContextValue | null>(null);

export function useAnalysis(): AnalysisContextValue {
  const value = useContext(AnalysisContext);
  if (!value) {
    throw new Error("useAnalysis must be used inside an AnalysisProvider");
  }
  return value;
}
