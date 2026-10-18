import type { ReactNode } from "react";
import { useAnalysis } from "../state/analysis-context";
import { ErrorState, LoadingState } from "./StateViews";

/**
 * Shared guard for every analysis-scoped screen.
 *
 * The persisted analysis record decides whether the screen can render at all,
 * so a missing/unreachable analysis produces one clear error state instead of a
 * pile of failing detail requests.
 */
export function AnalysisGuard({ children }: { children: ReactNode }) {
  const { status, statusLoading, statusError } = useAnalysis();

  if (statusLoading) {
    return <LoadingState label="Loading analysis record…" />;
  }
  if (statusError) {
    return <ErrorState error={statusError} title="This analysis could not be loaded" />;
  }
  if (!status) {
    return <LoadingState label="Loading analysis record…" />;
  }
  return <>{children}</>;
}
