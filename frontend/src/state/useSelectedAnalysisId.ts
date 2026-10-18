import { useLocation } from "react-router-dom";

/** Analysis id selected in the current route (`/analysis/<id>/...`), if any. */
export function useSelectedAnalysisId(): string | null {
  const { pathname } = useLocation();
  const match = /^\/analysis\/([^/]+)/.exec(pathname);
  if (!match) return null;
  return decodeURIComponent(match[1] ?? "");
}
