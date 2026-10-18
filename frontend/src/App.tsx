import { Navigate, Outlet, Route, Routes, useParams } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AnalystPage } from "./pages/AnalystPage";
import { FindingsPage } from "./pages/FindingsPage";
import { GraphExplorerPage } from "./pages/GraphExplorerPage";
import { IssueActionPage } from "./pages/IssueActionPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { RemediationPage } from "./pages/RemediationPage";
import { RepoAnalysisPage } from "./pages/RepoAnalysisPage";
import { AnalysisProvider } from "./state/AnalysisProvider";

/** Route branch that binds the URL's analysis id to the analysis context. */
function AnalysisBranch() {
  const { analysisId } = useParams<{ analysisId: string }>();
  if (!analysisId) {
    return <NotFoundPage />;
  }
  return (
    <AnalysisProvider key={analysisId} analysisId={analysisId}>
      <Outlet />
    </AnalysisProvider>
  );
}

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<RepoAnalysisPage />} />
        <Route path="/analysis/:analysisId" element={<AnalysisBranch />}>
          <Route index element={<Navigate to="findings" replace />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="graph" element={<GraphExplorerPage />} />
          <Route path="analyst" element={<AnalystPage />} />
          <Route path="remediation" element={<RemediationPage />} />
          <Route path="issue" element={<IssueActionPage />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
