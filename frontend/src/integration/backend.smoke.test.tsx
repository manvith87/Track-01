/**
 * @vitest-environment node
 *
 * Live-backend integration smoke test.
 *
 * These checks run the *frontend's own client code* against a real, running
 * BlastRadius backend — no fetch stubbing, no fixtures. They are skipped unless
 * explicitly enabled, because they require the FastAPI server and FalkorDB.
 *
 *   $env:BLASTRADIUS_FRONTEND_INTEGRATION = "1"
 *   $env:VITE_API_BASE_URL = "http://127.0.0.1:8000"
 *   $env:BLASTRADIUS_TEST_ANALYSIS_ID = "analysis_..."   # optional
 *   npx vitest run src/integration/backend.smoke.test.tsx
 *
 * `VITE_API_BASE_URL` must point at the backend because the Vitest environment
 * has no dev-server proxy.
 */

import { describe, expect, it } from "vitest";
import {
  getAnalysisVulnerabilities,
  getBlastRadius,
  getDependencyEdges,
  getFindingDetail,
  getFindings,
  getFixGroups,
  getGraphRecord,
  getGraphStatistics,
  getGraphStatus,
  getPackages,
  getRemediationCandidates,
} from "../api/endpoints";
import { buildExplorerData, highlightIdsForPaths } from "../graph/adapter";

const enabled = process.env.BLASTRADIUS_FRONTEND_INTEGRATION === "1";
const analysisId = process.env.BLASTRADIUS_TEST_ANALYSIS_ID ?? "analysis_9ea623c6550a26c0";
const baseUrl = (process.env.VITE_API_BASE_URL ?? "").trim();

describe.skipIf(!enabled)("live backend integration", () => {
  it("points at an absolute backend URL (no dev-server here)", () => {
    expect(baseUrl).toMatch(/^https?:\/\//);
  });

  it("reads the persisted analysis status for an existing analysis", async () => {
    const status = await getGraphStatus(analysisId);

    expect(status.analysis_id).toBe(analysisId);
    expect(status.status.length).toBeGreaterThan(0);
    expect(status.commit_sha).toMatch(/^[0-9a-f]{7,40}$/i);
  });

  it("returns a bounded graph page whose rows follow the documented shape", async () => {
    const record = await getGraphRecord(analysisId, { limit: 100 });

    expect(Array.isArray(record.rows)).toBe(true);
    expect(record.count).toBeGreaterThanOrEqual(record.rows.length);
    for (const row of record.rows) {
      // Each row is column-keyed (r/f/m/d/p/rp/rt/e/t); nodes carry labels+properties.
      const nodes = Object.values(row).filter(
        (value): value is { labels: string[]; properties: Record<string, unknown> } =>
          typeof value === "object" &&
          value !== null &&
          Array.isArray((value as { labels?: unknown }).labels),
      );
      expect(nodes.length).toBeGreaterThan(0);
      for (const node of nodes) {
        expect(node.labels.length).toBeGreaterThan(0);
        expect(typeof node.properties).toBe("object");
      }
    }
  });

  it("returns graph statistics and package/edge listings", async () => {
    const statistics = await getGraphStatistics(analysisId);
    expect(statistics.packages).toBeGreaterThanOrEqual(0);
    expect(statistics.dependency_edges).toBeGreaterThanOrEqual(0);

    const packages = await getPackages(analysisId, { limit: 5 });
    expect(packages.count).toBe(Math.min(5, packages.rows.length));

    const edges = await getDependencyEdges(analysisId, { limit: 5 });
    expect(Array.isArray(edges.rows)).toBe(true);
  });

  it("lists stored advisory matches and the modeled impact paths", async () => {
    const vulnerabilities = await getAnalysisVulnerabilities(analysisId, { limit: 5 });
    const items = vulnerabilities.items ?? [];
    expect(vulnerabilities.count).toBe(Math.min(5, items.length));

    const blastRadius = await getBlastRadius(analysisId, { depth: 2 });
    const paths = blastRadius.paths ?? [];
    expect(blastRadius.depth).toBe(2);
    for (const path of paths.slice(0, 3)) {
      expect(path.vulnerability_id.length).toBeGreaterThan(0);
      expect(path.affected_package_name.length).toBeGreaterThan(0);
      expect(Array.isArray(path.downstream_chain)).toBe(true);
    }
  });

  it("serves ranked findings and full detail for the first ranked finding", async () => {
    const findings = await getFindings(analysisId, { limit: 5 });
    expect(findings.count).toBe(Math.min(5, findings.findings.length));
    expect(findings.total).toBeGreaterThanOrEqual(findings.count);
    expect(findings.analysis_context.analysis_status.length).toBeGreaterThan(0);

    const first = findings.findings[0];
    if (!first) {
      // An analysis without findings is a legitimate state; nothing more to check.
      return;
    }
    expect(first.finding_id.length).toBeGreaterThan(0);
    expect(typeof first.priority.score).toBe("number");
    expect(first.priority.severity.source).toBeTruthy();

    const detail = await getFindingDetail(analysisId, first.finding_id);
    expect(detail.finding.finding_id).toBe(first.finding_id);
    if (!detail.remediation) {
      throw new Error(
        `finding ${first.finding_id} has no remediation payload; the UI shows an explicit empty state`,
      );
    }
    expect(detail.remediation.package_id).toBe(first.package.package_id);
  });

  it("serves the deterministic remediation ranking and candidate plans", async () => {
    const groups = await getFixGroups(analysisId, { limit: 5 });
    expect(groups.count).toBe(Math.min(5, groups.groups.length));
    for (const group of groups.groups) {
      expect(["confirmed_advisory", "potential_only", "no_advisory_resolution"]).toContain(group.coverage);
      expect(group.ranking.rank).toBeGreaterThan(0);
      // The backend never marks a candidate as resolver-verified.
      for (const candidate of group.candidates ?? []) {
        expect(candidate.resolver_executed).toBe(false);
      }
    }

    const candidates = await getRemediationCandidates(analysisId, { limit: 5 });
    expect(candidates.count).toBe(Math.min(5, candidates.plans.length));
    for (const plan of candidates.plans) {
      for (const candidate of plan.candidates ?? []) {
        expect(candidate.resolver_executed).toBe(false);
      }
    }
  });

  it("maps the real graph response through the Screen C adapter", async () => {
    const record = await getGraphRecord(analysisId, { limit: 500 });
    const data = buildExplorerData(record.rows, 500);

    expect(data.nodes.length).toBeGreaterThan(0);
    expect(data.rowsFetched).toBe(record.rows.length);
    const nodeIds = new Set(data.nodes.map((node) => node.id));
    expect(nodeIds.size).toBe(data.nodes.length);
    expect(data.nodes.some((node) => node.type === "package")).toBe(true);
    for (const node of data.nodes) {
      expect(node.label.length).toBeGreaterThan(0);
    }

    // Every edge the adapter built must reference two nodes it also produced.
    expect(data.edges.length).toBeGreaterThan(0);
    for (const edge of data.edges) {
      expect(nodeIds.has(edge.source)).toBe(true);
      expect(nodeIds.has(edge.target)).toBe(true);
      expect(edge.type.length).toBeGreaterThan(0);
    }

    // Highlighting is derived only from the server-returned impact paths.
    const blastRadius = await getBlastRadius(analysisId, { depth: 2 });
    const paths = blastRadius.paths ?? [];
    if (paths.length > 0) {
      const highlighted = highlightIdsForPaths(data, paths);
      expect(highlighted.size).toBeGreaterThan(0);
      for (const id of highlighted) {
        expect(id.startsWith("Package:") || id.startsWith("Vulnerability:")).toBe(true);
      }
      // The page is bounded, so some path endpoints may be outside it; at least
      // one highlighted endpoint must match a fetched node id (same convention).
      expect([...highlighted].some((id) => nodeIds.has(id))).toBe(true);
    }
  });
});
