import { useMemo, useState } from "react";
import type { FindingOut } from "../api/generated";
import { Badge, ConfidenceBadge, ReachabilityBadge, SeverityBadge } from "../components/badges";
import { FindingDetailPanel } from "../components/FindingDetail";
import { EmptyState, ErrorState, LoadingState, Notice, SectionCard } from "../components/StateViews";
import { formatNumber, formatScore } from "../lib/format";
import { useAnalysis } from "../state/analysis-context";
import { useFindings } from "../hooks/queries";
import { SearchIcon } from "../components/icons";

const PAGE_SIZES = [25, 50, 100, 200, 500] as const;

type SortKey = "server_rank" | "priority_desc" | "advisory_desc" | "package_asc" | "dependents_desc";

function advisoryScore(finding: FindingOut): number | null {
  const severity = finding.priority.severity;
  return severity.quantified && severity.numeric_score !== null && severity.numeric_score !== undefined
    ? severity.numeric_score
    : null;
}

export function FindingsPage() {
  const { analysisId } = useAnalysis();
  const [limit, setLimit] = useState<number>(50);
  const [skip, setSkip] = useState(0);
  const [query, setQuery] = useState("");
  const [reachability, setReachability] = useState("all");
  const [confidence, setConfidence] = useState("all");
  const [remediationOnly, setRemediationOnly] = useState(false);
  const [sort, setSort] = useState<SortKey>("server_rank");
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);

  const findings = useFindings(analysisId, skip, limit);

  const filtered = useMemo(() => {
    const rows = findings.data?.findings ?? [];
    const needle = query.trim().toLowerCase();
    const matches = rows.filter((finding) => {
      if (reachability !== "all" && finding.priority.reachability.status !== reachability) return false;
      if (confidence !== "all" && finding.confidence !== confidence) return false;
      if (remediationOnly && !finding.priority.remediation_available) return false;
      if (!needle) return true;
      const haystack = [
        finding.vulnerability_id,
        finding.vulnerability_summary ?? "",
        finding.package.package_name,
        ...(finding.aliases ?? []),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
    const sorted = [...matches];
    sorted.sort((left, right) => {
      switch (sort) {
        case "priority_desc":
          return right.priority.score - left.priority.score;
        case "advisory_desc":
          return (advisoryScore(right) ?? -1) - (advisoryScore(left) ?? -1);
        case "package_asc":
          return left.package.package_name.localeCompare(right.package.package_name);
        case "dependents_desc":
          return (
            (right.priority.reachability.dependent_component_count ?? 0) -
            (left.priority.reachability.dependent_component_count ?? 0)
          );
        default:
          return left.priority.rank - right.priority.rank;
      }
    });
    return sorted;
  }, [findings.data, query, reachability, confidence, remediationOnly, sort]);

  if (findings.isPending) {
    return <LoadingState label="Loading ranked findings…" />;
  }
  if (findings.isError) {
    return (
      <ErrorState
        error={findings.error}
        title="Could not load findings"
        onRetry={() => void findings.refetch()}
      />
    );
  }
  if (!findings.data) {
    return <EmptyState title="No findings response" />;
  }

  const { total, count, analysis_context } = findings.data;
  const firstShown = total === 0 ? 0 : skip + 1;
  const lastShown = skip + count;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      {!analysis_context.complete ? (
        <Notice tone="warning" title="Incomplete analysis data">
          <p>
            Graph ingestion status: {analysis_context.analysis_status} ·{" "}
            {formatNumber(analysis_context.warning_count)} warning(s),{" "}
            {formatNumber(analysis_context.error_count)} error(s) ·{" "}
            {formatNumber(analysis_context.resolved_packages)} resolved packages ·{" "}
            {formatNumber(analysis_context.dependency_edges)} dependency edges ·{" "}
            {formatNumber(analysis_context.vulnerability_edges)} advisory links.
          </p>
          {typeof analysis_context.declaration_targets_without_version === "number" &&
          analysis_context.declaration_targets_without_version > 0 ? (
            <p className="mt-1">
              {formatNumber(analysis_context.declaration_targets_without_version)} declared package(s) have no
              lockfile-resolved version, so they cannot be matched against advisories.
            </p>
          ) : null}
          {analysis_context.notes && analysis_context.notes.length > 0 ? (
            <ul className="mt-1 list-disc space-y-1 pl-4">
              {analysis_context.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
        </Notice>
      ) : null}

      <SectionCard
        title="Ranked findings"
        description="Advisory severity is reported verbatim by OSV. BlastRadius priority is a separate deterministic score — they are never merged."
        actions={
          <button
            type="button"
            onClick={() => void findings.refetch()}
            className="focus-ring rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
          >
            Refresh
          </button>
        }
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor="findings-search" className="block text-xs text-zinc-400">
                Search loaded page
              </label>
              <div className="mt-1 flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-950 px-2">
                <SearchIcon className="text-zinc-500" width={16} height={16} />
                <input
                  id="findings-search"
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="CVE, package, summary"
                  className="w-56 bg-transparent py-1.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label htmlFor="findings-reachability" className="block text-xs text-zinc-400">
                Reachability
              </label>
              <select
                id="findings-reachability"
                value={reachability}
                onChange={(event) => setReachability(event.target.value)}
                className="focus-ring mt-1 rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              >
                <option value="all">All statuses</option>
                <option value="direct">Direct dependency</option>
                <option value="reachable_from_entry">Modeled path from entry point</option>
                <option value="not_reachable">No modeled path found</option>
                <option value="unavailable">Reachability unavailable</option>
              </select>
            </div>

            <div>
              <label htmlFor="findings-confidence" className="block text-xs text-zinc-400">
                Confidence
              </label>
              <select
                id="findings-confidence"
                value={confidence}
                onChange={(event) => setConfidence(event.target.value)}
                className="focus-ring mt-1 rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              >
                <option value="all">All</option>
                <option value="verified">Verified match</option>
                <option value="reduced">Reduced confidence</option>
              </select>
            </div>

            <div>
              <label htmlFor="findings-sort" className="block text-xs text-zinc-400">
                Sort
              </label>
              <select
                id="findings-sort"
                value={sort}
                onChange={(event) => setSort(event.target.value as SortKey)}
                className="focus-ring mt-1 rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              >
                <option value="server_rank">Server rank</option>
                <option value="priority_desc">BlastRadius priority (high → low)</option>
                <option value="advisory_desc">Advisory score (high → low)</option>
                <option value="package_asc">Package name (A → Z)</option>
                <option value="dependents_desc">Dependents (high → low)</option>
              </select>
            </div>

            <div>
              <label htmlFor="findings-page-size" className="block text-xs text-zinc-400">
                Page size
              </label>
              <select
                id="findings-page-size"
                value={limit}
                onChange={(event) => {
                  setLimit(Number(event.target.value));
                  setSkip(0);
                }}
                className="focus-ring mt-1 rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </div>

            <label className="flex items-center gap-2 text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={remediationOnly}
                onChange={(event) => setRemediationOnly(event.target.checked)}
                className="focus-ring h-4 w-4 rounded border-zinc-600 bg-zinc-950"
              />
              Remediation available
            </label>
          </div>

          <p className="text-xs text-zinc-500">
            Text search, filters and sorting apply to the loaded page ({filtered.length} of {count} rows). The
            backend API supports pagination only, so use the page controls to reach other rows.
          </p>

          {total === 0 ? (
            <EmptyState
              title="No findings stored for this analysis"
              description="Either no resolved package matched an OSV advisory, or the advisory sync has not run yet. Run the OSV sync from the repository screen to populate findings."
            />
          ) : (
            <div className="overflow-x-auto rounded-lg border border-zinc-800">
              <table className="min-w-full divide-y divide-zinc-800 text-left text-sm">
                <caption className="sr-only">Ranked findings for this analysis</caption>
                <thead className="bg-zinc-900/70 text-xs uppercase tracking-wide text-zinc-400">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">
                      #
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Advisory
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Package
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Advisory severity
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      BlastRadius priority
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Modeled reachability
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Remediation
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/70">
                  {filtered.map((finding) => {
                    const isSelected = selectedFinding === finding.finding_id;
                    return (
                      <tr
                        key={finding.finding_id}
                        className={isSelected ? "bg-sky-500/5" : "hover:bg-zinc-900/40"}
                      >
                        <td className="px-3 py-2 font-mono text-xs text-zinc-400">{finding.priority.rank}</td>
                        <td className="px-3 py-2">
                          <div className="flex flex-col gap-1">
                            <span className="font-mono text-xs text-zinc-100">
                              {finding.vulnerability_id}
                            </span>
                            {finding.aliases && finding.aliases.length > 0 ? (
                              <span className="text-[11px] text-zinc-500">{finding.aliases.join(", ")}</span>
                            ) : null}
                            {finding.advisory_withdrawn ? (
                              <Badge tone="danger">Withdrawn advisory</Badge>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-col gap-1">
                            <span className="text-zinc-100">
                              {finding.package.package_name}{" "}
                              <span className="font-mono text-xs text-zinc-400">
                                {finding.package.package_version ?? "?"}
                              </span>
                            </span>
                            <span className="text-[11px] text-zinc-500">
                              {finding.package.dependency_role ?? "unknown role"}
                              {finding.package.is_dev ? " · dev" : ""}
                              {finding.package.is_optional ? " · optional" : ""}
                            </span>
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-col gap-1">
                            <SeverityBadge severity={finding.priority.severity} />
                            <span className="text-[11px] text-zinc-500">from the advisory record</span>
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-col gap-1">
                            <span className="text-base font-semibold text-violet-200">
                              {formatScore(finding.priority.score)}
                            </span>
                            <span className="text-[11px] text-zinc-500">
                              custom score · formula {finding.priority.formula_version}
                            </span>
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-col gap-1">
                            <ReachabilityBadge
                              status={finding.priority.reachability.status}
                              minHops={finding.priority.reachability.min_hops}
                            />
                            {typeof finding.priority.reachability.dependent_component_count === "number" ? (
                              <span className="text-[11px] text-zinc-500">
                                {formatNumber(finding.priority.reachability.dependent_component_count)}{" "}
                                dependent component(s)
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-col gap-1">
                            <Badge tone={finding.priority.remediation_available ? "success" : "neutral"}>
                              {finding.priority.remediation_available
                                ? "Advisory fix available"
                                : "No advisory fix"}
                            </Badge>
                            {finding.fixed_versions && finding.fixed_versions.length > 0 ? (
                              <span className="font-mono text-[11px] text-zinc-500">
                                {finding.fixed_versions.join(", ")}
                              </span>
                            ) : null}
                            <ConfidenceBadge confidence={finding.confidence} />
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <button
                            type="button"
                            className="focus-ring rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
                            aria-expanded={isSelected}
                            onClick={() => setSelectedFinding(isSelected ? null : finding.finding_id)}
                          >
                            {isSelected ? "Hide detail" : "Detail"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-3 py-4 text-sm text-zinc-400">
                        No row on this page matches the current filters.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-zinc-400">
            <span>
              Showing {formatNumber(firstShown)}–{formatNumber(lastShown)} of {formatNumber(total)} ranked
              findings
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={skip === 0}
                onClick={() => setSkip(Math.max(0, skip - limit))}
                className="focus-ring rounded border border-zinc-700 px-3 py-1 text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={lastShown >= total}
                onClick={() => setSkip(skip + limit)}
                className="focus-ring rounded border border-zinc-700 px-3 py-1 text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>

          {findings.data.limitations && findings.data.limitations.length > 0 ? (
            <Notice tone="warning" title="Response limitations">
              <ul className="list-disc space-y-1 pl-4">
                {findings.data.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </Notice>
          ) : null}
        </div>
      </SectionCard>

      {selectedFinding ? (
        <SectionCard
          title="Finding detail"
          description="Full risk explanation, priority factors and the package remediation plan."
          actions={
            <button
              type="button"
              onClick={() => setSelectedFinding(null)}
              className="focus-ring rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
            >
              Close
            </button>
          }
        >
          <FindingDetailPanel analysisId={analysisId} findingId={selectedFinding} />
        </SectionCard>
      ) : null}
    </div>
  );
}
