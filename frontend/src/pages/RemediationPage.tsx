import { useState } from "react";
import { Link } from "react-router-dom";
import type { AnalysisContext, FixGroup, RemediationCandidate } from "../api/generated";
import { AnalysisGuard } from "../components/AnalysisGuard";
import { Badge, CompatibilityBadge, CoverageBadge, ReachabilityBadge } from "../components/badges";
import { DataTable } from "../components/DataTable";
import { EmptyState, ErrorState, LoadingState, Notice, SectionCard } from "../components/StateViews";
import { useFixGroupDetail, useFixGroups, useRemediationCandidates } from "../hooks/queries";
import { formatNumber, formatScore } from "../lib/format";
import { useAnalysis } from "../state/analysis-context";

const PAGE_SIZES = [10, 25, 50] as const;

function PartialAnalysisNotice({ context }: { context: AnalysisContext }) {
  if (context.complete) return null;
  return (
    <Notice tone="warning" title="Incomplete analysis data">
      <p>
        Ingestion status: {context.analysis_status} · {formatNumber(context.warning_count ?? 0)} warning(s) ·{" "}
        {formatNumber(context.error_count ?? 0)} error(s) · {formatNumber(context.resolved_packages ?? 0)}{" "}
        resolved packages · {formatNumber(context.vulnerability_edges ?? 0)} advisory links. Remediation
        advice built on incomplete data can miss affected packages.
      </p>
      {typeof context.declaration_targets_without_version === "number" &&
      context.declaration_targets_without_version > 0 ? (
        <p className="mt-1">
          {formatNumber(context.declaration_targets_without_version)} declared package(s) have no resolved
          version and could not be matched to advisories.
        </p>
      ) : null}
      {context.notes && context.notes.length > 0 ? (
        <ul className="mt-1 list-disc space-y-1 pl-4">
          {context.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}
    </Notice>
  );
}

function CandidateValidation({ candidate }: { candidate: RemediationCandidate }) {
  return (
    <div className="space-y-2 text-[11px]">
      <ul className="space-y-1">
        {(candidate.resolves ?? []).map((evaluation, index) => (
          <li key={`${evaluation.vulnerability_id}-${index}`}>
            <span className="font-mono">{evaluation.vulnerability_id}</span>:{" "}
            <span
              className={
                evaluation.status === "resolves"
                  ? "text-emerald-300"
                  : evaluation.status === "not_resolving"
                    ? "text-red-300"
                    : "text-amber-300"
              }
            >
              {evaluation.status}
            </span>{" "}
            — {evaluation.detail}
          </li>
        ))}
        {(candidate.resolves ?? []).length === 0 ? (
          <li className="text-zinc-500">No advisory validation records.</li>
        ) : null}
      </ul>
      <ul className="space-y-1">
        {(candidate.constraint_checks ?? []).map((check, index) => (
          <li key={`${check.source}-${index}`}>
            <span className="font-mono">{check.constraint ?? "—"}</span> ({check.scheme}) —{" "}
            {check.satisfied === null || check.satisfied === undefined
              ? "unverifiable"
              : check.satisfied
                ? "satisfied"
                : "violated"}{" "}
            · {check.detail}
          </li>
        ))}
        {(candidate.constraint_checks ?? []).length === 0 ? (
          <li className="text-zinc-500">No declared constraints checked.</li>
        ) : null}
      </ul>
    </div>
  );
}

function CandidateRow({ candidate }: { candidate: RemediationCandidate }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm text-zinc-100">
          {candidate.current_version} → {candidate.proposed_version}
        </span>
        {candidate.selected ? (
          <Badge tone="accent">Selected by server ranking</Badge>
        ) : (
          <Badge tone="neutral">Alternate</Badge>
        )}
        <CompatibilityBadge value={candidate.compatibility} />
        {candidate.origin ? (
          <span className="text-[11px] text-zinc-500">origin: {candidate.origin}</span>
        ) : null}
        <span className="text-[11px] text-zinc-500">
          resolver executed: {candidate.resolver_executed ? "yes" : "no"}
        </span>
      </div>
      <p className="mt-1 text-xs text-zinc-400">{candidate.compatibility_detail}</p>
      <p className="mt-1 text-[11px] text-zinc-500">
        range-validated: {(candidate.resolved_finding_ids ?? []).length} · unknown:{" "}
        {(candidate.unknown_finding_ids ?? []).length} · not resolved:{" "}
        {(candidate.unresolved_finding_ids ?? []).length}
      </p>
      <div className="mt-2">
        <CandidateValidation candidate={candidate} />
      </div>
      {candidate.limitations && candidate.limitations.length > 0 ? (
        <ul className="mt-2 list-disc space-y-0.5 pl-4 text-[11px] text-amber-200">
          {candidate.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function GroupDetailPanel({
  analysisId,
  groupId,
  onClose,
}: {
  analysisId: string;
  groupId: string;
  onClose: () => void;
}) {
  const detail = useFixGroupDetail(analysisId, groupId);

  if (detail.isPending) return <LoadingState label="Loading fix group…" />;
  if (detail.isError) return <ErrorState error={detail.error} title="Could not load the fix group" />;
  if (!detail.data) return <EmptyState title="No group returned" />;

  const group = detail.data.group;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-mono text-sm text-zinc-100">
            {group.package_name} {group.current_version} → {group.proposed_version}
          </h3>
          <CoverageBadge value={group.coverage} />
          <CompatibilityBadge value={group.compatibility} />
          <Badge tone="neutral">rank {group.ranking.rank}</Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link
            to={`/analysis/${encodeURIComponent(analysisId)}/issue?group=${encodeURIComponent(group.group_id)}`}
            className="focus-ring rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-100 hover:bg-zinc-800"
          >
            Preview GitHub issue for this group
          </Link>
          <button
            type="button"
            onClick={onClose}
            className="focus-ring rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
          >
            Close
          </button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs">
          <p className="text-zinc-500">Advisory-confirmed resolutions</p>
          <p className="mt-1 text-lg font-semibold text-emerald-200">
            {formatNumber(group.ranking.verified_resolved_count)}
          </p>
          <p className="text-[11px] text-zinc-500">
            priority sum {formatScore(group.ranking.verified_resolved_priority_sum)}
          </p>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs">
          <p className="text-zinc-500">Reachable resolved findings</p>
          <p className="mt-1 text-lg font-semibold text-zinc-100">
            {formatNumber(group.ranking.reachable_resolved_count)}
          </p>
          <p className="text-[11px] text-zinc-500">
            highest finding priority {formatScore(group.ranking.highest_finding_priority)}
          </p>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs">
          <p className="text-zinc-500">Compatibility tier</p>
          <p className="mt-1 text-lg font-semibold text-zinc-100">
            {formatNumber(group.ranking.compatibility_tier)} · {group.ranking.compatibility_tier_label}
          </p>
          <p className="text-[11px] text-zinc-500">2 satisfied · 1 unverified · 0 violated</p>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs">
          <p className="text-zinc-500">Finding coverage</p>
          <p className="mt-1 text-sm text-zinc-100">
            {formatNumber((group.verified_resolved_finding_ids ?? []).length)} verified ·{" "}
            {formatNumber((group.potential_resolved_finding_ids ?? []).length)} potential ·{" "}
            {formatNumber((group.unresolved_finding_ids ?? []).length)} unresolved
          </p>
        </div>
      </div>

      {(group.resolved_findings?.length ?? 0) > 0 ? (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Findings validated against the proposed version
          </h4>
          <DataTable
            caption="Findings validated against the proposed version"
            rows={group.resolved_findings ?? []}
            rowKey={(finding) => finding.finding_id}
            initialRows={15}
            columns={[
              {
                key: "advisory",
                header: "Advisory",
                render: (finding) => (
                  <div>
                    <span className="font-mono text-xs text-zinc-100">{finding.vulnerability_id}</span>
                    {finding.aliases && finding.aliases.length > 0 ? (
                      <div className="text-[11px] text-zinc-500">{finding.aliases.join(", ")}</div>
                    ) : null}
                  </div>
                ),
              },
              {
                key: "package",
                header: "Package",
                render: (finding) => (
                  <span>
                    {finding.package.package_name}{" "}
                    <span className="font-mono text-xs text-zinc-400">
                      {finding.package.package_version ?? "?"}
                    </span>
                  </span>
                ),
              },
              {
                key: "validation",
                header: "Validation",
                render: (finding) => (
                  <div className="flex flex-col gap-1">
                    {(group.verified_resolved_finding_ids ?? []).includes(finding.finding_id) ? (
                      <Badge tone="success">Advisory-confirmed</Badge>
                    ) : (group.potential_resolved_finding_ids ?? []).includes(finding.finding_id) ? (
                      <Badge tone="warning">Potential only (not range-validated)</Badge>
                    ) : (
                      <Badge tone="neutral">Not resolved by this group</Badge>
                    )}
                  </div>
                ),
              },
              {
                key: "priority",
                header: "BlastRadius priority",
                render: (finding) => <span>{formatScore(finding.priority.score)}</span>,
              },
              {
                key: "reachability",
                header: "Modeled reachability",
                render: (finding) => (
                  <ReachabilityBadge
                    status={finding.priority.reachability.status}
                    minHops={finding.priority.reachability.min_hops}
                  />
                ),
              },
            ]}
          />
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Candidates ({group.candidates?.length ?? 0})
          </h4>
          <div className="space-y-2">
            {(group.candidates ?? []).map((candidate) => (
              <CandidateRow
                key={`${candidate.package_id}-${candidate.proposed_version}`}
                candidate={candidate}
              />
            ))}
            {(group.candidates ?? []).length === 0 ? (
              <EmptyState title="No candidate versions for this group" />
            ) : null}
          </div>
        </div>
        <div className="space-y-3">
          {(group.advisory_evidence?.length ?? 0) > 0 ? (
            <div>
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
                Advisory evidence
              </h4>
              <ul className="space-y-1 text-xs text-zinc-300">
                {group.advisory_evidence?.map((evidence) => (
                  <li key={evidence.vulnerability_id}>
                    <span className="font-mono">{evidence.vulnerability_id}</span>
                    {evidence.match_type ? ` · match ${evidence.match_type}` : ""}
                    {evidence.fixed_versions && evidence.fixed_versions.length > 0
                      ? ` · fixed: ${evidence.fixed_versions.join(", ")}`
                      : ""}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
              Dependency context
            </h4>
            <p className="text-xs text-zinc-400">
              Affected components: {formatNumber((group.affected_components ?? []).length)}
              {group.affected_components_truncated ? " (list truncated by the server)" : ""}
            </p>
            {group.affected_components && group.affected_components.length > 0 ? (
              <p className="mt-1 break-words font-mono text-[11px] text-zinc-500">
                {(group.affected_components ?? []).slice(0, 20).join(", ")}
                {group.affected_components.length > 20 ? " …" : ""}
              </p>
            ) : null}
            {group.entry_points && group.entry_points.length > 0 ? (
              <p className="mt-1 text-xs text-zinc-400">
                Entry points: <span className="font-mono text-[11px]">{group.entry_points.join(", ")}</span>
              </p>
            ) : null}
          </div>

          {(group.unresolved_relationships?.length ?? 0) > 0 ? (
            <Notice tone="warning" title="Unresolved relationships">
              <ul className="list-disc space-y-1 pl-4">
                {group.unresolved_relationships?.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </Notice>
          ) : null}

          {(group.migration_concerns?.length ?? 0) > 0 ? (
            <Notice tone="warning" title="Migration concerns">
              <ul className="list-disc space-y-1 pl-4">
                {group.migration_concerns?.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </Notice>
          ) : null}

          {(group.limitations?.length ?? 0) > 0 || (detail.data.limitations?.length ?? 0) > 0 ? (
            <Notice tone="warning" title="Limitations">
              <ul className="list-disc space-y-1 pl-4">
                {(group.limitations ?? []).map((item) => (
                  <li key={item}>{item}</li>
                ))}
                {(detail.data.limitations ?? []).map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </Notice>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function GroupsView({
  analysisId,
  skip,
  limit,
  onSkipChange,
  openGroupId,
  onOpenGroup,
}: {
  analysisId: string;
  skip: number;
  limit: number;
  onSkipChange: (skip: number) => void;
  openGroupId: string | null;
  onOpenGroup: (id: string | null) => void;
}) {
  const groups = useFixGroups(analysisId, skip, limit);

  if (groups.isPending) return <LoadingState label="Loading fix groups…" />;
  if (groups.isError)
    return (
      <ErrorState
        error={groups.error}
        title="Could not load fix groups"
        onRetry={() => void groups.refetch()}
      />
    );
  if (!groups.data) return <EmptyState title="No fix-groups response" />;

  const { groups: rows, total, count, analysis_context } = groups.data;
  const coverage = new Map<string, number>();
  for (const group of rows) coverage.set(group.coverage, (coverage.get(group.coverage) ?? 0) + 1);

  return (
    <div className="space-y-4">
      <PartialAnalysisNotice context={analysis_context} />

      {total === 0 ? (
        <EmptyState
          title="No fix groups for this analysis"
          description="The backend produced no ranked fix groups (no advisory fixed version resolved any stored finding). Candidates per package are still listed in the other view."
        />
      ) : (
        <>
          <p className="text-xs text-zinc-500">
            On this page: {formatNumber(coverage.get("confirmed_advisory") ?? 0)} advisory-confirmed ·{" "}
            {formatNumber(coverage.get("potential_only") ?? 0)} potential only ·{" "}
            {formatNumber(coverage.get("no_advisory_resolution") ?? 0)} without advisory resolution. Coverage
            is decided by the backend; the UI never re-labels a potential candidate as confirmed.
          </p>

          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="min-w-full divide-y divide-zinc-800 text-left text-sm">
              <caption className="sr-only">Ranked fix groups</caption>
              <thead className="bg-zinc-900/70 text-xs uppercase tracking-wide text-zinc-400">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Rank
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Package upgrade
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Coverage
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Findings
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Compatibility
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/70">
                {rows.map((group: FixGroup) => (
                  <tr key={group.group_id} className="align-top hover:bg-zinc-900/40">
                    <td className="px-3 py-2 font-mono text-xs text-zinc-400">{group.ranking.rank}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-col gap-1">
                        <span className="font-mono text-xs text-zinc-100">
                          {group.package_name} {group.current_version} → {group.proposed_version}
                        </span>
                        <span className="text-[11px] text-zinc-500">
                          {group.ecosystem ?? "unknown ecosystem"} · {group.dependency_role ?? "unknown role"}
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <CoverageBadge value={group.coverage} />
                    </td>
                    <td className="px-3 py-2 text-xs text-zinc-300">
                      <div>
                        {formatNumber((group.verified_resolved_finding_ids ?? []).length)} confirmed ·{" "}
                        {formatNumber((group.potential_resolved_finding_ids ?? []).length)} potential ·{" "}
                        {formatNumber((group.unresolved_finding_ids ?? []).length)} unresolved
                      </div>
                      <div className="text-[11px] text-zinc-500">
                        reachable: {formatNumber(group.ranking.reachable_resolved_count)} · priority sum:{" "}
                        {formatScore(group.ranking.verified_resolved_priority_sum)}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-col gap-1">
                        <CompatibilityBadge value={group.compatibility} />
                        <span className="text-[11px] text-zinc-500">
                          {group.ranking.compatibility_tier_label}
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => onOpenGroup(openGroupId === group.group_id ? null : group.group_id)}
                          aria-expanded={openGroupId === group.group_id}
                          className="focus-ring rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
                        >
                          {openGroupId === group.group_id ? "Hide detail" : "Inspect"}
                        </button>
                        <Link
                          to={`/analysis/${encodeURIComponent(analysisId)}/issue?group=${encodeURIComponent(group.group_id)}`}
                          className="focus-ring rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
                        >
                          Preview issue
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-zinc-400">
            <span>
              Showing {formatNumber(total === 0 ? 0 : skip + 1)}–{formatNumber(skip + count)} of{" "}
              {formatNumber(total)} fix groups
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={skip === 0}
                onClick={() => {
                  onOpenGroup(null);
                  onSkipChange(Math.max(0, skip - limit));
                }}
                className="focus-ring rounded border border-zinc-700 px-3 py-1 text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={skip + count >= total}
                onClick={() => {
                  onOpenGroup(null);
                  onSkipChange(skip + limit);
                }}
                className="focus-ring rounded border border-zinc-700 px-3 py-1 text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>

          {openGroupId ? (
            <SectionCard title="Fix group detail">
              <GroupDetailPanel
                analysisId={analysisId}
                groupId={openGroupId}
                onClose={() => onOpenGroup(null)}
              />
            </SectionCard>
          ) : null}

          {(groups.data.unresolved_findings?.length ?? 0) > 0 ? (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
                Findings no candidate was shown to resolve
              </h3>
              <DataTable
                caption="Unresolved findings"
                rows={groups.data.unresolved_findings ?? []}
                rowKey={(row) => row.finding_id}
                initialRows={10}
                columns={[
                  {
                    key: "advisory",
                    header: "Advisory",
                    render: (row) => <span className="font-mono text-xs">{row.vulnerability_id}</span>,
                  },
                  {
                    key: "package",
                    header: "Package",
                    render: (row) => (
                      <span>
                        {row.package_name}{" "}
                        <span className="font-mono text-xs text-zinc-400">{row.package_version ?? "?"}</span>
                      </span>
                    ),
                  },
                  { key: "reason", header: "Reason", render: (row) => <span>{row.reason}</span> },
                ]}
              />
              {groups.data.unresolved_findings_truncated ? (
                <Notice tone="warning" title="Unresolved findings list was truncated by the server">
                  The backend bounded this list for transport; the graph may contain more unresolved findings.
                </Notice>
              ) : null}
            </div>
          ) : null}

          {(groups.data.limitations?.length ?? 0) > 0 ? (
            <Notice tone="warning" title="Response limitations">
              <ul className="list-disc space-y-1 pl-4">
                {groups.data.limitations?.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </Notice>
          ) : null}
        </>
      )}
    </div>
  );
}

function CandidatesView({ analysisId, skip, limit }: { analysisId: string; skip: number; limit: number }) {
  const candidates = useRemediationCandidates(analysisId, skip, limit);

  if (candidates.isPending) return <LoadingState label="Loading remediation candidates…" />;
  if (candidates.isError) {
    return (
      <ErrorState
        error={candidates.error}
        title="Could not load remediation candidates"
        onRetry={() => void candidates.refetch()}
      />
    );
  }
  if (!candidates.data) return <EmptyState title="No candidates response" />;

  const { plans, total, count, analysis_context } = candidates.data;

  return (
    <div className="space-y-4">
      <PartialAnalysisNotice context={analysis_context} />

      {total === 0 ? (
        <EmptyState
          title="No affected packages with plans"
          description="No stored finding currently has an advisory fixed version to plan against."
        />
      ) : (
        <>
          <p className="text-xs text-zinc-500">
            Showing {formatNumber(skip + 1)}–{formatNumber(skip + count)} of {formatNumber(total)} affected
            packages. Candidates are proposals from advisory data — BlastRadius never applies them or edits
            dependency files.
          </p>

          <div className="space-y-4">
            {plans.map((plan) => (
              <SectionCard
                key={plan.package_id}
                title={`${plan.package_name} ${plan.current_version}`}
                description={`${plan.ecosystem ?? "unknown ecosystem"} · ${plan.dependency_role ?? "unknown role"} · ${formatNumber((plan.finding_ids ?? []).length)} stored finding(s)`}
              >
                <div className="space-y-3">
                  {plan.no_candidate_reason ? (
                    <Notice tone="warning" title="No candidate version">
                      {plan.no_candidate_reason}
                    </Notice>
                  ) : null}
                  <div className="grid gap-2 lg:grid-cols-2">
                    {(plan.candidates ?? []).map((candidate) => (
                      <CandidateRow
                        key={`${candidate.package_id}-${candidate.proposed_version}`}
                        candidate={candidate}
                      />
                    ))}
                    {(plan.candidates ?? []).length === 0 && !plan.no_candidate_reason ? (
                      <p className="text-xs text-zinc-400">No candidates returned for this package.</p>
                    ) : null}
                  </div>
                  {(plan.unresolved_relationships?.length ?? 0) > 0 ? (
                    <Notice tone="warning" title="Unresolved relationships">
                      <ul className="list-disc space-y-1 pl-4">
                        {plan.unresolved_relationships?.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </Notice>
                  ) : null}
                  {(plan.migration_concerns?.length ?? 0) > 0 ? (
                    <Notice tone="warning" title="Migration concerns">
                      <ul className="list-disc space-y-1 pl-4">
                        {plan.migration_concerns?.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </Notice>
                  ) : null}
                  {(plan.limitations?.length ?? 0) > 0 ? (
                    <Notice tone="warning" title="Limitations">
                      <ul className="list-disc space-y-1 pl-4">
                        {plan.limitations?.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </Notice>
                  ) : null}
                </div>
              </SectionCard>
            ))}
          </div>

          {(candidates.data.limitations?.length ?? 0) > 0 ? (
            <Notice tone="warning" title="Response limitations">
              <ul className="list-disc space-y-1 pl-4">
                {candidates.data.limitations?.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </Notice>
          ) : null}
        </>
      )}
    </div>
  );
}

function RemediationContent() {
  const { analysisId } = useAnalysis();
  const [view, setView] = useState<"groups" | "candidates">("groups");
  const [skip, setSkip] = useState(0);
  const [limit, setLimit] = useState(25);
  const [openGroupId, setOpenGroupId] = useState<string | null>(null);

  return (
    <div className="space-y-5">
      <SectionCard
        title="Remediation"
        description="Deterministic ranking from the backend: fix groups first, then the per-package candidate plans behind them."
        actions={
          <div className="flex items-center gap-2">
            <label htmlFor="remediation-page-size" className="text-xs text-zinc-400">
              Page size
            </label>
            <select
              id="remediation-page-size"
              value={limit}
              onChange={(event) => {
                setLimit(Number(event.target.value));
                setSkip(0);
                setOpenGroupId(null);
              }}
              className="focus-ring rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </div>
        }
      >
        <div role="tablist" aria-label="Remediation views" className="mb-4 flex gap-2">
          <button
            type="button"
            role="tab"
            aria-selected={view === "groups"}
            onClick={() => setView("groups")}
            className={`focus-ring rounded-lg px-3 py-1.5 text-sm ${
              view === "groups"
                ? "bg-sky-500/10 text-sky-100 ring-1 ring-inset ring-sky-500/30"
                : "text-zinc-300 hover:bg-zinc-800"
            }`}
          >
            Fix groups
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={view === "candidates"}
            onClick={() => setView("candidates")}
            className={`focus-ring rounded-lg px-3 py-1.5 text-sm ${
              view === "candidates"
                ? "bg-sky-500/10 text-sky-100 ring-1 ring-inset ring-sky-500/30"
                : "text-zinc-300 hover:bg-zinc-800"
            }`}
          >
            Candidate plans
          </button>
        </div>

        {view === "groups" ? (
          <GroupsView
            analysisId={analysisId}
            skip={skip}
            limit={limit}
            onSkipChange={setSkip}
            openGroupId={openGroupId}
            onOpenGroup={setOpenGroupId}
          />
        ) : (
          <CandidatesView analysisId={analysisId} skip={skip} limit={limit} />
        )}
      </SectionCard>
    </div>
  );
}

export function RemediationPage() {
  return (
    <AnalysisGuard>
      <RemediationContent />
    </AnalysisGuard>
  );
}
