import type { FindingOut } from "../api/generated";
import { useFindingDetail } from "../hooks/queries";
import { EmptyState, ErrorState, LoadingState, Notice, SectionCard } from "./StateViews";
import { ConfidenceBadge, MatchTypeBadge, ReachabilityBadge, SeverityBadge } from "./badges";
import { DataTable } from "./DataTable";
import { formatDateTime, formatNumber, formatScore, reachabilityLabel } from "../lib/format";

function Limitations({ items, title = "Limitations" }: { items?: string[] | null; title?: string }) {
  if (!items || items.length === 0) return null;
  return (
    <Notice tone="warning" title={title}>
      <ul className="list-disc space-y-1 pl-4">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </Notice>
  );
}

/** Advisory severity, exactly as the OSV record reported it. */
export function SeverityEvidenceBlock({ finding }: { finding: FindingOut }) {
  const severity = finding.priority.severity;
  return (
    <div className="space-y-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={severity} />
        <span className="text-xs text-zinc-400">
          source: {severity.source ?? "—"} · quantified: {severity.quantified ? "yes" : "no"}
        </span>
      </div>
      {severity.vector ? (
        <p className="break-all font-mono text-[11px] text-zinc-400">vector {severity.vector}</p>
      ) : null}
      {severity.entries && severity.entries.length > 0 ? (
        <ul className="space-y-1">
          {severity.entries.map((entry) => (
            <li key={entry} className="break-all font-mono text-[11px] text-zinc-400">
              {entry}
            </li>
          ))}
        </ul>
      ) : null}
      {severity.note ? <p className="text-xs text-zinc-500">{severity.note}</p> : null}
    </div>
  );
}

/** BlastRadius priority (custom, deterministic) with every factor shown. */
export function PriorityBlock({ finding }: { finding: FindingOut }) {
  const priority = finding.priority;
  return (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap items-baseline gap-3">
        <span className="text-2xl font-semibold text-violet-200">{formatScore(priority.score)}</span>
        <span className="text-xs text-zinc-400">
          BlastRadius priority (custom score, not CVSS) · position {priority.rank} · formula{" "}
          <span className="font-mono">{priority.formula_version}</span>
        </span>
      </div>
      <DataTable
        caption="Priority factors"
        initialRows={12}
        rows={priority.factors}
        rowKey={(factor) => factor.name}
        columns={[
          {
            key: "name",
            header: "Factor",
            render: (factor) => <span className="font-mono text-xs">{factor.name}</span>,
          },
          { key: "weight", header: "Weight", render: (factor) => <span>{formatScore(factor.weight)}</span> },
          {
            key: "normalized",
            header: "Normalized",
            render: (factor) => <span>{formatScore(factor.normalized)}</span>,
          },
          {
            key: "contribution",
            header: "Contribution",
            render: (factor) => <span>{formatScore(factor.contribution)}</span>,
          },
          {
            key: "raw",
            header: "Facts",
            render: (factor) => (
              <div className="max-w-md">
                <span className="break-all font-mono text-[11px] text-zinc-400">
                  {factor.raw ? JSON.stringify(factor.raw) : "—"}
                </span>
                {factor.notes && factor.notes.length > 0 ? (
                  <ul className="mt-1 list-disc pl-4 text-[11px] text-zinc-500">
                    {factor.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ),
          },
        ]}
      />
      <p className="text-xs text-zinc-500">
        Remediation available: {priority.remediation_available ? "yes" : "no"}
        {priority.remediation_note ? ` · ${priority.remediation_note}` : ""}
      </p>
    </div>
  );
}

export function ReachabilityBlock({ finding }: { finding: FindingOut }) {
  const reach = finding.priority.reachability;
  return (
    <div className="space-y-2 text-sm">
      <ReachabilityBadge status={reach.status} minHops={reach.min_hops} />
      <dl className="space-y-1 text-xs text-zinc-400">
        <div>
          <dt className="inline text-zinc-500">Interpretation: </dt>
          <dd className="inline">
            {reachabilityLabel(reach.status)} — this is graph-derived evidence, not a safety guarantee.
          </dd>
        </div>
        {reach.entry_points && reach.entry_points.length > 0 ? (
          <div>
            <dt className="inline text-zinc-500">Entry points: </dt>
            <dd className="inline font-mono">{[...reach.entry_points].join(", ")}</dd>
          </div>
        ) : null}
        {reach.min_hops ? (
          <div>
            <dt className="inline text-zinc-500">Shortest modeled path: </dt>
            <dd className="inline">{reach.min_hops} hop(s)</dd>
          </div>
        ) : null}
        {typeof reach.dependent_component_count === "number" ? (
          <div>
            <dt className="inline text-zinc-500">Dependents: </dt>
            <dd className="inline">
              {formatNumber(reach.dependent_component_count)}
              {reach.dependent_components_truncated ? " (list truncated by the server)" : ""}
              {reach.dependent_components && reach.dependent_components.length > 0
                ? ` · ${reach.dependent_components.join(", ")}`
                : ""}
            </dd>
          </div>
        ) : null}
        <div>
          <dt className="inline text-zinc-500">Scope exposure: </dt>
          <dd className="inline">{reach.scope_exposure ?? "unknown"}</dd>
        </div>
        <div>
          <dt className="inline text-zinc-500">Evidence available: </dt>
          <dd className="inline">
            {reach.evidence_available
              ? "yes (edges and entry packages defined)"
              : "no (incomplete graph data)"}
          </dd>
        </div>
      </dl>
      {reach.notes && reach.notes.length > 0 ? (
        <ul className="list-disc space-y-1 pl-4 text-xs text-zinc-400">
          {reach.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function FindingDetailPanel({ analysisId, findingId }: { analysisId: string; findingId: string }) {
  const detail = useFindingDetail(analysisId, findingId);

  if (detail.isPending) return <LoadingState label="Loading finding detail…" />;
  if (detail.isError) return <ErrorState error={detail.error} title="Could not load finding detail" />;
  if (!detail.data) return <EmptyState title="No detail returned" />;

  const { finding, remediation, limitations } = detail.data;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-mono text-sm text-zinc-100">{finding.vulnerability_id}</h3>
        <MatchTypeBadge matchType={finding.match_type} />
        <ConfidenceBadge confidence={finding.confidence} />
        <span className="text-xs text-zinc-500">finding {finding.finding_id}</span>
      </div>

      {finding.advisory_withdrawn ? (
        <Notice tone="danger" title="Advisory withdrawn">
          The OSV record carries a withdrawn timestamp. Treat any remediation advice with caution.
        </Notice>
      ) : null}

      <div className="grid gap-5 lg:grid-cols-2">
        <SectionCard title="Advisory severity (as reported)">
          <SeverityEvidenceBlock finding={finding} />
        </SectionCard>
        <SectionCard title="BlastRadius priority (deterministic)">
          <PriorityBlock finding={finding} />
        </SectionCard>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <SectionCard title="Modeled reachability">
          <ReachabilityBlock finding={finding} />
        </SectionCard>
        <SectionCard title="Package and provenance">
          <dl className="space-y-1 text-sm">
            <div>
              <dt className="inline text-zinc-400">Package: </dt>
              <dd className="inline font-mono text-zinc-100">
                {finding.package.package_name} {finding.package.package_version ?? "(version unknown)"}
              </dd>
            </div>
            <div>
              <dt className="inline text-zinc-400">Role: </dt>
              <dd className="inline">
                {finding.package.dependency_role ?? "unknown"}
                {finding.package.is_dev ? " · dev" : ""}
                {finding.package.is_optional ? " · optional" : ""}
                {finding.package.is_root_project ? " · root project" : ""}
              </dd>
            </div>
            <div>
              <dt className="inline text-zinc-400">Source manifest: </dt>
              <dd className="inline font-mono">{finding.package.source_manifest ?? "—"}</dd>
            </div>
            <div>
              <dt className="inline text-zinc-400">Advisory modified: </dt>
              <dd className="inline">{formatDateTime(finding.osv_modified)}</dd>
            </div>
            <div>
              <dt className="inline text-zinc-400">Last synced: </dt>
              <dd className="inline">{formatDateTime(finding.last_synced_at)}</dd>
            </div>
            <div>
              <dt className="inline text-zinc-400">Advisory fixed versions: </dt>
              <dd className="inline font-mono">
                {(finding.fixed_versions ?? []).join(", ") || "none reported"}
              </dd>
            </div>
          </dl>
          {finding.advisory_references && finding.advisory_references.length > 0 ? (
            <ul className="mt-3 space-y-1">
              {finding.advisory_references.map((reference) => (
                <li key={reference} className="break-all text-xs text-zinc-400">
                  {reference}
                </li>
              ))}
            </ul>
          ) : null}
        </SectionCard>
      </div>

      <SectionCard
        title="Package remediation plan"
        description="Candidates come from advisory fixed versions; constraints are checked, no resolver is ever executed."
      >
        {remediation ? (
          <div className="space-y-4">
            {remediation.no_candidate_reason ? (
              <Notice tone="warning" title="No candidate">
                {remediation.no_candidate_reason}
              </Notice>
            ) : null}
            <DataTable
              caption="Remediation candidates"
              rows={remediation.candidates ?? []}
              rowKey={(candidate) => `${candidate.package_id}-${candidate.proposed_version}`}
              columns={[
                {
                  key: "proposed",
                  header: "Proposed version",
                  render: (candidate) => (
                    <div>
                      <span className="font-mono text-zinc-100">
                        {candidate.current_version} → {candidate.proposed_version}
                      </span>
                      <div className="text-[11px] text-zinc-500">
                        origin: {candidate.origin ?? "unknown"}
                        {candidate.selected ? " · selected" : ""}
                        {candidate.resolver_executed === false ? " · no resolver executed" : ""}
                      </div>
                    </div>
                  ),
                },
                {
                  key: "compatibility",
                  header: "Compatibility",
                  render: (candidate) => (
                    <div className="max-w-xs">
                      <span className="text-xs">{candidate.compatibility ?? "unverified"}</span>
                      <div className="text-[11px] text-zinc-500">{candidate.compatibility_detail}</div>
                    </div>
                  ),
                },
                {
                  key: "resolves",
                  header: "Advisory validation",
                  render: (candidate) => (
                    <ul className="space-y-1 text-[11px]">
                      {(candidate.resolves ?? []).map((evaluation) => (
                        <li key={`${evaluation.vulnerability_id}-${evaluation.status}`}>
                          <span className="font-mono">{evaluation.vulnerability_id}</span>:{" "}
                          {evaluation.status} — {evaluation.detail}
                        </li>
                      ))}
                      {(candidate.resolves ?? []).length === 0 ? (
                        <li className="text-zinc-500">no validation records</li>
                      ) : null}
                    </ul>
                  ),
                },
                {
                  key: "constraints",
                  header: "Constraint checks",
                  render: (candidate) => (
                    <ul className="space-y-1 text-[11px]">
                      {(candidate.constraint_checks ?? []).map((check, index) => (
                        <li key={`${check.source}-${index}`}>
                          <span className="font-mono">{check.constraint ?? "—"}</span> ({check.scheme}) —{" "}
                          {check.satisfied === null
                            ? "unverifiable"
                            : check.satisfied
                              ? "satisfied"
                              : "violated"}{" "}
                          · {check.detail}
                        </li>
                      ))}
                      {(candidate.constraint_checks ?? []).length === 0 ? (
                        <li className="text-zinc-500">no declared constraints</li>
                      ) : null}
                    </ul>
                  ),
                },
              ]}
            />
            {(remediation.unresolved_relationships?.length ?? 0) > 0 ? (
              <Notice tone="warning" title="Unresolved dependency relationships">
                <ul className="list-disc space-y-1 pl-4">
                  {remediation.unresolved_relationships?.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </Notice>
            ) : null}
            {(remediation.migration_concerns?.length ?? 0) > 0 ? (
              <Notice tone="warning" title="Migration concerns reported by the backend">
                <ul className="list-disc space-y-1 pl-4">
                  {remediation.migration_concerns?.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </Notice>
            ) : null}
            <Limitations items={remediation.limitations} />
          </div>
        ) : (
          <EmptyState
            title="No remediation plan for this finding"
            description="The backend did not return a plan (no advisory fixed version, or no candidate survived validation)."
          />
        )}
      </SectionCard>

      <div className="grid gap-5 lg:grid-cols-2">
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Confidence reasons
          </h4>
          {finding.confidence_reasons && finding.confidence_reasons.length > 0 ? (
            <ul className="list-disc space-y-1 pl-4 text-xs text-zinc-400">
              {finding.confidence_reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-zinc-500">None reported.</p>
          )}
        </div>
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Finding limitations
          </h4>
          {finding.limitations && finding.limitations.length > 0 ? (
            <ul className="list-disc space-y-1 pl-4 text-xs text-zinc-400">
              {finding.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-zinc-500">None reported.</p>
          )}
        </div>
      </div>

      <Limitations items={limitations} title="Response limitations" />
    </div>
  );
}
