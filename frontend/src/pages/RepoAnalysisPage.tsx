import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import type { DependencyProvenance, RepositoryIngestResponse } from "../api/generated";
import { ingestRepository, persistAnalysis, syncVulnerabilities } from "../api/endpoints";
import { isApiError } from "../api/client";
import { CopyButton, SpinnerLabel, Stat, StatGrid } from "../components/data";
import { DataTable } from "../components/DataTable";
import { IngestionStatusBadge } from "../components/badges";
import { EmptyState, ErrorState, Notice, SectionCard, TruncationNotice } from "../components/StateViews";
import { useGraphHealth } from "../hooks/queries";
import { formatDateTime, formatDurationMs, formatNumber, shortSha, truncationNotes } from "../lib/format";
import { loadLastRepositoryUrl, saveLastRepositoryUrl } from "../lib/prefs";

function validateRepositoryUrl(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return "Repository URL is required.";
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return "Enter a valid URL, e.g. https://github.com/psf/requests";
  }
  if (url.protocol !== "https:") return "The backend only retrieves https:// repository URLs.";
  if (url.hostname.toLowerCase() !== "github.com") return "Only github.com repositories are supported.";
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length !== 2) {
    return "Use the repository root form https://github.com/<owner>/<repository>.";
  }
  return null;
}

function provenanceLabel(provenance: DependencyProvenance): string {
  const line = provenance.line_number ? `:${provenance.line_number}` : "";
  const section = provenance.section ? ` · ${provenance.section}` : "";
  return `${provenance.manifest_path}${line}${section}`;
}

export function RepoAnalysisPage() {
  const [repositoryUrl, setRepositoryUrl] = useState(() => loadLastRepositoryUrl());
  const [ref, setRef] = useState("");
  const [clientError, setClientError] = useState<string | null>(null);
  const [result, setResult] = useState<RepositoryIngestResponse | null>(null);

  const graphHealth = useGraphHealth();

  const ingest = useMutation({
    mutationFn: (input: { repository_url: string; ref: string | null }) => ingestRepository(input),
    onSuccess: (data) => {
      setResult(data);
      persist.reset();
      sync.reset();
    },
  });

  const persist = useMutation({
    mutationFn: (input: { analysisId: string; payload: RepositoryIngestResponse }) =>
      persistAnalysis(input.analysisId, input.payload),
  });

  const sync = useMutation({
    mutationFn: (analysisId: string) => syncVulnerabilities(analysisId),
  });

  const truncation = useMemo(() => truncationNotes(result?.truncated), [result]);

  const onSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const validation = validateRepositoryUrl(repositoryUrl);
    if (validation) {
      setClientError(validation);
      return;
    }
    setClientError(null);
    saveLastRepositoryUrl(repositoryUrl);
    ingest.mutate({ repository_url: repositoryUrl.trim(), ref: ref.trim() || null });
  };

  const analysisId = result?.analysis_id ?? null;
  const persistEnabled = Boolean(analysisId) && !persist.isPending && !persist.data;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <SectionCard
        title="Ingest a repository"
        description="Runs the real Phase 1 pipeline (metadata → retrieval → discovery → parsing → aggregation). The request is synchronous and bounded by the server's configured limits."
      >
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          <div className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <div>
              <label htmlFor="repository-url" className="block text-xs font-medium text-zinc-300">
                Repository URL <span className="text-red-300">*</span>
              </label>
              <input
                id="repository-url"
                name="repository-url"
                type="url"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                required
                aria-invalid={clientError ? true : undefined}
                aria-describedby={clientError ? "repository-url-error" : "repository-url-hint"}
                value={repositoryUrl}
                onChange={(event) => setRepositoryUrl(event.target.value)}
                placeholder="https://github.com/psf/requests"
                className="focus-ring mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600"
              />
              <p id="repository-url-hint" className="mt-1 text-xs text-zinc-500">
                Public github.com repositories only, e.g. https://github.com/psf/requests
              </p>
              {clientError ? (
                <p id="repository-url-error" role="alert" className="mt-1 text-xs text-red-300">
                  {clientError}
                </p>
              ) : null}
            </div>
            <div>
              <label htmlFor="repository-ref" className="block text-xs font-medium text-zinc-300">
                Branch / tag / commit (optional)
              </label>
              <input
                id="repository-ref"
                name="repository-ref"
                type="text"
                autoComplete="off"
                spellCheck={false}
                maxLength={255}
                value={ref}
                onChange={(event) => setRef(event.target.value)}
                placeholder="v2.32.3"
                className="focus-ring mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600"
              />
              <p className="mt-1 text-xs text-zinc-500">
                Unknown references are rejected, never silently replaced with the default branch.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={ingest.isPending}
              className="focus-ring rounded-lg bg-sky-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {ingest.isPending ? "Running ingestion…" : "Run ingestion"}
            </button>
            {ingest.isPending ? (
              <SpinnerLabel label="Retrieving and parsing the repository revision" />
            ) : null}
          </div>
        </form>

        {ingest.isPending ? (
          <div className="mt-4">
            <Notice tone="info" title="Synchronous request in progress">
              The server is fetching and parsing the repository now. There is no job queue and no progress
              percentage; a typed success or error envelope is returned when the work finishes.
            </Notice>
          </div>
        ) : null}

        {ingest.isError ? (
          <div className="mt-4">
            <ErrorState error={ingest.error} title="Ingestion failed" />
          </div>
        ) : null}
      </SectionCard>

      {result ? (
        <>
          <SectionCard
            title="Analysis overview"
            description="Everything on this page comes from the ingest response; nothing is estimated."
            actions={<IngestionStatusBadge status={result.status} />}
          >
            <div className="space-y-4">
              {result.status === "partial" || (result.errors?.length ?? 0) > 0 ? (
                <Notice tone="warning" title="Partial or errored analysis">
                  The backend reported{" "}
                  {formatNumber(result.summary.error_count ?? result.errors?.length ?? 0)} error(s) and{" "}
                  {formatNumber(result.summary.warning_count ?? result.warnings?.length ?? 0)} warning(s).
                  Sections below list every record the server returned; missing data is missing, not empty.
                </Notice>
              ) : null}

              <TruncationNotice notes={truncation} />

              <StatGrid>
                <Stat label="Files examined" value={formatNumber(result.summary.files_examined)} />
                <Stat label="Manifests detected" value={formatNumber(result.summary.manifests_detected)} />
                <Stat label="Manifests parsed" value={formatNumber(result.summary.manifests_parsed)} />
                <Stat label="Declarations" value={formatNumber(result.summary.declarations)} />
                <Stat label="Resolved packages" value={formatNumber(result.summary.resolved_packages)} />
                <Stat label="Dependency edges" value={formatNumber(result.summary.dependency_edges)} />
                <Stat
                  label="Warnings"
                  value={formatNumber(result.summary.warning_count)}
                  tone={(result.summary.warning_count ?? 0) > 0 ? "warning" : "default"}
                />
                <Stat
                  label="Errors"
                  value={formatNumber(result.summary.error_count)}
                  tone={(result.summary.error_count ?? 0) > 0 ? "danger" : "default"}
                />
              </StatGrid>

              <div className="grid gap-4 lg:grid-cols-2">
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
                    Repository
                  </h3>
                  <dl className="space-y-1 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <dt className="text-zinc-400">Identity</dt>
                      <dd className="font-mono text-zinc-100">
                        {result.repository?.identity.canonical_id ?? result.summary.repository_id ?? "—"}
                      </dd>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <dt className="text-zinc-400">Resolved commit</dt>
                      <dd className="font-mono text-zinc-100">
                        {result.reference.resolved_commit_sha
                          ? shortSha(result.reference.resolved_commit_sha)
                          : "—"}
                      </dd>
                      {result.reference.resolved_commit_sha ? (
                        <CopyButton value={result.reference.resolved_commit_sha} label="Copy SHA" />
                      ) : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <dt className="text-zinc-400">Resolution</dt>
                      <dd className="text-zinc-200">
                        {result.reference.ref_type}
                        {result.reference.is_default_branch ? " (default branch)" : ""} via{" "}
                        {result.reference.resolved_via}
                        {result.reference.sha_verified
                          ? " · SHA verified against the retrieved tree"
                          : " · SHA not independently verified"}
                      </dd>
                    </div>
                    {result.repository ? (
                      <div className="flex flex-wrap items-center gap-2">
                        <dt className="text-zinc-400">Metadata</dt>
                        <dd className="text-zinc-200">
                          {result.repository.metadata_source ?? "unknown source"}
                          {result.repository.primary_language
                            ? ` · ${result.repository.primary_language}`
                            : ""}
                          {result.repository.license_spdx_id ? ` · ${result.repository.license_spdx_id}` : ""}
                          {result.repository.is_archived ? " · archived" : ""}
                        </dd>
                      </div>
                    ) : null}
                    {result.repository?.commit.message ? (
                      <div>
                        <dt className="text-zinc-400">Commit message</dt>
                        <dd className="text-zinc-200">{result.repository.commit.message}</dd>
                      </div>
                    ) : null}
                  </dl>
                </div>

                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400">
                    Run summary
                  </h3>
                  <dl className="space-y-1 text-sm">
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-400">Duration</dt>
                      <dd className="text-zinc-200">{formatDurationMs(result.summary.duration_ms)}</dd>
                    </div>
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-400">Started</dt>
                      <dd className="text-zinc-200">{formatDateTime(result.summary.started_at)}</dd>
                    </div>
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-400">Retrieval strategy</dt>
                      <dd className="text-zinc-200">{result.summary.retrieval_strategy ?? "—"}</dd>
                    </div>
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-400">Direct / transitive / unknown</dt>
                      <dd className="text-zinc-200">
                        {formatNumber(result.summary.direct_declarations)} /{" "}
                        {formatNumber(result.summary.transitive_packages)} /{" "}
                        {formatNumber(result.summary.unknown_relation_packages)}
                      </dd>
                    </div>
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-400">Dev / optional declarations</dt>
                      <dd className="text-zinc-200">
                        {formatNumber(result.summary.dev_declarations)} /{" "}
                        {formatNumber(result.summary.optional_declarations)}
                      </dd>
                    </div>
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-400">Conflicting packages</dt>
                      <dd className="text-zinc-200">{formatNumber(result.summary.conflicting_packages)}</dd>
                    </div>
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-400">Symlinks / oversized files skipped</dt>
                      <dd className="text-zinc-200">
                        {formatNumber(result.summary.symlinks_skipped)} /{" "}
                        {formatNumber(result.summary.oversized_files_skipped)}
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>

              <Notice tone="info" title="Server-side limits applied to this run">
                <p className="text-xs">
                  Retrieval {result.limits.retrieval_strategy} · download timeout{" "}
                  {result.limits.download_timeout_seconds}s · git timeout {result.limits.git_timeout_seconds}s
                  · max run {result.limits.max_ingestion_seconds}s · ≤
                  {formatNumber(result.limits.max_files_scanned)} files scanned · ≤
                  {formatNumber(result.limits.max_manifests)} manifests · ≤
                  {formatNumber(result.limits.max_dependencies)} dependencies
                </p>
              </Notice>
            </div>
          </SectionCard>

          {(result.warnings?.length ?? 0) > 0 || (result.errors?.length ?? 0) > 0 ? (
            <SectionCard
              title="Warnings and errors"
              description="Verbatim records from the pipeline, with the stage and manifest location where known."
            >
              <div className="space-y-4">
                {(result.errors?.length ?? 0) > 0 ? (
                  <DataTable
                    caption="Ingestion errors"
                    rows={result.errors ?? []}
                    rowKey={(row, index) => `error-${index}-${row.code}`}
                    initialRows={10}
                    columns={[
                      {
                        key: "code",
                        header: "Code",
                        render: (row) => <span className="font-mono text-xs">{row.code}</span>,
                      },
                      {
                        key: "message",
                        header: "Message",
                        render: (row) => <span>{row.message}</span>,
                      },
                      { key: "stage", header: "Stage", render: (row) => <span>{row.stage ?? "—"}</span> },
                      {
                        key: "location",
                        header: "Location",
                        render: (row) => (
                          <span className="font-mono text-xs">
                            {row.manifest_path
                              ? `${row.manifest_path}${row.line_number ? `:${row.line_number}` : ""}`
                              : "—"}
                          </span>
                        ),
                      },
                      {
                        key: "retryable",
                        header: "Retryable",
                        render: (row) => <span>{row.retryable ? "yes" : "no"}</span>,
                      },
                    ]}
                  />
                ) : null}
                {(result.warnings?.length ?? 0) > 0 ? (
                  <DataTable
                    caption="Ingestion warnings"
                    rows={result.warnings ?? []}
                    rowKey={(row, index) => `warning-${index}-${row.code}`}
                    initialRows={10}
                    columns={[
                      {
                        key: "code",
                        header: "Code",
                        render: (row) => <span className="font-mono text-xs">{row.code}</span>,
                      },
                      { key: "message", header: "Message", render: (row) => <span>{row.message}</span> },
                      {
                        key: "severity",
                        header: "Severity",
                        render: (row) => <span>{row.severity ?? "—"}</span>,
                      },
                      { key: "stage", header: "Stage", render: (row) => <span>{row.stage ?? "—"}</span> },
                      {
                        key: "location",
                        header: "Location",
                        render: (row) => (
                          <span className="font-mono text-xs">
                            {row.manifest_path
                              ? `${row.manifest_path}${row.line_number ? `:${row.line_number}` : ""}`
                              : "—"}
                          </span>
                        ),
                      },
                    ]}
                  />
                ) : null}
              </div>
            </SectionCard>
          ) : null}

          <SectionCard
            title="Format coverage"
            description="What this build actually parses, and how this repository fared per format."
          >
            <DataTable
              caption="Format coverage"
              rows={result.coverage ?? []}
              rowKey={(row) => `coverage-${row.format}`}
              columns={[
                {
                  key: "format",
                  header: "Format",
                  render: (row) => <span className="font-mono text-xs">{row.format}</span>,
                },
                { key: "support", header: "Support", render: (row) => <span>{row.support_level}</span> },
                {
                  key: "detected",
                  header: "Detected",
                  render: (row) => <span>{row.detected_files ?? 0}</span>,
                },
                { key: "parsed", header: "Parsed", render: (row) => <span>{row.parsed_files ?? 0}</span> },
                { key: "failed", header: "Failed", render: (row) => <span>{row.failed_files ?? 0}</span> },
                { key: "notes", header: "Notes", render: (row) => <span>{row.notes ?? "—"}</span> },
              ]}
            />
          </SectionCard>

          <SectionCard title="Manifests" description="Every dependency file the discovery stage examined.">
            <DataTable
              caption="Dependency manifests"
              rows={result.manifests ?? []}
              rowKey={(row) => row.id}
              columns={[
                {
                  key: "path",
                  header: "Path",
                  render: (row) => (
                    <div>
                      <span className="font-mono text-xs">{row.path}</span>
                      <div className="text-[11px] text-zinc-500">
                        {row.format ?? row.unsupported_format ?? "unknown format"}
                        {row.is_lockfile ? " · lockfile" : ""}
                        {row.companion_manifest ? ` · companion: ${row.companion_manifest}` : ""}
                      </div>
                    </div>
                  ),
                },
                { key: "status", header: "Status", render: (row) => <span>{row.status}</span> },
                { key: "support", header: "Support", render: (row) => <span>{row.support_level}</span> },
                {
                  key: "counts",
                  header: "Declarations / resolved / edges",
                  render: (row) => (
                    <span>
                      {row.declaration_count ?? 0} / {row.resolved_count ?? 0} / {row.edge_count ?? 0}
                    </span>
                  ),
                },
                {
                  key: "codes",
                  header: "Codes",
                  render: (row) => (
                    <span className="font-mono text-[11px] text-zinc-400">
                      {[...(row.warning_codes ?? []), ...(row.error_codes ?? [])].join(", ") || "—"}
                    </span>
                  ),
                },
              ]}
            />
          </SectionCard>

          <SectionCard
            title="Declared dependencies"
            description="What the manifests ask for — declarations are not installations. Evidence shows where each fact came from."
          >
            <DataTable
              caption="Declared dependencies"
              rows={result.declarations ?? []}
              rowKey={(row, index) => `${row.normalized_name}-${index}`}
              columns={[
                {
                  key: "name",
                  header: "Package",
                  render: (row) => (
                    <div>
                      <span className="font-medium text-zinc-100">{row.normalized_name}</span>
                      {row.original_name !== row.normalized_name ? (
                        <span className="ml-1 text-[11px] text-zinc-500">
                          (declared as {row.original_name})
                        </span>
                      ) : null}
                      <div className="text-[11px] text-zinc-500">
                        {row.ecosystem ?? "unknown ecosystem"} · {row.scope ?? "unknown scope"} ·{" "}
                        {row.relation ?? "unknown relation"}
                        {row.is_exact_pin ? " · exact pin" : ""}
                      </div>
                    </div>
                  ),
                },
                {
                  key: "constraint",
                  header: "Constraint",
                  render: (row) => (
                    <span className="font-mono text-xs">
                      {row.version_constraint ?? "—"}
                      {row.constraint_scheme ? ` (${row.constraint_scheme})` : ""}
                    </span>
                  ),
                },
                {
                  key: "resolved",
                  header: "Resolved / referenced version",
                  render: (row) => (
                    <span className="font-mono text-xs">
                      {row.resolved_version ?? row.referenced_version ?? "unresolved"}
                      {row.resolved_from ? ` (from ${row.resolved_from})` : ""}
                    </span>
                  ),
                },
                {
                  key: "provenance",
                  header: "Evidence",
                  render: (row) => (
                    <div className="max-w-md">
                      <div className="font-mono text-[11px] text-zinc-400">
                        {provenanceLabel(row.provenance)}
                      </div>
                      <div className="text-[11px] text-zinc-500">{row.provenance.evidence}</div>
                    </div>
                  ),
                },
              ]}
            />
          </SectionCard>

          <SectionCard
            title="Resolved packages"
            description="Concrete versions taken from lockfiles. These are separate from declarations and never derived from a constraint."
          >
            <DataTable
              caption="Resolved packages"
              rows={result.resolved_packages ?? []}
              rowKey={(row) => row.id}
              columns={[
                {
                  key: "name",
                  header: "Package",
                  render: (row) => (
                    <span className="font-medium text-zinc-100">
                      {row.normalized_name}{" "}
                      <span className="font-mono text-xs text-zinc-300">{row.version}</span>
                    </span>
                  ),
                },
                {
                  key: "relation",
                  header: "Relation",
                  render: (row) => (
                    <span>
                      {row.relation ?? "unknown"}
                      {row.is_dev ? " · dev" : ""}
                      {row.is_optional ? " · optional" : ""}
                      {row.is_root_project ? " · root project" : ""}
                    </span>
                  ),
                },
                {
                  key: "source",
                  header: "Source manifest",
                  render: (row) => <span className="font-mono text-xs">{row.source_manifest}</span>,
                },
                {
                  key: "provenance",
                  header: "Evidence",
                  render: (row) => (
                    <div className="max-w-md">
                      <div className="font-mono text-[11px] text-zinc-400">
                        {provenanceLabel(row.provenance)}
                      </div>
                      <div className="text-[11px] text-zinc-500">{row.provenance.evidence}</div>
                    </div>
                  ),
                },
              ]}
            />
          </SectionCard>

          {(result.supported_formats?.length ?? 0) > 0 ? (
            <SectionCard
              title="Formats this build parses"
              description="Reported by the running backend, not aspirational."
            >
              <ul className="grid gap-2 sm:grid-cols-2">
                {result.supported_formats?.map((format) => (
                  <li
                    key={format.format}
                    className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 text-sm"
                  >
                    <p className="font-mono text-xs text-zinc-100">{format.format}</p>
                    <p className="mt-0.5 text-[11px] text-zinc-400">
                      {format.support_level}
                      {format.is_lockfile ? " · lockfile" : ""}
                    </p>
                    <p className="mt-1 text-[11px] text-zinc-500">{format.capabilities}</p>
                  </li>
                ))}
              </ul>
            </SectionCard>
          ) : null}

          <SectionCard
            title="Graph persistence and advisory sync"
            description="The supported sequence is: ingest (done) → persist to FalkorDB → OSV advisory sync. Each step is a separate, explicit server operation."
          >
            <div className="space-y-4">
              {graphHealth.data && !graphHealth.data.connected ? (
                <Notice tone="warning" title="FalkorDB is not reachable">
                  Persistence and everything downstream (findings, graph explorer, remediation) will fail
                  until the graph backend is available. Probe: {graphHealth.data.connection}
                  {graphHealth.data.error ? ` · ${graphHealth.data.error}` : ""}
                </Notice>
              ) : null}

              {analysisId ? (
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-sm text-zinc-300">
                    Analysis id: <span className="font-mono text-zinc-100">{analysisId}</span>
                  </span>
                  <CopyButton value={analysisId} label="Copy id" />
                </div>
              ) : (
                <Notice tone="warning" title="No analysis id in this response">
                  The ingest response carries no analysis id (usually because no commit could be resolved), so
                  this result cannot be persisted to the graph.
                </Notice>
              )}

              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  disabled={!persistEnabled}
                  onClick={() => {
                    if (analysisId) persist.mutate({ analysisId, payload: result });
                  }}
                  className="focus-ring rounded-lg bg-zinc-100 px-4 py-2 text-sm font-semibold text-zinc-900 hover:bg-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {persist.data
                    ? "Persisted"
                    : persist.isPending
                      ? "Persisting…"
                      : "Persist analysis to graph"}
                </button>
                {persist.isPending ? (
                  <SpinnerLabel label="Writing nodes and relationships (idempotent upsert)" />
                ) : null}
              </div>

              {persist.isError ? <ErrorState error={persist.error} title="Graph persistence failed" /> : null}

              {persist.data ? (
                <div className="space-y-3">
                  <Notice
                    tone={persist.data.status === "success" ? "success" : "warning"}
                    title={`Persisted (status: ${persist.data.status})`}
                  >
                    <p>
                      {formatNumber(persist.data.created)} created · {formatNumber(persist.data.updated)}{" "}
                      updated · {formatNumber(persist.data.unchanged)} unchanged
                      {persist.data.rejected > 0
                        ? ` · ${formatNumber(persist.data.rejected)} rejected`
                        : ""}{" "}
                      · {formatNumber(persist.data.nodes_created)} nodes ·{" "}
                      {formatNumber(persist.data.relationships_created)} relationships
                    </p>
                    {persist.data.rejected > 0 ? (
                      <p className="mt-1 text-xs">
                        Rejected records were reported by the server and are not in the graph. Details:{" "}
                        <span className="font-mono">{JSON.stringify(persist.data.details)}</span>
                      </p>
                    ) : null}
                  </Notice>
                  <div className="flex flex-wrap items-center gap-3">
                    <Link
                      to={`/analysis/${encodeURIComponent(persist.data.analysis_id)}/findings`}
                      className="focus-ring rounded-lg bg-sky-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-sky-400"
                    >
                      Open analysis
                    </Link>
                    <button
                      type="button"
                      disabled={sync.isPending || Boolean(sync.data)}
                      onClick={() => sync.mutate(persist.data.analysis_id)}
                      className="focus-ring rounded-lg border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-100 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {sync.data
                        ? "OSV sync done"
                        : sync.isPending
                          ? "Syncing advisories…"
                          : "Sync OSV advisories"}
                    </button>
                    {sync.isPending ? (
                      <SpinnerLabel label="Querying OSV for every resolved package/version" />
                    ) : null}
                  </div>
                </div>
              ) : null}

              {sync.isError ? <ErrorState error={sync.error} title="OSV sync failed" /> : null}

              {sync.data ? (
                <div className="space-y-3">
                  <Notice
                    tone={sync.data.status === "completed" ? "success" : "warning"}
                    title={`OSV sync: ${sync.data.status}`}
                  >
                    <p>
                      {formatNumber(sync.data.packages_scanned)} packages scanned ·{" "}
                      {formatNumber(sync.data.items_with_matches)} with matches ·{" "}
                      {formatNumber(sync.data.items_without_matches)} without matches ·{" "}
                      {formatNumber(sync.data.vulnerabilities_found)} advisories found ·{" "}
                      {formatNumber(sync.data.vulnerabilities_created)} created ·{" "}
                      {formatNumber(sync.data.vulnerabilities_updated)} updated ·{" "}
                      {formatNumber(sync.data.edges_created)} links created ·{" "}
                      {formatNumber(sync.data.skipped_edges)} links skipped
                    </p>
                    {sync.data.last_synced_at ? (
                      <p className="mt-1 text-xs">Last synced: {formatDateTime(sync.data.last_synced_at)}</p>
                    ) : null}
                  </Notice>
                  {(sync.data.errors?.length ?? 0) > 0 ? (
                    <DataTable
                      caption="OSV sync errors"
                      rows={sync.data.errors ?? []}
                      rowKey={(_row, index) => `sync-error-${index}`}
                      columns={[
                        {
                          key: "kind",
                          header: "Kind",
                          render: (row) => <span className="font-mono text-xs">{row.kind}</span>,
                        },
                        {
                          key: "package",
                          header: "Package",
                          render: (row) => (
                            <span>
                              {row.package_name ?? "—"} {row.version ?? ""}
                            </span>
                          ),
                        },
                        {
                          key: "vulnerability",
                          header: "Advisory",
                          render: (row) => (
                            <span className="font-mono text-xs">{row.vulnerability_id ?? "—"}</span>
                          ),
                        },
                        { key: "message", header: "Message", render: (row) => <span>{row.message}</span> },
                        {
                          key: "retryable",
                          header: "Retryable",
                          render: (row) => <span>{row.retryable ? "yes" : "no"}</span>,
                        },
                      ]}
                    />
                  ) : null}
                </div>
              ) : null}
            </div>
          </SectionCard>
        </>
      ) : (
        <EmptyState
          title="No analysis yet"
          description={
            <span>
              Run an ingestion above to see the real result. This screen performs no client-side analysis and
              never fabricates data. To explore an existing analysis, open it from the findings screen of a
              persisted analysis (analysis ids are stable:{" "}
              <span className="font-mono">analysis_&lt;hash&gt;</span>).
            </span>
          }
          action={
            isApiError(ingest.error) ? (
              <span className="text-xs text-zinc-500">
                Last error: <span className="font-mono">{ingest.error.code}</span>
              </span>
            ) : null
          }
        />
      )}
    </div>
  );
}
