import { useMemo, useState } from "react";
import type { ImpactPathOut } from "../api/generated";
import { Badge } from "../components/badges";
import { AnalysisGuard } from "../components/AnalysisGuard";
import { CopyButton, Stat, StatGrid } from "../components/data";
import { EmptyState, ErrorState, LoadingState, Notice, SectionCard } from "../components/StateViews";
import { SearchIcon } from "../components/icons";
import { GraphCanvas } from "../graph/GraphCanvas";
import {
  buildExplorerData,
  EDGE_TYPE_LABELS,
  highlightIdsForPaths,
  mergeNeighborhood,
  NODE_TYPE_LABELS,
  overlayVulnerabilities,
  type ExplorerNode,
  type ExplorerNodeType,
} from "../graph/adapter";
import {
  useAnalysisVulnerabilities,
  useBlastRadius,
  useGraphRecord,
  useGraphStatistics,
  useNeighborhood,
} from "../hooks/queries";
import { formatNumber } from "../lib/format";
import { useAnalysis } from "../state/analysis-context";

const LIMITS = [100, 200, 500, 1000] as const;
const DEPTHS = [1, 2, 3, 4, 5] as const;

const ALL_TYPES: ExplorerNodeType[] = [
  "repository",
  "file",
  "manifest",
  "declaration",
  "package",
  "vulnerability",
];

function NodeDetailPanel({
  node,
  depth,
  onExpand,
  onHighlightVulnerability,
}: {
  node: ExplorerNode;
  depth: number;
  onExpand: (packageId: string) => void;
  onHighlightVulnerability: (vulnerabilityId: string) => void;
}) {
  const packageId = typeof node.properties.id === "string" ? node.properties.id : null;
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="accent">{NODE_TYPE_LABELS[node.type]}</Badge>
        <span className="break-all font-mono text-xs text-zinc-100">{node.label}</span>
        <CopyButton value={node.id} label="Copy element id" />
        {node.nameOnly ? <Badge tone="warning">Name-only record (no node id returned)</Badge> : null}
      </div>

      {node.provenance.length > 0 ? (
        <div>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-400">Provenance</h4>
          <ul className="space-y-1 text-xs text-zinc-300">
            {node.provenance.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div>
        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-400">
          Properties returned by the API
        </h4>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-xs sm:grid-cols-[minmax(8rem,auto)_1fr]">
          {Object.entries(node.properties).map(([key, value]) => (
            <div key={key} className="contents">
              <dt className="font-mono text-zinc-500">{key}</dt>
              <dd className="break-all text-zinc-200">
                {value === null || value === undefined
                  ? "—"
                  : Array.isArray(value)
                    ? `[${value.map((item) => String(item)).join(", ")}]`
                    : String(value)}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="flex flex-wrap gap-2">
        {node.type === "package" && packageId && !node.nameOnly ? (
          <button
            type="button"
            className="focus-ring rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
            onClick={() => onExpand(packageId)}
          >
            Expand dependency neighborhood (depth {depth})
          </button>
        ) : null}
        {node.type === "vulnerability" ? (
          <button
            type="button"
            className="focus-ring rounded border border-amber-400/50 px-3 py-1 text-xs text-amber-100 hover:bg-amber-400/10"
            onClick={() => onHighlightVulnerability(String(node.properties.id ?? node.label))}
          >
            Highlight modeled paths for this advisory
          </button>
        ) : null}
      </div>
    </div>
  );
}

function GraphExplorerContent() {
  const { analysisId } = useAnalysis();
  const [limit, setLimit] = useState<number>(300);
  const [depth, setDepth] = useState<number>(2);
  const [highlightPaths, setHighlightPaths] = useState(false);
  const [focusVulnerability, setFocusVulnerability] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [expandedPackageId, setExpandedPackageId] = useState<string | null>(null);
  const [visibleTypes, setVisibleTypes] = useState<Set<ExplorerNodeType>>(new Set(ALL_TYPES));
  const [nodeListQuery, setNodeListQuery] = useState("");

  const record = useGraphRecord(analysisId, limit);
  const statistics = useGraphStatistics(analysisId);
  const vulnerabilities = useAnalysisVulnerabilities(analysisId, 500);
  const blastRadius = useBlastRadius(analysisId, depth);
  const neighborhood = useNeighborhood(expandedPackageId, depth);

  const data = useMemo(() => {
    const base = buildExplorerData(record.data?.rows ?? [], limit);
    const withVulnerabilities = overlayVulnerabilities(base, vulnerabilities.data?.items ?? []);
    const withNeighborhood = expandedPackageId
      ? mergeNeighborhood(withVulnerabilities, expandedPackageId, neighborhood.data?.edges ?? [])
      : withVulnerabilities;
    return { base, combined: withNeighborhood };
  }, [record.data, limit, vulnerabilities.data, expandedPackageId, neighborhood.data]);

  const highlighted = useMemo(() => {
    if (!highlightPaths) return new Set<string>();
    return highlightIdsForPaths(data.combined, blastRadius.data?.paths ?? [], focusVulnerability);
  }, [highlightPaths, data.combined, blastRadius.data, focusVulnerability]);

  const visibleNodes = useMemo(
    () => data.combined.nodes.filter((node) => visibleTypes.has(node.type)),
    [data.combined.nodes, visibleTypes],
  );
  const visibleIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEdges = useMemo(
    () => data.combined.edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)),
    [data.combined.edges, visibleIds],
  );

  const selectedNode = selectedNodeId
    ? (data.combined.nodes.find((node) => node.id === selectedNodeId) ?? null)
    : null;

  const nodeListMatches = useMemo(() => {
    const needle = nodeListQuery.trim().toLowerCase();
    const rows = visibleNodes.filter((node) => !needle || node.label.toLowerCase().includes(needle));
    return rows.slice(0, 200);
  }, [visibleNodes, nodeListQuery]);

  const countsByType = useMemo(() => {
    const counts = new Map<ExplorerNodeType, number>();
    for (const node of data.combined.nodes) {
      counts.set(node.type, (counts.get(node.type) ?? 0) + 1);
    }
    return counts;
  }, [data.combined.nodes]);

  // Highlighted ids the fetched page does not contain. Nothing is synthesized to
  // fill the gap, so the missing endpoints are reported instead of silently dropped.
  const highlightedOutsideView = useMemo(() => {
    if (highlighted.size === 0) return 0;
    const present = new Set(data.combined.nodes.map((node) => node.id));
    let missing = 0;
    for (const id of highlighted) {
      if (!present.has(id)) missing += 1;
    }
    return missing;
  }, [highlighted, data.combined.nodes]);

  if (record.isPending) {
    return <LoadingState label="Loading graph records…" />;
  }
  if (record.isError) {
    return (
      <ErrorState
        error={record.error}
        title="Could not load graph records"
        onRetry={() => void record.refetch()}
      />
    );
  }
  if (!record.data || record.data.count === 0) {
    return (
      <SectionCard title="Graph explorer" description="Read-only view over the persisted FalkorDB graph.">
        <EmptyState
          title="No graph records for this analysis"
          description="The graph API returned zero rows. Persist an ingestion result from the repository screen first — the explorer never invents nodes or edges."
        />
      </SectionCard>
    );
  }

  const stats = statistics.data;
  const pathList: ImpactPathOut[] = blastRadius.data?.paths ?? [];
  const neighborhoodOverflow = (neighborhood.data?.edges?.length ?? 0) > 0 && expandedPackageId !== null;

  return (
    <div className="space-y-5">
      {data.base.truncated ? (
        <Notice tone="warning" title="Rendering a bounded slice of the graph">
          The page fetched the first {formatNumber(record.data.count)} rows at a limit of{" "}
          {formatNumber(limit)}; the backend matched more rows than were returned. Increase the row limit or
          narrow your question — counts below come from the statistics endpoint, not from the rendered slice.
        </Notice>
      ) : null}

      {highlightPaths && highlightedOutsideView > 0 ? (
        <Notice tone="warning" title="Some highlighted path endpoints are outside the loaded slice">
          {formatNumber(highlightedOutsideView)}{" "}
          {highlightedOutsideView === 1
            ? "node reported by the impact paths is"
            : "nodes reported by the impact paths are"}{" "}
          not in the fetched page (limit {formatNumber(limit)} rows). Exactly these rows were returned by the
          graph API — expand a package neighborhood or raise the row limit to load the rest. Nothing is
          synthesized to fill the gap.
        </Notice>
      ) : null}

      <SectionCard
        title="Graph explorer"
        description="Nodes and relationships exactly as the graph API returned them. Reachability is never computed in the browser."
        actions={
          <button
            type="button"
            onClick={() => void record.refetch()}
            className="focus-ring rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
          >
            Refresh
          </button>
        }
      >
        <div className="space-y-4">
          <StatGrid>
            <Stat label="Repositories" value={formatNumber(stats?.repositories ?? 0)} />
            <Stat label="Files" value={formatNumber(stats?.files ?? 0)} />
            <Stat label="Manifests" value={formatNumber(stats?.manifests ?? 0)} />
            <Stat label="Declarations" value={formatNumber(stats?.declarations ?? 0)} />
            <Stat label="Package versions" value={formatNumber(stats?.packages ?? 0)} />
            <Stat label="Dependency edges" value={formatNumber(stats?.dependency_edges ?? 0)} />
            <Stat label="Resolved packages" value={formatNumber(stats?.resolved_packages ?? 0)} />
            <Stat
              label="Advisory links"
              value={formatNumber(stats?.vulnerability_edges ?? 0)}
              hint="Package–advisory edges stored in the graph"
            />
          </StatGrid>

          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor="graph-limit" className="block text-xs text-zinc-400">
                Row limit (bounded fetch)
              </label>
              <select
                id="graph-limit"
                value={limit}
                onChange={(event) => setLimit(Number(event.target.value))}
                className="focus-ring mt-1 rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              >
                {LIMITS.map((value) => (
                  <option key={value} value={value}>
                    {value} rows
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="graph-depth" className="block text-xs text-zinc-400">
                Path / neighborhood depth
              </label>
              <select
                id="graph-depth"
                value={depth}
                onChange={(event) => setDepth(Number(event.target.value))}
                className="focus-ring mt-1 rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              >
                {DEPTHS.map((value) => (
                  <option key={value} value={value}>
                    depth {value}
                  </option>
                ))}
              </select>
            </div>

            <label className="flex items-center gap-2 text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={highlightPaths}
                onChange={(event) => setHighlightPaths(event.target.checked)}
                className="focus-ring h-4 w-4 rounded border-zinc-600 bg-zinc-950"
              />
              Highlight server-reported impact paths
            </label>

            <div>
              <label htmlFor="graph-focus-vulnerability" className="block text-xs text-zinc-400">
                Focus advisory (optional)
              </label>
              <select
                id="graph-focus-vulnerability"
                value={focusVulnerability ?? ""}
                onChange={(event) => setFocusVulnerability(event.target.value || null)}
                className="focus-ring mt-1 max-w-xs rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
              >
                <option value="">All advisories</option>
                {(vulnerabilities.data?.items ?? []).map((item) => (
                  <option key={`${item.vulnerability_id}-${item.package_id}`} value={item.vulnerability_id}>
                    {item.vulnerability_id} · {item.package_name}
                  </option>
                ))}
              </select>
            </div>

            {highlightPaths || expandedPackageId ? (
              <button
                type="button"
                className="focus-ring rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-800"
                onClick={() => {
                  setHighlightPaths(false);
                  setFocusVulnerability(null);
                  setExpandedPackageId(null);
                }}
              >
                Clear overlays
              </button>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {ALL_TYPES.map((type) => (
              <label key={type} className="flex items-center gap-2 text-xs text-zinc-300">
                <input
                  type="checkbox"
                  checked={visibleTypes.has(type)}
                  onChange={(event) => {
                    setVisibleTypes((current) => {
                      const next = new Set(current);
                      if (event.target.checked) next.add(type);
                      else next.delete(type);
                      return next;
                    });
                  }}
                  className="focus-ring h-4 w-4 rounded border-zinc-600 bg-zinc-950"
                />
                {NODE_TYPE_LABELS[type]} ({formatNumber(countsByType.get(type) ?? 0)})
              </label>
            ))}
          </div>

          {neighborhood.isError ? (
            <ErrorState error={neighborhood.error} title="Neighborhood expansion failed" compact />
          ) : null}
          {neighborhoodOverflow ? (
            <Notice tone="info" title="Neighborhood expansion active">
              Added {formatNumber(neighborhood.data?.edges?.length ?? 0)} DEPENDS_ON relationships for the
              selected package at depth {depth}. The neighborhood API reports package names (no node ids), so
              unmatched packages are marked as name-only records.
            </Notice>
          ) : null}

          {visibleNodes.length === 0 ? (
            <EmptyState
              title="No elements match the current filters"
              description="Every node type is currently hidden. Re-enable a type above to render the graph."
            />
          ) : (
            <GraphCanvas
              nodes={visibleNodes}
              edges={visibleEdges}
              highlighted={highlighted}
              selectedId={selectedNodeId}
              onSelect={(id) => setSelectedNodeId(id)}
            />
          )}

          <p className="text-xs text-zinc-500">
            Rendering {formatNumber(visibleNodes.length)} of {formatNumber(data.combined.nodes.length)} loaded
            nodes and {formatNumber(visibleEdges.length)} relationships. Dashed package borders mark name-only
            records added from name-based APIs.
          </p>

          <div className="flex flex-wrap gap-4 text-xs text-zinc-400">
            {Object.entries(EDGE_TYPE_LABELS).map(([type, label]) => (
              <span key={type}>
                <span className="font-mono text-zinc-300">{type}</span> — {label}
              </span>
            ))}
          </div>
        </div>
      </SectionCard>

      {pathList.length > 0 ? (
        <SectionCard
          title="Impact paths reported by the server"
          description={`Blast-radius query at depth ${depth} returned ${formatNumber(pathList.length)} modeled path(s).`}
        >
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="min-w-full divide-y divide-zinc-800 text-left text-sm">
              <caption className="sr-only">Impact paths</caption>
              <thead className="bg-zinc-900/70 text-xs uppercase tracking-wide text-zinc-400">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Advisory
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Affected package
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Hops
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Downstream chain (server-reported)
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    <span className="sr-only">Highlight</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/70">
                {pathList.slice(0, 100).map((path, index) => (
                  <tr
                    key={`${path.vulnerability_id}-${path.affected_package_id}-${index}`}
                    className="align-top"
                  >
                    <td className="px-3 py-2 font-mono text-xs text-zinc-100">{path.vulnerability_id}</td>
                    <td className="px-3 py-2">
                      {path.affected_package_name}{" "}
                      <span className="font-mono text-xs text-zinc-400">
                        {path.affected_package_version ?? "?"}
                      </span>
                      {path.match_type ? (
                        <div className="text-[11px] text-zinc-500">match: {path.match_type}</div>
                      ) : null}
                    </td>
                    <td className="px-3 py-2">{formatNumber(path.hop_count)}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-zinc-400">
                      {(path.downstream_chain ?? []).join(" → ") || "—"}
                    </td>
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        className="focus-ring rounded border border-amber-400/50 px-2 py-1 text-xs text-amber-100 hover:bg-amber-400/10"
                        onClick={() => {
                          setHighlightPaths(true);
                          setFocusVulnerability(path.vulnerability_id);
                        }}
                      >
                        Highlight
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pathList.length > 100 ? (
            <p className="mt-2 text-xs text-zinc-500">
              Showing the first 100 of {formatNumber(pathList.length)} returned paths.
            </p>
          ) : null}
        </SectionCard>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <SectionCard
          title="Selected element"
          description="Properties and provenance of the node you selected on the canvas or in the list."
        >
          {selectedNode ? (
            <NodeDetailPanel
              node={selectedNode}
              depth={depth}
              onExpand={(packageId) => {
                setExpandedPackageId(packageId);
              }}
              onHighlightVulnerability={(vulnerabilityId) => {
                setHighlightPaths(true);
                setFocusVulnerability(vulnerabilityId);
              }}
            />
          ) : (
            <p className="text-sm text-zinc-400">
              Nothing selected. Click a node on the canvas, or choose one from the node list.
            </p>
          )}
        </SectionCard>

        <SectionCard
          title="Node list (accessible alternative)"
          description="The same loaded nodes as buttons, for keyboard and screen-reader navigation."
        >
          <div className="space-y-3">
            <div className="flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-950 px-2">
              <SearchIcon className="text-zinc-500" width={16} height={16} />
              <input
                type="search"
                value={nodeListQuery}
                onChange={(event) => setNodeListQuery(event.target.value)}
                placeholder="Filter loaded nodes"
                aria-label="Filter loaded nodes"
                className="w-full bg-transparent py-1.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
              />
            </div>
            <ul className="max-h-96 space-y-1 overflow-y-auto pr-1">
              {nodeListMatches.map((node) => (
                <li key={node.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedNodeId(node.id)}
                    aria-current={selectedNodeId === node.id ? "true" : undefined}
                    className={`focus-ring flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left text-xs ${
                      selectedNodeId === node.id
                        ? "bg-sky-500/10 text-sky-100"
                        : "text-zinc-300 hover:bg-zinc-900"
                    }`}
                  >
                    <span className="truncate">{node.label}</span>
                    <span className="shrink-0 text-[10px] uppercase tracking-wide text-zinc-500">
                      {NODE_TYPE_LABELS[node.type]}
                    </span>
                  </button>
                </li>
              ))}
              {nodeListMatches.length === 0 ? (
                <li className="text-xs text-zinc-500">No node matches.</li>
              ) : null}
            </ul>
            {visibleNodes.length > nodeListMatches.length ? (
              <p className="text-[11px] text-zinc-500">
                List bounded to 200 entries; refine the filter to reach the rest of the{" "}
                {formatNumber(visibleNodes.length)} loaded nodes.
              </p>
            ) : null}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

export function GraphExplorerPage() {
  return (
    <AnalysisGuard>
      <GraphExplorerContent />
    </AnalysisGuard>
  );
}
