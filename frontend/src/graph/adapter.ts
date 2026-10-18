/**
 * Pure mapping from real API responses to graph-explorer elements.
 *
 * Everything here is derived from data the backend returned:
 *
 * - `GET /analyses/{id}/graph` rows contain the real nodes (`r`, `f`, `m`,
 *   `d`, `p`, `rp`, `t`) and relationships (`rt` RESOLVES_TO, `e` DEPENDS_ON)
 *   of the analysis. Row association reproduces the query's own relationships
 *   (Repository-CONTAINS->SourceFile, Repository-HAS_MANIFEST->Manifest,
 *   Manifest-DECLARES->Declaration, Declaration-TARGETS->Package,
 *   Declaration-RESOLVES_TO->Package, Package-DEPENDS_ON->Package).
 * - `GET /analyses/{id}/vulnerabilities` adds the stored AFFECTED_BY links.
 * - `GET /analyses/{id}/vulnerabilities/blast-radius` paths are used only to
 *   highlight nodes the server returned as part of an impact path.
 * - `GET /packages/{id}/neighborhood` adds name-keyed dependency edges.
 *
 * No reachability is computed in the browser: a package is "in a modeled
 * path" only when the blast-radius response says so.
 */

import type { AnalysisVulnerabilityItem, ImpactPathOut } from "../api/generated";
import { asEdgeValue, asNodeValue, type GraphEdgeValue, type GraphNodeValue } from "../api/graphValues";

export type ExplorerNodeType =
  "repository" | "file" | "manifest" | "declaration" | "package" | "vulnerability";

export interface ExplorerNode {
  id: string;
  type: ExplorerNodeType;
  label: string;
  properties: Record<string, unknown>;
  /** Human readable provenance lines for the detail panel. */
  provenance: string[];
  /** Normalized package name when the backend reported one (for name joins). */
  nameKey?: string;
  /** True when the node only exists as a name (neighborhood expansion). */
  nameOnly?: boolean;
}

export interface ExplorerEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  properties: Record<string, unknown>;
  /** True when the relationship comes from a returned edge value or link row. */
  confirmed: boolean;
}

export interface ExplorerData {
  nodes: ExplorerNode[];
  edges: ExplorerEdge[];
  /** True when the fetched page was capped by the request limit. */
  truncated: boolean;
  rowsFetched: number;
}

const NODE_COLUMNS = ["r", "f", "m", "d", "p", "rp", "t"] as const;

const TYPE_BY_LABEL: Record<string, ExplorerNodeType> = {
  Repository: "repository",
  SourceFile: "file",
  DependencyManifest: "manifest",
  DependencyDeclaration: "declaration",
  Package: "package",
  Vulnerability: "vulnerability",
};

const EDGE_ID_BY_COLUMN: Record<string, string> = {
  f: "contains",
  m: "has_manifest",
  d: "declares",
  p: "targets",
  rp: "resolves_to",
  t: "depends_on",
};

function text(properties: Record<string, unknown>, key: string): string | null {
  const value = properties[key];
  if (typeof value === "string" && value.length > 0) return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return null;
}

function nodeId(node: GraphNodeValue): string {
  const primary = node.labels[0] ?? "Node";
  const propertyId = text(node.properties, "id");
  if (propertyId) return `${primary}:${propertyId}`;
  return `${primary}:#${node.internalId ?? "unknown"}`;
}

function nodeLabel(node: GraphNodeValue): string {
  const properties = node.properties;
  switch (node.labels[0]) {
    case "Repository":
      return text(properties, "id") ?? "repository";
    case "SourceFile":
    case "DependencyManifest":
      return text(properties, "path") ?? "file";
    case "DependencyDeclaration": {
      const name = text(properties, "original_name") ?? text(properties, "normalized_name") ?? "declaration";
      const constraint = text(properties, "version_constraint");
      return constraint ? `${name} ${constraint}` : name;
    }
    case "Package": {
      const name = text(properties, "normalized_name") ?? text(properties, "original_name") ?? "package";
      const version = text(properties, "version");
      return version ? `${name} ${version}` : name;
    }
    case "Vulnerability":
      return text(properties, "id") ?? "vulnerability";
    default:
      return text(properties, "id") ?? "node";
  }
}

function provenanceLines(node: GraphNodeValue): string[] {
  const p = node.properties;
  const lines: string[] = [];
  switch (node.labels[0]) {
    case "Repository":
      if (p.canonical_url) lines.push(`Repository: ${text(p, "canonical_url")}`);
      if (p.commit_sha) lines.push(`Commit: ${text(p, "commit_sha")}`);
      if (p.metadata_source) lines.push(`Metadata source: ${text(p, "metadata_source")}`);
      break;
    case "SourceFile":
      if (p.path) lines.push(`Path: ${text(p, "path")}`);
      if (p.size_bytes !== undefined) lines.push(`Size: ${text(p, "size_bytes")} bytes`);
      if (p.manifest_format) lines.push(`Format: ${text(p, "manifest_format")}`);
      if (p.support_level) lines.push(`Support: ${text(p, "support_level")}`);
      if (p.skipped_reason) lines.push(`Skipped: ${text(p, "skipped_reason")}`);
      break;
    case "DependencyManifest":
      if (p.path) lines.push(`Path: ${text(p, "path")}`);
      if (p.format) lines.push(`Format: ${text(p, "format")}`);
      if (p.status) lines.push(`Parse status: ${text(p, "status")}`);
      if (p.is_lockfile !== undefined) lines.push(`Lockfile: ${p.is_lockfile ? "yes" : "no"}`);
      if (p.declaration_count !== undefined) lines.push(`Declarations: ${text(p, "declaration_count")}`);
      if (p.resolved_count !== undefined) lines.push(`Resolved: ${text(p, "resolved_count")}`);
      if (p.companion_manifest) lines.push(`Companion: ${text(p, "companion_manifest")}`);
      break;
    case "DependencyDeclaration": {
      const section = text(p, "section");
      const line = text(p, "line_number");
      if (section) lines.push(`Section: ${section}`);
      if (line) lines.push(`Line: ${line}`);
      const evidence = text(p, "evidence");
      if (evidence) lines.push(`Evidence: ${evidence}`);
      const scheme = text(p, "constraint_scheme");
      if (scheme) lines.push(`Constraint scheme: ${scheme}`);
      const scope = text(p, "scope");
      if (scope) lines.push(`Scope: ${scope}`);
      break;
    }
    case "Package":
      if (p.version) lines.push(`Resolved version: ${text(p, "version")}`);
      if (p.source_manifest) lines.push(`Source manifest: ${text(p, "source_manifest")}`);
      if (p.relation) lines.push(`Relation: ${text(p, "relation")}`);
      if (p.dependency_count !== undefined)
        lines.push(`Recorded dependencies: ${text(p, "dependency_count")}`);
      break;
    case "Vulnerability":
      if (p.modified) lines.push(`OSV modified: ${text(p, "modified")}`);
      if (p.published) lines.push(`Published: ${text(p, "published")}`);
      if (p.source) lines.push(`Source: ${text(p, "source")}`);
      break;
    default:
      break;
  }
  return lines;
}

function packageNameKey(node: GraphNodeValue): string | undefined {
  if (node.labels[0] !== "Package") return undefined;
  return text(node.properties, "normalized_name") ?? undefined;
}

/**
 * Build explorer elements from one page of `GET /analyses/{id}/graph`.
 *
 * `limit` is the limit that produced the page; when the page is full the data
 * may be truncated (the caller surfaces that as a warning).
 */
export function buildExplorerData(rows: Array<Record<string, unknown>>, limit: number): ExplorerData {
  const nodes = new Map<string, ExplorerNode>();
  const edges = new Map<string, ExplorerEdge>();

  const nodeFor = (value: GraphNodeValue): ExplorerNode => {
    const id = nodeId(value);
    const existing = nodes.get(id);
    if (existing) return existing;
    const label = nodeLabel(value);
    let type = TYPE_BY_LABEL[value.labels[0] ?? ""];
    if (!type) type = "package"; // unknown labels never occur in practice; stay renderable
    const node: ExplorerNode = {
      id,
      type,
      label,
      properties: value.properties,
      provenance: provenanceLines(value),
    };
    const nameKey = packageNameKey(value);
    if (nameKey) node.nameKey = nameKey;
    nodes.set(id, node);
    return node;
  };

  const addEdge = (
    sourceNode: ExplorerNode,
    targetNode: ExplorerNode,
    type: string,
    properties: Record<string, unknown>,
    suffix: string,
  ) => {
    const id = `${sourceNode.id}|${type}|${targetNode.id}|${suffix}`;
    if (edges.has(id)) return;
    edges.set(id, { id, source: sourceNode.id, target: targetNode.id, type, properties, confirmed: true });
  };

  for (const row of rows) {
    const values = NODE_COLUMNS.map((column) => ({ column, value: asNodeValue(row[column]) }));
    const byColumn = new Map<string, ExplorerNode>();
    for (const { column, value } of values) {
      if (value) byColumn.set(column, nodeFor(value));
    }

    const resolvedEdge: GraphEdgeValue | null = asEdgeValue(row.rt);
    const dependsEdge: GraphEdgeValue | null = asEdgeValue(row.e);

    const r = byColumn.get("r");
    const f = byColumn.get("f");
    const m = byColumn.get("m");
    const d = byColumn.get("d");
    const p = byColumn.get("p");
    const rp = byColumn.get("rp");
    const t = byColumn.get("t");

    // Row association mirrors the OPTIONAL MATCH chain of GET_GRAPH exactly,
    // so every edge below is a relationship the backend actually matched.
    if (r && f) addEdge(r, f, "CONTAINS", {}, EDGE_ID_BY_COLUMN.f);
    if (r && m) addEdge(r, m, "HAS_MANIFEST", {}, EDGE_ID_BY_COLUMN.m);
    if (m && d) addEdge(m, d, "DECLARES", {}, EDGE_ID_BY_COLUMN.d);
    if (d && p) addEdge(d, p, "TARGETS", {}, EDGE_ID_BY_COLUMN.p);
    if (d && rp) {
      addEdge(
        d,
        rp,
        resolvedEdge?.type ?? "RESOLVES_TO",
        resolvedEdge?.properties ?? {},
        EDGE_ID_BY_COLUMN.rp,
      );
    }
    if (p && t) {
      addEdge(p, t, dependsEdge?.type ?? "DEPENDS_ON", dependsEdge?.properties ?? {}, EDGE_ID_BY_COLUMN.t);
    }
  }

  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    truncated: rows.length >= limit && limit > 0,
    rowsFetched: rows.length,
  };
}

/**
 * Add the stored vulnerability links from `GET /analyses/{id}/vulnerabilities`.
 *
 * The edge direction (Package-AFFECTED_BY->Vulnerability), the package id and
 * the advisory facts all come from the response.
 */
export function overlayVulnerabilities(data: ExplorerData, items: AnalysisVulnerabilityItem[]): ExplorerData {
  const nodes = new Map(data.nodes.map((node) => [node.id, node]));
  const edges = new Map(data.edges.map((edge) => [edge.id, edge]));

  for (const item of items) {
    const vulnerabilityId = `Vulnerability:${item.vulnerability_id}`;
    if (!nodes.has(vulnerabilityId)) {
      const provenance: string[] = [
        `Match type: ${item.match_type ?? "unknown"}`,
        ...(item.modified ? [`OSV modified: ${item.modified}`] : []),
        ...(item.fixed_versions && item.fixed_versions.length > 0
          ? [`Advisory fixed versions: ${item.fixed_versions.join(", ")}`]
          : []),
      ];
      nodes.set(vulnerabilityId, {
        id: vulnerabilityId,
        type: "vulnerability",
        label: item.vulnerability_id,
        properties: {
          id: item.vulnerability_id,
          summary: item.summary,
          aliases: item.aliases,
          fixed_versions: item.fixed_versions,
          match_type: item.match_type,
        },
        provenance,
      });
    }
    const packageNodeId = `Package:${item.package_id}`;
    if (!nodes.has(packageNodeId)) {
      // The package is not in the fetched page (e.g. the page was truncated).
      // Adding it keeps the reported link visible; it is marked as partial.
      nodes.set(packageNodeId, {
        id: packageNodeId,
        type: "package",
        label: `${item.package_name}${item.package_version ? ` ${item.package_version}` : ""}`,
        properties: {
          id: item.package_id,
          normalized_name: item.package_name,
          version: item.package_version,
        },
        provenance: ["Loaded from the vulnerabilities response (not part of the fetched graph page)."],
        nameKey: item.package_name,
        nameOnly: true,
      });
    }
    const edgeId = `${packageNodeId}|AFFECTED_BY|${vulnerabilityId}`;
    if (!edges.has(edgeId)) {
      edges.set(edgeId, {
        id: edgeId,
        source: packageNodeId,
        target: vulnerabilityId,
        type: "AFFECTED_BY",
        properties: {
          match_type: item.match_type,
          fixed_versions: item.fixed_versions,
          last_synced_at: item.last_synced_at,
        },
        confirmed: true,
      });
    }
  }

  return { ...data, nodes: [...nodes.values()], edges: [...edges.values()] };
}

/**
 * Ids to highlight for the server-reported impact paths.
 *
 * A node is highlighted only when the path response includes it; the browser
 * never walks the graph to extend a path.
 */
export function highlightIdsForPaths(
  data: ExplorerData,
  paths: ImpactPathOut[],
  vulnerabilityId?: string | null,
): Set<string> {
  const highlighted = new Set<string>();
  const nodesByName = new Map<string, string[]>();
  for (const node of data.nodes) {
    if (node.nameKey) {
      const list = nodesByName.get(node.nameKey) ?? [];
      list.push(node.id);
      nodesByName.set(node.nameKey, list);
    }
  }

  for (const path of paths) {
    if (vulnerabilityId && path.vulnerability_id !== vulnerabilityId) continue;
    highlighted.add(`Package:${path.affected_package_id}`);
    highlighted.add(`Vulnerability:${path.vulnerability_id}`);
    for (const name of path.downstream_chain ?? []) {
      for (const id of nodesByName.get(name) ?? []) {
        highlighted.add(id);
      }
    }
  }
  return highlighted;
}

export interface NeighborhoodEdgeRow {
  from?: unknown;
  to?: unknown;
  constraint?: unknown;
  to_resolved_version?: unknown;
}

/**
 * Merge `GET /packages/{id}/neighborhood` edges.
 *
 * The neighborhood API reports normalized package names (not ids), so name
 * matches reuse existing nodes and unknown names become explicitly marked
 * name-only nodes.
 */
export function mergeNeighborhood(
  data: ExplorerData,
  rootPackageId: string,
  edges: NeighborhoodEdgeRow[],
): ExplorerData {
  const nodes = new Map(data.nodes.map((node) => [node.id, node]));
  const relationships = new Map(data.edges.map((edge) => [edge.id, edge]));
  const rootNodeId = `Package:${rootPackageId}`;

  const byName = (name: string, version?: string | null): string => {
    for (const node of nodes.values()) {
      if (node.type === "package" && node.nameKey === name) return node.id;
    }
    const id = `Package name:${name}`;
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        type: "package",
        label: version ? `${name} ${version}` : name,
        properties: { normalized_name: name, version: version ?? null },
        provenance: ["Reported by the dependency-neighborhood API by name (no node id returned)."],
        nameKey: name,
        nameOnly: true,
      });
    }
    return id;
  };

  for (const edge of edges) {
    const from = typeof edge.from === "string" ? edge.from : null;
    const to = typeof edge.to === "string" ? edge.to : null;
    if (!from || !to) continue;
    const sourceId = from === nodes.get(rootNodeId)?.nameKey ? rootNodeId : byName(from);
    const targetName = to;
    const version = typeof edge.to_resolved_version === "string" ? edge.to_resolved_version : null;
    const targetId = byName(targetName, version);
    const id = `${sourceId}|DEPENDS_ON|${targetId}|neighborhood`;
    if (relationships.has(id)) continue;
    relationships.set(id, {
      id,
      source: sourceId,
      target: targetId,
      type: "DEPENDS_ON",
      properties: {
        constraint: typeof edge.constraint === "string" ? edge.constraint : null,
        to_resolved_version: version,
        source: "dependency-neighborhood",
      },
      confirmed: true,
    });
  }

  return { ...data, nodes: [...nodes.values()], edges: [...relationships.values()] };
}

/** Stable element id for one package row (used when focusing a package). */
export function packageNodeId(packageId: string): string {
  return `Package:${packageId}`;
}

/** List of package names present in the data (used to mark name joins). */
export function packageNameIndex(data: ExplorerData): Map<string, string> {
  const index = new Map<string, string>();
  for (const node of data.nodes) {
    if (node.nameKey && !index.has(node.nameKey)) index.set(node.nameKey, node.id);
  }
  return index;
}

export const NODE_TYPE_LABELS: Record<ExplorerNodeType, string> = {
  repository: "Repository",
  file: "Source file",
  manifest: "Manifest",
  declaration: "Declaration",
  package: "Package",
  vulnerability: "Vulnerability",
};

export const EDGE_TYPE_LABELS: Record<string, string> = {
  CONTAINS: "contains",
  HAS_MANIFEST: "has manifest",
  DECLARES: "declares",
  TARGETS: "targets",
  RESOLVES_TO: "resolves to",
  DEPENDS_ON: "depends on",
  AFFECTED_BY: "affected by",
};
