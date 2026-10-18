import { useEffect, useMemo, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetJsonBlock } from "cytoscape";
import type { ExplorerEdge, ExplorerNode } from "./adapter";

export interface GraphCanvasProps {
  nodes: ExplorerNode[];
  edges: ExplorerEdge[];
  highlighted: Set<string>;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}

const NODE_STYLE: Record<string, { color: string; shape: string; size: number }> = {
  repository: { color: "#38bdf8", shape: "round-rectangle", size: 46 },
  file: { color: "#71717a", shape: "round-rectangle", size: 26 },
  manifest: { color: "#f59e0b", shape: "round-rectangle", size: 32 },
  declaration: { color: "#2dd4bf", shape: "round-rectangle", size: 28 },
  package: { color: "#a78bfa", shape: "ellipse", size: 34 },
  vulnerability: { color: "#f87171", shape: "diamond", size: 40 },
};

const EDGE_STYLE: Record<string, { color: string; line: "solid" | "dashed" }> = {
  CONTAINS: { color: "#3f3f46", line: "solid" },
  HAS_MANIFEST: { color: "#52525b", line: "solid" },
  DECLARES: { color: "#0f766e", line: "solid" },
  TARGETS: { color: "#6d28d9", line: "dashed" },
  RESOLVES_TO: { color: "#0ea5e9", line: "solid" },
  DEPENDS_ON: { color: "#8b5cf6", line: "solid" },
  AFFECTED_BY: { color: "#ef4444", line: "solid" },
};

/**
 * Cytoscape's bundled typings narrow style values to literal unions; these
 * rules are static values checked against the Cytoscape style documentation, so
 * the helper performs the narrowing once instead of at every rule.
 */
function styleRule(selector: string, style: Record<string, string | number>): StylesheetJsonBlock {
  return { selector, style } as unknown as StylesheetJsonBlock;
}

function stylesheet(showEdgeLabels: boolean): StylesheetJsonBlock[] {
  const nodeRules = Object.entries(NODE_STYLE).map(([type, style]) =>
    styleRule(`node[type = "${type}"]`, {
      "background-color": style.color,
      shape: style.shape,
      width: style.size,
      height: style.size,
      label: "data(label)",
      color: "#e4e4e7",
      "font-size": 9,
      "text-wrap": "wrap",
      "text-max-width": 120,
      "text-valign": "bottom",
      "text-margin-y": 4,
      "border-width": 1,
      "border-color": "#18181b",
    }),
  );

  const edgeRules = Object.entries(EDGE_STYLE).map(([type, style]) =>
    styleRule(`edge[type = "${type}"]`, {
      "line-color": style.color,
      "target-arrow-color": style.color,
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      width: 1.4,
      "line-style": style.line,
      label: showEdgeLabels ? "data(label)" : "",
      "font-size": 7,
      color: "#a1a1aa",
      "text-rotation": "autorotate",
    }),
  );

  return [
    ...nodeRules,
    ...edgeRules,
    styleRule("node.nameOnly", { "border-style": "dashed", "border-width": 2, "border-color": "#e4e4e7" }),
    styleRule(".dimmed", { opacity: 0.18 }),
    styleRule("node.highlighted", {
      "border-width": 4,
      "border-color": "#fbbf24",
      "overlay-opacity": 0.08,
    }),
    styleRule("edge.highlighted", { width: 3, "line-color": "#fbbf24", "target-arrow-color": "#fbbf24" }),
    styleRule("node.selected", { "border-width": 4, "border-color": "#38bdf8" }),
  ];
}

export function GraphCanvas({ nodes, edges, highlighted, selectedId, onSelect }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  const elements = useMemo<ElementDefinition[]>(() => {
    const nodeElements = nodes.map((node) => ({
      group: "nodes" as const,
      data: {
        id: node.id,
        label: node.label,
        type: node.type,
        nameOnly: node.nameOnly === true ? "yes" : "no",
      },
    }));
    const edgeElements = edges.map((edge) => ({
      group: "edges" as const,
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: edge.type,
        label: typeof edge.properties.constraint === "string" ? edge.properties.constraint : "",
      },
    }));
    return [...nodeElements, ...edgeElements];
  }, [nodes, edges]);

  const showEdgeLabels = edges.length <= 120;

  // Create the Cytoscape instance once; data updates are applied below.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const cy = cytoscape({
      container,
      elements: [],
      style: stylesheet(showEdgeLabels),
      wheelSensitivity: 0.2,
      minZoom: 0.05,
      maxZoom: 4,
    });
    cyRef.current = cy;

    cy.on("tap", "node", (event) => {
      onSelectRef.current(String(event.target.id()));
    });
    cy.on("tap", "edge", () => {
      onSelectRef.current(null);
    });
    cy.on("tap", (event) => {
      if (event.target === cy) onSelectRef.current(null);
    });

    const observer = new ResizeObserver(() => {
      cy.resize();
    });
    observer.observe(container);

    return () => {
      observer.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
    // Created once; the element-sync effect below owns all subsequent changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Rebuild elements whenever the underlying API data changes, then lay out.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().remove();
      if (elements.length > 0) {
        cy.add(elements);
      }
    });
    if (elements.length > 0) {
      cy.layout({
        name: "cose",
        animate: false,
        numIter: 600,
        nodeRepulsion: () => 6000,
        idealEdgeLength: () => 80,
        padding: 24,
      } as cytoscape.LayoutOptions).run();
      cy.fit(undefined, 30);
    }
  }, [elements]);

  // Highlight and selection are classes only — no re-layout, no data change.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("highlighted dimmed selected");
      if (highlighted.size > 0) {
        cy.elements().addClass("dimmed");
        for (const id of highlighted) {
          const element = cy.getElementById(id);
          if (element.length > 0) {
            element.removeClass("dimmed");
            element.addClass("highlighted");
          }
        }
        cy.edges().forEach((edge) => {
          if (highlighted.has(String(edge.data("source"))) && highlighted.has(String(edge.data("target")))) {
            edge.removeClass("dimmed").addClass("highlighted");
          }
        });
      }
      if (selectedId) {
        const node = cy.getElementById(selectedId);
        if (node.length > 0) node.addClass("selected");
      }
    });
  }, [highlighted, selectedId, elements]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !selectedId) return;
    const node = cy.getElementById(selectedId);
    if (node.length > 0) {
      cy.animate({ center: { eles: node }, duration: 200 });
    }
  }, [selectedId]);

  return (
    <div
      ref={containerRef}
      className="graph-canvas w-full rounded-lg border border-zinc-800 bg-zinc-950"
      role="img"
      aria-label={`Dependency graph rendering ${nodes.length} nodes and ${edges.length} relationships. An equivalent node list with the same data is provided below the canvas.`}
    />
  );
}
