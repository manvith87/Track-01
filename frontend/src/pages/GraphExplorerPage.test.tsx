import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../test/renderApp";
import { stubFetch, type StubReply } from "../test/fetchMock";
import {
  ANALYSIS_ID,
  blastRadiusResponse,
  emptyGraphRecord,
  graphHealth,
  graphRecord,
  graphStatistics,
  graphStatus,
  vulnerabilitiesResponse,
} from "../test/fixtures";
import type { ExplorerEdge, ExplorerNode } from "../graph/adapter";

// The canvas itself is Cytoscape (canvas API, not DOM-assertable). Tests assert
// the exact props it receives; the mapping logic is unit-tested in adapter.test.ts.
vi.mock("../graph/GraphCanvas", () => ({
  GraphCanvas: ({
    nodes,
    edges,
    highlighted,
    selectedId,
  }: {
    nodes: ExplorerNode[];
    edges: ExplorerEdge[];
    highlighted: Set<string>;
    selectedId: string | null;
  }) => (
    <div
      data-testid="graph-canvas"
      data-nodes={nodes.length}
      data-edges={edges.length}
      data-highlighted={[...highlighted].sort().join(",")}
      data-selected={selectedId ?? ""}
    />
  ),
}));

function graphHandler(options: { graph?: StubReply; blastRadius?: StubReply } = {}) {
  return (url: string, _method: string): StubReply | undefined => {
    if (url.includes("/api/v1/graph/health")) return { status: 200, body: graphHealth };
    if (url.includes("/graph/status")) return { status: 200, body: graphStatus };
    if (url.includes("/graph/statistics")) return { status: 200, body: graphStatistics };
    if (url.includes("/vulnerabilities/blast-radius")) {
      return options.blastRadius ?? { status: 200, body: blastRadiusResponse };
    }
    if (url.includes("/vulnerabilities")) return { status: 200, body: vulnerabilitiesResponse };
    if (url.includes("/packages/pkg_1/neighborhood")) {
      return {
        status: 200,
        body: {
          package_id: "pkg_1",
          depth: 2,
          edges: [{ from: "requests", to: "idna", constraint: ">=2.5", to_resolved_version: "3.6" }],
        },
      };
    }
    if (url.includes("/graph")) return options.graph ?? { status: 200, body: graphRecord };
    return undefined;
  };
}

const graphRoute = `/analysis/${ANALYSIS_ID}/graph`;

describe("Screen C — graph explorer", () => {
  it("renders statistics from the API and passes real nodes/edges to the canvas", async () => {
    stubFetch(graphHandler());
    renderApp(graphRoute);

    const canvas = await screen.findByTestId("graph-canvas");
    // 7 nodes from the row + the vulnerability node from the advisories overlay.
    expect(canvas).toHaveAttribute("data-nodes", "8");
    // 6 relationships from the row + the AFFECTED_BY link.
    expect(canvas).toHaveAttribute("data-edges", "7");
    expect(canvas).toHaveAttribute("data-highlighted", "");

    // Statistics come from the statistics endpoint, not from the rendered slice.
    expect(screen.getByText("Dependency edges")).toBeInTheDocument();
    expect(screen.getByText("Advisory links")).toBeInTheDocument();
  });

  it("highlights only the nodes the blast-radius response included", async () => {
    stubFetch(graphHandler());
    renderApp(graphRoute);
    await screen.findByTestId("graph-canvas");

    const user = userEvent.setup();
    await user.click(screen.getByLabelText(/highlight server-reported impact paths/i));

    await waitFor(() => {
      expect(screen.getByTestId("graph-canvas")).toHaveAttribute(
        "data-highlighted",
        "Package:pkg_1,Package:pkg_3,Vulnerability:GHSA-aaaa-bbbb-cccc",
      );
    });
    // Every highlighted endpoint was part of the fetched page.
    expect(
      screen.queryByText("Some highlighted path endpoints are outside the loaded slice"),
    ).not.toBeInTheDocument();
  });

  it("reports path endpoints the bounded page does not contain instead of inventing nodes", async () => {
    stubFetch(
      graphHandler({
        blastRadius: {
          status: 200,
          body: {
            ...blastRadiusResponse,
            paths: [
              {
                ...blastRadiusResponse.paths[0],
                affected_package_id: "pkg_not_on_page",
                downstream_chain: ["left-pad"],
              },
            ],
          },
        },
      }),
    );
    renderApp(graphRoute);
    await screen.findByTestId("graph-canvas");

    const user = userEvent.setup();
    await user.click(screen.getByLabelText(/highlight server-reported impact paths/i));

    expect(
      await screen.findByText("Some highlighted path endpoints are outside the loaded slice"),
    ).toBeInTheDocument();
    // The canvas still receives exactly the API's nodes; the missing endpoint is
    // reported, never synthesized.
    const canvas = screen.getByTestId("graph-canvas");
    expect(canvas).toHaveAttribute("data-nodes", "8");
    expect(canvas).toHaveAttribute(
      "data-highlighted",
      "Package:pkg_not_on_page,Vulnerability:GHSA-aaaa-bbbb-cccc",
    );
  });

  it("lists server-reported impact paths with their downstream chains", async () => {
    stubFetch(graphHandler());
    renderApp(graphRoute);
    await screen.findByTestId("graph-canvas");

    expect(screen.getByText("Impact paths reported by the server")).toBeInTheDocument();
    expect(screen.getByText("requests 2.31.0")).toBeInTheDocument();
    expect(screen.getByText("certifi")).toBeInTheDocument();
  });

  it("shows an empty state when the analysis has no graph rows", async () => {
    stubFetch(graphHandler({ graph: { status: 200, body: emptyGraphRecord } }));
    renderApp(graphRoute);

    expect(await screen.findByText("No graph records for this analysis")).toBeInTheDocument();
    expect(screen.queryByTestId("graph-canvas")).not.toBeInTheDocument();
  });

  it("selects a node from the accessible list and expands its neighborhood by name", async () => {
    stubFetch(graphHandler());
    renderApp(graphRoute);
    await screen.findByTestId("graph-canvas");

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /requests 2\.31\.0\s*Package/i }));

    expect(screen.getByTestId("graph-canvas")).toHaveAttribute("data-selected", "Package:pkg_1");
    expect(
      screen.getByRole("button", { name: /expand dependency neighborhood \(depth 2\)/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("normalized_name")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /expand dependency neighborhood/i }));

    expect(await screen.findByText("Neighborhood expansion active")).toBeInTheDocument();
    // The name-only package from the neighborhood response becomes a 9th node.
    await waitFor(() => {
      expect(screen.getByTestId("graph-canvas")).toHaveAttribute("data-nodes", "9");
    });
  });
});
