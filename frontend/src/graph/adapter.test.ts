import { describe, expect, it } from "vitest";
import {
  buildExplorerData,
  highlightIdsForPaths,
  mergeNeighborhood,
  overlayVulnerabilities,
} from "./adapter";
import { blastRadiusResponse, graphRow, vulnerabilitiesResponse } from "../test/fixtures";

describe("buildExplorerData", () => {
  it("maps a real graph row into typed nodes and relationship edges", () => {
    const data = buildExplorerData([graphRow], 100);

    const ids = data.nodes.map((node) => node.id).sort();
    expect(ids).toEqual([
      "DependencyDeclaration:decl_1",
      "DependencyManifest:manifest_1",
      "Package:pkg_1",
      "Package:pkg_2",
      "Package:pkg_3",
      "Repository:github.com/example/demo",
      "SourceFile:file_1",
    ]);

    const types = new Map(data.nodes.map((node) => [node.id, node.type]));
    expect(types.get("Package:pkg_1")).toBe("package");
    expect(types.get("DependencyManifest:manifest_1")).toBe("manifest");
    expect(types.get("Repository:github.com/example/demo")).toBe("repository");

    const edges = data.edges.map((edge) => `${edge.source} -[${edge.type}]-> ${edge.target}`);
    expect(edges).toEqual([
      "Repository:github.com/example/demo -[CONTAINS]-> SourceFile:file_1",
      "Repository:github.com/example/demo -[HAS_MANIFEST]-> DependencyManifest:manifest_1",
      "DependencyManifest:manifest_1 -[DECLARES]-> DependencyDeclaration:decl_1",
      "DependencyDeclaration:decl_1 -[TARGETS]-> Package:pkg_1",
      "DependencyDeclaration:decl_1 -[RESOLVES_TO]-> Package:pkg_2",
      "Package:pkg_1 -[DEPENDS_ON]-> Package:pkg_3",
    ]);
    expect(data.edges.every((edge) => edge.confirmed)).toBe(true);
    expect(data.truncated).toBe(false);
  });

  it("deduplicates nodes shared across rows", () => {
    const data = buildExplorerData([graphRow, { ...graphRow, t: null, e: null }], 100);
    expect(data.nodes.filter((node) => node.id === "Package:pkg_1")).toHaveLength(1);
    expect(data.edges.filter((edge) => edge.type === "DEPENDS_ON")).toHaveLength(1);
  });

  it("flags a full page as truncated data", () => {
    const data = buildExplorerData([graphRow, graphRow], 2);
    expect(data.truncated).toBe(true);
  });

  it("ignores values that are not the documented node shape", () => {
    const data = buildExplorerData([{ r: { id: 1 }, f: "not-a-node" }], 100);
    expect(data.nodes).toHaveLength(0);
    expect(data.edges).toHaveLength(0);
  });

  it("records package names for name-based joins", () => {
    const data = buildExplorerData([graphRow], 100);
    const requests = data.nodes.find((node) => node.id === "Package:pkg_1");
    expect(requests?.nameKey).toBe("requests");
    expect(requests?.label).toBe("requests 2.31.0");
  });
});

describe("overlayVulnerabilities", () => {
  it("adds the stored advisory link and marks packages missing from the page", () => {
    const base = buildExplorerData([graphRow], 100);
    const withVulnerabilities = overlayVulnerabilities(base, [
      { ...vulnerabilitiesResponse.items[0], package_id: "pkg_404" },
    ]);

    const vulnerabilityNode = withVulnerabilities.nodes.find(
      (node) => node.id === "Vulnerability:GHSA-aaaa-bbbb-cccc",
    );
    expect(vulnerabilityNode?.type).toBe("vulnerability");

    const packageNode = withVulnerabilities.nodes.find((node) => node.id === "Package:pkg_404");
    expect(packageNode?.nameOnly).toBe(true);
    expect(packageNode?.provenance.join(" ")).toContain("vulnerabilities response");

    const link = withVulnerabilities.edges.find((edge) => edge.type === "AFFECTED_BY");
    expect(link).toMatchObject({ source: "Package:pkg_404", target: "Vulnerability:GHSA-aaaa-bbbb-cccc" });
  });

  it("does not duplicate links that already exist", () => {
    const base = buildExplorerData([graphRow], 100);
    const once = overlayVulnerabilities(base, vulnerabilitiesResponse.items);
    const twice = overlayVulnerabilities(once, vulnerabilitiesResponse.items);
    expect(twice.edges.filter((edge) => edge.type === "AFFECTED_BY")).toHaveLength(1);
    expect(twice.nodes.filter((node) => node.type === "vulnerability")).toHaveLength(1);
  });
});

describe("highlightIdsForPaths", () => {
  const base = buildExplorerData([graphRow], 100);

  it("highlights only nodes the server named in the impact paths", () => {
    const highlighted = highlightIdsForPaths(base, blastRadiusResponse.paths);

    expect(highlighted.has("Package:pkg_1")).toBe(true);
    expect(highlighted.has("Vulnerability:GHSA-aaaa-bbbb-cccc")).toBe(true);
    expect(highlighted.has("Package:pkg_3")).toBe(true); // "certifi" appears in the downstream chain
    expect(highlighted.has("Package:pkg_2")).toBe(false); // urllib3 is not in any returned path
  });

  it("filters by the focused advisory", () => {
    const highlighted = highlightIdsForPaths(base, blastRadiusResponse.paths, "GHSA-other");
    expect(highlighted.size).toBe(0);
  });

  it("returns nothing when the server reported no paths", () => {
    expect(highlightIdsForPaths(base, []).size).toBe(0);
  });
});

describe("mergeNeighborhood", () => {
  it("joins name-based neighborhood edges onto known packages", () => {
    const base = overlayVulnerabilities(buildExplorerData([graphRow], 100), vulnerabilitiesResponse.items);
    const merged = mergeNeighborhood(base, "pkg_1", [
      { from: "requests", to: "idna", constraint: ">=2.5", to_resolved_version: "3.6" },
      { from: "requests", to: "certifi", constraint: ">=2017", to_resolved_version: null },
    ]);

    const idna = merged.nodes.find((node) => node.id === "Package name:idna");
    expect(idna?.nameOnly).toBe(true);
    expect(idna?.label).toBe("idna 3.6");

    const edges = merged.edges.filter((edge) => edge.type === "DEPENDS_ON");
    expect(edges.some((edge) => edge.source === "Package:pkg_1" && edge.target === "Package:pkg_3")).toBe(
      true,
    );
    expect(edges.some((edge) => edge.source === "Package:pkg_1" && edge.target === "Package name:idna")).toBe(
      true,
    );
  });

  it("skips malformed neighborhood rows", () => {
    const base = buildExplorerData([graphRow], 100);
    const merged = mergeNeighborhood(base, "pkg_1", [
      { from: null, to: "idna" },
      { from: "requests", to: 42 },
    ]);
    expect(merged.edges.filter((edge) => String(edge.id).includes("neighborhood"))).toHaveLength(0);
  });
});
