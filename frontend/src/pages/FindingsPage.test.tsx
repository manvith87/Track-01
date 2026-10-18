import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../test/renderApp";
import { stubFetch, type StubReply } from "../test/fetchMock";
import {
  ANALYSIS_ID,
  findingDetailResponse,
  findingsResponse,
  graphHealth,
  graphStatus,
  VULN_ID,
} from "../test/fixtures";

const pageTwoFinding = {
  ...findingsResponse.findings[1],
  finding_id: "finding_3",
  vulnerability_id: "GHSA-page2-0000-1111",
  advisory_withdrawn: false,
  package: { ...findingsResponse.findings[1].package, package_name: "jinja2", package_version: "3.1.2" },
};

function findingsHandler(options: { findings?: (url: string) => StubReply } = {}) {
  return (url: string, _method: string): StubReply | undefined => {
    if (url.includes("/api/v1/graph/health")) return { status: 200, body: graphHealth };
    if (url.includes("/graph/status")) return { status: 200, body: graphStatus };
    if (url.includes("/findings/finding_1")) return { status: 200, body: findingDetailResponse };
    if (url.includes("/findings")) {
      if (options.findings) return options.findings(url);
      return { status: 200, body: findingsResponse };
    }
    return undefined;
  };
}

const findingsRoute = `/analysis/${ANALYSIS_ID}/findings`;

describe("Screen B — ranked findings", () => {
  it("keeps advisory severity and BlastRadius priority visually distinct", async () => {
    stubFetch(findingsHandler());
    renderApp(findingsRoute);

    expect(await screen.findByText(VULN_ID)).toBeInTheDocument();
    // Advisory severity, verbatim.
    expect(screen.getByText("CVSS_V3 9.8")).toBeInTheDocument();
    expect(screen.getAllByText(/from the advisory record/i).length).toBeGreaterThan(0);
    // BlastRadius priority, clearly labelled as a custom score.
    expect(screen.getByText("8.50")).toBeInTheDocument();
    expect(screen.getAllByText(/custom score · formula priority-v1/).length).toBeGreaterThan(0);
    // Modeled reachability wording never claims safety.
    expect(screen.getAllByText("Direct dependency").length).toBeGreaterThan(0);
    expect(screen.getByText("Reachability unavailable (incomplete graph data)")).toBeInTheDocument();
    // Withdrawn advisories are flagged.
    expect(screen.getByText("Withdrawn advisory")).toBeInTheDocument();
    // Partial analysis data is explained, including unmatched declarations.
    expect(screen.getByText("Incomplete analysis data")).toBeInTheDocument();
    expect(screen.getByText(/1 declared package\(s\) have no/)).toBeInTheDocument();
  });

  it("filters the loaded page and reports that filtering is page-scoped", async () => {
    stubFetch(findingsHandler());
    renderApp(findingsRoute);
    await screen.findByText(VULN_ID);

    expect(screen.getByText(/filters and sorting apply to the loaded page/)).toBeInTheDocument();

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/search loaded page/i), "flask");

    expect(screen.queryByText(VULN_ID)).not.toBeInTheDocument();
    expect(screen.getByText("GHSA-dddd-eeee-ffff")).toBeInTheDocument();
  });

  it("paginates with the API's skip/limit parameters", async () => {
    const calls = stubFetch(
      findingsHandler({
        findings: (url) =>
          url.includes("skip=50")
            ? {
                status: 200,
                body: { ...findingsResponse, skip: 50, count: 1, total: 60, findings: [pageTwoFinding] },
              }
            : { status: 200, body: { ...findingsResponse, total: 60 } },
      }),
    );
    renderApp(findingsRoute);
    await screen.findByText(VULN_ID);

    const user = userEvent.setup();
    expect(screen.getByRole("button", { name: /previous/i })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: /next/i }));

    expect(await screen.findByText("GHSA-page2-0000-1111")).toBeInTheDocument();
    expect(screen.getByText(/Showing 51–51 of 60 ranked findings/)).toBeInTheDocument();
    expect(calls.some((call) => call.url.includes("skip=50") && call.url.includes("limit=50"))).toBe(true);
  });

  it("shows an empty state (not fake data) when no findings are stored", async () => {
    stubFetch(
      findingsHandler({
        findings: () => ({ status: 200, body: { ...findingsResponse, total: 0, count: 0, findings: [] } }),
      }),
    );
    renderApp(findingsRoute);

    expect(await screen.findByText("No findings stored for this analysis")).toBeInTheDocument();
  });

  it("loads full finding detail with priority factors and the remediation plan", async () => {
    stubFetch(findingsHandler());
    renderApp(findingsRoute);
    await screen.findByText(VULN_ID);

    const user = userEvent.setup();
    await user.click(screen.getAllByRole("button", { name: "Detail" })[0] as HTMLElement);

    expect(
      await screen.findByRole("heading", { name: "BlastRadius priority (deterministic)" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Advisory severity (as reported)" })).toBeInTheDocument();
    expect(screen.getByText("advisory_severity")).toBeInTheDocument();
    expect(screen.getAllByText(/priority-v1/).length).toBeGreaterThan(0);

    const remediation = screen.getByRole("heading", { name: "Package remediation plan" }).closest("section");
    expect(remediation).not.toBeNull();
    const panel = within(remediation as HTMLElement);
    expect(panel.getByText(/2\.31\.0 → 2\.32\.0/)).toBeInTheDocument();
    expect(panel.getAllByText(/2\.32\.0/).length).toBeGreaterThan(0);
    expect(panel.getByText(/no resolver executed/i)).toBeInTheDocument();
    expect(panel.getAllByText(/satisfied/).length).toBeGreaterThan(0);
  });
});
