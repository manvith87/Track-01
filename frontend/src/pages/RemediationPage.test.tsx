import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../test/renderApp";
import { stubFetch, type StubReply } from "../test/fetchMock";
import {
  ANALYSIS_ID,
  fixGroupDetailResponse,
  fixGroupsResponse,
  graphHealth,
  graphStatus,
  remediationCandidatesResponse,
} from "../test/fixtures";

function remediationHandler(options: { groups?: StubReply; candidates?: StubReply } = {}) {
  return (url: string, _method: string): StubReply | undefined => {
    if (url.includes("/api/v1/graph/health")) return { status: 200, body: graphHealth };
    if (url.includes("/graph/status")) return { status: 200, body: graphStatus };
    if (url.includes("/remediation/groups/group_1")) {
      return { status: 200, body: fixGroupDetailResponse };
    }
    if (url.includes("/remediation/groups")) {
      return options.groups ?? { status: 200, body: fixGroupsResponse };
    }
    if (url.includes("/remediation/candidates")) {
      return options.candidates ?? { status: 200, body: remediationCandidatesResponse };
    }
    return undefined;
  };
}

const remediationRoute = `/analysis/${ANALYSIS_ID}/remediation`;

describe("Screen E — remediation ranking", () => {
  it("shows groups with server-decided coverage and never relabels potential as confirmed", async () => {
    stubFetch(remediationHandler());
    renderApp(remediationRoute);

    expect(await screen.findByText(/requests 2\.31\.0 → 2\.32\.0/)).toBeInTheDocument();
    expect(screen.getByText("Advisory-confirmed")).toBeInTheDocument();
    expect(screen.getByText("Constraints satisfied (not resolver-verified)")).toBeInTheDocument();
    expect(screen.getByText(/1 confirmed · 0 potential · 1 unresolved/)).toBeInTheDocument();
    expect(screen.getByText(/1 advisory-confirmed · 0 potential only/)).toBeInTheDocument();
    expect(screen.getByText(/never re-labels a potential candidate as confirmed/)).toBeInTheDocument();

    // Findings no candidate resolves stay visible with the server's reason.
    expect(screen.getByText("Findings no candidate was shown to resolve")).toBeInTheDocument();
    expect(screen.getByText("flask")).toBeInTheDocument();
    expect(
      screen.getByText(/The advisory carries no fixed version, so no candidate exists\./),
    ).toBeInTheDocument();
  });

  it("drills into a group with the full validated findings and candidate evidence", async () => {
    stubFetch(remediationHandler());
    renderApp(remediationRoute);
    await screen.findByText(/requests 2\.31\.0 → 2\.32\.0/);

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Inspect" }));

    expect(await screen.findByText("Fix group detail")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Findings validated against the proposed version" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Candidates (1)")).toBeInTheDocument();
    expect(screen.getAllByText(/2\.31\.0 → 2\.32\.0/).length).toBeGreaterThan(1);
    expect(screen.getByText(/resolver executed: no/)).toBeInTheDocument();
    expect(screen.getByText("Advisory evidence")).toBeInTheDocument();
    expect(screen.getByText(/match version/)).toBeInTheDocument();
  });

  it("lists per-package candidate plans with explicit constraint outcomes", async () => {
    stubFetch(remediationHandler());
    renderApp(remediationRoute);
    await screen.findByText(/requests 2\.31\.0 → 2\.32\.0/);

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Candidate plans" }));

    expect(await screen.findByText("requests 2.31.0")).toBeInTheDocument();
    expect(screen.getByText(/2\.31\.0 → 2\.32\.0/)).toBeInTheDocument();
    expect(screen.getByText(/Selected by server ranking/)).toBeInTheDocument();
    expect(screen.getByText(/2\.32\.0 satisfies >=2\.31\./)).toBeInTheDocument();
    expect(screen.getByText(/BlastRadius never applies them or edits dependency files/)).toBeInTheDocument();
  });

  it("shows an empty state when no group exists", async () => {
    stubFetch(
      remediationHandler({
        groups: { status: 200, body: { ...fixGroupsResponse, groups: [], total: 0, count: 0 } },
      }),
    );
    renderApp(remediationRoute);

    expect(await screen.findByText("No fix groups for this analysis")).toBeInTheDocument();
  });
});
