import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../test/renderApp";
import { envelope, stubFetch, type StubReply } from "../test/fetchMock";
import {
  ANALYSIS_ID,
  graphHealth,
  graphIngestResponse,
  ingestResponse,
  osvSyncResponse,
} from "../test/fixtures";

function screenAHandler(overrides: { ingest?: StubReply; persist?: StubReply; sync?: StubReply } = {}) {
  return (url: string, method: string): StubReply | undefined => {
    if (url.includes("/api/v1/graph/health")) return { status: 200, body: graphHealth };
    if (url.includes("/repositories/ingest") && method === "POST") {
      return overrides.ingest ?? { status: 200, body: ingestResponse };
    }
    if (url.includes("/graph") && method === "POST") {
      return overrides.persist ?? { status: 200, body: graphIngestResponse };
    }
    if (url.includes("/vulnerabilities") && method === "POST") {
      return overrides.sync ?? { status: 200, body: osvSyncResponse };
    }
    return undefined;
  };
}

async function submitRepository(url: string) {
  const user = userEvent.setup();
  const input = screen.getByLabelText(/repository url/i);
  await user.clear(input);
  await user.type(input, url);
  await user.click(screen.getByRole("button", { name: /run ingestion/i }));
  return user;
}

describe("Screen A — repository analysis", () => {
  it("rejects non-GitHub URLs before making any request", async () => {
    const calls = stubFetch(screenAHandler());
    renderApp("/");

    await submitRepository("https://gitlab.com/example/demo");

    expect(await screen.findByText(/only github\.com repositories are supported/i)).toBeInTheDocument();
    expect(calls.some((call) => call.url.includes("/repositories/ingest"))).toBe(false);
  });

  it("shows the real ingest result: declarations, resolved packages, warnings and truncation", async () => {
    stubFetch(screenAHandler());
    renderApp("/");

    await submitRepository("https://github.com/example/demo");

    expect(await screen.findByText("Analysis overview")).toBeInTheDocument();
    expect(screen.getByText("Ingestion: partial")).toBeInTheDocument();
    expect(screen.getByText(/reported 0 error\(s\) and 1 warning\(s\)/i)).toBeInTheDocument();
    expect(screen.getByText("Server response was bounded")).toBeInTheDocument();

    // Declarations and resolved packages are separate sections with distinct facts.
    expect(screen.getByRole("heading", { name: "Declared dependencies" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Resolved packages" })).toBeInTheDocument();
    expect(screen.getAllByText("requests").length).toBeGreaterThan(0);
    expect(screen.getAllByText("unresolved_version").length).toBeGreaterThan(0);

    // The resolved commit comes from the response.
    expect(screen.getByText("bbbbbbbbbbbb")).toBeInTheDocument();
  });

  it("persists the ingest response unchanged and then syncs OSV advisories", async () => {
    const calls = stubFetch(screenAHandler());
    renderApp("/");

    const user = await submitRepository("https://github.com/example/demo");
    await screen.findByText("Analysis overview");

    await user.click(screen.getByRole("button", { name: /persist analysis to graph/i }));

    expect(await screen.findByText(/persisted \(status: success\)/i)).toBeInTheDocument();
    const persistCall = calls.find(
      (call) => call.method === "POST" && call.url.includes(`/analyses/${ANALYSIS_ID}/graph`),
    );
    expect(persistCall?.body).toEqual({ result: ingestResponse });

    const openLink = screen.getByRole("link", { name: /open analysis/i });
    expect(openLink).toHaveAttribute("href", `/analysis/${ANALYSIS_ID}/findings`);

    await user.click(screen.getByRole("button", { name: /sync osv advisories/i }));
    expect(await screen.findByText(/OSV sync: completed/i)).toBeInTheDocument();
    expect(screen.getByText(/1 packages scanned|4 packages scanned/)).toBeInTheDocument();
    expect(
      calls.some(
        (call) => call.method === "POST" && call.url.endsWith(`/analyses/${ANALYSIS_ID}/vulnerabilities`),
      ),
    ).toBe(true);
  });

  it("surfaces the structured error envelope when ingestion fails", async () => {
    stubFetch(
      screenAHandler({
        ingest: envelope(502, "repository_unavailable", "Could not retrieve the repository.", {
          stage: "retrieval",
          retryable: true,
        }),
      }),
    );
    renderApp("/");

    await submitRepository("https://github.com/example/demo");

    expect(await screen.findByText("Ingestion failed")).toBeInTheDocument();
    expect(screen.getByText("Could not retrieve the repository.")).toBeInTheDocument();
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("repository_unavailable");
    expect(alert).toHaveTextContent("retrieval");
    expect(alert).toHaveTextContent(/retryable/i);
  });

  it("explains when the response carries no analysis id instead of pretending to persist", async () => {
    stubFetch(
      screenAHandler({
        ingest: { status: 200, body: { ...ingestResponse, analysis_id: null } },
      }),
    );
    renderApp("/");

    await submitRepository("https://github.com/example/demo");

    expect(await screen.findByText(/No analysis id in this response/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /persist analysis to graph/i })).toBeDisabled();
    });
  });
});
