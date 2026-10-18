import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../test/renderApp";
import { envelope, stubFetch, type StubReply } from "../test/fetchMock";
import { ANALYSIS_ID, agentResponse, graphHealth, graphStatus } from "../test/fixtures";

function analystHandler(overrides: { ask?: StubReply } = {}) {
  return (url: string, method: string): StubReply | undefined => {
    if (url.includes("/api/v1/graph/health")) return { status: 200, body: graphHealth };
    if (url.includes("/graph/status")) return { status: 200, body: graphStatus };
    if (url.includes("/ask") && method === "POST")
      return overrides.ask ?? { status: 200, body: agentResponse };
    return undefined;
  };
}

const analystRoute = `/analysis/${ANALYSIS_ID}/analyst`;

describe("Screen D — evidence-grounded analyst", () => {
  it("renders the answer with its evidence, tool calls and limitations", async () => {
    const calls = stubFetch(analystHandler());
    renderApp(analystRoute);

    expect(await screen.findByText("No questions asked yet")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^question$/i), "Which packages are affected?");
    await user.click(screen.getByRole("button", { name: /^ask$/i }));

    expect(
      await screen.findByText(/requests 2\.31\.0 is affected by GHSA-aaaa-bbbb-cccc/),
    ).toBeInTheDocument();
    expect(screen.getByText("Grounded in tool evidence")).toBeInTheDocument();
    expect(screen.getAllByText("get_blast_radius").length).toBeGreaterThan(0);
    expect(screen.getByText("requests 2.31.0 -> certifi (2 hops)")).toBeInTheDocument();
    expect(
      screen.getByText(/Paths are bounded by the relationships stored in the graph\./),
    ).toBeInTheDocument();
    expect(screen.getByText(/2 round\(s\)/)).toBeInTheDocument();

    const askCall = calls.find((call) => call.url.includes("/ask"));
    expect(askCall?.body).toEqual({ question: "Which packages are affected?" });
    // The UI never fabricates an answer locally.
    expect(screen.getByText(/Each question is an independent server request/)).toBeInTheDocument();
  });

  it("explains an unconfigured LLM provider instead of showing an answer", async () => {
    stubFetch(
      analystHandler({
        ask: envelope(503, "agent_not_configured", "The analysis agent has no LLM provider configured.", {
          stage: "agent",
        }),
      }),
    );
    renderApp(analystRoute);
    await screen.findByText("No questions asked yet");

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^question$/i), "What is most urgent?");
    await user.click(screen.getByRole("button", { name: /^ask$/i }));

    expect(
      await screen.findByText("The analysis agent is not configured on this server"),
    ).toBeInTheDocument();
    expect(screen.getByText(/agent_not_configured/)).toBeInTheDocument();
    // Deterministic screens remain usable; no answer was invented.
    expect(screen.queryByText(/Grounded in tool evidence/)).not.toBeInTheDocument();
  });

  it("surfaces provider errors distinctly from configuration errors", async () => {
    stubFetch(
      analystHandler({
        ask: envelope(502, "agent_provider_error", "The provider returned HTTP 429.", {
          stage: "agent",
          retryable: true,
        }),
      }),
    );
    renderApp(analystRoute);
    await screen.findByText("No questions asked yet");

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/^question$/i), "Summarize the risk.");
    await user.click(screen.getByRole("button", { name: /^ask$/i }));

    expect(await screen.findByText("The LLM provider returned an error")).toBeInTheDocument();
    expect(screen.getByText(/retryable/)).toBeInTheDocument();
  });

  it("offers suggested questions as real prompts", async () => {
    stubFetch(analystHandler());
    renderApp(analystRoute);
    await screen.findByText("No questions asked yet");

    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", {
        name: /Which fix groups resolve the most advisory-confirmed findings\?/i,
      }),
    );

    expect(screen.getByLabelText(/^question$/i)).toHaveValue(
      "Which fix groups resolve the most advisory-confirmed findings?",
    );
  });
});
