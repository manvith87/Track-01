import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../test/renderApp";
import { envelope, stubFetch, type StubReply } from "../test/fetchMock";
import {
  ANALYSIS_ID,
  findingsResponse,
  fixGroupsResponse,
  graphHealth,
  graphStatus,
  issueConfirm,
  issuePreview,
} from "../test/fixtures";

function issueHandler(overrides: { preview?: StubReply; confirm?: StubReply } = {}) {
  return (url: string, method: string): StubReply | undefined => {
    if (url.includes("/api/v1/graph/health")) return { status: 200, body: graphHealth };
    if (url.includes("/graph/status")) return { status: 200, body: graphStatus };
    if (url.includes("/remediation/github-issue/preview") && method === "POST") {
      return overrides.preview ?? { status: 201, body: issuePreview };
    }
    if (url.includes("/actions/github-issue/confirm") && method === "POST") {
      return overrides.confirm ?? { status: 201, body: issueConfirm };
    }
    if (url.includes("/remediation/groups")) return { status: 200, body: fixGroupsResponse };
    if (url.includes("/findings")) return { status: 200, body: findingsResponse };
    return undefined;
  };
}

/** Storage may be unavailable in the test environment; assert only when readable. */
function storageDump(): string {
  const parts: string[] = [];
  try {
    if (window.sessionStorage) parts.push(JSON.stringify(window.sessionStorage));
  } catch {
    /* storage unavailable */
  }
  try {
    if (window.localStorage) parts.push(JSON.stringify(window.localStorage));
  } catch {
    /* storage unavailable */
  }
  return parts.join("|");
}

const issueRoute = `/analysis/${ANALYSIS_ID}/issue`;

async function preparePreview() {
  const user = userEvent.setup();
  const select = await screen.findByLabelText(/choose a fix group/i);
  await screen.findByRole("option", { name: /requests 2\.31\.0 → 2\.32\.0/ });
  await user.selectOptions(select, "group_1");
  await user.click(screen.getByRole("button", { name: /prepare preview/i }));
  await screen.findByText("Server-prepared issue preview");
  return user;
}

describe("Screen F — approved GitHub issue action", () => {
  it("previews the exact server-composed issue and requires explicit confirmation", async () => {
    const calls = stubFetch(issueHandler());
    renderApp(issueRoute);

    const user = await preparePreview();
    expect(screen.getByText(issuePreview.title)).toBeInTheDocument();
    expect(screen.getByText(/Preview only — no request has been sent to GitHub\./)).toBeInTheDocument();

    const previewCall = calls.find((call) => call.url.includes("/remediation/github-issue/preview"));
    expect(previewCall?.body).toEqual({ group_id: "group_1" });

    // Confirmation is gated on both the review checkbox and the approval value.
    const confirmButton = screen.getByRole("button", { name: /confirm and create github issue/i });
    expect(confirmButton).toBeDisabled();

    await user.click(screen.getByLabelText(/I reviewed the exact title and body above/i));
    expect(confirmButton).toBeDisabled();

    await user.type(screen.getByLabelText(/approval secret/i), "s3cret-approval");
    expect(confirmButton).toBeEnabled();
  });

  it("sends the approval value once as a header and only shows the real GitHub result", async () => {
    const calls = stubFetch(issueHandler());
    renderApp(issueRoute);
    const user = await preparePreview();

    await user.click(screen.getByLabelText(/I reviewed the exact title and body above/i));
    await user.type(screen.getByLabelText(/approval secret/i), "s3cret-approval");
    await user.click(screen.getByRole("button", { name: /confirm and create github issue/i }));

    expect(await screen.findByText("Issue created")).toBeInTheDocument();
    expect(screen.getByText("example/demo#42")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: issueConfirm.issue_url })).toHaveAttribute(
      "href",
      issueConfirm.issue_url,
    );

    const confirmCall = calls.find((call) => call.url.includes("/actions/github-issue/confirm"));
    expect(confirmCall?.headers["X-BlastRadius-Approval"]).toBe("s3cret-approval");
    expect(confirmCall?.body).toEqual({
      action_id: issuePreview.action_id,
      payload_digest: issuePreview.payload_digest,
    });

    // The approval value is never persisted anywhere in the browser.
    expect(storageDump()).not.toContain("s3cret-approval");
    expect(screen.queryByLabelText(/approval secret/i)).not.toBeInTheDocument();
  });

  it("reports a stored result as a prevented duplicate instead of a new creation", async () => {
    stubFetch(
      issueHandler({
        confirm: { status: 200, body: { ...issueConfirm, created: false, state: "SUCCEEDED" } },
      }),
    );
    renderApp(issueRoute);
    const user = await preparePreview();

    await user.click(screen.getByLabelText(/I reviewed the exact title and body above/i));
    await user.type(screen.getByLabelText(/approval secret/i), "s3cret-approval");
    await user.click(screen.getByRole("button", { name: /confirm and create github issue/i }));

    expect(await screen.findByText(/Stored result returned — no new issue was created/)).toBeInTheDocument();
    expect(screen.queryByText("Issue created")).not.toBeInTheDocument();
  });

  it("invalidates an expired preview and demands a fresh one", async () => {
    stubFetch(
      issueHandler({
        confirm: envelope(410, "action_expired", "The action expired before confirmation.", {
          stage: "actions",
        }),
      }),
    );
    renderApp(issueRoute);
    const user = await preparePreview();

    await user.click(screen.getByLabelText(/I reviewed the exact title and body above/i));
    await user.type(screen.getByLabelText(/approval secret/i), "s3cret-approval");
    await user.click(screen.getByRole("button", { name: /confirm and create github issue/i }));

    expect(await screen.findByText("This preview can no longer be confirmed")).toBeInTheDocument();
    expect(screen.queryByText("Server-prepared issue preview")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /prepare preview/i })).toBeInTheDocument();
  });

  it("keeps the preview valid when the approval value is rejected", async () => {
    stubFetch(
      issueHandler({
        confirm: envelope(401, "action_unauthorized", "The approval value was not accepted.", {
          stage: "actions",
        }),
      }),
    );
    renderApp(issueRoute);
    const user = await preparePreview();

    await user.click(screen.getByLabelText(/I reviewed the exact title and body above/i));
    await user.type(screen.getByLabelText(/approval secret/i), "wrong-secret");
    await user.click(screen.getByRole("button", { name: /confirm and create github issue/i }));

    expect(await screen.findByText("Approval rejected")).toBeInTheDocument();
    expect(screen.getByText("Server-prepared issue preview")).toBeInTheDocument();
    // The typed value is cleared after the failed attempt.
    expect(screen.getByLabelText(/approval secret/i)).toHaveValue("");
  });

  it("explains a disabled write integration before any confirmation is possible", async () => {
    stubFetch(
      issueHandler({
        preview: envelope(403, "github_write_disabled", "GitHub write actions are disabled.", {
          stage: "actions",
        }),
      }),
    );
    renderApp(issueRoute);

    const user = userEvent.setup();
    const select = await screen.findByLabelText(/choose a fix group/i);
    await screen.findByRole("option", { name: /requests 2\.31\.0 → 2\.32\.0/ });
    await user.selectOptions(select, "group_1");
    await user.click(screen.getByRole("button", { name: /prepare preview/i }));

    expect(await screen.findByText("GitHub write actions are disabled on this server")).toBeInTheDocument();
    expect(screen.queryByLabelText(/approval secret/i)).not.toBeInTheDocument();
  });

  it("never exposes the approval secret in the DOM after a rejected attempt", async () => {
    stubFetch(
      issueHandler({
        confirm: envelope(401, "action_unauthorized", "The approval value was not accepted.", {
          stage: "actions",
        }),
      }),
    );
    renderApp(issueRoute);
    const user = await preparePreview();

    await user.click(screen.getByLabelText(/I reviewed the exact title and body above/i));
    await user.type(screen.getByLabelText(/approval secret/i), "super-secret-value");
    await user.click(screen.getByRole("button", { name: /confirm and create github issue/i }));
    await screen.findByText("Approval rejected");

    expect(document.body.innerHTML).not.toContain("super-secret-value");
    expect(screen.getByLabelText(/approval secret/i)).toHaveValue("");
  });
});
