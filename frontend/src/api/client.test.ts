import { describe, expect, it, vi } from "vitest";
import { ApiError, apiRequest, withQuery } from "./client";
import { envelope, stubFetch } from "../test/fetchMock";

describe("apiRequest", () => {
  it("parses successful JSON responses", async () => {
    stubFetch(() => ({ status: 200, body: { connected: true } }));
    await expect(apiRequest("/api/v1/graph/health")).resolves.toEqual({ connected: true });
  });

  it("maps the backend error envelope onto ApiError fields", async () => {
    stubFetch(() =>
      envelope(502, "graph_unavailable", "FalkorDB is unreachable", {
        stage: "graph",
        retryable: true,
        details: { connection: "127.0.0.1:6379" },
      }),
    );

    const error = await apiRequest("/api/v1/analyses/x/graph").catch((value: unknown) => value);

    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.status).toBe(502);
    expect(apiError.code).toBe("graph_unavailable");
    expect(apiError.message).toBe("FalkorDB is unreachable");
    expect(apiError.stage).toBe("graph");
    expect(apiError.retryable).toBe(true);
    expect(apiError.details).toEqual({ connection: "127.0.0.1:6379" });
    expect(apiError.isTransportFailure).toBe(false);
  });

  it("falls back to a generic error for non-envelope bodies (e.g. FastAPI validation)", async () => {
    stubFetch(() => ({
      status: 422,
      text: JSON.stringify({ detail: [{ loc: ["body", "repository_url"], msg: "field required" }] }),
    }));

    const error = (await apiRequest("/api/v1/repositories/ingest", { method: "POST", body: {} }).catch(
      (value: unknown) => value,
    )) as ApiError;

    expect(error.code).toBe("http_error");
    expect(error.status).toBe(422);
    expect(error.message).toContain("field required");
  });

  it("reports connection failures as retryable transport errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("connect ECONNREFUSED"))),
    );

    const error = (await apiRequest("/api/v1/graph/health").catch((value: unknown) => value)) as ApiError;

    expect(error.code).toBe("network_error");
    expect(error.status).toBe(0);
    expect(error.retryable).toBe(true);
    expect(error.isTransportFailure).toBe(true);
    expect(error.message).toContain("Is the backend running?");
  });

  it("enforces the per-request timeout", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_input: unknown, init?: RequestInit) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
          }),
      ),
    );

    const error = (await apiRequest("/api/v1/repositories/ingest", { timeoutMs: 15 }).catch(
      (value: unknown) => value,
    )) as ApiError;

    expect(error.code).toBe("request_timeout");
    expect(error.isAborted).toBe(true);
  });

  it("distinguishes caller aborts from timeouts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_input: unknown, init?: RequestInit) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
          }),
      ),
    );

    const controller = new AbortController();
    const pending = apiRequest("/api/v1/analyses/x/findings", { signal: controller.signal }).catch(
      (value: unknown) => value,
    );
    controller.abort();
    const error = (await pending) as ApiError;

    expect(error.code).toBe("request_aborted");
    expect(error.status).toBe(0);
  });

  it("rejects non-JSON success bodies instead of inventing data", async () => {
    stubFetch(() => ({ status: 200, text: "<html>proxy error</html>" }));

    const error = (await apiRequest("/api/v1/graph/health").catch((value: unknown) => value)) as ApiError;

    expect(error.code).toBe("invalid_response");
  });

  it("sends POST bodies as JSON with an Accept header", async () => {
    const calls = stubFetch(() => ({ status: 200, body: {} }));

    await apiRequest("/api/v1/repositories/ingest", {
      method: "POST",
      body: { repository_url: "https://github.com/psf/requests", ref: null },
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.headers.Accept).toBe("application/json");
    expect(calls[0]?.headers["Content-Type"]).toBe("application/json");
    expect(calls[0]?.body).toEqual({ repository_url: "https://github.com/psf/requests", ref: null });
  });
});

describe("withQuery", () => {
  it("omits empty values and preserves order", () => {
    expect(withQuery("/api/v1/analyses/x/findings", { skip: 0, limit: 50, unused: undefined })).toBe(
      "/api/v1/analyses/x/findings?skip=0&limit=50",
    );
  });

  it("returns the bare path when nothing is set", () => {
    expect(withQuery("/api/v1/graph/health", { skip: undefined, limit: null })).toBe("/api/v1/graph/health");
  });
});
