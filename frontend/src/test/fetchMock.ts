/**
 * Minimal fetch stub for component tests.
 *
 * Tests never claim integration coverage from these stubs: they exercise the
 * UI's own behaviour against recorded response *shapes*. Real end-to-end
 * verification runs against a live backend (see docs/PHASE7.md).
 */

import { vi } from "vitest";

export interface StubReply {
  status?: number;
  body?: unknown;
  /** Raw body text (used for non-JSON error bodies). */
  text?: string;
}

export interface RecordedCall {
  url: string;
  method: string;
  body: unknown;
  headers: Record<string, string>;
}

export type StubHandler = (url: string, method: string) => StubReply | undefined;

function responseFrom(reply: StubReply): Response {
  const status = reply.status ?? 200;
  const text = reply.text ?? JSON.stringify(reply.body ?? {});
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    text: async () => text,
  } as unknown as Response;
}

/** Install a fetch stub; returns the list of recorded calls for assertions. */
export function stubFetch(handler: StubHandler): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = typeof input === "string" ? input : String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push({
        url,
        method,
        body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
        headers: (init?.headers as Record<string, string>) ?? {},
      });
      const reply = handler(url, method);
      if (!reply) {
        return responseFrom({
          status: 404,
          body: {
            error: {
              code: "not_found",
              message: `No stub configured for ${method} ${url}`,
              stage: "test",
              retryable: false,
              details: {},
            },
          },
        });
      }
      return responseFrom(reply);
    }),
  );
  return calls;
}

export function envelope(
  status: number,
  code: string,
  message: string,
  extra?: Record<string, unknown>,
): StubReply {
  return {
    status,
    body: {
      error: {
        code,
        message,
        stage: extra?.stage ?? "test",
        retryable: extra?.retryable ?? false,
        details: extra?.details ?? {},
      },
    },
  };
}
