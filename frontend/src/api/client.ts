/**
 * Single typed HTTP client for the BlastRadius API.
 *
 * - Centralises the base URL (VITE_API_BASE_URL, empty = same origin proxy).
 * - Applies per-request timeouts and supports caller cancellation.
 * - Normalises every failure into an {@link ApiError} carrying the backend's
 *   structured error envelope (code/message/stage/retryable/details) when the
 *   server produced one, and safe fallbacks for network/timeout/non-JSON cases.
 */

export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    stage: string;
    retryable: boolean;
    details: Record<string, unknown>;
  };
}

export const API_BASE_URL: string = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

/** Default timeout for reads and small writes. */
export const DEFAULT_TIMEOUT_MS = 20_000;
/** Ingestion and OSV sync are synchronous and bounded by server-side limits. */
export const LONG_OPERATION_TIMEOUT_MS = 330_000;
/** The agent call includes one or more model rounds plus MCP tool calls. */
export const AGENT_TIMEOUT_MS = 120_000;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly stage: string;
  readonly retryable: boolean;
  readonly details: Record<string, unknown>;

  constructor(init: {
    status: number;
    code: string;
    message: string;
    stage?: string;
    retryable?: boolean;
    details?: Record<string, unknown>;
  }) {
    super(init.message);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.stage = init.stage ?? "unknown";
    this.retryable = init.retryable ?? false;
    this.details = init.details ?? {};
  }

  /** True when no HTTP response was received (offline, DNS, CORS, timeout). */
  get isTransportFailure(): boolean {
    return this.status === 0;
  }

  /** True when the request was aborted by the caller or the timeout. */
  get isAborted(): boolean {
    return this.code === "request_aborted" || this.code === "request_timeout";
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

export interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeoutMs?: number;
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const envelope = (value as { error?: unknown }).error;
  if (typeof envelope !== "object" || envelope === null) return false;
  return typeof (envelope as { message?: unknown }).message === "string";
}

async function toApiError(response: Response): Promise<ApiError> {
  const text = await response.text().catch(() => "");
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }
  if (isErrorEnvelope(parsed)) {
    const { code, message, stage, retryable, details } = parsed.error;
    return new ApiError({
      status: response.status,
      code: typeof code === "string" ? code : "http_error",
      message,
      stage: typeof stage === "string" ? stage : "unknown",
      retryable: Boolean(retryable),
      details: typeof details === "object" && details !== null ? details : {},
    });
  }
  const fallback = text.trim().slice(0, 300) || response.statusText || "Request failed";
  return new ApiError({ status: response.status, code: "http_error", message: fallback });
}

/**
 * Perform one API request. `path` is relative to the API base URL and must
 * start with "/" (e.g. "/api/v1/repositories/ingest").
 */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const controller = new AbortController();
  let timedOut = false;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const external = options.signal;
  const forwardAbort = () => controller.abort();
  external?.addEventListener("abort", forwardAbort);

  const headers: Record<string, string> = { Accept: "application/json", ...options.headers };
  let body: string | undefined;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: options.method ?? "GET",
      headers,
      body,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw await toApiError(response);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    const text = await response.text();
    if (!text) {
      return undefined as T;
    }
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new ApiError({
        status: response.status,
        code: "invalid_response",
        message: "The server returned a response that is not valid JSON.",
      });
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (timedOut) {
      throw new ApiError({
        status: 0,
        code: "request_timeout",
        message: `The request did not complete within ${Math.round(timeoutMs / 1000)}s.`,
        retryable: true,
      });
    }
    if (external?.aborted) {
      throw new ApiError({ status: 0, code: "request_aborted", message: "The request was cancelled." });
    }
    const message = error instanceof Error ? error.message : "Network request failed";
    throw new ApiError({
      status: 0,
      code: "network_error",
      message: `Could not reach the BlastRadius API (${message}). Is the backend running?`,
      retryable: true,
    });
  } finally {
    clearTimeout(timeout);
    external?.removeEventListener("abort", forwardAbort);
  }
}

export type QueryValue = string | number | boolean | null | undefined;

/** Build a query string, omitting empty values. */
export function withQuery(path: string, params: Record<string, QueryValue>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `${path}?${query}` : path;
}
