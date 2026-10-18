/** Shared TanStack Query client configuration. */

import { QueryClient } from "@tanstack/react-query";
import { isApiError } from "../api/client";

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // The backend is deterministic for reads; keep results fresh but never
        // poll. Failures are retried only when the envelope marks them
        // retryable and no response was received at all.
        staleTime: 15_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          if (failureCount >= 1) return false;
          return isApiError(error) && error.retryable && error.status === 0;
        },
      },
      mutations: { retry: false },
    },
  });
}
