import type { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { App } from "../App";
import { createQueryClient } from "../state/queryClient";

export interface RenderAppResult {
  queryClient: QueryClient;
  unmount: () => void;
}

/**
 * Render the whole application (router + providers) at a route.
 * Screens are exercised exactly as they are wired in production.
 */
export function renderApp(route = "/"): ReturnType<typeof render> {
  const queryClient = createQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[route]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
