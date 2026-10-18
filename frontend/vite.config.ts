import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The backend runs separately (FastAPI, default http://127.0.0.1:8000).
// The dev/preview servers proxy the API so the browser talks to one origin and
// no backend CORS configuration is required. Point the proxy (or
// VITE_API_BASE_URL for a deployed build) at another backend when needed.
const backendUrl = process.env.BLASTRADIUS_BACKEND_URL ?? "http://127.0.0.1:8000";

const proxy = {
  "/api": { target: backendUrl, changeOrigin: true },
  "/health": { target: backendUrl, changeOrigin: true },
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
  build: {
    // Cytoscape and the UI runtime are the bulk of the bundle; splitting them
    // keeps the app code chunk small and cacheable across releases.
    rollupOptions: {
      output: {
        manualChunks: {
          "vendor-cytoscape": ["cytoscape"],
          "vendor-react": ["react", "react-dom", "react-router-dom"],
          "vendor-query": ["@tanstack/react-query"],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    environmentOptions: {
      // A real origin so localStorage/sessionStorage behave like production.
      jsdom: { url: "http://localhost:5173/" },
    },
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
    css: false,
  },
});
