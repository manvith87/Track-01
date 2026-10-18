import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// jsdom does not implement ResizeObserver, which the graph canvas wrapper uses.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;

// Clipboard access is only used by copy buttons.
Object.defineProperty(navigator, "clipboard", {
  configurable: true,
  value: { writeText: () => Promise.resolve() },
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  try {
    window.sessionStorage?.clear();
    window.localStorage?.clear();
  } catch {
    // Storage can be unavailable in exotic environments; nothing to clear.
  }
});
