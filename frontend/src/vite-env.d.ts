/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the BlastRadius backend. Empty string (default) uses the same origin via the dev/preview proxy. */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
