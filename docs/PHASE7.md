# Phase 7 — Security Operations Frontend

Phase 7 adds the operator-facing web application for BlastRadius: a dark, neutral
security-ops workspace in `frontend/` that renders the **real** Phase 1–6 HTTP API.
It is a read-and-review surface plus one deliberately narrow write flow (the
Phase 6 approved GitHub issue). No backend behaviour, scoring, remediation logic,
graph storage or approval guard was changed or re-implemented in the browser.

Everything the UI shows comes from a backend response. Nothing is inferred,
fabricated, mocked (outside unit tests) or computed client-side — including
reachability, severity, priority, compatibility, coverage and issue content.

---

## 1. Scope

In scope:

| Screen | Route | Purpose |
|--------|-------|---------|
| A — Repository analysis | `/` | Validated repo URL + optional ref, real ingest → graph persist → OSV sync sequencing, declared vs resolved dependency data, advisories/graph statistics, warnings, open the analysis |
| B — Findings | `/analysis/:analysisId/findings` | Ranked findings with priority factors, advisory severity kept separate, modeled reachability, evidence, remediation summary, server-side filter/search/sort/pagination |
| C — Graph explorer | `/analysis/:analysisId/graph` | Cytoscape.js view over the persisted graph, statistics, neighbourhood expansion, server-reported impact-path highlighting, node details/provenance |
| D — Analyst | `/analysis/:analysisId/analyst` | Question panel for the existing Phase 4B agent API with suggested questions, tool-call summary, evidence, limitations, provider errors |
| E — Remediation | `/analysis/:analysisId/remediation` | Ranked fix groups, coverage (advisory-confirmed vs potential-only), compatibility status, unresolved findings, candidate plans, group drill-down |
| F — Approved issue | `/analysis/:analysisId/issue` | Server-composed issue preview (exact title/body/digest), explicit confirmation, real GitHub result only on success, duplicate/expiry/evidence-change handling |

Out of scope (unchanged by this phase): backend rewriting, scoring/remediation
formulas, hardcoded findings, replacing FalkorDB, automatic PRs or dependency
edits, removing approval guards, claiming unverified GitHub writes, and Phase 8.

## 2. Stack and project layout

React 19 + Vite 7 + TypeScript (strict) + Tailwind CSS 4 + Cytoscape.js 3 +
TanStack Query v5 + React Router 7. One typed API client; no second state library.

```
frontend/
  index.html
  package.json                 # dev / build / typecheck / lint / format / test / api:types
  vite.config.ts               # /api + /health proxy, vitest (jsdom) config, vendor chunking
  openapi.json                 # committed snapshot of the backend OpenAPI document
  scripts/generate-api-types.mjs
  src/
    api/
      client.ts                # base URL, timeout, abort, structured error envelope -> ApiError
      endpoints.ts             # one typed function per endpoint the UI uses
      generated.ts             # 83 interfaces generated from openapi.json (do not hand-edit)
      graphValues.ts           # narrowing helpers for FalkorDB row values
    graph/
      adapter.ts               # real graph rows -> explorer nodes/edges (+ overlays, highlighting)
      GraphCanvas.tsx          # Cytoscape canvas (elements, style, selection, fit)
    state/                     # query client, analysis context/provider, selected analysis id
    hooks/queries.ts           # query keys (always include analysisId) + read hooks
    components/                # Layout, guards, tables, badges, state views
    pages/                     # RepoAnalysisPage, FindingsPage, GraphExplorerPage,
                               # AnalystPage, RemediationPage, IssueActionPage, NotFoundPage
    lib/                       # formatting + prefs (theme/layout only - no secrets)
    test/                      # fetch stub, fixtures, full-app render helper, setup
    integration/               # opt-in live-backend smoke test
```

## 3. API contract (single source of truth)

`frontend/openapi.json` is a committed snapshot of `GET /openapi.json` from the
FastAPI app. `src/api/generated.ts` is generated from it:

```powershell
# refresh the snapshot (backend must be reachable), then regenerate types
Invoke-WebRequest http://127.0.0.1:8000/openapi.json -OutFile frontend/openapi.json
cd frontend
npm run api:types
```

Contract types are never hand-transcribed. `endpoints.ts` deliberately exposes
only the operations the six screens use (the standalone read-only OSV lookup
`GET /api/v1/osv/vulnerabilities` is intentionally not surfaced).

`client.ts` details:

- base URL from `VITE_API_BASE_URL` (empty = same origin, i.e. the dev/preview proxy);
- default timeout 20 s, longer for ingest/persist/sync/agent calls;
- `fetch` aborts on timeout and on caller cancellation; stale responses cannot
  overwrite a newer analysis because every query key contains `analysisId`;
- non-2xx responses are parsed into `ApiError { status, code, message, stage,
  retryable, details }` from the backend's `{"error": {...}}` envelope, with a
  safe fallback for non-JSON bodies;
- no credentials, tokens or secrets are attached by the client.

## 4. Running it

Prerequisites: Node.js 20+, Python 3.11+ for the backend, FalkorDB for the
analysis screens (the backend starts without it, but graph-backed screens then
report explicit 502/`connected: false` states).

```powershell
# 1) backend (from the repository root)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2) frontend (from frontend/)
npm install
npm run dev          # http://localhost:5173
```

`vite.config.ts` proxies `/api` and `/health` to `BLASTRADIUS_BACKEND_URL`
(default `http://127.0.0.1:8000`) for both `npm run dev` and `npm run preview`.
A backend on another host/port:

```powershell
$env:BLASTRADIUS_BACKEND_URL = "http://127.0.0.1:9000"; npm run dev
```

Deployed builds (frontend served separately from the API) set the client base URL
at build time:

```powershell
$env:VITE_API_BASE_URL = "https://api.example.internal"; npm run build
```

`npm run preview` serves `dist/` with the same proxy (port 4173).

## 5. Routing and analysis context

The URL is the context source of truth:

```
/                                      Screen A (new analysis)
/analysis/:analysisId                  -> redirects to /findings
/analysis/:analysisId/findings         B
/analysis/:analysisId/graph            C
/analysis/:analysisId/analyst          D
/analysis/:analysisId/remediation      E
/analysis/:analysisId/issue            F
```

`AnalysisBranch` wraps every analysis route in `AnalysisProvider key={analysisId}`,
so switching analyses remounts the branch; every TanStack Query key includes the
analysis id. `AnalysisGuard` resolves the graph-status record once per analysis and
renders loading → error → content, so a missing analysis produces one clear state
instead of per-widget failures. There is no polling: data is fetched on mount and
refetched only on explicit user action.

## 6. Screen-by-screen behaviour

### Screen A — repository analysis

- Validates the repository URL and ref locally first (shape only), then submits the
  real request. Only server-reported status is shown; there is no invented progress
  bar or job tracking.
- Real sequencing preserved and visible: `POST /repositories/ingest` →
  `POST /analyses/{id}/graph` (persist exactly what was returned) →
  `POST /analyses/{id}/vulnerabilities` (OSV sync). Each step's actual response is
  shown; a failure stops the sequence with the backend's envelope.
- Displays the resolved commit SHA, manifest list, declared dependencies and
  lockfile-resolved packages **separately** (a declaration is not a resolution),
  dependency edges, advisories/graph statistics and every warning.
- When the ingest response is capped by `BLASTRADIUS_MAX_API_RECORDS`, the UI states
  that persisting persists exactly those bounded records (`truncated` in both
  directions).
- After a successful persist the analysis can be opened directly; the id is also
  kept for later context.

### Screen B — findings

- Server-side `skip`/`limit` pagination; filter/search/sort are explicitly labelled
  as operating on the current server page (the UI never claims to re-rank).
- Each finding shows the advisory's raw severity value/type verbatim (with a
  display-only colour band), the BlastRadius priority score and its factors, modeled
  reachability, evidence references, remediation availability and completeness.
- Severity and priority are always visually and textually distinct. Reachability is
  "modeled path" wording only; "no path" is never phrased as "safe".
- Full detail (advisory metadata, graph evidence, remediation candidates with
  compatibility) loads from `GET /findings/{finding_id}`.

### Screen C — graph explorer

- Elements are built from `GET /analyses/{id}/graph` rows by `graph/adapter.ts`
  using the row association the backend returns (r→f `CONTAINS`, r→m
  `HAS_MANIFEST`, m→d `DECLARES`, d→p `TARGETS`, d→rp `RESOLVES_TO`, p→t
  `DEPENDS_ON`); edge type/properties come from the `rt`/`e` values when present.
- Node element ids are `${Label}:${properties.id}`; every label carries an `id`
  property (see `docs/GRAPH_SCHEMA.md`). Malformed values are skipped, never invented.
- Omitted labels are unavailable — only `Repository`, `SourceFile`,
  `DependencyManifest`, `DependencyDeclaration`, `Package` and (via the advisories
  overlay) `Vulnerability` are rendered, each visually distinct, with a filter per
  type and a statistics panel from `GET /graph/statistics`.
- Bounded rendering: the row limit and neighbourhood depth are user-controlled and
  capped; a truncation notice appears when the backend matched more rows than were
  returned, and counts always come from the statistics endpoint, not the rendered
  slice.
- Neighbourhood expansion (`GET /packages/{id}/neighborhood`) creates explicit
  `nameOnly` nodes for names that have no id in the page — names are never silently
  converted into ids.
- Impact-path highlighting uses only `GET /vulnerabilities/blast-radius` responses
  (optionally filtered to one advisory). Highlighted endpoints that are not in the
  fetched page are reported in a notice; nothing is synthesized to fill the gap.
- Selecting a node (canvas or the accessible list) shows its label, properties,
  provenance lines and file/line references where the graph carries them (e.g.
  declaration `evidence`/`line_number`). Reachability is never computed in the
  browser.

### Screen D — analyst

- Questions are sent to the existing `POST /analyses/{id}/ask`; the answer, evidence,
  tool-call summary, limitations/uncertainty, repository/commit references and
  provider/MCP errors are rendered exactly as returned.
- Suggested questions are prompts, not answers. No explanation is generated locally.
- `503 agent_not_configured` and `agent_provider_error` get tailored notices that
  include the server's own configuration message; the deterministic screens remain
  usable without any provider.
- The UI states plainly that answers are per-request and that no chat memory is
  persisted.

### Screen E — remediation

- Groups come from `GET /remediation/groups` with the server's ranking, coverage
  (`confirmed_advisory` / `potential_only` / `no_advisory_resolution`), verified vs
  potential vs unresolved finding ids, compatibility status and constraint checks.
- Unresolved findings are listed separately with the server's reason — never hidden.
- Candidate plans (`GET /remediation/candidates`) show advisory-derived candidate
  versions, per-constraint outcomes, `unknown` ranges and `resolver_executed: false`.
- Potential candidates are never relabelled as confirmed fixes; the schema has no
  "verified fix" wording for them. No score or compatibility is ever recomputed in
  the browser.
- Group drill-down (`GET /remediation/groups/{group_id}`) shows full validated
  findings, candidate evidence and advisory links.

### Screen F — approved GitHub issue

- A preview is created by `POST /analyses/{id}/remediation/github-issue/preview`
  (exactly one of `group_id`/`finding_id`). The server's title, body, digest,
  repository + commit, evidence, limitations, notes and `expires_at` are rendered
  verbatim. Preview is not success: the UI says no request has been sent to GitHub.
- Confirmation is a separate deliberate step: a review checkbox plus the approval
  value, then `POST /actions/github-issue/confirm` with
  `{"action_id", "payload_digest"}` and the `X-BlastRadius-Approval` header.
- Only the API's real result is shown. `created: false` (stored result for a repeated
  confirmation) is reported as "no new issue was created", with `reconciled` called
  out when present.
- The full error taxonomy has tailored notices:
  `403 github_write_disabled`, `503 action_authorization_not_configured`,
  `401 action_unauthorized`, `409/410 action_expired` / `action_consumed` /
  `action_evidence_changed` / `action_payload_mismatch`, plus
  `action_in_progress`, `github_write_ambiguous`, `github_permission_denied`,
  `github_credentials_invalid`, `action_repository_not_allowed`,
  `action_repository_invalid`, `action_not_configured` and the envelope fallback.
- Expired/consumed/evidence-changed/digest-mismatch responses **discard the preview**
  and require a new one; an unauthorized attempt keeps the preview but clears the
  typed value. No request is retried automatically.

## 7. Approval security (Screen F)

- `BLASTRADIUS_ACTIONS_GITHUB_TOKEN` and `BLASTRADIUS_ACTIONS_APPROVAL_SECRET` are
  never embedded in frontend code, Vite env vars, the compiled bundle, `localStorage`
  or `sessionStorage`. The bundle was searched for these names and for token
  patterns after the production build — zero matches.
- The only frontend env var is `VITE_API_BASE_URL` (a URL, not a credential).
- The approval value is entered per confirmation in a password field, held in the
  component's memory only, sent once as the `X-BlastRadius-Approval` header, and
  cleared on every settle (success or failure). It is not logged, echoed, cached by
  the query client or persisted.
- **Local-development-only flow:** because the backend may have no server-side
  session/identity integration, this screen asks the operator for the shared
  approval secret at confirmation time. That is acceptable only for a local or
  otherwise trusted single-operator deployment; it must not be exposed as an
  unauthenticated public page in production. A production deployment should put
  authentication/authorization in front of the API (the backend guard and digest
  validation stay exactly as implemented).
- No approval guard, digest check, expiry, evidence re-validation or idempotency
  behaviour is bypassed, weakened or duplicated in the frontend.

## 8. Degraded and unavailable services

| Condition | Backend response | UI behaviour |
|-----------|------------------|--------------|
| FalkorDB unreachable | `/graph/health` `connected: false`; graph endpoints 502 | explicit notices/error states with retry; no fake graph |
| Analysis has no persisted rows | `count: 0` | empty state explaining that the repo screen must persist first |
| Ingest caps hit | `truncated: true` | warning that persisting persists exactly the bounded records |
| No resolved packages | OSV sync `nothing_to_scan` | status shown verbatim; declarations vs resolved explained |
| No LLM provider | `503 agent_not_configured` | tailored notice incl. the server's configuration hint; other screens unaffected |
| Actions disabled | `403 github_write_disabled` | write screen explains the server switch; preview/confirm unavailable |
| Backend down | network error | `network_error` state with the base URL in the message and a retry action |

## 9. Backend additions made in Phase 7 (all additive)

Three additive changes were required to make real contracts usable; nothing else in
the backend changed, and `Settings.phase` is still `phase-4b-agent`.

1. `POST /repositories/ingest` now returns `analysis_id` (derived from repository id
   + commit) so the UI can persist/sync/open without parsing ids from elsewhere.
2. `POST /analyses/{id}/graph` accepts the ingest response body shape (the exact
   object the UI just received) in addition to the previous input.
3. `GET /analyses/{id}/graph` connects lazily like the other graph reads and
   serialises Node/Edge values to JSON-safe objects instead of raw driver rows.
   Row contract: node → `{id, labels, properties}`, edge → `{id, type, src, dst,
   properties}`.

Tests added: `tests/test_persist_roundtrip.py` (6), `tests/test_graph_service.py`
(+3), `tests/test_graph_api.py` (+1). Full backend suite: **920 passed, 15 skipped**.

## 10. Tests and verification

Frontend (from `frontend/`):

```powershell
npm run typecheck     # tsc -b, strict
npm run lint          # eslint
npm run format:check  # prettier
npm test              # vitest run: 53 unit/component tests in 8 files
npm run build         # tsc -b && vite build -> dist/
```

The unit/component tests render the whole application (QueryClientProvider +
MemoryRouter + `App`) against a stubbed `fetch` that returns recorded response
shapes, so every screen is exercised as wired in production. Mocks exist only at
this boundary; they are never presented as integration proof. Covered: repo
validation/submission, loading/error/partial states, declarations vs resolved
packages, findings filter/pagination, adapter node/edge mapping, evidence-path
highlighting incl. endpoints outside the bounded page, empty graph, agent answers
and provider errors, remediation grouping/coverage/unresolved findings, issue
preview + explicit confirmation, confirmation failure, expired preview, duplicate
prevention, unauthorized responses, and storage/DOM checks for the approval value.

Live-backend smoke test (requires the running backend; skipped by default):

```powershell
$env:BLASTRADIUS_FRONTEND_INTEGRATION = "1"
$env:VITE_API_BASE_URL = "http://127.0.0.1:8000"
$env:BLASTRADIUS_TEST_ANALYSIS_ID = "analysis_..."   # optional
npx vitest run src/integration/backend.smoke.test.tsx
```

It drives the frontend's own client + adapter against the real API: analysis status,
bounded graph rows, statistics, packages/edges, advisory matches, blast-radius paths,
ranked findings + detail, remediation groups/candidates (asserting
`resolver_executed: false`) and the Screen C adapter/highlight mapping.

Backend:

```powershell
python -m pytest -q     # 920 passed, 15 skipped (offline baseline preserved)
```

### Verified in this environment

- Production build: `✓ built in ~3 s`; chunks `index` ≈ 351 kB (99 kB gzip),
  `vendor-cytoscape` ≈ 443 kB (142 kB gzip), `vendor-react` ≈ 43 kB,
  `vendor-query` ≈ 44 kB; `npm run preview` serves `dist/` and proxies the API.
- `npm run dev` proxied real calls: `GET /api/v1/graph/health` →
  `{"connected":true,"graph_name":"blastradius",...}`.
- Real Screen A run through the dev proxy with `https://github.com/pypa/sampleproject`:
  resolve → commit `621e4974ca25ce531773def586ba3ed8e736b3fc`, 1 manifest,
  4 declarations, **0 resolved packages** (no lockfile), persist `success`
  (24 nodes created), OSV sync `nothing_to_scan` — honest for that repository,
  and a real exercise of the declarations-vs-resolved distinction.
- Real Screen B/C/E data from `analysis_9ea623c6550a26c0`
  (`github.com/example/demo`): 24 findings; finding detail for
  `finding_06521fcc4033fff1` → 3 candidate versions for `requests`;
  42 modeled impact paths at depth 2; 2 fix groups
  (`urllib3 2.2.1 → 2.8.0` — 17 advisory-confirmed, 1 potential;
  `requests 2.31.0 → 2.33.0` — 6 advisory-confirmed); candidate plans
  `requests` (3 candidates) and `urllib3` (7 candidates).
- Screen D real behaviour without credentials: `503 agent_not_configured` with the
  server message naming `BLASTRADIUS_AGENT_MODEL` / `BLASTRADIUS_AGENT_API_KEY`.
- Screen F real behaviour: `403 github_write_disabled` for both group- and
  finding-based previews, with the server hint `BLASTRADIUS_ACTIONS_ENABLED`; the
  confirmation path is therefore not reachable in this deployment.
- Integration smoke test: 8/8 passed against the live backend.

## 11. Limitations and not-verified-live features

- **No LLM credentials** in this environment: a live grounded answer, tool-call
  trace and provider error from a real model were not exercised. The unconfigured
  path and the UI's handling of each documented agent error code are verified.
- **No GitHub write token / sandbox repository**: live issue creation was not
  executed. The preview/confirm flow, digest binding, error taxonomy, expired-preview
  handling and duplicate-result rendering are verified against the real API and in
  component tests, but "issue actually created on GitHub" is unverified here.
- **No browser automation** was attached to this session, so UI verification was
  performed at the HTTP level (real proxied API calls, real bundle served by
  `npm run preview`, SPA fallback) plus full-app rendering in jsdom. Actual canvas
  painting by Cytoscape relies on the canvas API and is covered by the adapter unit
  tests and the live data checks, not by pixel-level browser assertions.
- **FalkorDB is not managed here** (no `docker` CLI); the running instance at
  `localhost:6379` was used as-is. Its existing data was never cleared.
- The OSV sync for a repository without a lockfile scans zero packages
  (`nothing_to_scan`); live OSV matching was verified against the pre-existing
  analysis whose resolved packages already carry advisories.
- Phase 8 was not started.
