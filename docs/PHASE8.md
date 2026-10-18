# Phase 8 — End-to-End Verification, Deployment Readiness & Submission

Phase 8 adds no product behaviour. It proves the existing system end to end on a
real stack, fixes the genuine defects that verification surfaced, and packages
the result for deployment and demo.

Every claim in this document is labelled:

* **verified live** — executed against the real stack in this environment
  (FalkorDB + backend + built frontend, with real GitHub and OSV.dev traffic);
* **verified offline** — covered by the deterministic test suite only;
* **not verified / blocked** — could not be executed here, with the exact reason
  and the environment/command needed to finish it elsewhere.

Verified environment: Windows 11 · Python 3.13.2 · Node v26.5.0 / npm 11.17.0 ·
FalkorDB on Redis base 8.10.2 · falkordb 1.7.1 · FastAPI 0.141.1 ·
uvicorn 0.52.4 · pydantic 2.13.4 · httpx 0.28.1 · mcp 2.3.0.

Verification ran against a dedicated graph
(`BLASTRADIUS_GRAPH_NAME=blastradius_phase8_verify`) with the default graph name
left untouched. Live opt-in suites use their own scratch graphs
(`blastradius_livetest`, `blastradius_osv_livetest`, `blastradius_mcp_livetest`).

---

## 1. Scope and outcome

| Area | Result |
|---|---|
| Full workflow on two repositories (no-lockfile + lockfile) | **verified live** |
| Graph records vs ingestion output (reconciliation) | **verified live**, exact |
| Cross-analysis node isolation | **verified live**, zero overlap |
| OSV sync → findings → evidence → impact paths | **verified live** (88 advisories, 90 findings, 50 paths) |
| Priorities and remediation groups | **verified live** (14 groups, 14 candidate plans) |
| AI agent question endpoint | 503 unconfigured path **verified live**; real LLM answer **blocked** (no credentials) |
| GitHub issue preview/confirm safeguards | **verified live** up to the read-only preflight; real issue write **blocked** (no token/repo) |
| Real-browser end-to-end UI | **verified live** (Microsoft Edge, built bundle, proxied API) |
| Deployment artifacts (Dockerfile, Compose, nginx) | authored, **not executable here** (no Docker CLI) |
| Docs, demo script, security review | this document + README Phase 8 section |

## 2. Architecture as verified

```
browser ── vite preview :4173 ──proxy /api,/health──► FastAPI :8000/:8010 ──► FalkorDB :6379
   │                                                        │
   │ same origin (no CORS)                                  ├─► api.github.com  (metadata, read)
   │                                                        ├─► api.osv.dev     (advisory lookups)
   │                                                        ├─► LLM provider   (optional, agent only)
   └─ MCP streamable HTTP  http://127.0.0.1:8000/mcp/  ◄────┤
                                                            └─► SQLite action store (Phase 6 audit)
```

| Component | Where | Notes |
|---|---|---|
| FalkorDB | `localhost:6379` | dependency graph; derived data, rebuildable from ingestion |
| Backend (REST + MCP) | `127.0.0.1:8000` (verification used `:8010`) | one FastAPI app; MCP mounted at `/mcp/` |
| Frontend | `npm run dev` `:5173` / `npm run preview` `:4173` | proxies `/api` + `/health` to `BLASTRADIUS_BACKEND_URL` |
| Frontend (container) | nginx `:80`, published as `:8080` | serves the built SPA, proxies the same paths |
| Action store | `BLASTRADIUS_ACTIONS_STORE_PATH` (SQLite) | confirmations, digests, idempotency, results |
| Retrieval workspace | OS temp dir | per-request clone/extract, ephemeral |

Writers/readers: only the backend touches FalkorDB and the action store. The
browser holds no token; it sends the operator approval secret once per
confirmation and never stores it.

### Statistics semantics (as returned by `GET /graph/statistics`)

| Field | Meaning |
|---|---|
| `files` / `manifests` / `declarations` | analysis-scoped `SourceFile` / `DependencyManifest` / `DependencyDeclaration` nodes |
| `packages` | `Package` nodes for the analysis's repository+commit **that carry a version** (unresolved placeholder packages are excluded) |
| `dependency_edges` | `DEPENDS_ON` relationships between those package nodes |
| `resolved_packages` | distinct packages referenced by `RESOLVES_TO` from a declaration |
| `vulnerability_edges` | `AFFECTED_BY` package→advisory edges |

## 3. Environment variables

Placeholders only; the canonical, commented list is `.env.example`. Secrets are
never committed, logged, or returned.

| Prefix | Key variables | Purpose |
|---|---|---|
| `BLASTRADIUS_LOG_*` | `LOG_LEVEL`, `LOG_JSON` | logging |
| `BLASTRADIUS_RETRIEVAL_*`, `BLASTRADIUS_MAX_*` | strategy, timeouts, byte/file/dependency caps | ingestion limits |
| `BLASTRADIUS_API_*` | `API_PREFIX`, `MAX_API_RECORDS` | REST surface |
| `BLASTRADIUS_GRAPH_*` | `GRAPH_HOST`, `GRAPH_PORT`, `GRAPH_NAME`, `GRAPH_SOCKET_TIMEOUT_SECONDS` | FalkorDB target |
| `BLASTRADIUS_OSV_*` | base URL, timeout, batch size | OSV.dev client |
| `BLASTRADIUS_AGENT_*` | `AGENT_MODEL`, `AGENT_API_KEY` (or `OPENAI_API_KEY`), `AGENT_BASE_URL`, `AGENT_MCP_URL`, timeouts/round caps | optional LLM agent |
| `BLASTRADIUS_ACTIONS_*` | `ACTIONS_ENABLED`, `ACTIONS_GITHUB_TOKEN`, `ACTIONS_APPROVAL_SECRET`, `ACTIONS_REPOSITORY_ALLOWLIST`, `ACTIONS_STORE_PATH`, `ACTIONS_PREVIEW_TTL_*` | Phase 6 write flow (off by default) |
| `BLASTRADIUS_BACKEND_URL` | proxy target | frontend dev/preview only |

## 4. How to run

### 4.1 Local path (verified live)

```powershell
# 1. FalkorDB (existing local instance used for verification)
docker run -d -p 6379:6379 falkordb/falkordb      # or any reachable FalkorDB

# 2. backend
python -m pip install -r requirements.txt
$env:BLASTRADIUS_GRAPH_NAME = "blastradius"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 3. frontend (production build served by the preview server)
cd frontend
npm ci
npm run build
$env:BLASTRADIUS_BACKEND_URL = "http://127.0.0.1:8000"
npm run preview -- --port 4173        # http://localhost:4173
```

Optional write enablement (only with a dedicated token and an authorized repo):

```powershell
$env:BLASTRADIUS_ACTIONS_ENABLED        = "true"
$env:BLASTRADIUS_ACTIONS_GITHUB_TOKEN   = "<fine-grained token, Issues: write>"
$env:BLASTRADIUS_ACTIONS_APPROVAL_SECRET= "<operator confirmation secret>"
$env:BLASTRADIUS_ACTIONS_REPOSITORY_ALLOWLIST = "owner/repo"
```

### 4.2 Docker Compose path (authored, **not verified** — no Docker CLI here)

```bash
cp .env.example .env       # set graph name and any optional credentials
docker compose up --build
# frontend http://localhost:8080 · API http://localhost:8000/api/v1 · MCP /mcp/
```

Artifacts: `Dockerfile`, `.dockerignore`, `frontend/Dockerfile`,
`frontend/nginx.conf`, `docker-compose.yml`. FalkorDB is **not published** to
the host (backend-only reachability); the action store lives on a named volume.

### 4.3 Health checks

| Check | Command |
|---|---|
| backend | `GET /health` → `{"status":"ok", ...}` (used by Compose healthcheck) |
| graph | `GET /api/v1/graph/health` (also exposed as the MCP `graph.health` tool) |
| FalkorDB | `redis-cli ping` (Compose healthcheck) |
| frontend | `GET /` (nginx healthcheck) |

## 5. Verification performed

### 5.1 End-to-end workflow — two repositories (verified live)

Run through the real REST API (workflow probe: ingest → persist → statistics →
OSV sync → findings → impact paths → groups → agent → issue preview).

**A. `github.com/pypa/sampleproject` @ `621e4974ca25ce531773def586ba3ed8e736b3fc`** (no lockfile)

| Step | Result |
|---|---|
| ingest | 200 in 2.8 s · files 12 · manifests 1/1 · declarations 4 · resolved 0 · edges 0 · status `success` |
| persist | 24 records · 24 nodes · 24 relationships |
| statistics | files 12 · manifests 1 · declarations 4 · packages 0 · edges 0 · vulnerability_edges 0 |
| OSV sync | `nothing_to_scan` (no versioned packages) |
| findings / impact paths / groups | 0 / 0 / 0 (consistent with an empty stale-free graph) |
| agent question | **503 `agent_not_configured`** (no LLM credentials) |
| issue preview | **403 `github_write_disabled`** (kill switch off) |

**B. `github.com/python-poetry/poetry` @ `539d7f732c34c821258a9853cd3078cbda34a717`** (poetry.lock)

| Step | Result |
|---|---|
| ingest | 200 in 5.5 s · files examined 473 (200 reported) · manifests 49 detected / 30 parsed / 19 skipped · declarations 115 · resolved 83 · edges 121 · warnings 38 · status `partial` |
| persist | 500 records · 500 nodes · 659 relationships |
| statistics | files 200 · manifests 49 · declarations 115 · **packages 83** · **dependency_edges 121** · resolved_packages 31 |
| OSV sync | `completed` · 83 scanned · 14 with matches · **88 vulnerabilities** · 88 created · **90 advisory edges** |
| findings | **90** total; finding detail 200 |
| impact paths | **50** modeled paths at depth 2 |
| remediation | **14 fix groups**; 14 candidate plans; group detail 200 |
| agent question | 503 `agent_not_configured` |
| issue preview | 403 `github_write_disabled` |

Note: during browser verification the operator also ingested their own
repository (`github.com/manvith87/blink-courses`, `partial`) into the
verification graph from the running UI. That subgraph was left untouched.

### 5.2 Graph reconciliation (verified live)

Every node kind written by persistence was compared against the ingestion
report for the same analysis.

| Analysis | Manifests | Declarations | Files | Edges | Missing / extra |
|---|---|---|---|---|---|
| sampleproject | 1 / 1 | 4 / 4 (0 dup) | 12 / 12 | 0 / 0 | 0 / 0 (4 version-less package placeholders excluded from the count) |
| poetry | 49 / 49 | 115 / 115 (0 dup) | 200 / 200 | 121 / 121 | 0 / 0 (50 version-less placeholders) |

* Cross-analysis overlap for manifest, declaration, file and package nodes: **0**.
* Phase 1 parser ids are never reused as graph node ids (**0**); the shared
  graph holds 119 distinct declaration nodes (115 + 4).
* The former collision id (`man_f2bd9ae079b54e9d`, path-scoped) is **absent**.
* Repository nodes carry their write identity (`owner`, `name`, `host`,
  `canonical_url`, `clone_url`, `api_url`, `commit_sha`), verified by query and
  by the `action_repository_invalid` preview defect disappearing.

### 5.3 Defects found by Phase 8 verification and fixed

| # | Defect | Fix | Regression test |
|---|---|---|---|
| 1 | `GET /graph/statistics` (and other read queries) timed out with 504 on a real graph (cartesian `OPTIONAL MATCH` chain) | rewrote with `WITH` boundaries | graph suites |
| 2 | `_detect_conflicts` crashed sorting `None` values | `None`-safe ordering | offline suite |
| 3 | Unhandled exceptions escaped the structured error envelope | catch-all `internal_error` envelope | offline suite |
| 4 | MCP `graph.health` used a stale settings path | routed through `_graph_services()` | offline suite |
| 5 | Read-only queries failed against a not-yet-created graph | settings accessor + RO retry | `test_get_repository_graph_connects_a_not_yet_connected_client` |
| 6 | Cross-analysis id collision: manifests/declarations were path-scoped, two analyses of the same path merged (manifests 48/49, declarations 119/115) | graph layer now always derives analysis-scoped ids | `test_manifest_and_declaration_nodes_are_scoped_to_the_analysis` |
| 7 | Two `DEPENDS_ON` variants of one conditional dependency were merged into one edge (121 → 120) | `variant_key` discriminator joins the relationship `MERGE` pattern | `test_conditional_dependency_variants_are_kept_separate` |
| 8 | Repository nodes lacked identity properties → issue preview failed with `409 action_repository_invalid` | merge nested `repository.identity` with top-level metadata | `test_repository_node_carries_its_write_identity` |
| 9 | Browser requested `/favicon.ico` → 404 on every page load | inline SVG icon in `index.html` (+ rebuild) | — (verified by re-run: no 404) |

No assertion was weakened and no failing test was converted to a skip.

### 5.4 GitHub action safeguards (verified live, no real write possible)

Backend on `:8020` with `ACTIONS_ENABLED=true`, a deliberately invalid local
token (placeholder, never a real credential), a local confirmation secret, an
allowlist of `python-poetry/poetry`, and a dedicated store. 9 requests:

| # | Request | Response |
|---|---|---|
| 1 | preview, allowlisted repo, invalid token | **503 `github_credentials_invalid`** (read-only preflight rejected) |
| 2 | preview, non-allowlisted repo | **403 `action_repository_not_allowed`** |
| 3 | confirm, no approval header | **401 `action_unauthorized`** |
| 4 | confirm, wrong secret | **401 `action_unauthorized`** |
| 5 | confirm, correct secret, unknown action | **404 `action_not_found`** |
| 6 | confirm, correct secret, wrong payload digest | **409 `action_payload_mismatch`** — state stays `PREVIEWED` |
| 7 | confirm, wrong secret, real seeded action | **401** — state stays `PREVIEWED` |
| 8 | confirm, correct secret, invalid token | **503 `github_credentials_invalid`** from the `_revalidate` preflight — state stays `PREVIEWED`, no issue created |

Outbound-call evidence from the server log: **exactly 2** GitHub requests for
all 9 calls (two `GET /repos/python-poetry/poetry → 401`, the two intended
preflights). Requests 3–7 triggered **zero** network calls — approval and digest
failures are rejected before any GitHub contact.

Misconfiguration modes:

| Deployment | Request | Response |
|---|---|---|
| enabled + token, **no confirmation secret** | confirm (with or without header) | **503 `action_authorization_not_configured`** |
| enabled, **no token** | preview and confirm | **503 `action_not_configured`** |

The live issue-creation test (`tests/test_actions_live.py`) remains unexecuted:
it requires an explicitly authorized sandbox repository plus
`BLASTRADIUS_ACTIONS_LIVE_CREATE=1` and real credentials — none exist here.

### 5.5 Real-browser verification (verified live)

Microsoft Edge driven by `playwright-core` (system channel, headless) against
the **built** bundle served by `npm run preview` proxying to the live backend.
Nine steps, all passed:

| Step | Evidence observed in the browser |
|---|---|
| landing | Screen A renders; ingest form present |
| ingest (UI) | `github.com/pypa/sampleproject` → success result rendered |
| persist (UI) | “Persisted (status: success)” |
| open analysis | routed to `/analysis/analysis_d4eded78aabc679f/findings` |
| findings (poetry) | real findings rendered (`zipp` visible, “Incomplete analysis” warning badge) |
| graph explorer | Cytoscape canvas rendered: **“Rendering 344 of 344 loaded nodes and 428 relationships”** |
| remediation | real groups rendered (`cryptography`, `urllib3`) |
| AI analyst | question submitted → UI shows the real agent-unconfigured message (503 path) |
| GitHub issue | selected group #1 `cryptography 3.1.1 → 49.0.0` → “Prepare preview” → UI shows the write-disabled error (403 path) |

Console: the only failed requests are the two intentional API outcomes above
(503 ask, 403 preview). A `/favicon.ico` 404 found in the first pass was fixed
(defect #9) and the re-run is clean. Nine screenshots and a JSON observation
file were captured (see §10).

### 5.6 Test suites

| Suite | Result |
|---|---|
| Python offline (`python -m pytest`, default) | **928 passed, 15 skipped** |
| Python live opt-in (`BLASTRADIUS_GRAPH_LIVE_TESTS=1 BLASTRADIUS_OSV_LIVE_TESTS=1 BLASTRADIUS_RUN_LIVE_TESTS=1`) | **11 passed** (4 graph integration, 3 OSV, 3 MCP, 1 read-only GitHub) in 22.4 s |
| Frontend (`npm --prefix frontend test -- --run`) | **53 passed, 8 skipped** (8 files passed, 1 skipped: the live-backend smoke file) |
| Action safeguard probes | 9/9 expected outcomes + 2/2 misconfiguration modes (§5.4) |

## 6. Deployment readiness

**Artifacts** — `Dockerfile` (python:3.13-slim, non-root user, git for the auto
retrieval strategy, `/health` HEALTHCHECK, action store on a volume),
`frontend/Dockerfile` (node build → nginx serve), `frontend/nginx.conf`
(SPA + `/api` + `/health` + `/mcp/` proxy, long timeouts for ingestion/OSV),
`docker-compose.yml` (falkordb + backend + frontend, only 8000/8080 published),
`.dockerignore`. **Not executed here** (no Docker CLI) — treat as reviewed but
unproven until built once.

**Persistence** — the graph is derived data: it can always be rebuilt by
re-ingesting + re-persisting (idempotent writers). The non-derived state is the
Phase 6 action store (confirmation audit + idempotency). Compose keeps it in the
`blastradius-actions` volume; FalkorDB data lives in `falkordb-data`.

**Backup / recovery**

1. Action store: copy the SQLite file (or snapshot the volume) — small and
   audit-relevant.
2. Graph: copy the FalkorDB data volume for a fast restore, or rebuild by
   replaying ingestion per analysis; no backup is *required* for correctness.
3. Recovery drill: stop backend → restore volume/file → start backend →
   `GET /health`, `GET /api/v1/graph/health`, re-run reconcile per analysis.

**Restricted exposure** — FalkorDB is not published to the host in Compose;
only the backend can reach it. The MCP endpoint is read-only (16 tools, no
write tool). The action token never reaches the browser.

**Secret hygiene (verified)** — no token/secret string appears in the
repository, the SPA bundle, the server logs, or the reports; `.env` is
gitignored (`!.env.example`); action settings hold secrets as `SecretStr`;
`GET` responses and error envelopes never echo credentials.

## 7. Limits, unverified features, blockers

| Item | Status | Reason | How to finish |
|---|---|---|---|
| Live LLM answer | **blocked** | no provider credentials | set `BLASTRADIUS_AGENT_MODEL` + `BLASTRADIUS_AGENT_API_KEY` (or `OPENAI_API_KEY`); then `POST /analyses/{id}/ask` or the Analyst screen; opt-in test `tests/test_agent_live.py` (`BLASTRADIUS_AGENT_LIVE_TESTS=1`) |
| Real GitHub issue creation | **blocked** | no write token / authorized sandbox repo | enable the four `BLASTRADIUS_ACTIONS_*` variables (§4.1) and confirm a preview against the allowlisted repo; opt-in test `tests/test_actions_live.py` (`BLASTRADIUS_ACTIONS_LIVE_CREATE=1`) |
| Docker Compose build/run | **blocked** | no Docker CLI in this environment | `docker compose up --build` on a Docker-capable machine; then re-run §5.1 through `:8080` |
| Pre-fix nodes in the default `blastradius` graph | known state | analyses persisted before the Phase 8 id/identity fixes keep path-scoped manifest ids and identity-less Repository nodes | re-ingest into a fresh graph, or remove that analysis subgraph and re-persist (derived data; operator decision — the shared graph was intentionally not modified) |
| API authentication | by design absent | the app is a local/operator tool | deploy behind an authenticating reverse proxy with TLS and network restrictions |
| Approval-secret entry flow | local-development-only | secret typed per confirmation, memory-only | production needs an authenticated operator UI / secret manager |
| Ingestion is synchronous and single-process; action store is single-host SQLite | known limit | no job queue by design | scale by adding a queue + shared store (out of scope) |
| Phase 1 parser limits | documented | `setup.py`/`setup.cfg` deliberately unparsed; messy fixtures can emit duplicate declaration ids; reported source files capped (200) | see README “Supported formats” / “Limitations” |
| `Settings.phase` string | unchanged | remains `phase-4b-agent` (phases 5–8 added no breaking API version) | — |

## 8. Security review (Phase 8)

Threat model in one line: everything is read-only except one deliberately
guarded external write (a GitHub issue), and the graph/action stores are only
reachable from the backend.

Checked and holding:

* **Kill switch** — every action endpoint and the MCP surface refuse without
  `BLASTRADIUS_ACTIONS_ENABLED=true`; the default deployment answers
  `403 github_write_disabled` (observed live).
* **Allowlist** — repositories outside `ACTIONS_REPOSITORY_ALLOWLIST` are
  rejected before any GitHub call (observed live).
* **Approval** — the confirmation secret is compared in constant time; missing
  or wrong values return `401` before store lookup, digest check, or network
  (observed live; store state unchanged).
* **Payload binding** — confirmations must present the exact digest of the
  stored preview; mismatches return `409` and never mutate state (observed live).
* **Revalidation** — before reserving an action the backend re-reads the target
  from GitHub with a read-only preflight; a failing preflight aborts with
  `503 github_credentials_invalid` and the action stays `PREVIEWED` (observed
  live — the write path was unreachable, which is the correct failure mode).
* **Idempotency** — confirmation reservation happens after all guard checks, so
  failed attempts cannot burn an action; a repeated successful confirmation
  would return the stored result (`created: false`).
* **Secret handling** — no token/approval value in logs, error envelopes, the
  SPA bundle, or the working tree (greps in §6); the SPA sends the secret once
  per confirm and clears it on settle (frontend test:
  “never exposes the approval secret in the DOM after a rejected attempt”).
* **MCP** — read-only tools only (no write tool exists); the graph health tool
  reports connectivity without exposing credentials.
* **Graph exposure** — Compose keeps FalkorDB off the host network; queries are
  parameterized and analysis-scoped; unknown ids answer 404, not full scans.

Residual risks (accepted, documented): no built-in API auth; single-host state;
the demo profile of the graph accepts unbounded analysis ids (parameterized,
validated against the store). Nothing in Phase 8 weakened a guard.

## 9. Demo script (hackathon, ~5 minutes)

1. **Start** (once): FalkorDB → `uvicorn app.main:app --port 8000` →
   `npm run preview` in `frontend/` with `BLASTRADIUS_BACKEND_URL`.
2. **Screen A** — `http://localhost:4173`: run ingestion for
   `https://github.com/python-poetry/poetry` (or `psf/requests`, or your own
   repo). Show the real summary: 473 files examined, 49 manifests, 115
   declarations, 83 resolved packages, 121 dependency edges, 38 warnings.
3. **Persist** the analysis to the graph, then press **Persist** again — the
   counts do not change (idempotent writers). Show `/graph/statistics`.
4. **OSV sync** — one click: 83 packages scanned → 88 advisories → 90 graph
   edges. Open **Findings**: 90 ranked findings; open one to show the evidence,
   affected ranges and modeled reachability.
5. **Graph explorer** — show the bounded slice rendering (“Rendering 344 of 344
   loaded nodes…”), highlight server-reported impact paths (50 paths at depth 2),
   expand a package neighborhood. Stress: reachability is computed by the
   backend, never in the browser.
6. **Remediation** — 14 fix groups with coverage (`confirmed_advisory` vs
   potential) and compatibility; drill into group #1
   (`cryptography 3.1.1 → 49.0.0`).
7. **AI analyst** — ask “Which advisories affect packages with a modeled path
   from an entry point?”. Without provider credentials the answer is the honest
   `503 agent_not_configured` message — the demo point is that the system never
   fabricates an answer.
8. **Approved issue** — select the group, press **Prepare preview**. With the
   kill switch off you get `403 github_write_disabled`; with the four
   `BLASTRADIUS_ACTIONS_*` variables set you show the exact server-composed
   issue, the payload digest, and the two-step confirmation. Close with the
   safeguard list from §5.4.

Honesty notes for the demo: advisory severity and BlastRadius priority are
always shown separately; “no modeled path” is never “safe”; potential
remediation is never “confirmed fix”.

## 10. Evidence index

| Artifact | Location |
|---|---|
| Workflow probe + results | `%TEMP%\opencode\phase8_workflow.py`, `phase8_*.json`, `phase8_workflow_results.json` |
| Reconciliation probe | `%TEMP%\opencode\reconcile_graph_v2.py` (console output quoted in §5.2) |
| Action safeguard probes + results | `%TEMP%\opencode\phase8_actions_check.py`, `phase8_actions_results.json`, `phase8_actions_config_checks.py`, `phase8_actions_config_*.json` |
| Browser drive script + observations | `%TEMP%\opencode\pw\phase8_browser_check.cjs`, `%TEMP%\opencode\phase8_shots\phase8_browser_results.json` |
| Browser screenshots (9) | `%TEMP%\opencode\phase8_shots\01_landing.png` … `09_issue.png` |
| Test tallies | §5.6 (commands included) |

## 11. Submission checklist

* [x] End-to-end workflow verified on two real repositories
* [x] Graph reconciliation exact; cross-analysis isolation proven
* [x] Defects found by verification fixed with regression tests
* [x] Action safeguards verified without exposing or weakening anything
* [x] Real-browser verification of the built frontend
* [x] Deployment artifacts authored (Compose path unverified: no Docker here)
* [x] README + `.env.example` + this document updated
* [ ] Live LLM answer and live GitHub issue creation — blocked by credentials,
      exact resume steps in §7
