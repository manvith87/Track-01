# BlastRadius Phase 4 — Scope Definition (MCP Server)

**Status:** Phase 4A (read-only MCP server) is **implemented**: `app/mcp/` is wired into the FastAPI application, the eleven tools below are registered, and offline + opt-in live tests cover them. Phase 4B (AI agent) remains scoped but unbuilt.

## 1. Purpose and scope

Phase 4 exposes BlastRadius's existing Phase 1–3 data (dependency graph and OSV vulnerability intelligence) to AI clients through a **Model Context Protocol (MCP) server**. The MCP server is **read-only** in Phase 4A: it surfaces existing graph reads and OSV lookups only. It never writes to FalkorDB, never mutates the FastAPI application, and never calls OSV ingestion endpoints that write graph data.

An **AI agent** (an LLM-backed planner that decides which MCP tools to call and synthesizes answers) is explicitly deferred to a later subphase (Phase 4B). Phase 4A provides the tool surface; Phase 4B would add the planner.

### Guiding principles carried from Phases 1–3

* **No fabricated data.** Every value returned comes from the graph or from OSV exactly as stored/fetched. No severity scores, fixed versions, dependency paths, or vulnerability records are invented.
* **Repository and analysis boundaries.** Every graph result is scoped to a single `repository_id` / `commit_sha` analysis unless the tool is explicitly cross-repository (and documented as such).
* **Read-only.** No tool in Phase 4A performs a graph write, a graph delete, an OSV ingest, or any mutation.
* **No arbitrary Cypher.** Tool inputs are validated arguments; the server builds the Cypher internally using existing, parameterized query templates. Clients cannot supply raw Cypher.

### Out of scope for Phase 4A

* AI agent / LLM planner (deferred to Phase 4B).
* Graph writes (ingestion, vulnerability mirroring, edge creation).
* GitHub repository ingestion (Phase 1 remains the only writer).
* OSV ingestion that writes to the graph (`POST /analyses/{id}/vulnerabilities`) — the MCP server may call the read-only `GET /osv/vulnerabilities` lookup but not the write path.
* Arbitrary Cypher execution.
* Authentication, authorization, or multi-tenancy beyond repository/commit scoping.

## 2. Architecture

### Transport choice: Streamable HTTP

**Recommendation:** MCP over **Streamable HTTP** (`POST` to a single endpoint, with optional SSE for server-to-client messages), served alongside the existing FastAPI application.

#### Trade-offs

| Criterion | stdio | Streamable HTTP |
|-----------|-------|-----------------|
| Fits FastAPI project | Poor — requires a separate stdio process | Excellent — mounts as an additional route on the same FastAPI app |
| Dev workflow (local) | Requires spawning a subprocess; harder to debug with standard HTTP tooling | Direct `curl`/`OpenAPI`-style inspection; works with existing uvicorn dev server |
| Deployment | Needs a process manager that forwards stdio | Works behind any HTTP reverse proxy / load balancer |
| Existing infra | No precedent in codebase | Reuses FastAPI, middleware, logging, request-id, error envelope |
| MCP spec compliance | Fully supported | Fully supported (MCP 2025-06-18+) |
| AI client compatibility | All clients support stdio | Most modern clients support Streamable HTTP |

**Decision:** Streamable HTTP. The project is a FastAPI web service; adding an MCP endpoint under the same process (e.g. `/mcp`) minimizes operational complexity, reuses the existing logging/request-id middleware, and avoids managing a second stdio process. stdio can be added later if a client requires it.

**Transport lifecycle note (implemented):** the MCP Starlette sub-app is mounted at `/mcp` (`streamable_http_app(json_response=True, streamable_http_path="/")`). ASGI only sends the `lifespan` scope to the top-level application — Starlette never dispatches startup/shutdown to a mounted sub-app — so `app/mcp/server.py` exposes `mcp_lifespan`, which runs the SDK's `StreamableHTTPSessionManager` (the `mcp.session_manager` instance created by `mount_mcp`) inside the FastAPI application's lifespan, and cancels it cleanly on shutdown. Without this, every MCP request fails with `Task group is not initialized`.

### Process and network boundaries

* The MCP server runs in the same Python process as the FastAPI app (or as a separate uvicorn worker sharing the same `app` object).
* It instantiates `GraphService(get_graph_client())` and `VulnerabilityGraphService(get_graph_client())` directly — the same seams used by `app/api/deps.py` — so no new data-access code is introduced.
* The OSV read-only lookup (`OsvService.lookup`) is used via `get_osv_service()`. OSV **ingestion/write** (`OsvService.sync`) is NOT exposed.
* All upstream calls (OSV.dev) and FalkorDB queries are subject to the same timeouts, retries, and caps already configured in `OsvSettings` and `GraphSettings`.
* MCP tool execution time is bounded by the existing FalkorDB socket timeouts and by tool-specific `limit` arguments.

### Library recommendation

Python `>=3.11` is required (`pyproject.toml`). Implemented with the official Python MCP SDK: `mcp>=2.0,<3.0` in `requirements.txt` (transitively included by `requirements-dev.txt`) and in `pyproject.toml`. The 2.x series is required because the code imports `mcp.server.mcpserver.MCPServer` (`streamable_http_app` / `session_manager` API), which does not exist in 1.x; the `<3.0` pin guards against breaking changes.

## 3. Proposed MCP tools

Each tool below maps to an existing service method. All are read-only. Argument names and limits mirror the existing FastAPI endpoints so behavior is consistent.

### 3.1 `graph.health`

**Purpose:** Report whether the configured FalkorDB graph is reachable.

**Arguments:** none.

**Validation/limits:** none.

**Existing method:** `GraphClient.ping()` (via `GraphService`), equivalent to `GET /api/v1/graph/health`.

**Output:**
```json
{
  "connected": bool,
  "graph_name": "blastradius",
  "connection": "localhost:6379/0 graph=blastradius",
  "error": null | string
}
```

**Scope:** connection-level (not analysis-scoped).

**Unavailable data:** `connected: false` with `error` set when FalkorDB is unreachable; never raises an unhandled error.

---

### 3.2 `analyses.list`

**Purpose:** List analyses persisted in the graph. (There is no existing "list all analyses" endpoint; this is a new read-only graph query built from existing primitives.)

**Arguments:** none.

**Validation/limits:** none.

**Existing method:** No exact equivalent exists in `GraphService`. This tool requires a new read-only Cypher query: `MATCH (a:Analysis) RETURN a.id, a.repository_id, a.commit_sha, a.status ORDER BY a.created_at SKIP $skip LIMIT $limit`. This is the one tool whose underlying query is not yet a service method; it is flagged as **new read-only query** (no schema change, no write).

**Output:** list of `{ analysis_id, repository_id, commit_sha, status }`.

**Scope:** cross-repository (lists all analyses); each row names its own `repository_id`/`commit_sha`.

**Unavailable data:** empty list when no analyses exist.

> **Note:** If the implementation team prefers to avoid any new query, this tool can be omitted from Phase 4A and marked as future work. All other tools require an `analysis_id` that the caller obtains out-of-band (e.g. from the Phase 1 ingest response or Phase 2 graph endpoint).

---

### 3.3 `analysis.status`

**Purpose:** Return graph ingestion status and incomplete-data indicators for one analysis.

**Arguments:**
* `analysis_id` (string, required) — stable analysis id (`stable_id("analysis", canonical_id, commit_sha)`).

**Validation/limits:** `analysis_id` must be non-empty.

**Existing method:** `GraphService.get_analysis_graph_status(analysis_id)`, equivalent to `GET /api/v1/analyses/{id}/graph/status`.

**Output:** `{ analysis_id, repository_id, commit_sha, status, created_at, updated_at }`.

**Scope:** analysis-scoped (repository/commit boundaries enforced by the query).

**Unavailable data:** raises `GraphRecordNotFoundError` → MCP error response; never returns fake data.

---

### 3.4 `analysis.statistics`

**Purpose:** Return actual node/relationship counts for one analysis.

**Arguments:**
* `analysis_id` (string, required).

**Validation/limits:** `analysis_id` must be non-empty.

**Existing method:** `GraphService.get_graph_statistics(analysis_id)`, equivalent to `GET /api/v1/analyses/{id}/graph/statistics`.

**Output:** `{ repositories, files, manifests, declarations, packages, dependency_edges, resolved_packages, vulnerability_edges }` (counts).

**Scope:** analysis-scoped.

**Unavailable data:** raises `GraphRecordNotFoundError` → MCP error response.

---

### 3.5 `analysis.packages`

**Purpose:** Return package declarations and known resolved versions for one analysis.

**Arguments:**
* `analysis_id` (string, required).
* `skip` (integer, optional, default 0, ge 0).
* `limit` (integer, optional, default 200, ge 1, le 1000).

**Validation/limits:** `analysis_id` non-empty; `skip`/`limit` clamped to the endpoint's existing bounds.

**Existing method:** `GraphService.get_repository_packages(analysis_id, skip, limit)`, equivalent to `GET /api/v1/analyses/{id}/packages`.

**Output:** `{ columns, rows, count, run_time_ms }` where rows carry `package_id`, `package_name`, `package_version`, `ecosystem`, `repository_id`, `commit_sha`, etc.

**Scope:** analysis-scoped.

**Unavailable data:** raises `GraphRecordNotFoundError` → MCP error response; empty `rows` when the analysis has no packages.

---

### 3.6 `analysis.dependency_edges`

**Purpose:** Return lockfile-derived dependency edges for one analysis.

**Arguments:**
* `analysis_id` (string, required).
* `skip` (integer, optional, default 0, ge 0).
* `limit` (integer, optional, default 200, ge 1, le 1000).

**Validation/limits:** as above.

**Existing method:** `GraphService.get_dependency_edges(analysis_id, skip, limit)`, equivalent to `GET /api/v1/analyses/{id}/dependency-edges`.

**Output:** `{ columns, rows, count, run_time_ms }`.

**Scope:** analysis-scoped.

**Unavailable data:** raises `GraphRecordNotFoundError` → MCP error response; empty rows when no edges exist.

---

### 3.7 `package.neighborhood`

**Purpose:** Return a bounded `DEPENDS_ON` neighbourhood of a package (upstream/downstream dependents within `depth` hops).

**Arguments:**
* `package_id` (string, required) — stable package id (`stable_id("pkg", canonical_id, commit_sha, normalized_name, version)`).
* `depth` (integer, optional, default 1, ge 1, le 5).

**Validation/limits:** `package_id` non-empty; `depth` clamped to 1–5.

**Existing method:** `GraphService.get_dependency_neighborhood(package_id, depth)`, equivalent to `GET /api/v1/packages/{id}/neighborhood`.

**Output:** `{ package_id, depth, edges }`.

**Scope:** analysis-scoped implicitly (the package id encodes repository/commit).

**Unavailable data:** empty `edges` when the package is unknown or has no neighbors; never fabricates edges.

---

### 3.8 `analysis.vulnerabilities`

**Purpose:** Return vulnerabilities confirmed for an analysis's resolved packages.

**Arguments:**
* `analysis_id` (string, required).
* `skip` (integer, optional, default 0, ge 0).
* `limit` (integer, optional, default 200, ge 1, le 1000).

**Validation/limits:** `analysis_id` non-empty; `skip`/`limit` clamped.

**Existing method:** `VulnerabilityGraphService.get_analysis_vulnerabilities(analysis_id, skip, limit)`, equivalent to `GET /api/v1/analyses/{id}/vulnerabilities`.

**Output:** list of `{ vulnerability_id, summary, package_id, package_name, package_version, ecosystem, match_type, fixed_versions, aliases, severities, published, modified, last_synced_at }`.

**Scope:** analysis-scoped (only packages in this analysis's repository/commit).

**Unavailable data:** raises `GraphRecordNotFoundError` when the analysis is unknown; empty list when no vulnerabilities are stored for it.

---

### 3.9 `analysis.blast_radius`

**Purpose:** Explainable impact chains from affected packages to downstream dependents (`hop_count == 0` is the affected package itself).

**Arguments:**
* `analysis_id` (string, required).
* `vulnerability_id` (string, optional) — restrict paths to one vulnerability id.
* `depth` (integer, optional, default 3, ge 0, le 5).
* `skip` (integer, optional, default 0, ge 0).
* `limit` (integer, optional, default 200, ge 1, le 1000).

**Validation/limits:** `analysis_id` non-empty; `depth` clamped to 0–5 (matches `MAX_IMPACT_DEPTH`); `skip`/`limit` clamped.

**Existing method:** `VulnerabilityGraphService.get_impact_paths(analysis_id, vulnerability_id, depth, skip, limit)`, equivalent to `GET /api/v1/analyses/{id}/vulnerabilities/blast-radius`.

**Output:** list of `{ vulnerability_id, vulnerability_summary, affected_package_id, affected_package_name, affected_package_version, downstream_chain, hop_count, match_type, fixed_versions }`.

**Scope:** analysis-scoped.

**Unavailable data:** raises `GraphRecordNotFoundError` for unknown analysis; empty rows when no impact paths exist.

---

### 3.10 `vulnerability.get`

**Purpose:** Return one stored OSV vulnerability record exactly as mirrored into the graph.

**Arguments:**
* `vulnerability_id` (string, required) — OSV record id (e.g. `GHSA-...`, `CVE-...`, `PYSEC-...`).

**Validation/limits:** `vulnerability_id` non-empty.

**Existing method:** `VulnerabilityGraphService.get_vulnerability(vulnerability_id)`, equivalent to `GET /api/v1/vulnerabilities/{id}` (record portion only).

**Output:** `{ id, summary, details, aliases, related, published, modified, withdrawn, severities, references, affected_packages, schema_version, source, created_at, updated_at }`.

**Scope:** cross-repository by design — returns the shared OSV record regardless of which analysis recorded it.

**Unavailable data:** raises `GraphRecordNotFoundError` → MCP error response when the id is not stored.

---

### 3.11 `vulnerability.components`

**Purpose:** Return graph components (packages) affected by one vulnerability, across all repositories.

**Arguments:**
* `vulnerability_id` (string, required).
* `skip` (integer, optional, default 0, ge 0).
* `limit` (integer, optional, default 200, ge 1, le 1000).

**Validation/limits:** `vulnerability_id` non-empty; `skip`/`limit` clamped.

**Existing method:** `VulnerabilityGraphService.get_vulnerability_components(vulnerability_id, skip, limit)`, equivalent to the components portion of `GET /api/v1/vulnerabilities/{id}`.

**Output:** list of `{ package_id, package_name, package_version, ecosystem, repository_id, commit_sha, match_type, fixed_versions, last_synced_at }`.

**Scope:** cross-repository by design (documents that rows carry their own `repository_id`/`commit_sha`; callers filter per analysis as needed).

**Unavailable data:** empty list when no components are linked; does not raise merely because no components exist (the vulnerability record itself may still exist — use `vulnerability.get` to check).

---

### 3.12 `osv.lookup` (read-only OSV query)

**Purpose:** Live read-only lookup of vulnerabilities for one package on OSV.dev. No graph writes.

**Arguments:**
* `name` (string, required, min 1, max 200) — package name (PyPI spelling).
* `ecosystem` (string, optional, default "pypi", max 100).
* `version` (string, optional, min 1, max 100) — exact resolved version; omitted means name-level (unconfirmed) lookup.

**Validation/limits:** ecosystem must be a supported OSV ecosystem (currently only `pypi` → `PyPI`); empty name rejected; version omitted → `match_type="name"`, `confirmed=false`.

**Existing method:** `OsvService.lookup(ecosystem, name, version)`, equivalent to `GET /api/v1/osv/vulnerabilities`.

**Output:** `{ ecosystem, upstream_ecosystem, package_name, version, match_type, confirmed, count, vulnerabilities[], errors[] }`.

**Scope:** cross-repository (OSV is a public upstream database; not tied to any analysis).

**Unavailable data:** upstream OSV errors surface as typed MCP errors (502/429/504 envelope equivalent); `count: 0` when no matches; malformed records are skipped and noted in `errors`.

> **Read-only guarantee:** this tool calls `OsvService.lookup` only. It never calls `OsvService.sync` or any graph-write path.

---

### Capabilities intentionally NOT included in Phase 4A

| Capability | Reason | Status |
|------------|--------|--------|
| `analysis.ingest` (write Phase 1 result to graph) | Write operation; out of scope for read-only Phase 4A | Future work |
| `analysis.ingest_vulnerabilities` (OSV sync + graph write) | Write operation | Future work |
| `osv.ingest` | Write operation | Future work |
| `graph.cypher` (arbitrary execution) | Security risk; never exposed | Never (by design) |
| AI agent / planner | Deferred | Phase 4B |
| `analyses.list` | No existing service method; would require a new read-only query | Future work |

## 4. Security and correctness

* **Read-only:** every tool maps to a `read_only=True` graph query or an OSV `lookup`. No `MERGE`/`CREATE`/`DELETE`/`SET` writes are reachable from MCP tools.
* **No arbitrary Cypher:** tool arguments are validated primitives (strings, integers with bounds). The server constructs Cypher internally from existing templates; client input is never interpolated into a query string.
* **No fabricated data:** severities, references, fixed versions, and ranges are echoed exactly as OSV/stored; missing metadata is absent (`null`/empty), never invented. No risk scores are computed.
* **Repository boundaries:** all graph reads are scoped by `repository_id`/`commit_sha` derived from `analysis_id` or `package_id`. The only cross-repository tools (`vulnerability.get`, `vulnerability.components`, `osv.lookup`) are documented as such.
* **Result limits:** every list tool has `skip`/`limit` bounded (default 200, max 1000). `depth` is bounded (max 5). OSV lookup text is truncated per `OsvSettings`.
* **No secrets:** no credentials, tokens, or passwords are returned. `GraphSettings.has_credentials` is never exposed; passwords/usernames are redacted in `connection_label`.
* **Error handling:** `GraphRecordNotFoundError` → MCP "not found" error; `GraphError`/transport failures → MCP error with retryable flag where applicable; upstream OSV failures → typed error (network_failure / rate_limited / invalid_input). MCP never returns a 500 with a stack trace to the client.

## 5. Testing

### 5.1 Offline tests (deterministic, default suite)

* MCP server instantiates with **fake/double services** injected through the same seams as production (`GraphService`, `VulnerabilityGraphService`, `OsvService`): `tests/test_mcp_server.py` exercises each tool directly for happy path, validation errors (bad `analysis_id`, out-of-range `depth`), not-found behavior, empty results, scope boundaries, and read-only guarantees (no write methods called).
* Protocol-level HTTP tests (`tests/test_mcp_http.py`): the real FastAPI app is served by uvicorn on a loopback port in a thread and driven with the official SDK client (`streamable_http_client` + `ClientSession`), verifying the full MCP lifecycle — initialize/negotiate, the required `notifications/initialized` message (sent internally by `ClientSession.initialize`; subsequent requests being served proves the server accepted it), `tools/list` with all eleven documented tool names, `tools/call` with structured results, JSON-RPC error mapping (`MCPError(INVALID_PARAMS)` from tools → protocol error), session DELETE on close plus clean re-initialization, clean app shutdown, and the parent REST API staying reachable. Graph/OSV services are faked via the `app.mcp.tools` seams; no FalkorDB connection and no OSV network request are made.
* SDK contract exercised by these tests: a tool raising `MCPError` (e.g. invalid arguments) is delivered as a JSON-RPC **error** to the client; an unregistered tool answered by the SDK's tool manager surfaces as `CallToolResult(isError=True)` (tool-execution error) rather than a JSON-RPC error.
* In-process `TestClient` notes (verified, not used by the protocol tests — the real loopback HTTP client above is stricter): `TestClient(app)` without entering the context manager never runs the app lifespan, so the session manager is not started and MCP requests raise `RuntimeError: Task group is not initialized`. With `with TestClient(app)` the lifespan runs and MCP works, but requests must carry a `Host` header with an explicit `host:port` matching the SDK's DNS-rebinding allowlist (e.g. `127.0.0.1:8000`); TestClient's default `Host: testserver` is answered `421 Misdirected Request`.
* Tests run with `python -m pytest` and are skipped only by platform limitation (e.g. symlinks on Windows), never by network.

### 5.2 Opt-in live integration tests

* Gated on `BLASTRADIUS_GRAPH_LIVE_TESTS=1` (FalkorDB) and, for OSV, `BLASTRADIUS_OSV_LIVE_TESTS=1`; skipped by default.
* Use **dedicated test graphs** (e.g. `blastradius_mcp_livetest`) via `GraphSettings(graph_name=...)` so cleanup can never delete the default `blastradius` graph or user/demo data.
* Teardown wipes only the dedicated test graph (`MATCH (n) DETACH DELETE n` on that graph name).
* Test data uses unique repository/commit ids distinct from demo ids (`a*40`/`b*40`).
* No containers, volumes, or graph data are deleted outside the dedicated test graph.

## 6. Acceptance criteria

* All Phase 1–3 tests still pass offline (baseline preserved: 529 passed, 9 skipped, 0 failed — the pre-4A baseline; the current full offline suite is 558 passed, 12 skipped, 0 failed).
* New Phase 4 MCP offline tests pass deterministically with no network.
* MCP tools return graph facts only; no invented severities, scores, or vulnerability records.
* Read-only enforcement: no graph-write method is reachable from any MCP tool (verifiable by code review + tests asserting write methods are never invoked).
* `/health` continues to report `graph: true/false` correctly; the FastAPI app's existing routes and behaviors are unchanged (the MCP mount and lifespan wiring are purely additive).
* Documentation (`docs/PHASE4.md`) accurately reflects the implemented tool set.

## 7. Implementation sequence (for reference, not executed now)

1. Add `mcp` SDK to requirements (runtime) and dev requirements (tests).
2. Create `app/mcp/server.py` — MCP Streamable HTTP server mounted on the FastAPI app, exposing the tools above.
3. Add `app/mcp/tools.py` — thin wrappers calling `GraphService`/`VulnerabilityGraphService`/`OsvService`.
4. Add `app/mcp/schemas.py` — input/output Pydantic models for each tool.
5. Write offline tests in `tests/test_mcp_server.py` using fakes.
6. Write opt-in live tests in `tests/test_mcp_live.py` using dedicated graphs.
7. Update `docs/GRAPH_SCHEMA.md` if any new read-only query is added (e.g. `analyses.list`).
8. Link `docs/PHASE4.md` from README.md.

**As implemented (Phase 4A):** steps 1–3, 5–6, 8 done, plus
`tests/test_mcp_http.py` (protocol-level HTTP tests, see §5.1) and the
`mcp_lifespan` session-manager wiring in `app/mcp/server.py` + `app/main.py`
(see the transport lifecycle note in §2). Step 4 was not needed — the tools
return plain JSON-safe dicts validated/narrowed by the existing services, so
no separate `app/mcp/schemas.py` module was required. `analyses.list` was
never added (no new graph query), so `docs/GRAPH_SCHEMA.md` is unchanged.

## 8. Files that would change in implementation (not now)

* `requirements.txt`, `requirements-dev.txt` — add `mcp` SDK.
* `app/mcp/` — new package (server, tools, schemas).
* `app/main.py` — mount MCP route (optional; could be a separate entrypoint).
* `tests/test_mcp_server.py`, `tests/test_mcp_live.py` — new tests.
* `docs/PHASE4.md` — this document.
* `README.md` — link to `docs/PHASE4.md` (optional).

**As changed (Phase 4A):** `requirements.txt` (`mcp>=2.0,<3.0`),
`app/mcp/` (server + tools only — no `schemas.py` needed), `app/main.py`
(mount + lifespan), `app/graph/queries.py` (`neighborhood_template(depth)`
builder), `app/graph/service.py` (missing-import fix + neighborhood params),
`tests/test_mcp_server.py`, `tests/test_mcp_live.py`,
`tests/test_mcp_http.py`, this document, `README.md`.

## 9. Explicitly preserved (unchanged in Phase 4)

* `app/main.py` FastAPI application and all existing routes (the MCP mount and `lifespan` argument are additions, not route changes).
* `app/api/v1/` routers (`repositories.py`, `graph.py`, `vulnerabilities.py`).
* `app/graph/service.py`, `app/graph/queries.py`, `app/graph/schemas.py` — one exception, behavior-preserving read-path fixes made while wiring the MCP tools (no schema change, no API change): `queries.py` replaced the constant `GET_NEIGHBORHOOD` with the `neighborhood_template(depth)` builder (parameterized `$depth` is rejected by FalkorDB inside variable-length patterns, so `1<=depth<=5` is validated and only the integer is inlined), and `service.py` gained the missing `DependencyRelation` import plus matching parameter narrowing. The `docs/GRAPH_SCHEMA.md` neighbourhood example stays a fixed illustration; the implementation validates and inlines the requested depth.
* `app/osv/` — client, config, errors, models, service.
* `app/models/`, `app/ingestion/`, `app/core/`.
* Graph schema (nodes, relationships, properties) in `docs/GRAPH_SCHEMA.md`.
* All existing tests and test counts (Phase 4 additions only ever add new test modules).
* FalkorDB configuration, containers, volumes, and graph data.
