# BlastRadius Phase 4B — Evidence-Grounded AI Agent (Implementation Record)

Status: **implemented and tested offline** (live LLM execution NOT tested — no
provider credentials exist in this environment; see §9).

Phase 4A is complete and unchanged: the mounted read-only MCP server
(`/mcp/`, 11 tools, Streamable HTTP) was already verified end-to-end with an
independent MCP client.  Phase 4B builds *on top of* that surface; it does
not rebuild, duplicate or bypass it.

## 1. Purpose and scope

Phase 4B adds a security-question answering agent:

* `POST /api/v1/analyses/{analysis_id}/ask` accepts a security question about
  one ingested analysis and returns a structured, evidence-grounded answer.

The agent:

1. discovers the callable tool schemas from the **real** MCP server via
   `tools/list` (no duplicated tool registry);
2. sends the question, the analysis context and the discovered schemas to one
   configurable LLM provider supporting tool/function calling;
3. validates every model-requested tool call before execution;
4. executes permitted calls through an MCP client (official Python SDK) and
   feeds the **actual** results back;
5. repeats under strict round/latency/size budgets;
6. returns an answer that passed a deterministic grounding check over the
   collected evidence.

### Supported question shapes

* What vulnerabilities are associated with this analysis?
* Explain the evidence behind this finding.
* Which components appear in the reported impact paths?
* What is the dependency neighborhood of this package?
* What information is missing from the analysis?
* Look up this advisory/package using OSV.

### Explicitly out of scope for Phase 4B

* risk scoring, remediation planning, scheduled refresh;
* GitHub actions, frontend work;
* graph writes, OSV ingestion, arbitrary Cypher, shell/repository execution;
* multi-provider matrix (exactly one dialect is implemented, §3.1);
* autonomous background execution (the agent runs only inside one request).

## 2. Architecture

```
client ── POST /api/v1/analyses/{id}/ask ──┐
                                           ▼
                              app/api/v1/agent.py  (route, pre-flight 404,
                                           │        error envelope, response model)
                                           ▼
                              app/agent/agent.py   (BlastAgent: bounded loop)
             ┌─────────────────────────────┼──────────────────────────────┐
             ▼                             ▼                              ▼
   app/agent/provider.py          app/agent/mcp_client.py        app/agent/evidence.py
   (LLM adapter; httpx;           (official MCP SDK;             (tool-call records,
    OpenAI-compatible Chat         tools/list + tools/call)       evidence refs,
    Completions + tool calls)             │                       grounding scanner)
                                          ▼
                              the Phase 4A MCP server at
                              BLASTRADIUS_AGENT_MCP_URL (default
                              http://127.0.0.1:8000/mcp/) — same process
                              or any reachable deployment
```

Files:

| File | Responsibility |
|------|----------------|
| `app/agent/config.py` | `AgentSettings` (`BLASTRADIUS_AGENT_*`), provider dialect, limits |
| `app/agent/errors.py` | `AgentError` hierarchy riding the shared error envelope |
| `app/agent/provider.py` | `LLMProvider` interface + `OpenAICompatProvider` + `build_provider` |
| `app/agent/mcp_client.py` | `MCPToolClient`: Streamable HTTP session, discovery, execution, result capping |
| `app/agent/evidence.py` | `ToolCallRecord`, `EvidenceReference`, `AgentResult`, grounding scanner |
| `app/agent/agent.py` | `BlastAgent.ask()` / `ask_sync()`: the bounded loop |
| `app/api/v1/agent.py`, `agent_schemas.py` | FastAPI endpoint, request/response models |
| `app/api/deps.py` | `get_agent()` dependency (overridable in tests) |

Reuse: graph/OSV facts flow exclusively through the existing Phase 4A MCP
tools, which call the existing `GraphService` / `VulnerabilityGraphService` /
`OsvService` interfaces.  Nothing in Phase 4B touches FalkorDB, OSV or GitHub
directly.

### 2.1 Process model

The route is a sync `def` handler (existing repo convention): FastAPI runs it
in the threadpool, and `BlastAgent.ask_sync()` runs its own event loop
(`asyncio.run`) for the MCP client.  When the agent's `MCP_URL` points at the
same uvicorn process (the default), the agent simply opens a second loopback
HTTP connection to the mounted `/mcp/` endpoint — verified in
`tests/test_agent_integration.py`.  Deployments on a different port or host
set `BLASTRADIUS_AGENT_MCP_URL` accordingly.

## 3. Provider configuration

One configurable provider is implemented: **`openai-compat`** — the OpenAI
Chat Completions API with function calling, usable against OpenAI or any
OpenAI-compatible endpoint (Azure OpenAI gateways, OpenRouter, Groq, vLLM,
LM Studio, Ollama's OpenAI-compatible server, ...) by changing `BASE_URL`.
It uses `httpx` directly (no new dependency) with injectable transports for
deterministic tests, mirroring `app/osv/client.py`.

| Variable | Default | Notes |
|----------|---------|-------|
| `BLASTRADIUS_AGENT_PROVIDER` | `openai-compat` | only supported dialect |
| `BLASTRADIUS_AGENT_MODEL` | *(required)* | empty ⇒ `agent_not_configured` |
| `BLASTRADIUS_AGENT_API_KEY` | *(empty)* | falls back to `OPENAI_API_KEY`; `SecretStr`, never logged/returned |
| `BLASTRADIUS_AGENT_BASE_URL` | `https://api.openai.com/v1` | http(s) absolute URL |
| `BLASTRADIUS_AGENT_MCP_URL` | `http://127.0.0.1:8000/mcp/` | agent → MCP endpoint |
| `BLASTRADIUS_AGENT_TIMEOUT_SECONDS` | `60` | overall per-question budget |
| `BLASTRADIUS_AGENT_PROVIDER_TIMEOUT_SECONDS` | `30` | per provider call |
| `BLASTRADIUS_AGENT_MAX_ROUNDS` | `4` | 1–8 |
| `BLASTRADIUS_AGENT_MAX_TOOL_CALLS_PER_ROUND` | `4` | 1–8 |
| `BLASTRADIUS_AGENT_MAX_QUESTION_CHARS` | `1000` | enforced again in the loop |
| `BLASTRADIUS_AGENT_MAX_TOOL_RESULT_CHARS` | `20000` | per MCP result |
| `BLASTRADIUS_AGENT_MAX_EVIDENCE_CHARS` | `120000` | total evidence budget |
| `BLASTRADIUS_AGENT_MAX_OUTPUT_CHARS` | `8000` | final answer truncation |
| `BLASTRADIUS_AGENT_STRICT_GROUNDING` | `true` | withhold vs flag ungrounded answers |

Malformed numeric/boolean env values fail fast with a `ValueError` naming the
variable (existing repo convention).  With no credentials configured the
endpoint returns `503 agent_not_configured` **before** opening MCP.

## 4. The bounded agent loop

```
ask(question, analysis_id, max_rounds?) ->
  validate question (non-empty, <= max_question_chars)
  build provider            (AgentNotConfiguredError if unconfigured)
  connect MCP + discover tools (tools/list — the registry)
  messages = [system prompt (facts/injection/scope policies), user question]
  for round in 1..max_rounds:
      check overall deadline                      -> time_budget_exhausted
      provider.complete(messages, discovered specs)
      if no tool calls: final answer -> grounding scan -> result
      for each requested call (<= max per round):
          malformed arguments?                     -> rejected
          name not in MCP discovery?               -> rejected (injected tools unexecutable)
          missing required argument (from schema)? -> rejected
          analysis_id != session scope?            -> rejected (cross-analysis)
          evidence budget exhausted?               -> rejected
          execute via MCP (read_timeout = remaining budget)
          record evidence; append ACTUAL result as a tool-role message
  exhausted -> deterministic fallback summary + incomplete=true
             (max_rounds_reached / time_budget_exhausted / ...)
```

Rejections and tool failures are fed back to the model as structured
`{"error": ..., "executed": false}` tool messages so it can correct course —
and are surfaced to the API client in `tool_calls` (`rejected`/`failed`) plus
machine-readable `limitations`.  Rejected calls are never executed.

### 4.1 Grounding validation

Every final answer is scanned for claims that must exist verbatim in the
collected evidence text:

* advisory identifiers: `CVE-YYYY-NNNN+`, `GHSA-...`;
* OSV/advisory links (`https://osv.dev/...`, `https://mig.gosource.dev/...`);
* scored severity claims (`severity 9.8`, `CVSS 7.5`);
* "fixed in <version>" claims.

Ungrounded markers ⇒ `grounded=false`; in `strict_grounding` (default) the
answer text is **withheld** and replaced with a deterministic refusal that
points at the structured evidence; non-strict mode keeps the text but flags
`ungrounded_content_flagged`.  The scanner is a deterministic tripwire
against the highest-harm fabrication classes; it is **not** a semantic proof
(see §8 limitations).

The response additionally carries: `repository_id` / `commit_sha` (extracted
from tool results when present), `advisory_links` (advisory URLs found in
evidence), `tool_calls`, `evidence` (bounded excerpts), `limitations`,
`rounds_used`, `grounded`, `incomplete`.

## 5. MCP integration details

* Transport: `mcp.client.streamable_http.streamable_http_client` +
  `mcp.client.session.ClientSession` (official SDK 2.x) — the same family the
  Phase 4A server implements.
* Discovery: `tools/list` once per question; the resulting 11 tool schemas
  are the *only* callable surface (converted to provider function specs).
* Execution: `tools/call` with `read_timeout_seconds` bound to the remaining
  overall budget; results are parsed from `structured_content` (or JSON text
  content) and size-capped per result.
* Error taxonomy: tool errors (`is_error=true`) become `AgentToolError`
  recorded as `failed` calls; connect/session/protocol failures become
  `AgentMCPUnavailableError` → `502 agent_mcp_unavailable`.
* Session lifecycle: one session per question, closed in the same task;
  a failed `streamable_http_client` entry is never “exited” (that would
  re-enter a half-built anyio task group), and transport-internal
  cancellation is converted into the deterministic error above.

## 6. API surface

`POST /api/v1/analyses/{analysis_id}/ask`

Request: `{"question": "...", "max_rounds": 1..8?}` (schema cap 1000 chars —
the configurable loop cap applies additionally; `max_rounds` is clamped to
the server cap).

Response: `analysis_id`, `answer`, `grounded`, `incomplete`, `rounds_used`,
`tool_calls[]`, `evidence[]`, `limitations[]`, `repository_id`, `commit_sha`,
`advisory_links[]`.

Errors (shared envelope, existing mapping):

| Status | Code | When |
|--------|------|------|
| 404 | `repository_not_found` | analysis not persisted (pre-flight, before any LLM spend) |
| 422 | `invalid_input` | schema validation (empty/oversized question, bad max_rounds) |
| 400 | `invalid_input` | loop-level question validation (config-capped) |
| 503 | `agent_not_configured` | no model/key |
| 502 | `agent_provider_error` | provider HTTP/parse failure (auth, 4xx/5xx, malformed body) |
| 504 | `agent_timeout` | provider timeout |
| 502 | `agent_mcp_unavailable` | MCP connect/session/discovery failure |

Credentials never appear in responses; tool-call arguments are echoed via
`strip_argument_values` (bounded, string-only values).

## 7. Security boundaries

* **Read-only by construction**: the only executable tools are the 11
  read-only MCP tools; there is no Cypher, shell, repository-execution,
  graph-write, OSV-ingest or GitHub-write surface in the agent code or its
  dependencies.
* **Prompt injection**: advisory/repository content arrives only in
  tool-role messages; the system prompt forbids treating content as
  instructions; name validation against MCP discovery makes injected tool
  names (`osv.ingest`, `graph.delete`, ...) unexecutable; argument validation
  blocks scope escape.  Tested with injected payloads end-to-end.
* **Cross-analysis containment**: analysis-scoped tools must carry the
  session's `analysis_id`; mismatches are rejected and never executed
  (tested over the real transport).
* **Fabrication prevention**: grounding scanner (§4.1) + system prompt facts
  policy + deterministic fallback summaries.  Output-side identifier checks
  are the hard guarantee; semantic hallucination beyond the scanned classes
  remains a residual risk (§8).
* **Resource abuse**: bounded rounds, per-round calls, evidence chars,
  per-result chars, output chars, provider timeouts and an overall deadline.
* **Secrets**: `SecretStr` API key; never logged (only
  `connection_label` — provider/model/base URL/key *source*) and never
  echoed in errors.

## 8. Known limitations

* Live LLM execution was **not tested** — this environment has no provider
  credentials (verified: no `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/etc. present).
  The adapter is verified against mocked HTTP (wire format, status mapping,
  timeouts, malformed payloads); orchestration is verified with deterministic
  doubles and over the real MCP transport.
* The grounding scanner covers identifier/link/score/fixed-version patterns,
  not semantic paraphrase (e.g. "the library is affected" inferred from a
  path with no advisory).  The system prompt and evidence-format steering
  mitigate but cannot deterministically eliminate this class.
* `max_question_chars` is enforced twice: request-schema cap 1000 and the
  configurable loop cap (raising 400); a config cap *above* 1000 cannot
  raise the schema limit.
* Stub-tested provider path assumes OpenAI-compatible dialects only.

## 9. Testing

Offline (default suite; no network, no FalkorDB, no OSV):

| Module | Covers |
|--------|--------|
| `tests/test_agent_config.py` | env parsing, defaults, credential states, caching, fail-fast errors |
| `tests/test_agent_provider.py` | wire format + auth header, strict response parsing, malformed args, HTTP 401/429/5xx mapping, timeout/transport errors, secret non-leakage |
| `tests/test_agent_loop.py` | discovery-as-registry, tool selection, sequential calls, invalid tools/args, per-round and evidence budgets, round/time caps, grounding withhold/flag/pass, provider & MCP failure modes, empty/incomplete results |
| `tests/test_agent_api.py` | response schema, validation (422/400), 404 pre-flight, error-envelope mapping (503/502/504/400), secret non-leakage, real unconfigured-agent path |
| `tests/test_agent_integration.py` | **real MCP transport over loopback HTTP**: happy path, 11-tool discovery, injected/cross-scope rejection, identifier surfacing, provider failure envelope, max-rounds bound, direct loop over real MCP |
| `tests/test_agent_live.py` | opt-in LIVE LLM query (skipped without `BLASTRADIUS_AGENT_LIVE_TESTS=1` + credentials) |

Verified results (commands actually executed):

```
python -m pytest tests/test_agent_config.py tests/test_agent_provider.py -q      # 40 passed
python -m pytest tests/test_agent_loop.py -q                                     # 27 passed
python -m pytest tests/test_agent_api.py -q                                      # 17 passed
python -m pytest tests/test_agent_integration.py -q                              # 8 passed
python -m pytest tests/test_mcp_http.py -q                                       # 7 passed (Phase 4A regression)
python -m pytest -q                                                              # 650 passed, 13 skipped, 0 failed
```

The 13 skips are the opt-in live suites (GitHub ×1, graph ×4, OSV ×3, MCP ×3,
agent ×1) plus the Windows symlink test — unchanged except the new agent
live skip.

## 10. Explicitly preserved

Phase 1 ingestion, Phase 2 graph engine, Phase 3 OSV intelligence and Phase
4A MCP server behaviour are untouched except for strictly additive changes:

* `ErrorCode` gained four `agent_*` values; `IngestionStage` gained `AGENT`
  (additive enum members only);
* `Settings.phase` is `phase-4b-agent` (asserted in `tests/test_api.py`);
* `app/api/v1/router.py` includes the new agent router;
* `app/api/deps.py` gained `get_agent()`;
* `pyproject.toml`: `app.agent` added to the explicit package list;
* no dependency changes (provider uses existing `httpx`; MCP uses the
  already-installed `mcp` 2.x SDK).
