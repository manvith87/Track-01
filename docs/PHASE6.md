# BlastRadius Phase 6 — User-Approved GitHub Remediation Issues

Status: **implemented and tested offline**. Previews, digests, the persistent
action store, the GitHub issue client and the confirmation workflow are all
covered by deterministic tests with a mocked GitHub transport. Creating a real
issue is a write operation and is therefore **disabled by default**; the opt-in
live test has not been executed in this environment (no GitHub credentials, no
designated sandbox repository were available).

See `docs/PHASE5.md` for the remediation evidence this phase turns into an
issue, and `README.md` for the phase overview.

## 1. Purpose and scope

Phase 6 answers one question: **"Turn this verified remediation plan into a
GitHub issue — but only after a human explicitly approved exactly this
payload."**

In scope:

- a deterministic, evidence-backed Markdown issue preview (title + body) built
  from the Phase 5 fix-group/finding output;
- a canonical payload digest that binds a confirmation to the exact previewed
  repository, analysis, commit, selection, title and body;
- an explicit authorization step (dedicated approval secret) plus a configurable
  kill switch (`BLASTRADIUS_ACTIONS_ENABLED`) that defaults to *off*;
- one GitHub REST write — `POST /repos/{owner}/{repo}/issues` — and nothing
  else;
- an atomic, auditable action store with expiry, replay protection, duplicate
  suppression and safe recovery from ambiguous write outcomes;
- a preview-only MCP tool so the agent can *prepare* a proposal.

Explicitly out of scope:

- pull requests, package upgrades, repository file edits, releases, comments,
  issue closing or any other GitHub mutation;
- caller-supplied repositories, severities, fixed versions or issue bodies;
- LLM/agent-initiated writes — no LLM-callable write tool exists;
- executing package managers, resolvers or builds;
- issuing a second write to "fix" an ambiguous first outcome;
- fetching or storing GitHub credentials anywhere but the process environment.

## 2. Architecture

```
Phase 5 RemediationService (read-only evidence)
        │  report.findings / report.groups
        ▼
GitHubIssueService (app/actions/service.py)
        │
        ├── target resolution      app/actions/service.py::_resolve_target
        │     analysis.Repository row -> canonical owner/name (Phase 1 parser)
        │     rejects non-github hosts, malformed owner/name, id conflicts,
        │     missing records and (optional) allowlist misses
        │
        ├── issue content          app/actions/issue_content.py
        │     deterministic Markdown template + escaping + caps + marker
        │
        ├── digest                 app/actions/digest.py
        │     sha256 over canonical JSON of every bound field
        │
        ├── action store           app/actions/store.py (SQLite, WAL, CAS)
        │     PREVIEWED -> EXECUTING -> SUCCEEDED | FAILED
        │     PREVIEWED -> EXPIRED
        │
        ├── GitHub preflight       app/github/issue_client.py
        │     GET /repos/{owner}/{repo}  (existence, rename, has_issues,
        │     fine-grained permissions) — never follows redirects
        │
        └── GitHub write           app/github/issue_client.py
              POST /repos/{owner}/{repo}/issues
              + GET /search/issues reconciliation after ambiguity
        │
        ├── app/api/v1/actions.py    2 write-gated HTTP endpoints
        ├── app/mcp/tools.py         remediation.issue_preview (preview only)
        └── app/agent/agent.py       prompt guardrails (prepare, never write)
```

The **only** production write path in BlastRadius is
`GitHubIssueClient.create_issue`; the read-only ingestion client
(`app/ingestion/github_api.py`) is unchanged and cannot write.

## 3. Permissions and credentials

BlastRadius needs the smallest permission set GitHub offers:

| GitHub permission | Why |
|-------------------|-----|
| `Metadata: read` | `GET /repos/{owner}/{repo}` preflight (existence, rename detection, `has_issues`, permissions) |
| `Issues: write` | `POST /repos/{owner}/{repo}/issues` (create one issue) and `GET /search/issues` reconciliation |

Recommended: a **fine-grained personal access token or GitHub App
installation token**, restricted to *only* the repositories BlastRadius may
write to. A classic token needs `repo` (private repositories) or `public_repo`
(public repositories only); neither is least-privilege, so prefer fine-grained.

Additional rules:

- the write token is read from `BLASTRADIUS_ACTIONS_GITHUB_TOKEN` — a
  **dedicated** variable, never the Phase 1 ingestion token;
- the confirmation secret is read from `BLASTRADIUS_ACTIONS_APPROVAL_SECRET`;
  without it every confirmation is refused
  (`503 action_authorization_not_configured`), never silently allowed;
- both are held as `SecretStr`, are never logged, never returned in an error
  envelope or preview/confirm response, and never persisted in the action
  store;
- tokens are only ever sent as an `Authorization: Bearer` header to the
  configured API base URL (which must be `https://`);
- no other GitHub host, path or method is reachable: the client builds every
  URL from the validated `owner`/`name` and fixed path segments, and a 3xx
  redirect is treated as an evidence change instead of being followed.

Failure handling is explicit: `401` → `503 github_credentials_invalid`, `403`
(non-rate-limit) → `403 github_permission_denied` with the required permission
list, `404` → `404 repository_not_found`, `429` / rate-limited `403` →
`429 rate_limit_exceeded` with safe rate-limit details. BlastRadius never
attempts to work around missing permissions (no token grinding, no alternate
endpoints, no scraping).

## 4. Configuration (`BLASTRADIUS_ACTIONS_*`)

All settings are optional; safe defaults apply.

| Variable | Default | Meaning |
|----------|---------|---------|
| `BLASTRADIUS_ACTIONS_ENABLED` | `false` | Master switch. While false, preview and confirm answer `403 github_write_disabled`. |
| `BLASTRADIUS_ACTIONS_GITHUB_TOKEN` | unset | Dedicated write token (`Issues: write`, `Metadata: read`). Unset → `503 action_not_configured`. |
| `BLASTRADIUS_ACTIONS_APPROVAL_SECRET` | unset | Confirmation secret. Unset → every confirm answers `503 action_authorization_not_configured`. |
| `BLASTRADIUS_ACTIONS_GITHUB_API_BASE_URL` | `https://api.github.com` | Must be `https://`; for GitHub Enterprise Server use e.g. `https://github.example.com/api/v3`. |
| `BLASTRADIUS_ACTIONS_USER_AGENT` | `BlastRadius/0.1 (+https://github.com/blastradius)` | `User-Agent` header. |
| `BLASTRADIUS_ACTIONS_TIMEOUT_SECONDS` | `20` | Per-request HTTP timeout (> 0). |
| `BLASTRADIUS_ACTIONS_PREVIEW_TTL_SECONDS` | `900` | How long a preview stays confirmable. |
| `BLASTRADIUS_ACTIONS_STORE_PATH` | platform temp dir + `blastradius-actions/actions.sqlite3` | Persistent action store. Set a durable path in production: replay/duplicate guarantees survive restarts only with a stable file. |
| `BLASTRADIUS_ACTIONS_RETENTION_SECONDS` | `604800` | Purge horizon for `PREVIEWED`/`EXPIRED`/`FAILED` rows; `SUCCEEDED` rows are always kept for audit/idempotency. |
| `BLASTRADIUS_ACTIONS_REPOSITORY_ALLOWLIST` | unset (no restriction) | Optional comma-separated `owner/repo` / `github.com/owner/repo` / full URL entries. When set, only these canonical ids may be previewed or written. |
| `BLASTRADIUS_ACTIONS_MAX_TITLE_CHARS` | `256` | Title cap (16–256). |
| `BLASTRADIUS_ACTIONS_MAX_BODY_CHARS` | `60000` | Body cap (1000–65000). Truncation keeps the action marker. |

Invalid values fail fast at configuration load (e.g. `TIMEOUT_SECONDS=0`,
non-`https` base URL, malformed allowlist entry) rather than at request time.

## 5. Workflow: preview → approve → confirm

### 5.1 Preview

```
POST /api/v1/analyses/{analysis_id}/remediation/github-issue/preview
{"group_id": "fixgroup_..."}          # or {"finding_id": "finding_..."} — exactly one
```

1. `BLASTRADIUS_ACTIONS_ENABLED` and the token are checked first; otherwise
   nothing else happens (`403` / `503`).
2. The Phase 5 `RemediationService` recomputes the report for `analysis_id`
   from the persisted graph/OSV facts (unknown analysis/group/finding → `404`).
3. The write target is resolved server-side from the analysis `Repository`
   record: canonical owner/name are rebuilt through the Phase 1 URL validator
   and must match the stored canonical id; a non-GitHub host, embedded
   credentials, malformed name, missing record or allowlist miss is rejected
   (`409 action_repository_invalid` / `403 action_repository_not_allowed`).
4. A **read-only** preflight `GET /repos/{owner}/{repo}` verifies the
   repository is still accessible, is not renamed/moved (`full_name` must match
   exactly; redirects are not followed), is not archived-blocked and that
   `has_issues` is true (`409 github_issues_disabled` otherwise). A read-only
   token produces an explicit permission note in the preview instead of a
   silent later failure.
5. The deterministic issue content is built from the Phase 5 evidence (section
   6) and its canonical digest is computed (section 7).
6. One `PREVIEWED` record (payload, digest, title, body, timestamps, expiry) is
   persisted; then the preview response is returned with
   `state: "PREVIEWED"`, the server-issued `action_id`, `payload_digest`,
   `expires_at` and a note stating that no write has happened.

A preview performs **no GitHub write**: the tests assert that the only HTTP
traffic is the read-only `GET`.

### 5.2 Approve

Approval is out-of-band by design: the operator inspects the preview (title,
body, target, digest, expiry) and decides. Nothing in the HTTP request, the
agent, or a natural-language message can approve a write by itself.

### 5.3 Confirm

```
POST /api/v1/actions/github-issue/confirm
X-BlastRadius-Approval: <BLASTRADIUS_ACTIONS_APPROVAL_SECRET>
{"action_id": "act_...", "payload_digest": "sha256:..."}
```

1. Kill switch + token gate (as in preview).
2. Authorization: the configured secret must exist
   (`503 action_authorization_not_configured` otherwise) and the header must
   match it using a constant-time comparison (`401 action_unauthorized` for a
   missing or wrong value — the response distinguishes "missing" from
   "invalid" for the operator, never echoes the secret).
3. The stored action is loaded (`404 action_not_found` for unknown/malformed
   ids) and the submitted digest must equal the stored digest
   (`409 action_payload_mismatch`).
4. Stored-state dispatch: `SUCCEEDED` returns the stored result with
   `created: false` (idempotent replay); `FAILED`/`EXPIRED`/
   in-flight handlers below; otherwise the expiry is re-checked
   (`410 action_expired`, state → `EXPIRED`).
5. **Evidence revalidation**: the preview is regenerated from the current graph
   facts and compared with the stored record — repository, commit, selection,
   title, body and digest must all match. Any mismatch (advisory text changed,
   commit moved, group no longer exists, repository record changed) aborts with
   `409 action_evidence_changed` and creates nothing.
6. A second repository preflight runs; problems surface as the same typed
   errors as in preview.
7. The record is atomically reserved (`PREVIEWED → EXECUTING`). A concurrent
   caller loses the race and gets `409 action_in_progress` (or the stored
   result if it arrives after completion) — the CAS guarantees exactly one
   executor.
8. `POST /repos/{owner}/{repo}/issues` with exactly `{"title", "body"}` from
   the stored record.
9. On a valid response with a usable issue identifier: `EXECUTING → SUCCEEDED`
   with `issue_number`/`issue_url`/`executed_at`, and the result is returned
   with `created: true`.
10. On a definitive failure (validation, permission, credentials, rate limit,
    issues-disabled): `EXECUTING → FAILED` with a safe `failure_category`, the
    typed error is returned, and the action is consumed (a replay gets
    `409 action_consumed`; it is never retried automatically).
11. On an **ambiguous** outcome (timeout/transport error, 5xx, or a 2xx whose
    payload lacks a usable identifier): BlastRadius searches
    `GET /search/issues` for the unique marker embedded in the issue body.
    Exactly one match → `SUCCEEDED` with `reconciled: true`. Zero or many
    matches (or a failed search) → `FAILED` with category
    `github_write_ambiguous` and a `502 github_write_ambiguous` response. The
    issue is never blindly re-created.

## 6. Issue content template (`blastradius-issue-v1`)

The body is deterministic Markdown generated only from server-side models:

1. **Target** — canonical `owner/repo`, analysed commit (with link) and
   analysis id.
2. **Proposed change** — package, ecosystem, dependency role, current version,
   proposed version (with the explicit note that it comes from
   advisory-declared fixed-version data and is *never invented*), coverage,
   compatibility status, "resolver executed: no", and verified/potential/
   unresolved finding counts. When no advisory fixed version exists, the
   proposed version is `none` with the recorded reason.
3. **Verified findings** (or **Verified finding**) — id, advisory link,
   escaped summary, recorded fixed versions and the range-validation verdict.
4. **Potential coverage (not range-validated)** — findings that advisory data
   cannot validate against the proposed version.
5. **Advisory evidence** — IDs, declared fixed versions, OSV modification
   dates and links.
6. **Modeled graph evidence** — modeled reachability, dependency role, counts
   and example impacted components, with the explicit statement that modeled
   paths are **not proof of runtime exploitability**.
7. **Compatibility and constraints** — constraint checks and their recorded
   evidence; "no resolver was executed, so transitive resolution is not
   verified".
8. **Unresolved relationships and migration concerns** — recorded unknowns.
9. **Suggested validation steps** — honest manual checks (never "this upgrade
   was tested").
10. **Limitations** — the Phase 5 report/group limitations plus template
    limitations (proposal only, not tested, priorities are custom and not
    CVSS).
11. The unique action marker `<!-- blastradius-action: <action_id> -->` used
    only for outcome reconciliation.

Safety properties:

- all untrusted text (advisory summaries, aliases, references, component
  names) is escaped for inline Markdown: `&`, `<`, `>` are entity-encoded,
  backticks are replaced in code spans, and only `http(s)` references become
  autolinks (so `javascript:`/`data:` text can never render as a link);
- a forged marker inside advisory text cannot collide with the real one: the
  real marker stays unique, and the tests assert exactly one marker line;
- lists are capped deterministically (findings 25, components 50, entry paths
  25, checks 50, references 40) with explicit "(+n more … not shown)" notes;
- title/body caps: titles truncate with `…`; oversized bodies truncate with a
  note **and keep the action marker** so reconciliation always works;
- no secrets, tokens, absolute local paths or raw provider exceptions are ever
  part of the content.

The body always says it is a proposal: no upgrade has been applied or tested,
no resolver/build ran, and no repository file changed.

## 7. Approval binding: digest and expiry

The digest is `sha256:<64 hex>` over the canonical JSON (sorted keys, compact
separators, UTF-8) of:

```
template_version, action_id, analysis_id,
repository_id, repository_owner, repository_name, commit_sha,
group_id, finding_id, title, body
```

Consequences:

- the confirm request must submit the exact digest string returned by the
  preview (format is validated as `sha256:[0-9a-f]{64}`);
- changing any bound field — including swapping the repository, the commit or
  a single character of the body — produces a different digest and is rejected
  with `409 action_payload_mismatch` before any HTTP write;
- the template version is part of the payload, so a template change cannot
  silently match an old digest;
- the action id is random (`act_` + 32 hex chars) and appears in both the
  digest and the issue marker, tying the stored record, the digest and the
  created issue together.

**Expiry.** Each preview carries `expires_at` (default 900 s after
`created_at`). Confirmation after expiry is rejected and the record is
transitioned to `EXPIRED` (`410 action_expired`). Expired records can never be
renewed or re-armed — the operator must re-preview (which produces a new action
id and digest, reflecting current evidence).

**Replay.** Replaying a successful confirmation returns the stored result with
`created: false` and never issues a second write. Replay of `FAILED`,
`EXPIRED` or in-flight actions is rejected (`409 action_consumed` /
`410 action_expired` / `409 action_in_progress`).

## 8. Idempotency, state machine and recovery

State machine (enforced atomically by `ActionStore`):

```
PREVIEWED ──confirm──> EXECUTING ──success──> SUCCEEDED
    │                      │
    │                      └──definitive failure or ambiguous outcome──> FAILED
    └──expiry observed on confirm──> EXPIRED
```

- The store is a small SQLite database (WAL journal, `busy_timeout`) holding
  one row per action: ids, state, digest, title/body, timestamps, `expires_at`,
  `approved_at`, `executed_at`, issue number/URL, `reconciled` flag and a safe
  `failure_category`/`failure_message`. It never stores tokens or the approval
  secret.
- Transitions are compare-and-set (`UPDATE … WHERE state = ?`) under
  `BEGIN IMMEDIATE`; a losing race observes the committed state instead of
  proceeding.
- `try_reserve` refuses expired previews and double execution; the winner
  alone performs the HTTP write.
- `SUCCEEDED` rows are retained by `purge()` (they are the idempotency and
  audit record); old `PREVIEWED`/`EXPIRED`/`FAILED` rows are deleted after
  `BLASTRADIUS_ACTIONS_RETENTION_SECONDS`.
- An ambiguous write is **consumed** with a unique-marker reconciliation
  attempt and never retried automatically: a human must inspect the search
  result (or the GitHub UI) and, if needed, create a fresh preview.
- Failure categories are safe, machine-readable codes
  (e.g. `github_permission_denied`, `github_write_ambiguous`,
  `github_issue_creation_failed`) — never provider exception text.

## 9. Error taxonomy

All errors use the shared envelope
`{"error": {"code", "message", "stage", "retryable", "details"}}`.

| Code | HTTP | Meaning |
|------|------|---------|
| `invalid_input` | 400/422 | Malformed request: unknown query parameters, extra/invalid body fields, both or neither selector, bad digest format. |
| `repository_not_found` | 404 | Unknown analysis/group/finding; repository invisible to the token (preflight). |
| `github_write_disabled` | 403 | `BLASTRADIUS_ACTIONS_ENABLED` is false. |
| `action_not_configured` | 503 | No write token configured. |
| `action_authorization_not_configured` | 503 | No approval secret configured. |
| `action_unauthorized` | 401 | Missing/invalid `X-BlastRadius-Approval` header. |
| `action_not_found` | 404 | Unknown action id. |
| `action_payload_mismatch` | 409 | Submitted digest ≠ stored digest. |
| `action_expired` | 410 | Preview TTL elapsed; action is expired. |
| `action_consumed` | 409 | Action already failed definitively (never retryable in place). |
| `action_in_progress` | 409 | Another confirmation currently executes this action. |
| `action_evidence_changed` | 409 | Regenerated payload/repository no longer matches the stored record (rename, moved commit, changed advisory text, stale group). |
| `action_repository_invalid` | 409 | Repository record missing/conflicting/malformed or not GitHub. |
| `action_repository_not_allowed` | 403 | Repository outside `BLASTRADIUS_ACTIONS_REPOSITORY_ALLOWLIST`. |
| `action_store_error` | 500 | Local action store failure (no write attempted). |
| `github_credentials_invalid` | 503 | GitHub rejected the token (401). |
| `github_permission_denied` | 403 | Token lacks `Issues: write` / `Metadata: read` (403 without rate-limit headers). |
| `github_issues_disabled` | 409 | Repository has issues disabled (or returns 410). |
| `github_issue_creation_failed` | 502 | Definitive create failure (unexpected 4xx). |
| `github_write_ambiguous` | 502 | Create outcome unknown and reconciliation was inconclusive; action consumed, never retried. |
| `rate_limit_exceeded` | 429 | GitHub rate limit (429 or 403 with rate-limit headers). |
| `network_failure` | 502 | Read preflight/search transport or 5xx failure. |

No error message, detail or log line contains the token or the approval secret.

## 10. HTTP API examples

Preview (PowerShell / curl):

```bash
curl -s -X POST \
  http://127.0.0.1:8000/api/v1/analyses/<analysis_id>/remediation/github-issue/preview \
  -H "Content-Type: application/json" \
  -d "{\"group_id\": \"<fixgroup_id>\"}"
```

Abridged response (`201`):

```json
{
  "action_id": "act_931801f21972f271c3a7004bb55a1202",
  "state": "PREVIEWED",
  "template_version": "blastradius-issue-v1",
  "repository": {
    "canonical_id": "github.com/example/priority-demo",
    "owner": "example",
    "name": "priority-demo",
    "full_name": "example/priority-demo",
    "html_url": "https://github.com/example/priority-demo"
  },
  "analysis_id": "...",
  "commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
  "selection": {"group_id": "...", "finding_id": null},
  "title": "[BlastRadius] Upgrade requests 2.32.0 → 2.32.1 — resolve 1 verified finding(s)",
  "body": "## BlastRadius remediation plan\n…",
  "payload_digest": "sha256:74e472989e92f…",
  "created_at": "2026-03-01T12:00:00Z",
  "expires_at": "2026-03-01T12:15:00Z",
  "verified_finding_count": 1,
  "potential_finding_count": 0,
  "limitations": ["reachability_traversal_bounded_at_5_hops"],
  "notes": ["No GitHub write has been performed. The issue is created only after an explicitly authorized confirmation of this action (before it expires)."]
}
```

Confirm:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/actions/github-issue/confirm \
  -H "Content-Type: application/json" \
  -H "X-BlastRadius-Approval: $BLASTRADIUS_ACTIONS_APPROVAL_SECRET" \
  -d "{\"action_id\": \"act_931801f21972f271c3a7004bb55a1202\", \"payload_digest\": \"sha256:74e472989e92f…\"}"
```

Abridged response (`200`):

```json
{
  "action_id": "act_931801f21972f271c3a7004bb55a1202",
  "state": "SUCCEEDED",
  "repository": {"canonical_id": "github.com/example/priority-demo", "...": "..."},
  "analysis_id": "...",
  "commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
  "title": "[BlastRadius] Upgrade requests 2.32.0 → 2.32.1 — resolve 1 verified finding(s)",
  "issue_number": 42,
  "issue_url": "https://github.com/example/priority-demo/issues/42",
  "created": true,
  "reconciled": false,
  "executed_at": "2026-03-01T12:03:11Z"
}
```

Replaying the same request returns the identical result with
`"created": false` and performs no GitHub write.

## 11. MCP tool and agent guardrails

- `remediation.issue_preview(analysis_id, group_id | finding_id)` returns the
  same proposal object as the HTTP preview (action id, digest, title, body,
  expiry, notes). It is read-only and looks exactly like the API response.
- There is **no MCP tool** that can confirm or create an issue. A compromised
  or confused model cannot spend the approval secret.
- The agent system prompt instructs the model to treat
  `remediation.issue_preview` as preparation only: it must never claim an issue
  was created, must never alter the action id/digest, and must tell the user
  that creation requires an operator-authorized confirmation of the previewed
  payload.

## 12. Tests and actual results

Offline by default — every HTTP call is served by `httpx.MockTransport`, so no
network access, credentials, FalkorDB or LLM are needed.

```bash
python -m pytest tests/test_actions_config.py tests/test_actions_issue_content.py \
    tests/test_github_issue_client.py tests/test_actions_store.py \
    tests/test_actions_service.py tests/test_actions_api.py \
    tests/test_actions_mcp.py -q
```

Result: **162 passed** (22 config + 14 content + 30 client + 18 store +
42 service + 27 API + 9 MCP). Coverage highlights:

- config: disabled-by-default, env parsing, https enforcement, allowlist
  normalization, cache reset, secret never in labels/repr;
- content: required sections, no-fixed-version honesty, escaping/injection
  (forged marker, `javascript:` references), unique marker, truncation keeps
  the marker, caps, secrets absent;
- client: preflight metadata, permission hints, every error mapping (401/403/
  404/410/422/429/5xx/timeouts/redirects), read-only reconciliation search,
  malformed item skipping, lifecycle;
- store: CAS transitions, duplicate/expired reservations, restart
  persistence, concurrent single winner, purge retention;
- service: preview never writes; unknown/malformed/allowlisted repositories;
  preflight failures; authorization (missing/wrong/unconfigured); digest
  mismatch; expiry; replay; consumed/in-progress actions; evidence
  revalidation (advisory text, commit, stale group, repository record);
  concurrency; ambiguous outcome reconciliation success/failure/duplicates;
  no secrets persisted;
- API: wire contracts, envelopes, status codes, rejection of caller-supplied
  facts, OpenAPI visibility;
- MCP: preview-only surface, selector validation, disabled-write reporting,
  never posts/searches.

Full default suite: **910 passed, 15 skipped** — the 15 skips are the
pre-existing opt-in live suites (graph, OSV, ingestion, MCP, LLM), the Windows
symlink test, and the two new Phase 6 live tests (disabled by default).

## 13. Live write test safety (`tests/test_actions_live.py`)

Creating a real issue is opt-in and triple-guarded. Nothing runs unless
`BLASTRADIUS_ACTIONS_LIVE_TESTS=1`; the read-only preflight test additionally
needs `BLASTRADIUS_ACTIONS_LIVE_REPOSITORY=<owner/repo>`; the write test
additionally needs an exact, id-bound authorization:

```bash
$env:BLASTRADIUS_ACTIONS_LIVE_TESTS = "1"
$env:BLASTRADIUS_ACTIONS_ENABLED = "true"
$env:BLASTRADIUS_ACTIONS_GITHUB_TOKEN = "<fine-grained token: Issues write + Metadata read>"
$env:BLASTRADIUS_ACTIONS_APPROVAL_SECRET = "<secret>"
$env:BLASTRADIUS_ACTIONS_LIVE_REPOSITORY = "your-name/your-sandbox"
$env:BLASTRADIUS_ACTIONS_LIVE_CREATE = "github.com/your-name/your-sandbox"   # must match exactly
python -m pytest tests/test_actions_live.py -m live_write -s
```

Guards:

- **exact-match authorization** — `…_LIVE_CREATE` must equal the canonical id
  of `…_LIVE_REPOSITORY`; a mismatch fails loudly before the client is built;
- **denylist** — well-known unrelated public repositories
  (`psf/requests`, `urllib3/urllib3`, `pallets/flask`, `django/django`,
  `nodejs/node`, `torvalds/linux`) are refused even if misconfigured;
- the created issue is clearly labelled `[BlastRadius live test]`, carries the
  standard action marker, and is intentionally left open (the client has no
  close/delete capability) — close it manually;
- **status in this environment: not executed.** No GitHub write token and no
  designated sandbox repository were available, so no live issue was created
  here. The test is skipped in every normal run.

## 14. Limitations and unresolved items

- **One operator secret.** Authorization is a single shared secret, not
  per-user authentication/roles; anyone who can set the header can confirm.
  Deployments must also restrict access to the confirm endpoint
  (network policy, reverse proxy auth) and keep the store on a durable,
  access-controlled path.
- **Local store scope.** SQLite CAS protects concurrent confirmations on one
  host and across restarts on the same file. It is not a distributed lock: a
  multi-node deployment sharing a store is not supported (single-writer
  assumptions; WAL over network filesystems is unsafe). A shared database
  would be the follow-up.
- **Ambiguous writes are consumed, not repaired.** Search indexing can lag; a
  "zero matches" result marks the action `FAILED github_write_ambiguous` even
  though the issue may appear shortly after. This is deliberate fail-safe
  behaviour — inspect GitHub, then re-preview if a duplicate would be wrong.
- **No issue lifecycle management.** Updates, comments, labels, assignment,
  closure and deletion are out of scope; the created issue is immutable from
  BlastRadius' perspective.
- **Evidence revalidation can fail for honest reasons.** Any new analysis,
  advisory refresh or graph change between preview and confirm invalidates the
  action (`409 action_evidence_changed`); re-preview to proceed.
- **Read-only token hinting is heuristic.** The preflight note is derived from
  GitHub's `permissions` block; write permission can still be revoked between
  preview and confirm, which then fails definitively at create time.
- **No frontend.** Approval is API/MCP-operator driven; no UI was built.
- The global phase string remains `phase-4b-agent` (Phase 5 precedent); it does
  not reflect Phase 6.

## 15. Reproduction

```bash
# full offline suite (includes all Phase 6 tests; live tests skipped)
python -m pytest -q

# Phase 6 only
python -m pytest tests/test_actions_config.py tests/test_actions_issue_content.py \
    tests/test_github_issue_client.py tests/test_actions_store.py \
    tests/test_actions_service.py tests/test_actions_api.py \
    tests/test_actions_mcp.py -q

# start the API and try a preview (writes stay disabled until configured)
uvicorn app.main:app --port 8000
curl -s -X POST \
  http://127.0.0.1:8000/api/v1/analyses/<analysis_id>/remediation/github-issue/preview \
  -H "Content-Type: application/json" -d "{\"group_id\": \"<fixgroup_id>\"}"
```
