# BlastRadius Phase 5 — Deterministic Prioritization & Evidence-Backed Remediation

Status: **implemented and tested offline**. The Phase 5 engine is LLM-free: it
computes everything from the graph/advisory facts persisted by Phases 2 and 3,
so it remains fully usable when no LLM provider is configured or reachable.
No graph writes, repository writes, installs, builds, pull requests or issues
are performed.

See `docs/PHASE4B.md` for the agent surface this phase extends and
`docs/GRAPH_SCHEMA.md` for the underlying graph model.

## 1. Purpose and scope

Phase 5 answers two questions deterministically:

1. **Which finding should be investigated first, and why?**
   Version-confirmed findings are ranked by a documented custom formula whose
   factor contributions, advisory severity evidence, modeled reachability and
   remediation availability are exposed per finding.
2. **What upgrade would address which findings, and how far can that be
   verified?**
   Remediation candidates come only from advisory-declared fixed versions and
   are validated against the stored OSV ranges and the recorded dependency
   constraints. Fix groups rank dependency changes by *verified* impact.

In scope:

- deterministic per-finding priority with per-factor contributions;
- OSV-range validation of advisory fixed versions;
- constraint evaluation against recorded declarations and `DEPENDS_ON` edges;
- per-package candidates, grouping and metric-based group ranking;
- read-only HTTP API and read-only MCP tools;
- an extended agent prompt so the model can *explain* results without
  recomputing or inventing them.

Explicitly out of scope:

- modifying repository files, lockfiles, packages or GitHub state;
- installing packages or executing resolvers/builds;
- inventing fixed versions that no advisory declares;
- computing CVSS scores from vectors;
- treating custom priorities as CVSS;
- LLM-driven scoring or ranking;
- persistence of derived Phase 5 results (everything is recomputed per request).

## 2. Architecture

```
Phase 2 graph facts ─┐
                     ├──> RemediationService (app/remediation/service.py)
Phase 3 OSV facts ───┘             │
                                   ├── priority.py   formula + factor breakdown
                                   ├── ranges.py     OSV range validation
                                   ├── candidates.py advisory fixed versions + constraints
                                   └── groups.py     grouping + metric ranking
                                            │
                     ┌──────────────────────┼──────────────────────┐
                     ▼                      ▼                      ▼
          app/api/v1/remediation.py  app/mcp/tools.py       app/agent/agent.py
          (5 read-only GET routes)   (4 read-only tools)    (explanation rules only)
```

Files added or changed:

| File | Responsibility |
|------|----------------|
| `app/remediation/models.py` | Typed output contract shared by API, MCP and agent |
| `app/remediation/versions.py` | PEP 440 version parsing, constraints, prefix wildcards |
| `app/remediation/ranges.py` | OSV interval reconstruction and proposed-version validation |
| `app/remediation/severity.py` | Verbatim advisory severity parsing (never vector-to-score) |
| `app/remediation/priority.py` | `blastradius-priority-v1` formula, ranking, tie-breaks |
| `app/remediation/candidates.py` | Candidate generation, constraint checks, compatibility, selection |
| `app/remediation/groups.py` | Fix groups, coverage, metrics, unresolved findings |
| `app/remediation/service.py` | Analysis-scoped orchestration, bounds and limiting tokens |
| `app/graph/queries.py` | Extended vulnerability read + two bounded aggregations |
| `app/graph/vulnerability.py` | Entry-path and dependency-impact read methods |
| `app/api/v1/remediation.py`, `remediation_schemas.py` | Five read-only endpoints |
| `app/api/deps.py` | `get_remediation_service()` dependency (overridable) |
| `app/mcp/tools.py` | Four new read-only MCP tools (15 total) |
| `app/agent/agent.py` | Phase 5 explanation rules appended to the system prompt |
| `tests/remediation_support.py` | Canned graph fixtures/helpers |
| `tests/test_remediation_*.py` | 97 deterministic Phase 5 tests |
| `tests/test_agent_integration.py` | Real-MCP-transport priority tool test |

No existing Phase 1–4 service was replaced. The existing vulnerability query
(`GET_VULNERABILITIES`) was *extended* with the extra columns Phase 5 needs
(`ranges_json`, severity/reference/fixed-version fields, package relation/scope
flags) so there is still exactly one findings query. Phase 3's mapping ignores
the extra columns.

## 3. Graph inputs and bounds

The service reads, for one `analysis_id`:

- the analysis status row and graph statistics;
- resolved packages, declarations and `DEPENDS_ON` edges;
- the existing `AFFECTED_BY` findings (via the extended query);
- two new analysis-scoped aggregations:
  - `modeled_entry_paths_template(depth)` — shortest modeled `DEPENDS_ON` path
    from an entry package (a `direct` package or the lockfile root project) to
    each affected package;
  - `dependency_impact_summary_template(depth)` — distinct downstream
    dependent packages per affected package.

Both traversals are bounded at **5 hops**. Entry paths and dependent lists are
used as *modeled evidence only*; absence of a path is never reported as proof
that a package is unexploitable.

Processing caps (exceeding one is always reported, never silently dropped):

| Cap | Value | Limitation token |
|-----|-------|------------------|
| Findings | 1000 | `findings_truncated` |
| Packages | 2000 | `packages_truncated` |
| Declarations | 2000 | `declarations_truncated` |
| Dependency edges | 5000 | `dependency_edges_truncated` |
| Constraint sources per package | 100 | `constraint_checks_truncated` |
| Unresolved relationships per package | 20 | `unresolved_relationships_truncated (+N more)` |
| Inline unresolved findings in the API groups response | 200 | `unresolved_findings_truncated` |
| Inline unresolved findings in the MCP groups tool | 100 | `unresolved_findings_truncated` (boolean) |

Additional explicit tokens: `no_modeled_dependency_edges`,
`reachability_traversal_bounded_at_5_hops`, `no_entry_packages_defined`,
`no_confirmed_vulnerabilities`. Each finding also carries
`advisory_withdrawn` / `match_type_not_version` limitations when applicable.

## 4. Priority: `blastradius-priority-v1`

This is a **custom BlastRadius score, never a CVSS score**. Advisory severity is
carried separately in `priority.severity` exactly as OSV reported it.

```text
score = 100 * (0.40 * severity
             + 0.30 * reachability
             + 0.20 * impact
             + 0.10 * remediation)
```

Every factor is normalized to `[0, 1]`; `priority.factors` exposes `name`,
`weight`, `normalized`, `contribution`, the `raw` facts used, and explanatory
`notes`.

### 4.1 Factor normalization

| Factor | Weight | Normalization |
|--------|--------|---------------|
| Severity | 0.40 | Advisory numeric score / 10, clamped to `[0,1]`. If several numeric entries exist, the highest wins (ties by score type). Vector-only or absent severity ⇒ neutral `0.5`. CVSS vectors are never converted. |
| Reachability | 0.30 | `direct` = 1.0 (the affected package is itself a `direct` declaration or the root project); `reachable_from_entry` = 0.75 (a modeled path exists); `not_reachable` = 0.35 (the graph had dependency edges and entry packages, but no path within 5 hops was found); `unavailable` = 0.5 (the analysis lacks the data needed to model reachability). |
| Impact | 0.20 | `min(1, log2(1 + c) / 3)` where `c` is the number of distinct dependent components backed by modeled `DEPENDS_ON` paths. `c = 0` → 0.0; `c = 7` already saturates at 1.0. |
| Remediation | 0.10 | `1.0` when the advisory declares at least one fixed version for this package; `0.25` when it does not. |

Missing data is **neutral, never zero**: a finding with no advisory severity is
not treated as harmless. Likewise `not_reachable` is explicitly documented as
"no modeled path was found", not proof of unexploitability, and still scores
above zero.

`priority.reachability` additionally exposes `dependent_component_count`, up to
25 sorted `dependent_components` (with `dependent_components_truncated`),
`scope_exposure` (`dev` > `optional` > `runtime` > `unknown`), `entry_points`,
`min_hops` and `evidence_available`.

### 4.2 Ranking and tie-breaks

Findings are sorted by:

1. `score` descending;
2. advisory numeric severity descending (findings without a numeric score last);
3. reachability tier descending (`direct` > `reachable_from_entry` >
   `unavailable` > `not_reachable`);
4. `finding_id` ascending.

The same input always produces the same scores, ranks and group ids. Finding ids
are analysis-scoped: `stable_id("finding", analysis_id, package_id, vulnerability_id)`.

## 5. Advisory range validation

`app/remediation/ranges.py` reconstructs affected intervals from the stored
`ranges_json` payload (the same data carried by `AFFECTED_BY`):

- `introduced` starts an interval (inclusive); a missing introduced bound starts
  at `0`;
- `fixed` and `limit` close an interval **exclusively**;
- `last_affected` closes it **inclusively**;
- an interval left open is affected to infinity;
- only `ECOSYSTEM` and `SEMVER` range types are version-comparable.

A proposed version gets one of three statuses per finding:

| Status | Meaning |
|--------|---------|
| `resolves` | No reconstructed affected interval contains the proposed version **and** the same reconstruction re-confirms the current resolved version is affected. |
| `not_resolving` | The proposed version still falls inside an affected interval. |
| `unknown` | Missing/invalid JSON, GIT-only ranges, explicit enumeration-only data, unparsable versions/events, or ranges that do not re-confirm the current version. |

Nothing is guessed or coerced. A resolution is never claimed from advisory prose
or from the mere existence of a fixed version.

## 6. Candidates and compatibility

Candidates are generated **only** from advisory-declared fixed versions for the
finding's package. They are never invented, and versions merely mentioned in
advisory text are ignored.

### 6.1 Constraint evaluation

Recorded constraint sources come from declarations (manifest path/line, parsed
scheme) and incoming `DEPENDS_ON` edges (`from` package/version). Evaluation:

- empty constraint or scheme `any` ⇒ satisfied (no restriction);
- PEP 440 `SpecifierSet` constraints ⇒ satisfied/violated;
- prefix wildcards `*`, `2.*`, `2.3.*`, `==2.*`, `!=2.*` ⇒ deterministic release
  prefix match;
- Poetry syntax (`^`, `||`, bare `~`) ⇒ `None` (unknown), never guessed;
- non-PEP 440 specifier/version ⇒ `None` (unknown).

### 6.2 Compatibility statuses

| Status | Meaning |
|--------|---------|
| `constraints_satisfied` | No recorded constraint rejects the version (and at least one could be evaluated). |
| `constraints_violated` | At least one recorded constraint rejects it. The candidate remains visible with an explicit limitation. |
| `unverified` | No constraints exist, or one or more cannot be evaluated. |

`resolver_executed` is always `false`: no resolver is ever run, so
`constraints_satisfied` never implies that transitive resolution was verified.

### 6.3 Candidate ordering and selection

Within one package, candidates are ordered best-first by:

1. not violating a recorded constraint;
2. more range-validated (`resolves`) findings;
3. higher compatibility tier (`satisfied` > `unverified` > `violated`);
4. more `unknown` resolutions;
5. smaller proposed version (least disruptive by PEP 440 order).

The first candidate is marked `selected`. A package with no advisory fixed
version gets `no_candidate_reason` and an explicit limitation instead of a
manufactured target. Advisory fixed versions must parse for ordering; unparsable
ones sort last. A proposed version below the current version is flagged in the
candidate limitations.

## 7. Fix groups and ranking

A fix group is exactly one dependency change: the **selected candidate for one
affected package**. Every finding belongs to the group of its package, so no
finding is counted twice.

Coverage:

- `confirmed_advisory` — at least one range-validated resolution;
- `potential_only` — no range-validated resolution, but at least one unknown;
- `no_advisory_resolution` — neither.

Each group exposes the selected candidate and alternates, advisory evidence,
affected components, entry points, constraint checks, unresolved relationships,
migration concerns, and its ranking metrics. Only **verified** resolutions count
toward ranking:

| Metric | Meaning |
|--------|---------|
| `verified_resolved_count` | Range-validated findings resolved by the selected candidate |
| `verified_resolved_priority_sum` | Sum of the BlastRadius priorities of exactly those findings |
| `reachable_resolved_count` | Verified resolutions whose reachability is `direct`/`reachable_from_entry` |
| `compatibility_tier` / `label` | 2 satisfied, 1 unverified, 0 violated |
| `highest_finding_priority` | Highest verified priority (or `null`) |

Group order (higher first):

1. `verified_resolved_count`;
2. `verified_resolved_priority_sum`;
3. compatibility tier;
4. package name, then current version, then proposed version (stable ties).

Findings that the selected candidate cannot verifiably resolve are listed in
`unresolved_findings` with a reason: no advisory fix exists, or the range data
says the proposed version does not resolve them. Potential-only coverage stays
visible but never inflates the ranking. Shared upgrades do not claim findings
from neighbouring packages, because each group is scoped to one package.

## 8. Provenance

Every finding carries: `finding_id`, `analysis_id`, `repository_id`,
`commit_sha`, vulnerability id/summary/aliases/references, advisory
`osv_modified`/`last_synced_at`, package id/name/version/ecosystem/role/scope
flags/groups/marker/source manifest, `match_type`, advisory fixed versions,
priority evidence and confidence (`verified`/`reduced` with reasons).

Every candidate carries: package/current version, the advisory-sourced
`proposed_version` and `origin="osv_fixed_version"`, per-finding range
evaluations (status/detail/fixed versions/interval count), constraint checks
with exact recorded origins, compatibility status/detail, `resolver_executed`,
and limitations.

Every group carries analysis/repository/commit scope, advisory evidence,
constraints, unresolved relationships and migration concerns. Manifest paths and
line numbers appear only where the graph recorded them; no file name, line
number, package, version, CVE or dependency edge is invented. Advisory text is
never interpreted as an instruction.

## 9. HTTP API (read-only)

Mounted under `/api/v1`:

| Route | Purpose | Pagination |
|-------|---------|------------|
| `GET /analyses/{analysis_id}/findings` | Ranked findings + analysis context | `skip >= 0`, `limit` 1–500 (default 50) |
| `GET /analyses/{analysis_id}/findings/{finding_id}` | One finding, factors and its package plan | — |
| `GET /analyses/{analysis_id}/remediation/candidates` | Per-package candidates and checks | `skip >= 0`, `limit` 1–200 (default 50) |
| `GET /analyses/{analysis_id}/remediation/groups` | Ranked groups + unresolved findings | `skip >= 0`, `limit` 1–200 (default 20) |
| `GET /analyses/{analysis_id}/remediation/groups/{group_id}` | One group with evidence | — |

All routes are `GET` only. `POST` (or any other method) returns the shared error
envelope with `http_405`. Query parameters outside the documented pagination set
(`severity`, `cvss`, `cve`, `fixed_version`, ...) are rejected with
`400 invalid_input` and the offending names in `details`; caller-supplied
advisory data is never accepted. Missing analyses/findings/groups return `404`
with `repository_not_found` and the scoped ids in `details`; invalid pagination
returns `422` with `invalid_input`. Error responses always use
`{"error": {"code", "message", "stage", "retryable", "details"}}`.

Finding ids and group ids are analysis-scoped; ids minted for another analysis
are `404` for the requested analysis.

## 10. MCP tools (read-only)

Phase 4A's eleven tools are unchanged. Four narrowly scoped tools were added
(15 total):

| Tool | Arguments | Returns |
|------|-----------|---------|
| `findings.priority` | `analysis_id`, `skip >= 0`, `limit` 1–100 (default 25) | Ranked findings + analysis context + limitations |
| `findings.detail` | `analysis_id`, `finding_id` | One finding, factors and package plan |
| `remediation.groups` | `analysis_id`, `skip >= 0`, `limit` 1–100 (default 10) | Ranked groups + at most 100 unresolved findings |
| `remediation.group` | `analysis_id`, `group_id` | One group with evidence/checks |

Each tool validates non-empty ids and numeric bounds, scopes reads to the
requested analysis, and maps graph/missing-record failures to MCP
`INVALID_PARAMS` errors. No write, ingest, arbitrary-Cypher, PR or issue tool is
exposed.

## 11. Agent integration

The Phase 4B agent may explain Phase 5 results, but the system prompt now
explicitly requires it to:

- use only tool-returned priorities, versions and compatibility statuses;
- never compute or adjust scores itself;
- never label the custom priority as CVSS or derive a CVSS score from a vector;
- never invent an upgrade version, file, line or dependency edge;
- distinguish advisory-confirmed resolution from compatibility, and report
  unresolved/unknown evidence as such.

`tests/test_agent_integration.py` drives `findings.priority` through the real
MCP transport (loopback HTTP + official MCP SDK), in addition to the offline
agent-loop tests. Existing prompt-injection tests remain in force: unknown tool
names and cross-analysis arguments are rejected before execution.

## 12. Tests and actual results

Deterministic Phase 5 suite (no network, no FalkorDB, no LLM):

```bash
python -m pytest tests/test_remediation_ranges.py tests/test_remediation_versions.py \
    tests/test_remediation_priority.py tests/test_remediation_service.py \
    tests/test_remediation_api.py tests/test_remediation_mcp.py -q
# 97 passed
```

| Module | Tests | Coverage |
|--------|-------|----------|
| `test_remediation_ranges.py` | 14 | Interval boundaries, open ranges, multiple ranges, GIT/enumeration/unparsable ⇒ unknown, current-version re-confirmation |
| `test_remediation_versions.py` | 12 | PEP 440, exact pins, wildcards, Poetry syntax, invalid specifiers/versions, ordering |
| `test_remediation_priority.py` | 20 | Exact formula arithmetic, neutral missing data, vector-only severity, reachability tiers, log impact, remediation factor, determinism, tie-breaks, dependent cap, scope exposure |
| `test_remediation_service.py` | 22 | End-to-end report, plans/candidates, cross-analysis 404, no-fix path, pin violations, Poetry unverified, multi-fix selection, grouping/ranking/coverage, no double counting, entry/impact evidence, truncation, read-only queries |
| `test_remediation_api.py` | 14 | All five routes, pagination caps, 404/422/400 envelopes, 405 mutations, caller-supplied data rejected, OpenAPI |
| `test_remediation_mcp.py` | 15 | Four tools, pagination, validation/errors, id scoping, serialized evidence |

Additional agent coverage: one new real-MCP-transport test for
`findings.priority`; all 15 tools are discovered from the real MCP server.

Full offline regression on this machine:

```text
python -m pytest -q -rs
748 passed, 13 skipped
```

The 13 skips are the pre-existing opt-in live suites (GitHub, FalkorDB graph,
OSV, MCP, live LLM) plus the Windows symlink test. The live FalkorDB graph suite
was not enabled, so the two new Cypher aggregations are verified structurally
and against canned graph results, not against a live database in this run.

## 13. Limitations and unresolved items

- **No resolver execution.** Compatibility means "recorded constraints do not
  reject this version". Transitive resolution, peer conflicts and build
  compatibility are not verified.
- **Range evidence depends on stored data.** GIT-only ranges, enumeration-only
  advisories and missing/unparsable `ranges_json` stay `unknown`; no resolution
  is claimed for them.
- **Only advisory fixed versions.** A safe upgrade that no advisory lists is not
  proposed. Conversely, an advisory-listed version that violates recorded
  constraints remains visible but flagged.
- **One package per group.** Cross-package coordination (e.g. a framework
  upgrade requiring several packages) is not grouped as a single change; groups
  are per-package and never claim neighbours' findings.
- **Zero-verified groups remain visible.** A candidate that resolves nothing is
  still returned with `coverage=no_advisory_resolution` and verified count 0;
  consumers should rank/filter on the exposed metrics.
- **Recomputed per request.** Priority/remediation results are not persisted;
  every call re-reads the graph and recomputes deterministically.
- **Processing caps.** Very large analyses are truncated with explicit tokens;
  results are complete only up to those bounds.
- **No live database/LLM run.** Phase 5 itself is LLM-independent, but this
  environment has no provider credentials and the opt-in live graph suite was
  not enabled.
- **No GitHub actions.** Pull requests, issues, commits and package installs are
  intentionally not implemented.

## 14. Reproduction

```bash
# all offline tests
python -m pytest -q -rs

# Phase 5 only
python -m pytest tests/test_remediation_ranges.py tests/test_remediation_versions.py \
    tests/test_remediation_priority.py tests/test_remediation_service.py \
    tests/test_remediation_api.py tests/test_remediation_mcp.py -q

# start the API and query one analysis
python -m uvicorn app.main:app --reload
curl "http://127.0.0.1:8000/api/v1/analyses/$ANALYSIS/findings?limit=10"
curl "http://127.0.0.1:8000/api/v1/analyses/$ANALYSIS/remediation/groups"
```
