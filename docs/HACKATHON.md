# BlastRadius — Hackathon Demo & Presentation Kit

> Operating manual for presenting BlastRadius and recording the demo video:
> pitch, slides, click-by-click script, recording plan, hosting options, checklist, backups, Q&A.
>
> Verified against the app as it exists today: **928 Python tests passing**, a **live end-to-end agent run**
> (real LLM → real MCP tool call executed → grounded answer, 7.5 s), UI served from `frontend/dist`.

---

## 1. The one-liner

> **"When a CVE drops, scanners tell you which packages are vulnerable. BlastRadius shows you who can
> actually *reach* them — a graph-powered blast-radius analysis with an evidence-grounded AI analyst and
> human-approved fixes."**

**30-second version (memorize):**

1. Software supply chains are deep — the next big attack hides four levels down in transitive dependencies.
2. Existing tools list CVEs per package. They don't answer: does anything in *my* project actually reach it,
   along which path, and what is the smallest fix?
3. BlastRadius: GitHub repo → exact-commit dependency graph in FalkorDB → OSV advisories mapped onto the
   graph → an AI analyst that answers using **read-only graph tools (MCP), grounded in the tool results** →
   prioritized fix groups → one gated, human-approved GitHub issue.
4. Eight phases, 928 automated tests, live-verified end to end.

## 2. Slide outline (10 slides, paste-ready)

1. **Title** — BlastRadius. *"From CVE list to blast radius."* Team names + one-line hook.
2. **Problem** — supply-chain attacks (xz, event-stream, SolarWinds); transitive depth; manual triage;
   scanners answer *"is it vulnerable?"* — not *"is it reachable, along which path, and what do I fix first?"*
3. **Solution — the pipeline** (redraw this on the slide):

   ```
   GitHub repo ──► Ingest (exact SHA · 4 manifest formats · provenance)
                        │
                        ▼
                  Dependency graph in FalkorDB  ◄── OSV.dev advisories matched onto the graph
                        │
                        ▼
                  Read-only MCP tools (16)  ◄── AI agent (any OpenAI-compatible LLM)
                        │
                        ▼
   React UI: Findings · Graph explorer · AI analyst · Remediation · GitHub issue
   ```

4. **Live demo** (bare transition slide).
5. **Ingestion with proof** — exact commit SHA recorded and verified; target repo code is **never executed**;
   unknown refs are rejected (never silently defaulted); 4 formats (`requirements.txt`, `pyproject.toml`,
   `poetry.lock`, `uv.lock`); every declaration keeps its provenance.
6. **The graph is the point** — blast radius = reachability paths. Tool list includes
   `analysis.blast_radius`, `analysis.vulnerabilities`, `package.neighborhood`, `findings.priority`,
   `remediation.groups`, `remediation.issue_preview`. Versions are never invented — exact-version vs
   name-only advisory matching is labeled.
7. **AI analyst, grounded** — discovers tools over MCP, calls them, answers. UI shows the
   *"Grounded in tool evidence"* badge, rounds used, the raw tool-call table and cited advisory links.
8. **Remediation + gated write** — fix groups ranked by coverage ("this upgrade clears N advisory-confirmed
   findings"); issue preview shows the exact payload; writes are **off** unless an operator enables them
   with a dedicated token + approval secret + repo allowlist.
9. **Quality & safety** — 928 offline tests; live E2E: real LLM executed `graph.health` over MCP and
   answered grounded in 7.5 s; target code never executed; secrets never logged; MCP surface is read-only.
10. **Roadmap + ask** — npm/JS + container image ecosystems, CI bot (PR comments), multi-tenant auth,
    hosted demo. Close with your event's ask (feedback / prize / partners).

## 3. Live demo script (~5 min, click-by-click)

Environment: UI `http://localhost:4173` · API `http://127.0.0.1:8000` · FalkorDB `localhost:6379` (see §4).

### Variant A — full live run

1. **(15 s) Open on the Repository tab.** "Everything starts from one public GitHub repo."
2. **(60–90 s) Paste the demo repo URL → click `Run ingestion`.** While it runs: "It resolves the *exact*
   commit, fetches only that revision, parses four manifest formats and records provenance for every
   dependency — and it never runs a single line of the project's code."
3. **Result panel:** point at *Resolved commit* ("SHA verified against the retrieved tree"), the stat grid
   (files / manifests / declarations / resolved packages / edges) and the warnings/errors honesty note.
4. **(20 s) Click `Persist analysis to graph`.** "Packages, versions and edges become graph nodes — this is
   what powers reachability."
5. **(20 s) Click `Sync OSV advisories`.** "OSV.dev advisories are matched onto the graph — exact-version
   where a lockfile pins, name-only otherwise, and it tells you which is which."
6. **Click `Open analysis` → Findings tab. (40 s)** Open the top finding: priority factors, advisory
   details, matched-by, evidence path. "Each row explains *why* it ranks there."
7. **Graph explorer. (60 s)** Show the dependency graph; select the vulnerable package; show the path from
   an entry point. "That's the blast radius — not 'you use it', but 'this chain reaches it'."
8. **AI analyst. (60–90 s)** Ask the first suggested question:
   *"Which packages are affected by advisories and have a modeled path from an entry point?"*
   While it works: "Watch its tool calls — it's choosing real graph queries over MCP, not guessing."
   Point at the *Grounded in tool evidence* badge, rounds, tool-call table, advisory links.
9. **Remediation. (40 s)** Fix groups ordered by coverage; open one: candidates + compatibility.
   "Prioritized, grouped fixes — not a raw CVE dump."
10. **GitHub issue. (40 s)** Generate the preview: title, body, evidence. Attempt confirm with writes
    disabled → the UI explains `github_write_disabled`: "By design — nothing is written to GitHub unless an
    operator opts in with a dedicated token, an approval secret and a repo allowlist." (If you did enable
    writes for a sandbox repo, confirm one live; the approval-secret gate is part of the story.)
11. **(15 s) Close.** "Eight phases, 928 tests, live-verified. Point it at your repo."

### Variant B — short (3–4 min, zero waiting)

Pre-seed steps 2–5 in advance; start the demo at *Findings*; do steps 6–10 only. Say: "I ran ingestion and
the OSV sync during setup — the recorded SHA is right there."

## 4. Environment — start / stop (the verified path)

```powershell
# Terminal 1 — FalkorDB (usually already running; start if needed)
docker run --name falkordb -p 6379:6379 falkordb/falkordb:2.2.0

# Terminal 2 — backend (load .env first so the AI analyst works)
Get-Content .env | ForEach-Object { if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$') { Set-Item "env:$($Matches[1])" $Matches[2].Trim() } }
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 3 — frontend (built bundle; proxies /api and /health to :8000)
cd frontend
npm run build      # once, or whenever sources change
npm run preview    # http://localhost:4173
```

Then open **http://localhost:4173** and check the graph badge in the header is connected.

Notes:

- Graph namespace: `blastradius` on `localhost:6379` (override with `$env:BLASTRADIUS_GRAPH_NAME`).
- The backend does **not** auto-load `.env` — always run the loader line first.
- **Do not use Docker Compose for the demo** — it is authored but was never executed on this machine; the
  commands above are the verified path.
- Stop: `Ctrl+C` in each terminal; FalkorDB keeps its data.

## 5. Recording the demo video

**Tooling**

- OBS Studio (free, best control) — or Windows Game Bar (`Win+G`) for a quick take.
- Record 1080p / 30 fps; capture the browser full-screen (`F11`); zoom 110–125 % for readable UI.
- Clean browser window (hide bookmarks bar), notifications off (Focus Assist), extra tabs closed.
- Microphone narration beats subtitles; keep a printed copy of §3 at eye level.

**Segment plan** (record separately, stitch later — free re-takes):

| # | Segment | Target |
|---|---------|--------|
| 1 | Hook + what it is (slides 1–3 over the UI) | 30–40 s |
| 2 | Ingestion run (or B-roll if pre-seeded) | 40–60 s |
| 3 | Findings deep-dive | 30–45 s |
| 4 | Graph explorer / blast radius | 45–60 s |
| 5 | AI analyst question + grounded answer | 45–60 s |
| 6 | Remediation | 30–40 s |
| 7 | GitHub issue preview + write-gate story | 30–45 s |
| 8 | Close (slides 9–10) | 20–30 s |

**Tips**

- Rehearse each segment twice; speak slower than feels natural; pause 1 s before every click.
- Don't cut the LLM wait — narrate over it: "it's choosing tools over MCP right now…".
- Pre-warm the analyst right before recording (ask one question), then reload once for a clean state.
- Keep terminal windows out of frame (or show them deliberately for the ingest narration).
- Export H.264 1080p, under ~200 MB.

## 6. If a LIVE URL is required (not just a video)

Ranked honestly under deadline pressure:

1. **Local recording only** — recommended; a video is usually enough. Nothing to expose, nothing to break.
2. **Cloud VM (Ubuntu)**: the same three commands as §4 (Docker for FalkorDB; Python + Node on the VM) +
   firewall rules. Works; budget an hour for setup.
3. **Docker Compose on a VM**: `docker compose up --build` — artifacts look right (FalkorDB internal-only,
   nginx proxies `/api`), but they have **never been executed**, so verify well before demo day.

⚠️ **Before any public exposure:** the app has **no authentication** — anyone with the URL can ingest
repos, query graphs and spend your LLM tokens. Protect it with a reverse proxy + basic auth, or a random
high port only during judging, or a temporary tunnel (e.g. `cloudflared`) you close afterwards. Rotate the
Groq key after the event. Never ship `.env` anywhere.

## 7. Backup plan (rehearse the failures)

- **Record everything the day before.** If venue Wi-Fi dies, play the recording.
- Once an analysis is persisted, Findings / Graph / Remediation / Issue preview need **no LLM and no
  internet** — only the AI analyst does.
- If the analyst fails on stage: "the provider is rate-limited on this network — here's the rehearsal
  answer" → show screenshot or switch to the recorded video.
- Free-tier rate limits are per-minute; leave a minute between full rehearsals.
- Keep a **second validated repo** ready in case ingest #1 is slow that day.
- Put screenshots (grounded badge, tool-call table, graph path, issue preview) in the slide deck as
  fallbacks.

## 8. Day-of checklist

- [ ] FalkorDB, backend, frontend started (§4); header badge shows the graph connected.
- [ ] Demo repo pre-seeded (ingest → persist → sync) in the graph namespace you're presenting.
- [ ] Analyst pre-warmed; page reloaded once after.
- [ ] Browser full-screen, zoom set, notifications off.
- [ ] Screen sleep disabled; charger plugged in.
- [ ] Recording tool armed (5 s countdown) before each segment.
- [ ] Slides open in a second window (`Alt+Tab` ready).
- [ ] Phone hotspot as network backup.
- [ ] Printed copy of the script + Q&A (§3, §10).

## 9. Choosing and validating the demo repo

Goal: a public Python repo that produces a **visible, version-confirmed** CVE story.

- Prefer repos with `requirements.txt`/`pyproject.toml` **plus a lockfile** (`poetry.lock`/`uv.lock`)
  pinning slightly old versions — those give "matched by exact version" findings.
- Small-to-mid size — live ingestion stays under a minute.
- Candidates to try: deliberately-vulnerable demo apps (e.g. `adeyosemanputra/pygoat`) or any app pinned
  to 2021–2023-era dependencies. **Validate before choosing.**
- Validation loop: ingestion + OSV sync → check that Findings shows several advisory-confirmed entries and
  at least one interesting graph path.

## 10. Q&A cheat sheet

| Question | Answer |
|---|---|
| Different from Dependabot/Snyk? | Those flag known-vulnerable versions. BlastRadius maps advisories onto *your* dependency graph: reachability paths, blast-radius counts, grouped remediation by coverage, grounded explanations — with honest matching labels. |
| Is the AI hallucinating? | It can only answer from tool results (16 read-only MCP tools). Answers carry the *Grounded in tool evidence* badge, the raw tool-call list and cited advisory links; ungrounded output is flagged or withheld. |
| Safe to point at a repo? | The target's code is never executed (no setup.py, no installs, no imports); extraction is hardened; a commit SHA is pinned and verified; retrieval carries no credentials. |
| Write access to GitHub? | Off by default. Writes need an operator to enable them *and* configure a dedicated token + approval secret + repo allowlist. Previews carry a payload digest; mismatches invalidate the write. |
| Why a graph database? | Reachability is a graph question ("who can reach package X, through which paths"). FalkorDB traversals are native; `analysis.blast_radius` is a first-class tool. |
| Data sources? | GitHub REST + git/archive for retrieval, OSV.dev for advisories, FalkorDB for the graph. No private data required. |
| Coverage? | Python today: `requirements.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`. Roadmap: npm/JS, container images, SBOM import. |
| Which LLM? | Provider-agnostic: any OpenAI-compatible endpoint (the demo runs on one). No lock-in. |
| Scale? | Bounded queries + server limits; synchronous ingestion with caps; roadmap: async jobs and auth for multi-user hosting. |

## 11. Small details that impress judges

- "**SHA verified against the retrieved tree**" — provenance honesty (and it says so when it *can't*
  verify).
- Unknown refs are **rejected**, never silently replaced by the default branch.
- The analyst page shows **raw tool calls** — real queries, real results.
- Attempting the GitHub write shows a **refusal notice** — security posture as a feature.
- `analysis.blast_radius` is literally a tool name — the product thesis is in the API surface.
- Say both test numbers: 928 offline tests + 1 live end-to-end test.
