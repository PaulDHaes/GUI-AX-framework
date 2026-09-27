# GUI-AX — Feature & Architecture Reference

> This document is the detailed feature and architecture companion to the
> [README](README.md). The README is the overview and quick-start; this file
> describes every page, service, and bridge endpoint in depth and how they fit
> together.

> **Tested with:** the AWS cloud provider. Other Ax-supported providers
> (DigitalOcean, Azure, Linode, GCP, Hetzner, IBM Cloud, Scaleway, Exoscale)
> should work through Ax but are unverified here.

## What GUI-AX is

GUI-AX is a web dashboard for [Ax](https://github.com/attacksurge/ax) (the
`ax`/axiom distributed-recon framework), turning its command-line workflow into
a browser UI. It launches distributed reconnaissance scans across a cloud
fleet, auto-imports and organises the results into a target database, and layers
project management, triage, CVE inventory, and reporting-oriented features on
top.

**Core capabilities**

- **Launch distributed scans** across a fleet from a form (Launch Scan), a
  one-click preset (Quick Scan), or a chained DAG pipeline (Workflows).
- **Auto-import results** from a wide range of recon tools into a unified target
  store, grouped and deduplicated by domain / scan name.
- **Fleet control** — power on/off, exec, SSH, terminate Ax-managed instances.
- **Triage & inventory** — cross-target findings triage with false-positive
  marking, SearchSploit/CVE lookups, and an NVD-backed CVE inventory of detected
  technologies.
- **Multi-user, projects & teams** with role-based access and Ghostwriter
  integration for per-consultant deep links.
- **AI assistance** via a local (Ollama) or Claude backend, with a local
  deterministic fallback so it works with no keys at all.
- **MCP server** so agents and reporting tools can drive the platform.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  GUI-AX frontend  (React 19 + Vite, Tailwind, Radix/shadcn)   │
│  App.tsx (dashboard, targets, vulns, docs) + components/*      │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTP/REST (Bearer token)
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  Bridge  (tools/axiom-bridge.py — Flask + flask-cors)         │
│   • REST API + auth gate            • JSON stores (data/*.json)│
│   • Polling import watcher          • Ax command executor (zsh)│
│   • CVE / SearchSploit / AI proxies • Geo enrichment           │
└───────┬───────────────────────────┬──────────────────────────┘
        │ spawns                     │ subprocess (zsh -l)
        ▼                            ▼
┌────────────────────┐      ┌───────────────────────────────────┐
│ workflow-runner.py │      │  Ax framework (github.com/         │
│ mcp-server.py      │      │  attacksurge/ax): axiom-scan,      │
│                    │      │  axiom-ls, axiom-fleet, ax update  │
└────────────────────┘      └──────────────────┬────────────────┘
                                               ▼
                              Cloud fleet (AWS / others via Ax)
```

**Frontend stack** (from `package.json`): React 19.2, `react-dom` 19.2,
`react-router-dom` 7.9, Vite 6.2 + `@vitejs/plugin-react`, Tailwind CSS 3.4 (+
`tailwindcss-animate`), Radix UI primitives in a shadcn-style `components/ui/`
layer, `lucide-react` icons, `recharts` for charts, and `d3` + `topojson-client`
+ `world-atlas` for the Geo Map. TypeScript throughout.

**Backend stack**: Flask + flask-cors, standard-library `urllib`/`sqlite3`/
`subprocess`, optional `geoip2` (offline IP geolocation) and `mcp` + `httpx`
(MCP server). Ax commands run through a `zsh -l` login shell so `~/.zshrc` puts
`~/.axiom/interact` on `PATH`.

**Data stores** (all JSON, under the `data/` directory next to `STORE_PATH`):

- `axiom_bridge_store.json` — main store: `targets`, `fleet`, and embedded
  `users` / `teams` / `invites` lists.
- `scans.json` — launched/in-flight scan records (merged with `~/.axiom/stats.log`).
- `users.json` — sidecar user records (used by admin/project management and
  Ghostwriter sync); also holds per-user `prefs` including `active_project`.
- `projects.json` — projects keyed by token, with `linked_scans`.
- `user_workflows.json` — per-user saved workflows.
- `inventory.json` — CVE inventory snapshot.
- `cve_cache.json` — 7-day disk cache of CVE lookups.
- `scan_prefixes.json` — fleet prefixes tracked from active scans.

Passwords are stored as SHA-256 hex digests. This is adequate for a
single-instance recon dashboard whose real security boundary is the network
perimeter.

## Auto-import pipeline

Scan output written into `imports/` (directly or via a subfolder named after the
scanner) is picked up and merged into the target store.

- **Polling watcher, not filesystem events.** A background daemon thread
  (`_import_watcher_thread`) re-scans `imports/` every `WATCHER_INTERVAL`
  seconds (default **300**). An initial scan also runs at startup, and
  `POST /api/imports/scan` triggers one on demand. There is no watchdog/event
  observer.
- **Classification** is by parent directory (`imports/nuclei/` → nuclei), then
  by filename pattern (e.g. `amass-out.txt` → amass), then by Ax output naming
  (e.g. `httpx+<timestamp>.txt` → httpx). Human-readable scan names are looked up
  in `scans.json` so imported targets keep their `programName` (e.g. a
  `gw-acme-5` label) for project filtering.
- **Modular importers** live in `tools/importers/` and self-register via a
  `HANDLES` list into a registry (`tools/importers/__init__.py`); unknown
  scanners fall back to `import_generic`. Coverage:
  - `import_subdomain` — amass, subfinder, assetfinder, dnsx, findomain,
    shuffledns, puredns, massdns, gobuster, chaos, and many more (JSON / JSONL /
    TXT, plus amass JSON).
  - `import_ports` — nmap / nmapx (XML `-oX`, normal `-oN`, grepable `-oG`),
    naabu, rustscan, masscan, unimap.
  - `import_httpx` — httpx, tlsx, tlscout (JSON / JSONL / TXT).
  - `import_nuclei` — nuclei JSON / JSONL / TXT, plus a nuclei-markdown export
    directory.
  - `import_gowitness` — gowitness SQLite bundle (with a `screenshots/` folder)
    plus JSON / JSONL / TXT; it moves its own bundle into
    `processed/gowitness-<ts>/` and screenshots are served from there.
  - `import_ffuf` — ffuf CSV / JSON / JSONL / TXT (stored as INFO findings).
  - `import_whois` — whois TXT / JSON / CSV / XML, plus `.dir`-mode batches.
  - `import_generic` — fallback host/hostname/domain/ip/url extractor.
- **Merging & persistence.** Files sharing a scan-name prefix merge into one
  target; hosts are grouped by root domain; subdomains/ports/vulnerabilities are
  deduplicated. Freshly imported hosts that already carry an IP are opportunistically
  geolocated (offline, cached). Processed files/folders are moved to
  `imports/processed/`. `POST /api/imports/reimport` moves everything back out of
  `processed/` and re-parses it (useful after a store reset).

Binary/image files are skipped; SQLite databases are only handled by the
gowitness importer.

## Pages & navigation

The sidebar (`App.tsx`) is grouped into **Recon**, **Infrastructure**, and
**Account**:

- **Recon** — Dashboard `/`, Targets `/targets` (detail at `/targets/:id`),
  Vulnerabilities `/vulns`, Findings Triage `/triage`, CVE Inventory
  `/inventory`, Projects `/projects`, Workflows `/workflow`, and a collapsible
  **Scans** group: Quick Scan `/quickscan`, Launch Scan `/scans?tab=launcher`,
  Active / Monitor `/scans?tab=active`, Output Viewer `/scans?tab=output`.
- **Infrastructure** — Fleet `/fleet`, Wordlists `/wordlists`, Settings
  `/settings`.
- **Account** — My Profile `/profile`, Admin `/admin` (shown only to the `admin`
  role), Documentation `/docs`.

Routing uses `react-router-dom`. Unknown routes render a placeholder.

### Active project

Users select an **active project** on the Projects page. It is stored server-side
per user at `GET`/`PATCH /api/users/me/prefs` (key `active_project`). The
Dashboard, Vulnerabilities, Findings Triage, and CVE Inventory pages default
their project filter to it (`lib/useActiveProject.ts`).

### Dashboard (`App.tsx` — `DashboardHomeExternal`)

Full-screen recon overview:

- **Header filters**: a team/user scope selector ("All", "Personal (no team)",
  per-team) that filters client-side by team-slug prefixes (including
  `wf-<slug>-` workflow scans), and — when the user has projects — a project
  filter that fetches server-side via `GET /api/targets?projectToken=<token>`.
- **Stat cards, row 1**: Scans (total targets), Subdomains, Open Ports,
  Vulnerabilities.
- **Stat cards, row 2**: Critical / High, Active Scans, Fleet Nodes
  (active/total), Scan Success (% completed).
- **Panels**: Top Open Ports (donut chart + top-5 legend), a CVE Inventory
  summary card (totals, "+N new" badge, per-severity counts, fed by
  `GET /api/inventory`), and Fleet Health (running/stopped/terminated +
  utilization).
- **Global Recon Map**: `components/GeoMap.tsx` (d3 + world-atlas) plotting
  target locations from WHOIS and IP geolocation.
- **Recent Scans** table with scanner-aware result labels (e.g. httpx/gowitness
  → "N websites", nmap → "N ports", nuclei → "N vulns", amass/subfinder →
  "N subs"), status badges, and links to target detail. A **Top Assets** list
  accompanies it.

Colour treatment follows the light ("Airtable editorial") and dark ("Raycast
developer-tools") design systems described in `DESIGN.md` / `DESIGN-LIGHT.md`.

### Targets (`App.tsx` — `TargetsList` / `TargetDetail`)

- **`/targets`** is a card/grid list (not a table). Each card shows domain,
  `programName`, subdomain/port/vuln counts, scanner-type chips derived from the
  source filenames, user tags, a computed risk score with a coloured accent, and
  a status badge. Controls: free-text search, scanner-type filter pills, refresh,
  and a "New Scan" shortcut. The empty state offers a
  "Re-import from processed/" action (`POST /api/imports/reimport`).
- **`/targets/:id`** shows tabs conditioned on the detected scan type:
  Subdomains, Websites (this is where gowitness screenshots appear), Ports, Vulns
  (severity filter + search + pagination), Raw Output (whois), and Map (renders
  `components/TopologyGraph.tsx` for subdomain/port data). Notes and tags are an
  inline collapsible panel saved with `PATCH /api/targets/:id`. A downloads menu
  exports the target as JSON / CSV / TXT, links a raw-source ZIP
  (`/api/targets/:id/raw-zip`) and per-bundle gowitness ZIPs
  (`/api/gowitness-bundle/<bundle>/zip`), and offers a Markdown report on the
  Vulns tab.

### Vulnerabilities (`App.tsx` — `VulnsPage`)

All vulnerabilities flattened across targets. Severity chips (ALL / CRITICAL /
HIGH / MEDIUM / LOW / INFO, each with a live count, syncable via a `?sev=` URL
param), free-text search, and a project filter (auto-selecting the active
project). An **Export** dropdown downloads the currently filtered list as JSON,
CSV, or TXT entirely client-side.

### Findings Triage (`components/FindingsTriage.tsx`)

Cross-target findings view backed by `GET /api/findings` (server-side dedup by
name+severity, with `affectedDomains`, project/prefix/severity/search filters and
pagination):

- **Mark false positive** — `POST /api/findings/mark-fp` (persisted per target).
- **SearchSploit lookup** — `GET /api/searchsploit/<query>`; when searchsploit is
  not installed on the bridge the UI links out to exploit-db.com instead.
- **CVE lookup** — `GET /api/cve/<id>`.
- **AI summary** — `POST /api/ai/analyze`.
- **Export CSV** of the findings.

### CVE Inventory (`components/InventoryMonitor.tsx`)

Matches detected technologies/versions to CVEs.

- **Technology extraction** happens on the bridge from nuclei findings
  (template id + `rawContent`); only entries with a determinable version are
  kept, to keep NVD queries meaningful.
- **NVD query** (`_query_nvd`) keyword-searches the NVD CVE 2.0 API (paginated,
  optional `NVD_API_KEY` for a higher rate limit) and marks each CVE `verified`
  only when a CPE match confirms the version — otherwise it is flagged
  **unverified**.
- **Enrichment** from `github.com/CVEProject/cvelistV5`: the **KEV** flag comes
  from the CISA ADP container, **PoC** references from references tagged
  exploit/PoC (or GitHub PoC-looking URLs), plus affected products. Single and
  batch lookups (`GET /api/cve/<id>`, `POST /api/cve/batch`, capped at ~30 IDs)
  are cached on disk for 7 days.
- **UI**: KEV / PoC / NEW / unverified badges with a legend bar and hover
  tooltips; filters for project, search, severity, and new-only; a background
  refresh with progress (`POST /api/inventory/refresh`,
  `GET /api/inventory/status`).
- **AI Analysis panel** — separate from the shared AI backend. It calls
  `POST /api/inventory/ai-analyze` with the provider chosen in the panel
  (**anthropic**, **openai**, or **ollama**); the API key/model/base-URL and
  chunk size are kept in browser `localStorage`, and the inventory is sent in
  chunks.

### Scans (`/scans`, tabbed)

- **Quick Scan** (`components/QuickScan.tsx`) — one-click preset recon. Pick from
  a module list (default `httpx` + `nuclei`), a target, a fleet size (default 3),
  optional scan name and extra args, then launch each module via
  `POST /api/axiom/scan`. It reads `target` and `module` from URL query params,
  which is how Ghostwriter deep-links into it (see Ghostwriter integration).
- **Launch Scan** (`components/ScanLauncher.tsx`) — the full scan form:
  - Scan name, multi-line targets, module selection, and auto-generated output
    filenames.
  - **Fleet control**: spin up N instances (`--spinup`), fleet prefix
    (`--fleet`), regions (`--regions`), remove-when-done (`--rm-when-done`),
    shutdown-when-done (`--shutdown-when-done`), custom SSH (`--custom-ssh`),
    cache (`--cache`).
  - **Options that reach `axiom-scan`**: remote wordlist (`-w`), threads
    (`--threads`), max runtime (`--max-runtime`), don't-shuffle, don't-split,
    expand-cidr, anew, quiet, unsafe, and free-form extra args.
  - **Split mode** (`splitModulesPerInstance`) runs one `axiom-scan` per module
    on dedicated instances.
  - **Command preview** via `POST /api/axiom/scan/preview` shows the exact
    command before launching, and `projectToken` associates the scan with a
    project.
  - *Note:* the form also surfaces local-folder, local-config, and
    local-wordlist-distribution inputs, but the current bridge does **not**
    forward these to `axiom-scan`.
- **Active / Monitor** (`components/ActiveScans.tsx`) — live scan status and
  history. Each scan runs in a dedicated **tmux session** on the bridge host, so
  it survives a browser refresh (`tmux attach -t <session>` to watch it
  manually). The bridge reports status by merging `scans.json` with
  `~/.axiom/stats.log`; cancel via `POST /api/axiom/scans/<id>/cancel`.
- **Output Viewer** (`components/ScanOutput.tsx`) — per-scan logs, targets,
  screenshots, and downloads served from the scan endpoints below.

### Fleet (`components/FleetControl.tsx` / `FleetManager.tsx`)

Fleet overview (name, status, IP, provider, region, type) from `GET /api/fleet`
(cached, TTL `FLEET_CACHE_TTL`, default 30s; `?refresh=true` bypasses the cache,
`?filter=managed|all`). Actions, all restricted to Ax-managed instances
validated against `~/.axiom/selected.conf`:

- Power on/off — `POST /api/axiom/fleet/power`
- Execute command — `POST /api/axiom/fleet/exec`
- SSH command — `POST /api/axiom/fleet/ssh`
- Terminate — `POST /api/axiom/fleet/rm`
- Tracked scan prefixes — `GET`/`POST`/`DELETE /api/axiom/fleet/prefixes`

### Workflows (`components/WorkflowBuilder.tsx` + `tools/workflow-runner.py`)

A DAG pipeline editor that chains scans so each step feeds the next.

- **Step model**: each step links to zero or more parents. No parent = a root
  that consumes the workflow's initial targets; one parent = sequential; multiple
  parents = fan-in that waits for all parents and merges/deduplicates their
  outputs.
- **Provisioner-aware module picker** (`services/provisioner.ts`): only modules
  present on the detected fleet image are selectable; others are greyed out with
  the image(s) that would provide them. Images: **barebones**, **default**,
  **reconftw**, **extras**.
- **Built-in templates** (7 playbooks): IP Recon, Deep IP Scan, Quick Domain
  Recon, Full Domain Recon, Bug Bounty, Subdomain Probe, and URL Audit.
- **Custom templates** are saved to both browser `localStorage` and the server
  (`GET`/`POST`/`DELETE /api/workflows/user`), round-tripping the full branch
  structure.
- **Execution** (`POST /api/workflow/run`): the runner topologically sorts steps
  into execution "waves", runs siblings in a wave in parallel threads, spins up a
  per-step fleet sized from the step weight and target count (never more
  instances than targets), waits for real completion (filesystem-first, with a
  bridge-status fallback), passes structured output downstream, and always tears
  the step's fleet down afterwards. The UI polls
  `GET /api/workflow/<run>/status` (~4s) for per-step progress and logs, and can
  `POST /api/workflow/<run>/abort`.

### Settings (`components/Settings.tsx`)

Tabbed: **Connection**, **Ax Updater** (streams `GET /api/axiom/update`; version
info from `GET /api/axiom/version`), **Geo Map** (toggle online IP-geolocation
fallback; status from `GET /api/geo/status`, enrichment via
`POST /api/geo/enrich`), **MCP Server** (start/stop/status via `/api/mcp/*`),
**AI Analysis** (shows provider status from `GET /api/ai/status`), and
**Projects**. Standalone projects created here live only in the bridge; projects
synced from Ghostwriter are managed there.

### Account & admin

- **Login** (`components/LoginPage.tsx`) — credential login against the bridge.
- **My Profile** (`components/UserProfile.tsx`) — self-service password change.
- **Admin** (`components/AdminPanel.tsx`, `admin` role only) — tabs for **Users**,
  **Teams**, and **Invites**: create users and set roles, manage teams, and issue
  invite codes.
- **Documentation** (`/docs`, inline in `App.tsx`) — sections: Quick Start, Scan
  Modules, Dashboard Guide, Themes, Importing Results, Fleet Management,
  Notifications, Workflow Builder, Findings Triage.

## Authentication & multi-user

- Auth is a **Bearer-token** gate, enabled only when `GUI_AX_PASSWORD` is set;
  with it empty the dashboard runs open with full admin access (single-user
  fallback).
- `index.tsx` wraps `window.fetch` to attach `Authorization: Bearer
  <ax_auth_token>` (from `localStorage`) to every request, and in production
  rewrites `http://localhost:5000` to a relative path (so nginx proxies it).
- Login (`POST /api/auth/login`) checks the multi-user store first, then the
  env-var single-user admin, and returns a token; `GET /api/auth/status` reports
  identity, role, and accessible projects; `POST /api/auth/logout` revokes it.
- `GUI_AX_STATIC_TOKEN` is always valid and always admin, so sessions survive a
  bridge restart. On first run an admin user is bootstrapped from
  `GUI_AX_USERNAME` / `GUI_AX_PASSWORD`.
- Regular users see only scans/targets for their assigned projects (plus personal
  and workflow scans); admins see everything.

## AI integration

Two independent paths, both keyless-friendly:

- **Shared backend** — `GET /api/ai/status` and `POST /api/ai/analyze`. In
  `"auto"` mode the bridge prefers **Ollama** (`OLLAMA_URL`, `OLLAMA_MODEL`),
  then **Claude** (`ANTHROPIC_API_KEY`, `CLAUDE_MODEL`); if neither is available
  it returns HTTP 400 and the frontend falls back to a local deterministic
  analysis. Nothing uses Gemini.
- **CVE Inventory panel** — `POST /api/inventory/ai-analyze` with a
  browser-selected provider (anthropic / openai / ollama) and a key kept in
  `localStorage` (see CVE Inventory above).

The service file `services/geminiService.ts` is a legacy name that calls the
bridge's `/api/ai` endpoints — it does not talk to Gemini.

## Bundled offline tooling

The Docker image installs and wires up two extra tools:

- **SearchSploit** (Exploit-DB) — cloned to `/opt/exploitdb`, exposed at
  `GET /api/searchsploit/<query>` (used in Findings Triage), and registered as an
  Ax scan module via `tools/axiom-modules/searchsploit.json` for use against the
  fleet.
- **Metasploit Framework** — installed and registered as an Ax scan module via
  `tools/axiom-modules/metasploit.json` (for the module to run remotely,
  `msfconsole` must also be on the fleet base image).

## Ghostwriter integration

The bridge exposes an admin API used by a companion Ghostwriter Django app:

- Sync projects and users — `POST`/`GET /api/admin/projects`,
  `GET`/`POST /api/admin/users`, `DELETE /api/admin/users/<username>`.
- Per-user token for embedded views — `POST /api/admin/users/<username>/token`
  (so each consultant sees their own data inside the iframe).
- Retag historical targets to a project label — `POST /api/projects/<token>/retag-targets`.
- Scans labelled `gw-<client-slug>-…` (e.g. `gw-acme-5`) map to a project by
  client slug.
- The UI accepts `?autoauth=<token>` (handled in `App.tsx`), which stores the
  token and strips it from the URL — used for Ghostwriter deep links and the
  embedded Quick Scan iframe.

## Bridge API reference

HTTP methods are taken from the `@app.route` decorators in
`tools/axiom-bridge.py`.

**Health & config**

- `GET /health`
- `GET /api/axiom/config`

**Auth**

- `GET /api/auth/status` · `POST /api/auth/login` · `POST /api/auth/logout`

**Targets**

- `GET /api/targets` (optional `?projectToken=`) · `DELETE /api/targets` (bulk)
- `GET`/`PATCH`/`DELETE /api/targets/<id>`
- `GET /api/targets/<id>/raw-zip` · `GET /api/targets/<id>/risk`

**Imports & debug**

- `GET`/`POST /api/imports/scan` · `POST /api/imports/upload` ·
  `POST /api/imports/reimport`
- `GET /api/debug/store`
- `GET /api/screenshots/<path>` · `GET /api/gowitness-bundle/<bundle>/zip`

**Fleet**

- `GET /api/fleet` · `GET /run-axiom-ls`
- `GET`/`POST`/`DELETE /api/axiom/fleet/prefixes`
- `POST /api/axiom/fleet/power` · `POST /api/axiom/fleet/exec` ·
  `POST /api/axiom/fleet/ssh` · `POST /api/axiom/fleet/rm`

**Scans & modules**

- `GET /api/axiom/modules`
- `POST /api/axiom/scan` · `POST /api/axiom/scan/preview`
- `GET /api/axiom/scans` · `GET /api/axiom/scans/<id>`
- `PUT`/`DELETE /api/axiom/scans/<id>/project` ·
  `POST /api/axiom/scans/<id>/cancel` · `POST /api/axiom/scans/<id>/complete`
- `GET /api/axiom/scans/<id>/targets` · `GET /api/axiom/scans/<id>/logs` ·
  `GET /api/axiom/scans/<id>/screenshots` · `GET /api/axiom/scans/<id>/img/<path>`
- `GET /api/axiom/scans/filesystem/discover`
- `GET /api/axiom/update` · `GET /api/axiom/version`

**Workflows**

- `POST /api/workflow/run` · `GET /api/workflow/<run>/status` ·
  `GET /api/workflow/<run>/log` · `POST /api/workflow/<run>/abort`
- `GET`/`POST /api/workflows/user` · `DELETE /api/workflows/user/<id>`

**Projects**

- `GET`/`POST /api/admin/projects`
- `GET /api/projects/mine` · `POST /api/projects` ·
  `PATCH`/`DELETE /api/projects/<token>`
- `GET /api/projects/<token>/linked-scans` ·
  `POST /api/projects/<token>/retag-targets`

**Users, teams & invites**

- `GET`/`POST /api/users` · `GET /api/users/me` ·
  `GET`/`PATCH /api/users/me/prefs` · `PUT /api/users/me/password`
- `PATCH`/`DELETE /api/users/<id>` · `PUT /api/users/<id>/password`
- `GET`/`POST /api/teams` · `DELETE /api/teams/<id>`
- `GET`/`POST /api/invites` · `GET /api/invites/my` ·
  `POST /api/invites/accept` · `DELETE /api/invites/<id>`
- `GET`/`POST /api/admin/users` · `DELETE /api/admin/users/<username>` ·
  `POST /api/admin/users/<username>/token`

**CVE, SearchSploit, inventory & AI**

- `GET /api/cve/<id>` · `POST /api/cve/batch`
- `GET /api/searchsploit/<query>`
- `GET /api/inventory` · `POST /api/inventory/refresh` ·
  `GET /api/inventory/status` · `POST /api/inventory/ai-analyze`
- `GET /api/ai/status` · `POST /api/ai/analyze`

**Findings, wordlists & geo**

- `GET /api/findings` · `POST /api/findings/mark-fp`
- `GET /api/wordlists`
- `GET /api/geo/status` · `POST /api/geo/enrich`

**MCP** (admin-only)

- `GET /api/mcp/status` · `POST /api/mcp/start` · `POST /api/mcp/stop`

## MCP server (`tools/mcp-server.py`)

A Model Context Protocol server (FastMCP) that lets MCP clients (Claude Desktop,
agents, reporting tools) drive the platform as a logged-in account. It is a thin
adapter over the bridge REST API.

- **19 tools**: `start_scan`, `start_full_scan`, `build_workflow`, `list_scans`,
  `get_scan`, `get_scan_output`, `get_workflow_status`, `list_vulnerabilities`,
  `list_targets`, `get_target`, `list_users`, `add_user`, `list_teams`,
  `create_team`, `add_user_to_team`, `create_invite`, `list_fleet`,
  `terminate_fleet`, `whoami`.
- **Auto-terminate enforced**: MCP-launched scans set `rmWhenDone`, and workflows
  set `autoTerminateFleet`, so fleets never leak.
- **Fleet cap**: `GUIAX_MAX_INSTANCES` (default 5) clamps every launch.
- **Transports**: `stdio` (Claude Desktop) plus `sse` and `streamable-http` (for
  remote agents). The bridge's `POST /api/mcp/start` only launches the network
  transports (default `streamable-http` on `:8787`); stdio is launched directly.
- **Auth**: `GUIAX_TOKEN` (static) or `GUIAX_USERNAME`/`GUIAX_PASSWORD`; when
  started from the Settings UI the bridge injects the calling account's token so
  actions are attributed to that user.

## Deployment

- **Development** — `docker-compose.yml`: builds the all-in-one image (Ax +
  dashboard), runs the Vite dev server with source bind-mounts for hot reload,
  and exposes **3000** (UI), **5000** (bridge), and **8787** (MCP). `tmux` is
  required in the container for scan execution. `tools/start-dev.sh` runs the
  bridge + Vite on bare metal.
- **Production** — `docker-compose.prod.yml` + `Dockerfile.prod`: nginx serves
  the pre-built frontend on **:80** and proxies `/api/` to the bridge on
  **:5000**; MCP is available on **:8787**. No source bind-mounts.
- Secrets come from a git-ignored `.env` (see `.env.example`).

## Environment variables

**Bridge** — `PORT`, `HOST`, `STORE_PATH`, `IMPORTS_PATH`, `AXIOM_HOME`,
`AXIOM_LS_PATH`, `AXIOM_TMP`, `WATCHER_INTERVAL`, `FLEET_CACHE_TTL`,
`GUI_AX_USERNAME`, `GUI_AX_PASSWORD`, `GUI_AX_SECRET_KEY`, `GUI_AX_STATIC_TOKEN`,
`ANTHROPIC_API_KEY`, `CLAUDE_MODEL`, `OLLAMA_URL`, `OLLAMA_MODEL`, `NVD_API_KEY`,
`WF_LOG_DIR`, and a GeoIP database path via `GEOIP_DB_PATH`
(`tools/importers/base.py`). AWS hardening: `AWS_MAX_ATTEMPTS`, `AWS_RETRY_MODE`,
`AXIOM_EXCLUDED_REGIONS` (see `tools/setup-aws-region-filter.sh`).

**Workflow runner** — `BRIDGE_URL`, `WF_BRIDGE_TOKEN`, `WF_POLL_INTERVAL`,
`WF_SCAN_TIMEOUT`, `WF_LOG_DIR`.

**MCP server** — `GUIAX_BRIDGE_URL`, `GUIAX_TOKEN`, `GUIAX_USERNAME`,
`GUIAX_PASSWORD`, `GUIAX_DEFAULT_REGION`, `GUIAX_MAX_INSTANCES`, `GUIAX_MCP_HOST`,
`GUIAX_MCP_PORT`.

## Theming

Dual design system toggled from the top bar and persisted in `localStorage`
(`applyTheme` toggles a `.dark` class on `<html>`; default is light). Light mode
is the "Airtable editorial" palette (white canvas, per-card solid-accent stat
tiles); dark mode is the "Raycast developer-tools" palette (near-black canvas,
hairline borders, per-card accent glow on hover). See `DESIGN.md` and
`DESIGN-LIGHT.md` for the full palettes and rules to follow when changing the UI.
