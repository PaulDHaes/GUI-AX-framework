# GUI-AX — Dashboard for the Ax Recon Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node ≥ 18](https://img.shields.io/badge/Node-%E2%89%A518-brightgreen)](https://nodejs.org/)
[![Python ≥ 3.9](https://img.shields.io/badge/Python-%E2%89%A53.9-blue)](https://python.org/)

A React + Flask dashboard for [Ax](https://github.com/attacksurge/ax) — the distributed cloud reconnaissance framework. Turns Ax's CLI tools into a real-time web UI for managing fleets, launching scans, and exploring results.

## ![Dashboard Screenshot](./images/dashboard.jpg)

> **⚠️ Tested Environment:** This dashboard has been developed and tested exclusively with **AWS** as the cloud provider. Other providers (DigitalOcean, Azure, Linode, GCP, etc.) are supported by Ax and should work, but have not been verified with this dashboard. If you encounter provider-specific issues, please open an issue.

---

## 🚦 Quick Start — from zero to first scan

> **New to Ax too?** Follow every step. Already have Ax configured? Jump to [step 3](#3-start-the-dashboard).

> **Want to see the full installation processes manually or using Docker** checkout [Installation](#Installation).

### 1. Install everything with one command

Run this on your Linux or macOS machine:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/PaulDHaes/GUI-AX-framework/main/tools/gui-ax-install.sh)
```

The installer will walk you through:

- Installing Node.js ≥ 18 and Python ≥ 3.9 if missing
- Cloning **Ax** to `~/.axiom` and running `axiom-configure` to connect your cloud account (DigitalOcean, AWS, Azure, Linode, etc.)
- Cloning this dashboard to `~/gui-ax-framework`
- Installing all dependencies (`npm install`, `pip install flask flask-cors`)
- Creating a `.env` config file

If you want to **skip Ax setup** and just install the dashboard:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/PaulDHaes/GUI-AX-framework/main/tools/gui-ax-install.sh) --skip-ax
```

---

### 2. Configure your cloud provider (first time only)

If the installer ran `axiom-configure` for you, this is already done. If you skipped it:

```bash
axiom-configure --run
```

This sets up your cloud API key and SSH key so Ax can provision instances. See the [Ax docs](https://github.com/attacksurge/ax) for provider-specific instructions.

Once configured, test it:

```bash
# Spin up a small test fleet (1 instance)
axiom-fleet myfleet -i 1

# Confirm it appeared
axiom-ls

# Tear it down
axiom-rm myfleet\* -f
```

---

### 3. Start the dashboard

```bash
cd ~/gui-ax-framework
bash tools/start-dev.sh
```

This starts both the Flask bridge (port **5000**) and the Vite UI (port **3000**) together.

Open **http://localhost:3000** in your browser.

The dashboard auto-connects to `http://localhost:5000` by default. Go to **Settings** to verify the health check shows ✅ _Bridge is reachable_.

> **🐳 Docker / Remote users:** Both ports **3000** (UI) and **5000** (bridge API) must be exposed and accessible. If running inside Docker, map both ports: `-p 3000:3000 -p 5000:5000`. If running on a remote server, ensure both ports are open in your firewall / security group.

---

### 4. Provision a fleet & run your first scan

1. Go to **Fleet Manager** → click **Initialise Fleet**, choose a size (start with 3 instances)
2. Wait for instances to go green (~60 seconds)
3. Go to **Scan Launcher** → pick a module (e.g. `httpx`), paste your targets, click **Launch**
4. Watch live progress in **Active Scans**
5. Click any completed scan to view results — structured tables, screenshot gallery, and raw logs

> **💡 How scans run:** Each scan launches in its own **tmux session** on the bridge server. This means scans keep running even if you close the browser. To manually inspect a running scan, attach to its tmux session: `tmux ls` to list sessions, then `tmux attach -t <session-name>`. The dashboard's Active Scans page polls the bridge for status updates automatically.

---

### 5. Keep Ax up to date

Ax releases frequent updates with new modules and bug fixes. Update from the dashboard:

**Settings → Ax Updater → Pull latest Ax**

Or from the terminal:

```bash
ax update
```

---

## What it does

### 🚀 Scan Launcher

Launch distributed scans across your entire cloud fleet with a few clicks. Pick a module (nuclei, amass, nmap, httpx, ffuf, …), enter your targets, configure options, and fire. The UI shows which tools are available per provisioner image (barebones, default, reconftw, etc.) so you only see what's actually installed on your fleet.

## ![scanlauncher-1 Screenshot](./images/run-scan-1.jpg)

## ![scanlauncher-2 Screenshot](./images/run-scan-2.jpg)

> **Tested modules:** The following modules have been verified end-to-end with this dashboard: `nuclei`, `amass`, `subfinder`, `httpx`, `nmap`, `naabu`, `ffuf`, `gowitness`, `dnsx`, `whois`, and `masscan`. Other Ax modules should work but may not have structured output parsing — results will still appear as raw log lines.

### 🧩 Workflow Builder

Chain scans into automated pipelines instead of launching each module by hand. The Workflow Builder is a **DAG (directed-acyclic-graph) pipeline editor** — you add modules as steps and link them together, and the output of each step is fed automatically into the next. No more copying files between tools or dropping output into `imports/` by hand.

- **Sequential, parallel & fan-in steps** — link a step to one parent to run it after that step completes, leave it unlinked to run it as a parallel root, or give it multiple parents to join several branches (fan-in). Classic recon chain:

  ```
  subfinder  →  httpx (live host filter)  →  nuclei
                                         ↘  gowitness
  ```

- **AMI-aware module picker** — like the Scan Launcher, the builder only offers modules that are actually baked into your fleet's provisioner image (barebones / default / reconftw / extras). Unavailable modules are greyed out with a badge showing which image would provide them, so you can't build a pipeline your fleet can't run.
- **Saveable custom templates** — build a pipeline once, click **Save as template**, and it's stored (in your browser's `localStorage`) alongside the built-in playbooks. Custom templates round-trip the full branch structure, so reloading one restores every sequential/parallel/fan-in link exactly. Delete them from the template gallery when you're done.
- **Built-in playbooks** — a set of ready-made linear pipelines you can load and tweak as a starting point.
- **Backend step sequencer** — pipelines are executed by `tools/workflow-runner.py`, which topologically sorts the steps, groups them into execution "waves", launches each module via the bridge, waits for real completion, and passes structured output downstream. The UI polls run status live and shows per-step progress, logs, and an abort button.

### 🖥️ Fleet Manager

View and control every instance in your Ax fleet — provider, region, IP, status, specs, and cost. Power instances on/off, SSH in, run commands across the whole fleet, or delete instances directly from the UI. Supports DigitalOcean, AWS, Azure, Linode, and more.

### 📊 Active Scans

Real-time monitor for running `axiom-scan` jobs. See live progress, elapsed time, and output as it arrives. Cancel scans from the dashboard. Scans that fail due to missing tools or bad container images are clearly flagged as **failed** with the reason extracted from logs — no more false "completed" statuses.

Each scan runs in a dedicated **tmux session** so it persists independently of the browser. You can attach to any running scan's tmux session from the terminal (`tmux attach -t <scan-session>`) for direct log access.

### 🔍 Per-scan Output Viewer

## ![vulns Screenshot](./images/vulns.jpg)

## ![outputscan Screenshot](./images/output-scan.jpg)

Deep-dive into any individual scan result:

- **Screenshot gallery** — tall image cards (with lightbox) for gowitness / webscreenshot / aquatone scans
- **Structured tables** — HTTP results (status code · URL · title), port results (port · state · service), vulnerability results (severity · template · target)
- **Smart filter chips** — filter by HTTP status code, nuclei severity, or nmap port state with a single click
- **Full-text search** — search across all raw log lines
- **Failure banner** — red alert with the exact log lines that caused the failure if a scan went wrong

### 📁 Auto-Import & Target Database

Drop scan output into `imports/` and the bridge auto-parses it. Results land in a searchable target database with subdomains, open ports, vulnerabilities, whois data, and HTTP info — all merged per target even when sourced from multiple tools.

Supported formats imported automatically:
| Tool | Format |
|------|--------|
| nuclei | JSON |
| amass | JSON / plain text |
| nmap | XML |
| nmapx | XML |
| httpprobe | plain |
| httpx | JSON |
| dnsx | JSON / plain text |
| subfinder | JSON |
| whois | plain text (`.dir` batch folders) |
| gowitness | plain text |
| ffuf | JSON |

### ✅ Tested Modules & Provider

| Aspect                      | Details                                                                                                                                 |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Cloud provider**          | AWS (tested) — other Ax-supported providers should work but are unverified                                                              |
| **Scan modules (verified)** | `nuclei`, `amass`, `subfinder`, `httpx`, `nmap`, `naabu`, `ffuf`, `gowitness`, `dnsx`, `whois`, `masscan`                               |
| **Import parsers**          | nuclei (JSON), amass (JSON/txt), nmap (XML), httpx (JSON), ffuf (JSON), gowitness (txt), subfinder (JSON), dnsx (JSON/txt), whois (dir) |
| **Scan execution**          | Each scan runs in a dedicated **tmux session** — survives browser close, attachable from terminal                                       |

### 🗺️ Geographic Map

D3 world map showing where your assets are located. Dots are colour-coded green → yellow → red by asset count, and stay readable at any zoom level. It draws from **two independent geo sources**:

- **WHOIS** — the registrant country from whois scans, plotted at the country centroid (white ring).
- **IP geolocation** — forward-resolves every host and geolocates its IP to a **city-level** dot (cyan ring). Two providers:
  - **Locate by IP** (offline) — looks IPs up in a local **MaxMind GeoLite2** database. Fully private: no target IP ever leaves your machine. Hosts imported with an IP already present (from httpx/dnsx) are geolocated automatically on import.
  - **Online ↗** (no signup) — uses the free [ip-api.com](https://ip-api.com) service, so it works with **zero setup**. The trade-off: your target IPs are sent to a third party, and the free tier is HTTP with a ~15 req/min limit. Only ever runs when you click the button.

  Both cache results per IP, and the button DNS-resolves any hosts that don't yet have an IP.

> **Choosing a provider:** the offline route is the private default and appears whenever a database is present. To enable it, create a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup), download **GeoLite2-City.mmdb**, drop it at `data/GeoLite2-City.mmdb` (or set `GEOIP_DB_PATH`), and install `geoip2` (bundled in the Docker image and installer). Don't want the signup? Just use **Online ↗** — no key or database needed.

> **Disabling online lookups:** if you'd rather never send IPs off-box, turn off **Settings → Map & Privacy → Allow online IP lookups**. The Online button disappears and only the offline provider is offered. (The offline auto-enrich on import never uses the network regardless.)

### 🔗 Topology Graph

D3 force-directed graph of a target's attack surface: domain → subdomains → open ports, rendered interactively.

### 🤖 Risk Analysis

Built-in local risk scoring for targets based on vulnerability severity, open port count, and attack surface size. Provides a 0–10 risk score with prioritised remediation guidance — no external API key required.

### 🔄 Ax Framework Updater

Keep Ax in sync from the dashboard — a dedicated Settings tab shows the current Ax version and lets you pull the latest changes to `~/.axiom` with a single click. The bridge streams git output in real time so you can watch the update happen.

## ![Dashboard Screenshot](./images/system-update.jpg)

### 🔌 MCP Server (drive the dashboard from AI tools)

An optional **Model Context Protocol** server ([tools/mcp-server.py](tools/mcp-server.py)) exposes the platform's core functions as MCP tools, so any MCP client — Claude Desktop, an agent, or a reporting workflow such as **Ghostwriter** — can operate the dashboard as a specific logged-in account. It's a thin adapter over the bridge REST API, so all logic and auth stay in one place.

**Tools exposed** (19): `start_scan`, `start_full_scan`, `build_workflow`, `list_scans`, `get_scan`, `get_scan_output`, `get_workflow_status`, `list_vulnerabilities`, `list_targets`, `get_target`, `list_users`, `add_user`, `list_teams`, `create_team`, `add_user_to_team`, `create_invite`, `list_fleet`, `terminate_fleet`, `whoami`.

- **Auto-terminate is enforced** — every scan or workflow launched through MCP spins up a fresh fleet and tears it down when done. An MCP caller can never leave cloud instances running.
- **Acts as one account** — point it at a bridge and give it a token or username/password; all actions are attributed to that user. Run one instance per account for per-user isolation.
- **Reporting-ready** — `list_vulnerabilities` returns flattened, severity-sorted findings (`target · severity · name · matched · type · description`) ideal for pulling into a Ghostwriter report, and `list_scans` / `get_target` expose the underlying scan data.

**Turn it on from the dashboard** — go to **Settings → MCP Server** and flip the toggle. The bridge launches the server as a background process (streamable-HTTP on port `8787` by default), points it back at itself, and runs it **as your logged-in account**. The panel shows the live status, the client endpoint to hand to your MCP tool, and a tail of the server log; flip it off to stop the process. (Admin only when auth is enabled; port `8787` is already published in `docker-compose.yml`.)

**Or run it manually** (stdio for Claude Desktop, HTTP for remote/agents):

```bash
# stdio (local)
GUIAX_USERNAME=alice GUIAX_PASSWORD=… python3 tools/mcp-server.py

# streamable HTTP (remote tools / Ghostwriter integration)
python3 tools/mcp-server.py --transport streamable-http --host 0.0.0.0 --port 8787
```

Configure with env vars: `GUIAX_BRIDGE_URL` (default `http://localhost:5000`), `GUIAX_TOKEN` **or** `GUIAX_USERNAME`/`GUIAX_PASSWORD`, `GUIAX_DEFAULT_REGION`, `GUIAX_MAX_INSTANCES` (fleet cap, default 5).

Example Claude Desktop entry (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "gui-ax": {
      "command": "python3",
      "args": ["/absolute/path/to/gui-ax-framework/tools/mcp-server.py"],
      "env": { "GUIAX_BRIDGE_URL": "http://localhost:5000",
               "GUIAX_USERNAME": "alice", "GUIAX_PASSWORD": "your-password" }
    }
  }
}
```

> **Ghostwriter workflow:** run the server with `--transport streamable-http` next to the bridge; an operator (or an agent working alongside Ghostwriter) authenticates as their dashboard account and can then pull `list_vulnerabilities` / scan data into a report **and** kick off `start_full_scan` / `build_workflow` against the right targets without leaving their reporting flow. Ghostwriter has no native MCP client today, so this is consumed via an MCP-capable agent or a small connector — see the note below.

### 👥 Multi-user, Teams & Invites

The dashboard supports **multiple users** with a login screen and role-based access. Admins get an **Admin Panel** to create users, manage roles, and reset passwords; everyone gets a **User Profile** page to change their own password.

- **Login & sessions** — users authenticate against the bridge (`/api/auth/login`); the Admin nav and panel are gated to the `admin` role.
- **Teams** — group users into project teams. The dashboard can scope the target view to _all_, _personal_, or a specific team, so team members only see the scans and workflows that belong to their project (direct scans are prefixed `teamSlug/…` and workflow scans `wf-teamSlug-…`).
- **Invites** — admins issue invite codes that new users redeem to join a team.

> **Single-user fallback:** if no users are configured, the dashboard runs open with full admin access — the same behaviour as before auth existed — so existing single-user setups keep working unchanged.

---

## How it works

```
┌──────────────────────────────────────────────────────┐
│         React / TypeScript  (Vite — port 3000)       │
│  Fleet · Scans · Workflows · Targets · Map · Risk    │
└──────────────────────┬───────────────────────────────┘
                       │  HTTP REST  (localhost:5000)
                       ▼
┌──────────────────────────────────────────────────────┐
│            axiom-bridge.py  (Python / Flask)         │
│                                                      │
│  ① REST API — fleet, scan, target, import endpoints  │
│  ② Subprocess wrapper — shells out to Ax CLI via zsh │
│  ③ Scan runner — each scan launched in its own tmux  │
│     session (survives browser close)                 │
│  ④ File watcher — polls imports/ and auto-parses     │
│     tool output (nuclei, nmap, httpx, ffuf, …)       │
│  ⑤ Flat JSON store — target DB merged across tools   │
│  ⑥ Workflow sequencer — runs DAG pipelines in waves  │
│     (workflow-runner.py), feeding step → step        │
└──────────────────────┬───────────────────────────────┘
                       │  subprocess / zsh
                       ▼
┌──────────────────────────────────────────────────────┐
│              Ax framework  (~/.axiom)                │
│   axiom-scan · axiom-ls · axiom-exec · axiom-power   │
└──────────────────────┬───────────────────────────────┘
                       │  SSH / cloud API
                       ▼
┌──────────────────────────────────────────────────────┐
│  Cloud fleet  (AWS tested · DO / Azure / GCP /       │
│  Linode / Hetzner / IBM / Scaleway / Exoscale)       │
└──────────────────────────────────────────────────────┘
```

### What the bridge actually does

The Flask bridge (`tools/axiom-bridge.py`) is the only piece talking to Ax. The React frontend never calls Ax directly — it speaks REST to the bridge, and the bridge shells out to `axiom-scan`, `axiom-ls`, `axiom-exec`, and friends via a `subprocess` call into `zsh`.

**Scan lifecycle:**

1. UI sends `POST /api/axiom/scan` with module, targets, and fleet name
2. Bridge builds an `axiom-scan` command and launches it inside a named **tmux session** (`ax-scan-<id>`)
3. Bridge polls the tmux session for output and exposes it via `GET /api/axiom/scans/<id>/output`
4. When the scan finishes, Ax drops result files into the configured output path
5. Bridge detects the output and moves it into `imports/` for auto-parsing
6. Parser normalises tool output (JSON / XML / plain text) and merges it into the flat target store

**Why tmux?** Scans keep running even if you close the browser tab, lose connectivity, or restart the UI. You can always `tmux attach -t ax-scan-<id>` to watch a scan in real time from any terminal.

**Risk scoring** is entirely local and deterministic — no external API calls. The scorer weights vulnerabilities by severity (critical → 5 pts, high → 4, medium → 2, low → 1), adds a small factor for open port count and subdomain spread, and clamps the result to a 0–10 scale. No Gemini key or any other AI service is needed or used for this feature.

---

## Installation

### One-liner (recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/PaulDHaes/GUI-AX-framework/main/tools/gui-ax-install.sh)
```

The installer will:

1. Check / install system dependencies (git, Node.js ≥ 18, Python ≥ 3.9)
2. Offer to install the **Ax framework** itself (`~/.axiom`) — full setup or clone-only
3. Clone this repo to `~/gui-ax-framework`
4. Run `npm install` and `pip install flask flask-cors`
5. Generate a `.env` config (ports, optional Gemini key)
6. Optionally create a systemd service (Linux)

**Flags:**

```
--skip-ax          Dashboard only, don't touch Ax
--unattended       Silent install with all defaults
--update           Pull latest changes for both repos
--dir <path>       Custom install directory
--port <port>      Bridge API port  (default 5000)
--ui-port <port>   UI port          (default 3000)
```

---

### Manual install

**Prerequisites:** Node.js ≥ 18, Python ≥ 3.9, git, and [Ax](https://github.com/attacksurge/ax) installed & configured.

```bash
# 1. Clone
git clone https://github.com/PaulDHaes/GUI-AX-framework ~/gui-ax-framework
cd ~/gui-ax-framework

# 2. Frontend dependencies
npm install

# 3. Backend dependencies
pip3 install flask flask-cors

# 4. Config (copy and edit)
cp .env.example .env
```

---

### Docker install (all-in-one)

Run everything — Ax framework + dashboard — inside a single Docker container. No need to install Ax on your host. This is the same approach as the [official Ax Docker install](https://github.com/attacksurge/ax?tab=readme-ov-file#docker), with the dashboard added on top.

```bash
# 1. Clone the dashboard
git clone https://github.com/PaulDHaes/GUI-AX-framework ~/gui-ax-framework
cd ~/gui-ax-framework

# 2. Build and start
docker compose up --build -d

# 3. Open a shell in the container (auto-prompts axiom-configure on first run)
docker exec -it gui-ax-dashboard zsh
```

**First run:** When you open a shell, it detects Ax isn't configured yet and prompts you to run `axiom-configure --run` — the same interactive setup flow as a fresh Ax install (select cloud provider, enter API keys, build Packer image). The dashboard is already running in the background.

**Subsequent runs:** Ax is already configured, so you get dropped straight into a zsh shell with a status summary. The dashboard is running in tmux.

Once running:

- **http://localhost:3000** — Dashboard UI
- **http://localhost:5000** — Bridge API

**Inside the container:**

Everything lives inside the container — Ax at `/root/.axiom`, dashboard at `/app`. The dashboard runs in a tmux session called `dashboard` with two windows (bridge + Vite). Scans launch in their own tmux sessions, just like a native install.

```bash
# Open a shell (zsh, same as official Ax Docker)
docker exec -it gui-ax-dashboard zsh

# View the dashboard logs
tmux attach -t dashboard

# List all tmux sessions (dashboard + any running scans)
tmux ls

# Run Ax commands directly — everything is on PATH
axiom-ls
axiom-fleet myfleet -i 3
axiom-scan ...
```

**What persists across container restarts:**

| Docker volume | Mounts to   | Contents                             |
| ------------- | ----------- | ------------------------------------ |
| `gui-ax-data` | `/app/data` | Target store (imported scan results) |

> **Note:** Ax config (cloud accounts, SSH keys, Packer images) lives inside the container. If you remove the container (`docker compose down`), you'll need to re-run `axiom-configure --run`. Use `docker compose stop` / `docker compose start` to preserve everything.

To stop / restart / reset:

```bash
docker compose stop          # stop without removing (preserves Ax config)
docker compose start         # restart a stopped container
docker compose down          # remove container (Ax config lost, data volume kept)
docker compose down -v       # full reset — wipes everything
```

---

## Running

```bash
# Start the Flask bridge  (terminal 1)
python3 tools/axiom-bridge.py

# Start the Vite UI       (terminal 2)
npm run dev
```

Or both at once:

```bash
bash tools/start-dev.sh
```

Or with Docker:

```bash
docker compose up --build
```

| Service    | Default URL           |
| ---------- | --------------------- |
| Dashboard  | http://localhost:3000 |
| Bridge API | http://localhost:5000 |

> **Note:** Scans are launched in **tmux sessions** by the bridge. Make sure `tmux` is installed on the machine running the bridge (`brew install tmux` on macOS, `apt install tmux` on Linux). List active scan sessions with `tmux ls`.

---

## Configuration

Create a `.env` file in the repo root (the installer does this for you, or copy from `.env.example`):

```env
# Optional — enables the Gemini AI panel
GEMINI_API_KEY=your_key_here

# Flask bridge port
PORT=5000

# Override data/import paths (defaults are relative to repo root)
# STORE_PATH=./data/axiom_bridge_store.json
# IMPORTS_PATH=./imports
```

| Variable         | Default                          | Description                                    |
| ---------------- | -------------------------------- | ---------------------------------------------- |
| `GEMINI_API_KEY` | _(blank)_                        | Google Gemini key — AI panel disabled if unset |
| `PORT`           | `5000`                           | Flask bridge port                              |
| `STORE_PATH`     | `./data/axiom_bridge_store.json` | Persistent target store                        |
| `IMPORTS_PATH`   | `./imports`                      | Directory watched for scan results             |
| `GEOIP_DB_PATH`  | `./data/GeoLite2-City.mmdb`      | MaxMind GeoLite2 DB for offline IP geolocation on the Geo Map (optional) |

---

## Importing scan results

Drop scan output into `imports/` and the bridge picks it up automatically:

```
imports/
├── nuclei-output.jsonl        # Nuclei JSONL
├── amass-output.json          # Amass JSON / txt
├── nmap-scan.xml              # Nmap XML
├── httpx-results.jsonl        # HTTPx JSONL
├── dnsx-results.txt           # DNSx plain text
├── whois+02-26_23-34.dir/     # Whois batch folder (axiom-scan output)
│   ├── example.com
│   ├── target.org
│   └── ...
└── processed/                 # Auto-moved after import
```

Parsed results merge into the target database — multiple tool outputs for the same domain are combined into one target entry.

---

## Project structure

```
gui-ax-framework/
├── components/
│   ├── FleetManager.tsx     # Instance list, power, SSH, delete
│   ├── FleetControl.tsx     # Fleet-wide exec & control
│   ├── ScanLauncher.tsx     # Scan builder (module, targets, fleet)
│   ├── WorkflowBuilder.tsx  # DAG pipeline editor + saveable templates
│   ├── ActiveScans.tsx      # Live scan monitor (with failure detection)
│   ├── ScanOutput.tsx       # Per-scan output: tables, screenshot gallery, filters
│   ├── GeoMap.tsx           # D3 world map (whois geo dots)
│   ├── TopologyGraph.tsx    # D3 attack-surface graph
│   ├── LoginPage.tsx        # Auth / login screen
│   ├── AdminPanel.tsx       # User & team management (admin only)
│   ├── UserProfile.tsx      # Per-user profile / password change
│   ├── Settings.tsx         # App settings + Ax updater
│   └── ui/                  # shadcn/ui primitives
├── services/
│   ├── axiomProvider.ts     # Bridge API client / state provider
│   └── provisioner.ts       # AMI/provisioner module-availability map
├── tools/
│   ├── axiom-bridge.py      # Flask API + file watcher (main backend)
│   ├── workflow-runner.py   # Backend workflow step sequencer (DAG waves)
│   ├── mcp-server.py        # Model Context Protocol server (AI-tool access)
│   ├── gui-ax-install.sh    # One-liner installer
│   ├── ax-update.sh         # Pull latest Ax framework (~/.axiom)
│   ├── start-dev.sh         # Start bridge + UI together
│   └── docker-entrypoint.sh # Docker container entrypoint
├── Dockerfile               # Container image build
├── docker-compose.yml       # One-command Docker startup
├── imports/                 # Drop scan output here
│   └── processed/           # Auto-moved after import
├── data/                    # Persistent JSON store (git-ignored)
├── .env.example             # Environment variable template
└── .env                     # Your config (not committed)
```

---

## Bridge API reference

Key endpoints exposed by `axiom-bridge.py`:

| Method   | Path                                   | Description                         |
| -------- | -------------------------------------- | ----------------------------------- |
| `GET`    | `/health`                              | Health check                        |
| `GET`    | `/api/axiom/fleet`                     | List all instances                  |
| `POST`   | `/api/axiom/fleet/power`               | Power on/off instance               |
| `DELETE` | `/api/axiom/fleet/<name>`              | Delete instance                     |
| `GET`    | `/api/axiom/modules`                   | List scan modules                   |
| `POST`   | `/api/axiom/scan`                      | Launch a new scan                   |
| `GET`    | `/api/axiom/scans`                     | List all scans                      |
| `GET`    | `/api/axiom/scans/filesystem/discover` | Discover scans from filesystem      |
| `GET`    | `/api/axiom/scans/<id>`                | Get scan details + failure info     |
| `GET`    | `/api/axiom/scans/<id>/output`         | Raw scan log output                 |
| `DELETE` | `/api/axiom/scans/<id>`                | Delete a scan                       |
| `GET`    | `/api/axiom/scans/<id>/screenshots`    | List screenshot paths for scan      |
| `GET`    | `/api/axiom/scans/<id>/img/<path>`     | Serve screenshot image              |
| `GET`    | `/api/axiom/targets`                   | List all targets                    |
| `DELETE` | `/api/axiom/targets/<id>`              | Delete a target                     |
| `GET`    | `/api/axiom/update`                    | Stream Ax framework git pull output |
| `GET`    | `/api/geo/status`                      | Offline IP-geolocation availability |
| `POST`   | `/api/geo/enrich`                      | Resolve + geolocate host IPs (Geo Map) |
| `POST`   | `/api/workflow/run`                    | Launch a workflow pipeline          |
| `GET`    | `/api/workflow/<id>/status`            | Workflow run status + per-step state |
| `GET`    | `/api/workflow/<id>/log`               | Workflow run log                    |
| `POST`   | `/api/workflow/<id>/abort`             | Abort a running workflow            |
| `GET`    | `/api/mcp/status`                      | MCP server process status           |
| `POST`   | `/api/mcp/start` · `/api/mcp/stop`     | Start / stop the MCP server (admin) |
| `GET`    | `/api/auth/status`                     | Current auth / session status       |
| `POST`   | `/api/auth/login`                      | Log in                              |
| `POST`   | `/api/auth/logout`                     | Log out                             |
| `GET`    | `/api/users` · `/api/users/me`         | List users / current user           |
| `POST`   | `/api/users`                           | Create a user (admin)               |
| `GET`    | `/api/teams`                           | List teams                          |
| `POST`   | `/api/teams`                           | Create a team (admin)               |
| `POST`   | `/api/invites` · `/api/invites/accept` | Issue / redeem a team invite        |

---

## Keeping Ax up to date

The dashboard and Ax are two separate projects. Use any of these methods to keep Ax current:

### Option A — Settings UI (easiest)

Open **Settings → Ax Updater** in the dashboard and click **Pull latest Ax**. The bridge runs `git pull` on `~/.axiom` and streams the output live.

### Option B — Update script

```bash
bash tools/ax-update.sh
```

Pulls the latest Ax, re-sources PATH, and optionally restarts the bridge.

### Option C — Installer `--update` flag

```bash
bash tools/gui-ax-install.sh --update
```

Updates both the dashboard repo **and** Ax in one shot.

### Option D — Manual git

```bash
git -C ~/.axiom pull --ff-only origin main
```

---

## 🗺️ Roadmap / TODO

Things that don't exist yet but are planned or being explored. PRs and ideas welcome.

> **✅ Recently shipped** (previously on this list): **scan chaining & automated pipelines** (see [Workflow Builder](#-workflow-builder)), **scan templates / playbooks** (saveable custom workflow templates), a **multi-user & auth layer** with teams and invites (see [Multi-user, Teams & Invites](#-multi-user-teams--invites)), and an **MCP server** for AI-tool access (see [MCP Server](#-mcp-server-drive-the-dashboard-from-ai-tools)).

### Scheduled & recurring scans

Cron-style scheduling so you can run a subdomain enumeration every Monday or a nuclei sweep every 24 hours against a saved target list — with delta alerting to highlight new findings since the last run.

### Notifications & webhooks

- **Slack / Discord / Teams** messages when a scan completes or a critical vuln is found
- Generic **outbound webhook** support (POST a JSON payload to any URL)
- Optional **email digest** with new findings summary

### Extra basic features that didn't make the initial cut but are on the backlog

- **VPS cost estimator** — rough monthly cost based on instance types and uptime
- **Better active scan output parsing** — more structured data extraction for modules like `ffuf` and `gowitness` that currently show raw logs, better live view
- **Scan tagging & categorisation** — better labeling and categorisation of scans for easier filtering and historical analysis

---

## Related

- [Ax](https://github.com/attacksurge/ax) — distributed cloud recon framework

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, branch naming conventions, and the PR process.

## Security

Found a vulnerability? Please read [SECURITY.md](SECURITY.md) before opening a public issue.

## License

MIT — see [LICENSE](LICENSE) for details.
