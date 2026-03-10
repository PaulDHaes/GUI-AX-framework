# GUI-AX — Dashboard for the Ax Recon Framework

[![CI](https://github.com/PaulDHaes/GUI-AX-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/PaulDHaes/GUI-AX-framework/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node ≥ 18](https://img.shields.io/badge/Node-%E2%89%A518-brightgreen)](https://nodejs.org/)
[![Python ≥ 3.9](https://img.shields.io/badge/Python-%E2%89%A53.9-blue)](https://python.org/)

A React + Flask dashboard for [Ax](https://github.com/attacksurge/ax) — the distributed cloud reconnaissance framework. Turns Ax's CLI tools into a real-time web UI for managing fleets, launching scans, and exploring results.

---

## What it does

### 🚀 Scan Launcher

Launch distributed scans across your entire cloud fleet with a few clicks. Pick a module (nuclei, amass, nmap, httpx, ffuf, …), enter your targets, configure options, and fire. The UI shows which tools are available per provisioner image (barebones, default, reconftw, etc.) so you only see what's actually installed on your fleet.

### 🖥️ Fleet Manager

View and control every instance in your Ax fleet — provider, region, IP, status, specs, and cost. Power instances on/off, SSH in, run commands across the whole fleet, or delete instances directly from the UI. Supports DigitalOcean, AWS, Azure, Linode, and more.

### 📊 Active Scans

Real-time monitor for running `axiom-scan` jobs. See live progress, elapsed time, and output as it arrives. Cancel scans from the dashboard. Scans that fail due to missing tools or bad container images are clearly flagged as **failed** with the reason extracted from logs — no more false "completed" statuses.

### 🔍 Per-scan Output Viewer

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

### 🗺️ Geographic Map

D3 world map showing where whois-registered entities are located. Dots are colour-coded green → yellow → red by entity count per country. Zoom-invariant — dots stay readable at any zoom level.

### 🔗 Topology Graph

D3 force-directed graph of a target's attack surface: domain → subdomains → open ports, rendered interactively.

### 🤖 Gemini AI Panel

Optional AI sidebar powered by Google Gemini. Analyse a selected target for risk, or chat with a security-aware assistant in context. Requires a `GEMINI_API_KEY`.

### 🔄 Ax Framework Updater

Keep Ax in sync from the dashboard — a dedicated Settings tab shows the current Ax version and lets you pull the latest changes to `~/.axiom` with a single click. The bridge streams git output in real time so you can watch the update happen.

---

## Architecture

```
┌────────────────────────────────────────────┐
│         React / TypeScript  (Vite)         │
│  Fleet · Scans · Map · Targets · AI panel  │
└───────────────────┬────────────────────────┘
                    │  REST  (localhost:5000)
                    ▼
┌────────────────────────────────────────────┐
│         axiom-bridge.py  (Flask)           │
│  • Ax CLI executor  (axiom-scan / ls / exec)│
│  • imports/ watcher  →  auto-parse results │
│  • Result normaliser + persistent store    │
│  • DELETE / target management endpoints   │
└───────────────────┬────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────┐
│           Ax framework  (~/.axiom)         │
│      axiom-scan · axiom-ls · axiom-exec    │
└───────────────────┬────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────┐
│    Cloud fleet  (DO / AWS / Azure / GCP)   │
│       instance-1 · instance-2 · … · n      │
└────────────────────────────────────────────┘
```

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

| Service    | Default URL           |
| ---------- | --------------------- |
| Dashboard  | http://localhost:3000 |
| Bridge API | http://localhost:5000 |

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
│   ├── ActiveScans.tsx      # Live scan monitor (with failure detection)
│   ├── ScanOutput.tsx       # Per-scan output: tables, screenshot gallery, filters
│   ├── GeoMap.tsx           # D3 world map (whois geo dots)
│   ├── TopologyGraph.tsx    # D3 attack-surface graph
│   ├── Settings.tsx         # App settings + Ax updater
│   └── ui/                  # shadcn/ui primitives
├── services/
│   ├── axApi.ts             # Axios API client
│   ├── axiomProvider.ts     # Data context / state
│   ├── geminiService.ts     # Gemini AI calls
│   └── importService.ts     # Import helpers
├── tools/
│   ├── axiom-bridge.py      # Flask API + file watcher (main backend)
│   ├── gui-ax-install.sh    # One-liner installer
│   ├── ax-update.sh         # Pull latest Ax framework (~/.axiom)
│   └── start-dev.sh         # Start bridge + UI together
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

## Related

- [Ax](https://github.com/attacksurge/ax) — distributed cloud recon framework
- [Nuclei](https://github.com/projectdiscovery/nuclei) — vulnerability scanner
- [Amass](https://github.com/owasp-amass/amass) — subdomain enumeration
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP probing

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, branch naming conventions, and the PR process.

## Security

Found a vulnerability? Please read [SECURITY.md](SECURITY.md) before opening a public issue.

## License

MIT — see [LICENSE](LICENSE) for details.
