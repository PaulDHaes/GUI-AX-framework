# Axiom Dashboard - Complete Security Reconnaissance Platform

> **Tested with:** AWS cloud provider. Other Ax-supported providers (DigitalOcean, Azure, Linode, GCP, Hetzner, IBM Cloud, Scaleway, Exoscale) should work but are unverified.
>
> **Verified modules:** `nuclei`, `amass`, `subfinder`, `httpx`, `nmap`, `naabu`, `ffuf`, `gowitness`, `dnsx`, `whois`, `masscan`

## Project Overview

### What is Axiom Dashboard?

Axiom Dashboard is a comprehensive web-based user interface for [Axiom](https://github.com/pry0cc/axiom), a dynamic infrastructure framework for security reconnaissance. It transforms Axiom's powerful command-line tools into an intuitive, real-time dashboard that manages distributed security scanning across cloud infrastructure.

**Core Purpose:**

- **Simplify Distributed Scanning**: Execute security reconnaissance tools (nuclei, amass, nmap, httpx, etc.) across dozens or hundreds of cloud instances simultaneously
- **Centralize Results**: Automatically aggregate and organize scan results from multiple sources into a unified target database
- **Fleet Management**: Control cloud infrastructure (power on/off, execute commands, monitor status) from a single interface
- **Real-time Monitoring**: Track active scans, view progress, and receive results as they complete

### The Problem It Solves

Traditional security reconnaissance is slow and limited by single-machine resources. Running tools like nuclei or amass against large attack surfaces can take hours or days. Axiom solves this by distributing workloads across cloud instances, but requires command-line expertise and manual result aggregation.

**Axiom Dashboard bridges this gap by:**

1. Providing a visual interface for Axiom's distributed scanning capabilities
2. Automatically importing and organizing scan results from multiple tools
3. Eliminating manual file management and result parsing
4. Making distributed cloud scanning accessible to teams without CLI expertise

### Key Capabilities

- **Launch Distributed Scans**: Start scans across your entire fleet with a few clicks
- **Real-time Fleet Control**: Power on/off instances, execute commands, monitor cloud costs
- **Automated Result Processing**: Auto-import results from amass, nmap, nuclei, httpx, gowitness, and more
- **Target Intelligence**: Build comprehensive target profiles combining subdomain enumeration, port scans, and vulnerability data
- **Scan History**: Track all scans, view logs, and analyze historical data

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Axiom Dashboard UI                       │
│  (React/TypeScript - Vite - shadcn/ui components)           │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Scan Launcher│  │Fleet Control │  │Active Scans  │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Target List  │  │ Stats        │  │ Topology     │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP/REST API
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Axiom Bridge (Python/Flask)                    │
│                                                             │
│  • REST API Server (Flask + CORS)                           │
│  • Result Parser (amass, nmap, nuclei, gowitness, etc.)     │
│  • Data Store (JSON) - targets & fleet state                │
│  • Axiom Command Executor (subprocess + zsh)                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Axiom Framework                          │
│                                                             │
│  • axiom-scan: Distribute scans across fleet                │
│  • axiom-ls: List instance status                           │
│  • axiom-exec: Execute commands on instances                │
│  • axiom-power: Control instance power states               │
│  • axiom-rm: Terminate instances                            │
│  • ax update: update ax framework                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Cloud Infrastructure (Fleet)                   │
│                                                             │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐           │
│  │ VM 1 │  │ VM 2 │  │ VM 3 │  │ ...  │  │ VM N │           │
│  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘           │
│  AWS • Azure • DigitalOcean • Linode • GCP                  │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

#### 1. Scan Launch Flow

```
User Interface → Bridge API → axiom-scan command → Fleet Instances
                    ↓
              Scan Record Created
              (scans.json)
                    ↓
         Scan launched in dedicated tmux session
         (persists even if browser is closed)
                    ↓
         Background Thread Monitors
              Scan Progress
                    ↓
         Results Written to imports/
                    ↓
         File Watcher Detects New Files
                    ↓
         Parser Extracts Data → Updates Targets
                    ↓
         UI Refreshes → Shows New Results
```

#### 2. Fleet Management Flow

```
User Action (Power/Exec/RM) → Bridge API → Axiom Command
                                  ↓
                         Execute via zsh subprocess
                                  ↓
                         Command runs on instances
                                  ↓
                         Results returned to API
                                  ↓
                         UI displays output
                                  ↓
                         Fleet status auto-refreshes
```

#### 3. Auto-Import Flow

```
Scanner Output File → imports/[scanner]/ directory
                         ↓
               File Watcher Detects Creation
                         ↓
               Classify Scanner Type
        (amass/nmap/nuclei/httpx/gowitness/etc.)
                         ↓
               Parse File Format
            (JSON/JSONL/TXT/XML/SQLite)
                         ↓
               Extract Targets/Results
                         ↓
          Merge into Existing Targets or Create New
     (Group by domain/scan name, deduplicate entries)
                         ↓
          Update axiom_bridge_store.json
                         ↓
          Move File to imports/processed/
                         ↓
          Dashboard Displays New Data
```

## Implemented Features

### 1. **Dashboard Home** (App.tsx - DashboardHomeExternal)

Modern full-screen dashboard with comprehensive reconnaissance intelligence:

**Primary Statistics Cards:**

- Total Targets: Count of all discovered targets with growth trend
- Total Subdomains: Aggregate subdomain count across all targets
- Critical Vulnerabilities: High-priority security issues requiring immediate attention
- Axiom Fleet Status: Active instances vs total fleet capacity

**Secondary Statistics Cards:**

- Total Ports: Aggregate count of all discovered open ports
- Total Vulnerabilities: All severity levels combined
- High + Critical: Vulnerabilities requiring urgent remediation
- Active Scans: Real-time count of currently running scans

**Visual Analytics:**

- Vulnerability Distribution Chart: Bar chart showing severity breakdown (Critical/High/Medium/Low)
- Fleet Utilization: Pie chart of active vs idle instances
- Fleet Regional Distribution: Instance count by geographic region

**Recent Scans Table:**

- Intelligent result labeling based on scanner type:
  - HTTPx/GoWitness scans: Shows "X websites"
  - Nmap/Masscan scans: Shows "X ports"
  - Nuclei scans: Shows "X vulns"
  - Amass/Subfinder scans: Shows "X subs"
- Real-time status badges (Running/Completed)
- Scan timestamp tracking
- Quick navigation to scan details

**Layout:**

- Full-screen responsive grid layout
- Optimized for 4K, desktop, tablet, and mobile
- Cards organized in 4-column grid with proper wrapping
- Removed empty GeoMap component (no location data available)

### 2. **Scan Launcher** (ScanLauncher.tsx)

**Basic Options:**

- Scan name with auto-generated output filenames
- Multi-line target input (domains, IPs, CIDRs, URLs)
- Module selection (nuclei, amass, nmap, httpx, ffuf, masscan, gowitness)
- Output file specification

**Advanced Options:**

- **Wordlists:**
  - Remote wordlist (-w): Use existing wordlist on instances
  - Local wordlist upload (-wL/--distribute-wordlist): Upload and distribute across fleet
- **File Uploads:**
  - Local folder upload (--local-folder): Upload templates, configs, etc.
  - Config file upload (--local-config): Upload module-specific configs
- **Performance:**
  - Thread count (--threads)
  - Max runtime (--max-runtime): Auto-kill after duration (e.g., "2h", "30m")
  - Extra arguments: Pass additional flags to modules
- **Target Processing:**
  - Don't shuffle (--dont-shuffle): Keep original target order
  - Don't split (--dont-split): Upload full file to each instance
  - Expand CIDRs (--expand-cidr): Auto-expand CIDR ranges
- **Output:**
  - Anew mode (--anew): Deduplicate results
  - Quiet mode (--quiet): Suppress terminal output
  - Unsafe mode (--unsafe): Disable safe-target substitution

### 2. **Active Scans** (ActiveScans.tsx)

Real-time scan monitoring and history:

**How scans execute:**

- Each scan is launched in a dedicated **tmux session** on the bridge server
- Scans persist even if the browser is closed or the UI is refreshed
- Users can attach to a running scan's tmux session from the terminal: `tmux attach -t <session-name>`
- List all active scan sessions with `tmux ls`
- The bridge polls tmux sessions and `stats.log` to report status back to the UI

**Running Scans:**

- Live progress tracking with progress bars
- Scan duration counter
- Module and target count display
- Cancel scan capability
- Auto-refresh every 5 seconds

**Scan History:**

- Completed, failed, and cancelled scans
- Status badges with visual indicators
- Duration calculation
- Filterable table view
- Timestamp tracking

### 3. **Fleet Control** (FleetControl.tsx)

Comprehensive fleet management:

**Power Management:**

- Power on/off individual instances or patterns
- Bulk power control for all instances
- Status monitoring (active, inactive, etc.)

**Command Execution:**

- Execute shell commands across fleet
- Pattern-based instance selection
- Real-time output display
- Support for axiom-exec workflows

**Instance Management:**

- SSH command copy (one-click copy to clipboard)
- Individual instance power control
- Instance termination with confirmation
- Fleet overview table with:
  - Name, Status, IP, Provider, Region, Instance Type
  - Quick action buttons per instance

**Fleet Information:**

- Real-time instance count
- Status badges with color coding
- Provider and region distribution
- Instance type display

### 4. **Backend API Endpoints** (axiom-bridge.py)

**Scan Management:**

- `POST /api/axiom/scan` - Launch distributed scan
- `GET /api/axiom/scans` - List all scans
- `GET /api/axiom/scans/<id>` - Get scan details
- `POST /api/axiom/scans/<id>/cancel` - Cancel running scan
- `GET /api/axiom/modules` - List available scan modules

**Fleet Control:**

- `POST /api/axiom/fleet/power` - Power on/off instances
- `POST /api/axiom/fleet/ssh` - Get SSH command
- `POST /api/axiom/fleet/exec` - Execute command on fleet
- `POST /api/axiom/fleet/rm` - Terminate instances

**Data Management:**

- `GET /api/targets` - Get all scan targets
- `GET /api/fleet` - Get fleet status (via axiom-ls)
- `GET /run-axiom-ls` - Direct axiom-ls execution

**Workflows:**

- `POST /api/workflow/run` - Launch a DAG pipeline (steps + config)
- `GET /api/workflow/<id>/status` - Run status + per-step state
- `GET /api/workflow/<id>/log` - Run log
- `POST /api/workflow/<id>/abort` - Abort a running workflow

**Auth, Users & Teams:**

- `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/auth/status`
- `GET /api/users` · `GET /api/users/me` · `POST /api/users` - User management
- `GET /api/teams` · `POST /api/teams` - Team management
- `POST /api/invites` · `POST /api/invites/accept` - Team invites

### 5. **Auto-Import System**

Automated scan result processing:

**Supported Scanners:**

- **Amass**: JSON and TXT formats - Subdomain enumeration
- **Nmap/nmapx**: XML format - Port scanning and service detection
- **Nuclei**: JSON (JSONL) and TXT formats - Vulnerability scanning
- **GoWitness**: SQLite databases, JSON, JSONL, TXT - Screenshot and web probing
- **HTTPx**: JSON, JSONL, TXT formats - HTTP probe results
- **DNSx**: JSON, JSONL, TXT formats - DNS resolution data
- **AssetFinder**: JSON, TXT formats - Subdomain discovery

**Features:**

- Real-time file watching with Python threading timer (periodic polling)
- Automatic scanner type detection from filename patterns (e.g., `httpx+01-16_09-39-08.txt` → httpx)
- Scanner-specific subdirectories (imports/amass/, imports/nmap/, etc.)
- Intelligent scan grouping by filename prefix
- Domain-based target merging (all scans for example.com combine into one target)
- Binary file filtering (skips images, but processes SQLite databases for gowitness)
- Duplicate detection and deduplication
- Processed file archiving with timestamp preservation

**File Organization:**

```
imports/
  ├── amass/       # Amass subdomain enumeration results
  ├── nmap/        # Nmap port scan results (XML)
  ├── nmapx/       # Distributed nmap results
  ├── nuclei/      # Nuclei vulnerability scan results (JSONL)
  ├── gowitness/   # GoWitness screenshot databases and exports
  ├── httpx/       # HTTPx HTTP probe results
  ├── dnsx/        # DNSx DNS resolution data
  └── processed/   # Archived processed files (auto-moved after import)
```

**Smart Import Logic:**

1. **File Detection**: Watches all scanner subdirectories + root imports/ folder
2. **Classification**:
   - Parent directory (e.g., file in `imports/nuclei/` → nuclei scanner)
   - Filename pattern (e.g., `amass-out.txt` → amass scanner)
   - Axiom output format (e.g., `httpx+timestamp.txt` → httpx scanner)
3. **Format Detection**: Automatic based on file extension and content validation
4. **Data Extraction**:
   - **Subdomains**: Extract from amass, dnsx, assetfinder, httpx, gowitness
   - **Ports**: Extract from nmap XML with service detection
   - **Vulnerabilities**: Parse nuclei JSONL with severity mapping
   - **URLs**: Extract from gowitness SQLite databases
5. **Target Merging**:
   - Files with same prefix merge (e.g., `acme-amass.txt` + `acme-nuclei.json` → single "acme" target)
   - Root domain extraction for grouping (api.example.com → example.com)
   - Duplicate subdomain/port/vulnerability filtering
6. **Persistence**: All data saved to `data/axiom_bridge_store.json`

### 6. **Workflow Builder** (WorkflowBuilder.tsx + workflow-runner.py)

A DAG (directed-acyclic-graph) pipeline editor for chaining scans so the output of each step feeds the next automatically.

- **Step linking**: steps link via parent references — no parent = parallel root, one parent = sequential, multiple parents = fan-in/join.
- **AMI-aware module picker**: only modules baked into the fleet's provisioner image (barebones / default / reconftw / extras) are selectable; the rest are greyed out with the image that would provide them (shared logic in `services/provisioner.ts`).
- **Saveable custom templates**: pipelines can be saved as reusable templates in browser `localStorage`, round-tripping the full branch structure; built-in linear playbooks ship alongside them.
- **Backend sequencer**: `tools/workflow-runner.py` topologically sorts steps, groups them into execution "waves", launches each module through the bridge, waits for real completion, and passes structured output downstream. The UI polls run status for live per-step progress, logs, and abort.

### 8. **MCP Server** (tools/mcp-server.py)

A Model Context Protocol server that lets MCP clients (Claude Desktop, agents, or reporting tools like Ghostwriter) operate the platform as a logged-in account. Thin adapter over the bridge REST API.

- **19 tools**: scans (`start_scan`, `start_full_scan`, `build_workflow`, `list_scans`, `get_scan`, `get_scan_output`, `get_workflow_status`), reporting (`list_vulnerabilities`, `list_targets`, `get_target`), admin (`list_users`, `add_user`, `list_teams`, `create_team`, `add_user_to_team`, `create_invite`), fleet (`list_fleet`, `terminate_fleet`, `whoami`).
- **Auto-terminate enforced**: every MCP-launched scan/workflow spins up a fresh fleet and tears it down when done.
- **Transports**: stdio (Claude Desktop) and streamable-HTTP/SSE (remote agents).
- **Auth**: configured per-account via `GUIAX_TOKEN` or `GUIAX_USERNAME`/`GUIAX_PASSWORD`; all actions attributed to that user.

### 7. **Multi-user, Teams & Invites** (LoginPage.tsx / AdminPanel.tsx / UserProfile.tsx)

- **Auth**: login/logout backed by the bridge; role-based UI (the Admin panel is gated to the `admin` role).
- **Admin panel**: create users, manage roles, reset passwords.
- **User profile**: self-service password change.
- **Teams**: users grouped into project teams; the target view scopes to _all_ / _personal_ / a specific team (direct scans prefixed `teamSlug/…`, workflow scans `wf-teamSlug-…`).
- **Invites**: admins issue invite codes that new users redeem to join a team.
- **Single-user fallback**: with no users configured, the dashboard runs open with full admin access, preserving pre-auth behaviour.

## Usage Examples

### Launch a Nuclei Scan

```typescript
// From ScanLauncher component
scanName: "acme-vuln-scan"
targets: "example.com\napi.example.com\napp.example.com"
module: "nuclei"
outputFile: "acme-nuclei-results.txt"
options: {
  localFolder: "~/nuclei-templates",
  threads: 50,
  maxRuntime: "2h",
  anew: true,
  quiet: true
}
```

### Execute Command on Fleet

```typescript
// From FleetControl component
pattern: "myfleet*"; // Select all instances starting with "myfleet"
command: "df -h"; // Check disk usage
```

### Power Control

```typescript
// Power off all instances
action: "off";
pattern: "*";

// Power on specific fleet
action: "on";
pattern: "recon-fleet*";
```

## Data Flow

### Scan Lifecycle

1. User launches scan via ScanLauncher
2. Bridge creates scan record in scans.json
3. Bridge constructs axiom-scan command with all options
4. Scan launches in a dedicated **tmux session** (persists independently of browser)
5. Scan executes across fleet
6. Results auto-import via file watcher
7. ActiveScans shows real-time progress
8. Completed results appear in scan history and targets list

### Fleet Monitoring

1. Fleet data fetched from axiom-ls every 30 seconds
2. FleetContrImplementation

### Frontend Stack

**Framework & Build:**

- **React 18** with TypeScript for type safety
- **Vite** for fast development and optimized production builds
- **React Router** for client-side routing

**UI Components:**

- **shadcn/ui**: Pre-built, accessible components (built on Radix UI)
- **Tailwind CSS**: Utility-first CSS framework
- **Lucide React**: Icon library
- **Recharts**: Data visualization for scan metrics

**State Management:**

- Component-level state with React hooks
- API polling for real-time updates (configurable intervals)
- No global state management needed (simple API-driven architecture)

**Key Frontend Files:**

```
components/
  ├── ScanLauncher.tsx      # Scan configuration and launch UI
  ├── ActiveScans.tsx       # Real-time scan monitoring
  ├── FleetControl.tsx      # Fleet management interface
  ├── FleetManager.tsx      # Fleet overview and actions
  ├── GeoMap.tsx            # Geographic fleet distribution
  ├── TopologyGraph.tsx     # Network topology visualization
  ├── Settings.tsx          # App settings + Ax updater
  └── ui/                   # shadcn/ui base components
```

### Backend Architecture

**Python/Flask API Server:**

- **Flask**: Lightweight WSGI web framework
- **Flask-CORS**: Cross-origin resource sharing for frontend access
- **Watchdog**: File system event monitoring for auto-import
- **SQLite3**: Built-in for gowitness database reading
- **Subprocess**: Executes axiom commands via zsh shell

**API Endpoints Structure:**

```python
# Health & Status
GET  /health                          # Bridge health check

# Target Management
GET  /api/targets                     # List all targets
GET  /api/targets/<id>                # Get specific target details

# Fleet Management
GET  /api/fleet                       # Get fleet status (via axiom-ls)
POST /api/axiom/fleet/power           # Power control (on/off)
POST /api/axiom/fleet/exec            # Execute command on fleet
POST /api/axiom/fleet/ssh             # Get SSH connection string
POST /api/axiom/fleet/rm              # Terminate instances

# Scan Management
GET  /api/axiom/modules               # List available scan modules
POST /api/axiom/scan                  # Launch new distributed scan
GET  /api/axiom/scans                 # List all scans (from stats.log)
GET  /api/axiom/scans/<id>            # Get scan details
POST /api/axiom/scans/<id>/cancel     # Cancel running scan
GET  /api/axiom/scans/<id>/logs       # Get scan logs

# Filesystem Discovery
GET  /api/axiom/scans/filesystem/discover  # Discover scans from filesystem
```

**Data Persistence:**

```
data/
  ├── axiom_bridge_store.json  # Main target database
  └── scans.json                # Active/pending scan records

imports/
  ├── [scanner]/                # Scanner-specific subdirectories
  └── processed/                # Archived processed files

~/.axiom/
  ├── stats.log                 # Axiom scan history (read by bridge)
  ├── selected.conf             # Currently selected instances
  └── logs/                     # Scan output logs
```

**File Watcher Implementation:**

The bridge uses a background threading timer that periodically scans the `imports/` directory for new files:

```python
# Background thread checks imports/ every 300 seconds (configurable)
# 1. Skip binary/image files
# 2. Classify scanner type (directory or filename)
# 3. Detect file format (JSON/XML/TXT/SQLite)
# 4. Process file with appropriate parser
# 5. Merge into target database
# 6. Move to processed/ folder
```

**Parser Examples:**

_Amass JSON Parser:_

```python
# Input: [{"name": "api.example.com"}, {"name": "app.example.com"}]
# Output: Target with id="amass-out", domain="example.com",
#         subdomains=[{"hostname": "api.example.com"}, ...]
```

_Nuclei JSONL Parser:_

```python
# Input: {"template-id": "cve-2021-1234", "info": {"severity": "high"},
#         "matched-at": "https://example.com/admin"}
# Output: Vulnerability entry with severity mapping, host extraction
```

_GoWitness SQLite Parser:_

```python
# Queries: SELECT DISTINCT url FROM urls
# Extracts hostnames from URLs: https://example.com:443 → example.com
```

### Environment & Configuration

**Environment Variables:**

```bash
# Bridge Configuration
PORT=5000                                    # API server port
STORE_PATH=./data/axiom_bridge_store.json   # Target database path
IMPORTS_PATH=./imports                       # Scan results folder
AXIOM_LS_PATH=~/.axiom/interaction/axiom-ls # Axiom CLI path
```

**Axiom Integration:**

- Bridge executes axiom commands via subprocess with zsh login shell
- Ensures ~/.zshrc is sourced to load axiom paths
- Validates instance names against selected.conf for safety
- Prevents accidental operations on non-axiom instances

### Deployment Considerations

**Development Mode:**

```bash
# Terminal 1 - Start backend
python3 tools/axiom-bridge.py

# Terminal 2 - Start frontend
npm run dev
```

**Production Deployment:**

```bash
# Build frontend
npm run build

# Serve via nginx/caddy with backend proxy
# Or use Flask in production mode with gunicorn/waitress
```

**Docker Deployment (Future):**

> Both ports **3000** (UI) and **5000** (bridge API) must be exposed. `tmux` must be installed in the container.

```dockerfile
# Multi-stage build
# Stage 1: Build React app
# Stage 2: Python runtime with Flask + tmux
# Expose ports: 3000 (frontend), 5000 (API)
```

### Security Considerations

**Input Validation:**

- Sanitize scan names, target inputs, and command arguments
- Validate instance patterns against axiom's selected.conf
- Prevent arbitrary command injection in fleet exec

**Fleet Operations:**

- Only allow operations on axiom-managed instances
- Require confirmation for destructive actions (rm, power off)
- Rate limiting on power/exec endpoints (prevent abuse)

**API Security:**

- CORS configured for localhost development
- Production should add authentication (JWT/OAuth)
- API keys for fleet operations
- Rate limiting and request throttling

### Performance Optimizations

**Frontend:**

- Lazy loading of components
- Memoization of expensive computations
- Debounced API polling
- Virtual scrolling for large target lists

**Backend:**

- File watcher uses efficient event-based monitoring (not polling)
- JSON database is fast for <10k targets (consider SQLite for scale)
- Subprocess commands cached where appropriate
- Background threads for long-running operations

**Scaling:**

- Current architecture supports 100s of targets and 10s of concurrent scans
- For 1000s of targets, migrate to PostgreSQL or MongoDB
- For 100s of concurrent scans, add Redis for job queue

## Setup & Installation

### Prerequisites

**System Requirements:**

- Linux or macOS (Windows via WSL)
- Python 3.8+
- Node.js 18+
- tmux (required for scan execution)
- Axiom framework installed and configured

**Axiom Setup:**

```bash
# Install Axiom
git clone https://github.com/pry0cc/axiom ~/.axiom/
cd ~/.axiom/
./interact/axiom-configure

# Initialize fleet
axiom-fleet myfleet -i 5  # Create 5 instances
axiom-select 'myfleet*'   # Select all instances
```

### Dashboard Installation

```bash
# Clone repository
git clone <repo-url>
cd axiom-dashboard-ui

# Install frontend dependencies
npm install

# Install backend dependencies
pip3 install flask flask-cors

# Create required directories
mkdir -p data imports/{amass,nmap,nmapx,nuclei,gowitness,httpx,dnsx,processed}

# Start backend
python3 tools/axiom-bridge.py

# Start frontend (new terminal)
npm run dev
```

### First Run

1. **Verify Axiom**: Ensure `axiom-ls` works and shows your fleet
2. **Check API**: Visit http://localhost:5000/health (should return `{"status": "ok"}`)
3. **Access Dashboard**: Open http://localhost:5173
4. **View Fleet**: FleetControl tab should show your instances
5. **Launch Test Scan**: Try a simple scan to verify integration

## Technical Notes

- **UI Framework**: Components use shadcn/ui for consistent, accessible design
- **Real-time Updates**: Polling intervals vary by component (5-30 seconds)
- **State Persistence**: Targets and scan state stored in JSON files
- **Command Execution**: All axiom commands run via subprocess with zsh
- **Error Handling**: User-friendly error messages with fallback states
- **Responsive Design**: Mobile/tablet/desktop optimized layouts
- **Type Safety**: Full TypeScript coverage for compile-time error catching
- **Testing**: Component tests with React Testing Library (future enhancement)
- **Logging**: Structured logging with severity levels for debugging

3. Parser processes based on scanner type
4. Results merged into existing targets if domain matches
5. Vulnerabilities, subdomains, ports added to target data
6. File moved to processed/ archive
7. Dashboard auto-refreshes to show new data

## Future Enhancements

### Potential Additions:

1. **Scan Templates**: Pre-configured scan profiles (e.g., "Full Recon", "Quick Vulnerability Check")
2. **Cost Tracking**: Real-time cloud cost estimation based on fleet usage
3. **Alerts**: Notifications for critical vulnerabilities or fleet issues
4. **Reporting**: Export combined scan results as PDF/HTML reports
5. **Timeline View**: Visual timeline of all scans for a target
6. **Diff View**: Compare scan results over time to identify changes
7. **Automation Rules**: Trigger scans automatically when new targets detected
8. **Resource Metrics**: Show CPU/memory/disk usage per instance (via axiom-exec)

## Technical Notes

- Components use shadcn/ui for consistent styling
- Real-time updates via polling (5-30 second intervals)
- Scan state persisted in JSON files
- All axiom commands executed via subprocess
- Error handling with user-friendly messages
- Responsive design for mobile/tablet/desktop
