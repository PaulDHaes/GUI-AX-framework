# GUI-AX-framework
GUI web interface for the AX/axiom framework.
A comprehensive web-based dashboard for [Axiom](https://github.com/pry0cc/axiom) - the dynamic infrastructure framework for distributed security reconnaissance.

## Overview

Axiom Dashboard transforms Axiom's powerful command-line tools into an intuitive, real-time dashboard for managing distributed security scanning across cloud infrastructure.

**Key Features:**

- 🚀 **Launch Distributed Scans** - Execute nuclei, amass, nmap, httpx, and more across your entire fleet
- 🖥️ **Fleet Management** - Control cloud instances (power on/off, SSH, execute commands)
- 📊 **Real-time Monitoring** - Track active scans, view progress, and receive results live
- 📁 **Auto-Import Results** - Automatically aggregate scan results from multiple tools
- 🗺️ **Geographic Visualization** - View your fleet distribution on an interactive map

## Architecture

```
┌─────────────────────────────────────────┐
│       React/TypeScript Frontend         │
│         (Vite + shadcn/ui)              │
└──────────────────┬──────────────────────┘
                   │ REST API
                   ▼
┌─────────────────────────────────────────┐
│     Axiom Bridge (Python/Flask)         │
│  • File Watcher for scan imports        │
│  • Axiom CLI command executor           │
│  • Result parser & aggregator           │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│         Axiom Framework                  │
│   axiom-scan • axiom-ls • axiom-exec    │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│     Cloud Fleet (AWS/Azure/DO/GCP)      │
│      VM1 • VM2 • VM3 • ... • VMn        │
└─────────────────────────────────────────┘
```

## Prerequisites

- **Node.js** (v18+)
- **Python 3** with pip
- **Axiom** installed and configured ([installation guide](https://github.com/pry0cc/axiom#installation))

## Quick Start

### 1. Install Frontend Dependencies

```bash
npm install
```

### 2. Install Backend Dependencies

```bash
pip3 install flask flask-cors watchdog
```

### 3. Start the Backend (Axiom Bridge)

```bash
python3 tools/axiom-bridge.py
```

The bridge runs on port 5000 and watches `imports/` for new scan results.

### 4. Start the Frontend

```bash
npm run dev
```

Open http://localhost:5173 in your browser.

## Configuration

### Environment Variables

| Variable         | Default                          | Description                              |
| ---------------- | -------------------------------- | ---------------------------------------- |
| `AXIOM_LS_PATH`  | `~/.axiom/interact/axiom-ls`     | Path to axiom-ls executable              |
| `AXIOM_TMP`      | `~/.axiom/tmp`                   | Axiom temp directory for scans           |
| `STORE_PATH`     | `./data/axiom_bridge_store.json` | Persistent data store                    |
| `IMPORTS_PATH`   | `./imports`                      | Directory to watch for scan results      |
| `PORT`           | `5000`                           | Bridge API port                          |
| `GEMINI_API_KEY` | -                                | Optional: Gemini API key for AI features |

### Importing Scan Results

Drop scan output files into the `imports/` subdirectories:

```
imports/
├── amass/      # Amass subdomain enumeration
├── nmap/       # Nmap port scans (XML)
├── nuclei/     # Nuclei vulnerability scans
├── httpx/      # HTTPx probe results
├── gowitness/  # GoWitness screenshots
└── dnsx/       # DNSx resolution results
```

Files are automatically processed and moved to `imports/processed/`.

## Supported Scan Modules

The dashboard integrates with Axiom's distributed scanning for:

- **nuclei** - Vulnerability scanning
- **amass** - Subdomain enumeration
- **nmap/masscan** - Port scanning
- **httpx** - HTTP probing
- **ffuf** - Web fuzzing
- **gowitness** - Screenshot capture
- **dnsx** - DNS resolution
- **whois** - Domain information

## Project Structure

```
axiom-dashboard-ui/
├── components/          # React UI components
│   ├── FleetControl.tsx    # Fleet management panel
│   ├── ScanLauncher.tsx    # Scan configuration & launch
│   ├── ActiveScans.tsx     # Running scan monitor
│   ├── GeoMap.tsx          # Geographic fleet map
│   └── ui/                 # shadcn/ui components
├── services/            # API services
│   ├── axApi.ts            # Axios API client
│   └── axiomProvider.ts    # Axiom data context
├── tools/               # Backend utilities
│   └── axiom-bridge.py     # Flask API bridge
├── imports/             # Scan result import directory
└── data/                # Persistent data store
```

## Development

```bash
# Run frontend in dev mode
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## License
MIT
