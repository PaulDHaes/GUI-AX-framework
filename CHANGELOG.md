# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [1.0.0] — 2026-03-10

### Added

#### Scan failure detection

- Bridge now reads axiom log files and detects failure patterns (`command not found`, `unable to find image`, `pull access denied`, `no such file`, `exit code`, `fatal:`)
- Scans that fail due to missing tools or bad container images are marked `failed` instead of `completed`
- `failure_reason` and `failure_lines` fields added to scan objects returned by the API
- Red failure banner displayed in ScanOutput when a scan has a logged failure reason

#### Screenshot gallery (ScanOutput)

- Screenshot modules (gowitness, webscreenshot, aquatone, eyewitness) now render a tall image gallery (`h-64` cards) instead of raw text
- Click any screenshot to open a full-screen lightbox overlay
- Bridge exposes two new endpoints: `GET /api/axiom/scans/<id>/screenshots` and `GET /api/axiom/scans/<id>/img/<path>`

#### Per-module result tables and filters (ScanOutput)

- **HTTP/fuzzing modules** (httpx, ffuf): structured table with status code, URL, title; filter chips for each distinct status code
- **Port modules** (nmap, masscan): structured table with port, state, service; filter chips for each port state
- **Vulnerability modules** (nuclei): structured table with severity badge, template name, target; filter chips for each severity level
- Full-text search bar across all raw log lines
- Module category auto-detection (`getScanCategory`) drives which table/filters are shown

#### Ax framework updater

- New `GET /api/axiom/update` streaming endpoint in the bridge — runs `git pull` on `~/.axiom` and streams output line-by-line
- New **Ax Updater** tab in Settings — shows current Ax version/commit and a **Pull latest Ax** button with live log output
- New `tools/ax-update.sh` standalone update script

#### GitHub / repo hygiene

- Added `.env.example` template
- Expanded `.gitignore` (venv, flask/, data/\*.json, imports/processed/, temp, todo)
- Added `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
- Added `.github/ISSUE_TEMPLATE/bug_report.yml` and `feature_request.yml`
- Added `.github/PULL_REQUEST_TEMPLATE.md`
- Added `.github/workflows/ci.yml` (TypeScript type-check + Python syntax check)
- Updated `README.md` with CI badge, feature docs, API reference table, Ax update section

### Fixed

- `folder_path` undefined reference in `get_scan` fallback code (now correctly uses `scan_path`)
- Missing `except` clause on logs-dir `try:` block in `discover_scans_from_filesystem`
- Removed `watchdog` from pip install requirements (not actually used at runtime)

---

## [0.1.0] — initial release

- React + TypeScript + Vite frontend
- Flask bridge (`axiom-bridge.py`) connecting to Ax CLI
- Fleet Manager, Scan Launcher, Active Scans, GeoMap, TopologyGraph
- Auto-import watcher for nuclei / amass / nmap / httpx / dnsx / whois / ffuf output
- Gemini AI panel (optional)
- One-liner installer (`gui-ax-install.sh`)
