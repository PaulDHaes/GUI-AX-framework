#!/usr/bin/env python3
"""
Axiom Bridge — Flask API + file watcher.

Watches imports/ for scan output files and dispatches them to the
modular importers in tools/importers/.  Persists all data to a single
JSON store and serves the React dashboard via /api/*.

Usage:
  pip3 install flask flask-cors
  python3 tools/axiom-bridge.py

Environment variables:
  STORE_PATH        — path to JSON store   (default: ./data/axiom_bridge_store.json)
  IMPORTS_PATH      — imports folder        (default: ./imports)
  PORT              — listen port           (default: 5000)
  WATCHER_INTERVAL  — seconds between scans (default: 300)
  AXIOM_LS_PATH     — path to axiom-ls
  FLEET_CACHE_TTL   — fleet cache seconds   (default: 30)
"""

import sys as _sys
from pathlib import Path as _Path
# Ensure tools/ is on sys.path so "import importers" resolves correctly.
_tools_dir = str(_Path(__file__).resolve().parent)
if _tools_dir not in _sys.path:
    _sys.path.insert(0, _tools_dir)

from flask import Flask, jsonify, request, abort, send_file, Response
from flask_cors import CORS
import os
import re
import json
import subprocess
import traceback
from pathlib import Path
from datetime import datetime
import time
import threading
import shutil
import shlex

def find_axiom_ls():
    """Locate axiom-ls executable.
    Priority: AXIOM_LS_PATH env -> AXIOM_HOME/.axiom -> current user's ~/.axiom -> PATH
    """
    env_path = os.environ.get("AXIOM_LS_PATH")
    if env_path:
        return env_path

    axiom_home = os.environ.get("AXIOM_HOME")
    candidate_dirs = []
    if axiom_home:
        candidate_dirs.append(Path(axiom_home))

    # Current user's home ~/.axiom
    candidate_dirs.append(Path.home() / ".axiom")

    candidates = []
    for base in candidate_dirs:
        candidates.extend([
            base / "interact" / "axiom-ls",
            base / "interaction" / "axiom-ls",
        ])

    candidates.extend([
        Path("/usr/local/bin/axiom-ls"),
        Path("/usr/bin/axiom-ls"),
    ])

    for c in candidates:
        if c.exists():
            return str(c)

    # Fallback to PATH resolution
    return "axiom-ls"



AXIOM_LS_PATH = find_axiom_ls()
STORE_PATH = os.environ.get("STORE_PATH", "./data/axiom_bridge_store.json")
# Use absolute path for imports, expand ~ and relative paths
IMPORTS_PATH = os.path.abspath(os.path.expanduser(os.environ.get("IMPORTS_PATH", "./imports")))
PROCESSED_PATH = os.path.join(IMPORTS_PATH, "processed")

# Axiom temp directory - use container-friendly path if ~/.axiom doesn't exist
AXIOM_TMP = os.environ.get("AXIOM_TMP")
if not AXIOM_TMP:
    # Try ~/.axiom/tmp first (native axiom installation)
    axiom_home_tmp = os.path.expanduser("~/.axiom/tmp")
    if os.path.exists(os.path.dirname(axiom_home_tmp)):
        AXIOM_TMP = axiom_home_tmp
        os.makedirs(AXIOM_TMP, exist_ok=True)
    else:
        # Fallback to /tmp/axiom-bridge for Docker containers
        AXIOM_TMP = "/tmp/axiom-bridge/tmp"
        os.makedirs(AXIOM_TMP, exist_ok=True)
        print(f"[bridge] Using container-friendly temp path: {AXIOM_TMP}")

# Scanner-specific subdirectories
AMASS_PATH = os.path.join(IMPORTS_PATH, "amass")
NMAP_PATH = os.path.join(IMPORTS_PATH, "nmap")
NMAPX_PATH = os.path.join(IMPORTS_PATH, "nmapx")
NUCLEI_PATH = os.path.join(IMPORTS_PATH, "nuclei")
GOWITHNESS_PATH = os.path.join(IMPORTS_PATH, "gowitness")
HTTPX_PATH = os.path.join(IMPORTS_PATH, "httpx")
DNSX_PATH = os.path.join(IMPORTS_PATH, "dnsx")
WHOIS_PATH = os.path.join(IMPORTS_PATH, "whois")
FFUF_PATH = os.path.join(IMPORTS_PATH, "ffuf")

PORT = int(os.environ.get("PORT", "5000"))
# How often (seconds) the background thread re-scans imports/ for new files.
# Override with WATCHER_INTERVAL env var. Default 300 = 5 minutes.
WATCHER_INTERVAL = int(os.environ.get("WATCHER_INTERVAL", "300"))

app = Flask(__name__)
CORS(app)

# store format: { "targets": [ {id, domain, sources, created_at} ], "fleet": [...] }
DEFAULT_STORE = {"targets": [], "fleet": []}

# Fleet cache with TTL to avoid hammering AWS
FLEET_CACHE = {
    "data": [],
    "timestamp": 0,
    "ttl": 30  # Cache for 30 seconds (configurable via FLEET_CACHE_TTL env var)
}
FLEET_CACHE["ttl"] = int(os.environ.get("FLEET_CACHE_TTL", "30"))

# Track fleet prefixes/names used by active scans
# This helps the fleet endpoint show instances created by scans even if they're not in selected.conf yet
SCAN_PREFIXES_FILE = os.path.join(os.path.dirname(STORE_PATH) or ".", "scan_prefixes.json")

def load_scan_prefixes():
    """Load persisted scan prefixes from file"""
    try:
        if os.path.exists(SCAN_PREFIXES_FILE):
            with open(SCAN_PREFIXES_FILE, "r") as f:
                data = json.load(f)
                return set(data.get("prefixes", []))
    except Exception as e:
        print(f"[bridge] Failed to load scan prefixes: {e}")
    return set()

def save_scan_prefixes(prefixes):
    """Save scan prefixes to file for persistence"""
    try:
        os.makedirs(os.path.dirname(SCAN_PREFIXES_FILE) or ".", exist_ok=True)
        with open(SCAN_PREFIXES_FILE, "w") as f:
            json.dump({"prefixes": list(prefixes)}, f)
    except Exception as e:
        print(f"[bridge] Failed to save scan prefixes: {e}")

SCAN_INSTANCES = {
    "prefixes": load_scan_prefixes(),  # Fleet prefixes from active scans (e.g., "example", "dvw-prod")
    "lock": threading.Lock()
}


def classify_by_filename(filename):
    """Classify a file by its filename pattern (e.g., amass-out.txt -> amass)"""
    lower = filename.lower()

    # Skip hidden and binary files
    if filename.startswith("."):
        return None

    skip_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"]
    if any(lower.endswith(ext) for ext in skip_extensions):
        return None

    if any(skip in lower for skip in ["processed", "readme", "license", "index"]):
        return None

    # Remove extension
    name_without_ext = ".".join(filename.split(".")[:-1])

    # Extract module name: handle axiom output formats like
    #   amass-out.txt       -> amass
    #   dnsx-out-full-2.txt -> dnsx
    #   httpx+01-16_09-39-08 -> httpx
    if "-" in name_without_ext:
        module = name_without_ext.split("-")[0].lower()
    else:
        module = name_without_ext.lower()

    # Strip +timestamp suffix (axiom scan format)
    if "+" in module:
        module = module.split("+")[0]

    # Strip trailing digits
    import re
    module = re.sub(r'\d+$', '', module)

    return module if module else None


# ── Periodic import scanner ──────────────────────────────────────────────────

def scan_imports_dir(verbose: bool = True) -> int:
    """Scan imports/ for unprocessed files and process them.

    Returns the number of newly imported files/folders.
    Called once on startup, then periodically by the background watcher thread,
    and on-demand via GET/POST /api/imports/scan.
    """
    new_files = 0
    try:
        store = load_store()
        existing_sources: set = set()
        for target in store.get("targets", []):
            for source in target.get("sources", []):
                existing_sources.add(source)

        # ── Root-level files (flat drop zone) ─────────────────────────────
        root_files = [f for f in Path(IMPORTS_PATH).iterdir()
                      if f.is_file() and not f.name.startswith(".")]
        for filepath in root_files:
            if filepath.name in existing_sources:
                continue
            scanner_type = classify_by_filename(filepath.name)
            if scanner_type:
                if verbose:
                    print(f"[watcher] Processing: {filepath.name}  ->  scanner={scanner_type}")
                try:
                    process_import_file(filepath, scanner_type=scanner_type)
                    new_files += 1
                except Exception as e:
                    print(f"[watcher] Error processing {filepath.name}: {e}")
                    traceback.print_exc()

        # ── .dir output folders (e.g. whois+timestamp.dir) ────────────────
        dir_folders = [d for d in Path(IMPORTS_PATH).iterdir()
                       if d.is_dir() and d.name.endswith(".dir")
                       and "processed" not in d.parts]
        for dir_path in dir_folders:
            if verbose:
                print(f"[watcher] Processing .dir folder: {dir_path.name}")
            try:
                process_dir_folder(dir_path)
                new_files += 1
            except Exception as e:
                print(f"[watcher] Error processing .dir folder {dir_path.name}: {e}")
                traceback.print_exc()

        # ── Gowitness subdir ───────────────────────────────────────────────
        if Path(GOWITHNESS_PATH).exists():
            for filepath in Path(GOWITHNESS_PATH).iterdir():
                if filepath.is_file() and filepath.suffix in [".sqlite3", ".db", ".json", ".jsonl", ".txt"]:
                    if filepath.name not in existing_sources:
                        if verbose:
                            print(f"[watcher] Processing gowitness file: {filepath.name}")
                        try:
                            process_import_file(filepath, scanner_type="gowitness")
                            new_files += 1
                        except Exception as e:
                            print(f"[watcher] Error: {e}")
            # Also handle sub-folders dropped into imports/gowitness/
            # e.g. imports/gowitness/my-export/ containing gowitness.db + screenshots/
            for subdir in Path(GOWITHNESS_PATH).iterdir():
                if not subdir.is_dir() or "processed" in subdir.parts:
                    continue
                sub_db_files = [
                    f for f in subdir.iterdir()
                    if f.is_file() and f.suffix in (".sqlite3", ".db")
                    and f.name not in existing_sources
                ]
                for db_file in sub_db_files:
                    if verbose:
                        print(f"[watcher] Processing gowitness subfolder: {subdir.name}/{db_file.name}")
                    try:
                        process_import_file(db_file, scanner_type="gowitness")
                        new_files += 1
                    except Exception as e:
                        print(f"[watcher] Error processing gowitness subfolder: {e}")
                        traceback.print_exc()
                if sub_db_files:
                    # db + screenshots/ were moved to processed/gowitness-TS/ — remove empty subdir
                    try:
                        remaining = list(subdir.iterdir())
                        if not remaining:
                            subdir.rmdir()
                            if verbose:
                                print(f"[watcher] ✓ Removed empty gowitness subdir: {subdir.name}/")
                        else:
                            # Move residual content to processed/ to avoid re-scanning
                            os.makedirs(PROCESSED_PATH, exist_ok=True)
                            dest = Path(PROCESSED_PATH) / subdir.name
                            if dest.exists():
                                shutil.rmtree(dest)
                            shutil.move(str(subdir), str(dest))
                            if verbose:
                                print(f"[watcher] ✓ Moved residual gowitness subfolder → processed/{subdir.name}/")
                    except Exception as e:
                        print(f"[watcher] Could not clean up gowitness subfolder {subdir.name}: {e}")

        # ── Nuclei subdir: imports/nuclei/ (.md + .txt/.jsonl flat files) ──
        if Path(NUCLEI_PATH).exists():
            nuclei_md = [
                f for f in Path(NUCLEI_PATH).iterdir()
                if f.is_file() and f.suffix.lower() == ".md"
                and f.name not in existing_sources
            ]
            if nuclei_md:
                if verbose:
                    print(f"[watcher] Processing {len(nuclei_md)} nuclei .md file(s) in imports/nuclei/")
                try:
                    from importers.import_nuclei import process_nuclei_md_files as _pnmd
                    _pnmd(nuclei_md, "nuclei-md-import")
                    new_files += len(nuclei_md)
                except Exception as e:
                    print(f"[watcher] Error processing nuclei .md files: {e}")
                    traceback.print_exc()
            # Also pick up any .txt/.jsonl/.json nuclei files in the subdir
            for filepath in Path(NUCLEI_PATH).iterdir():
                if filepath.is_file() and filepath.suffix in [".txt", ".jsonl", ".json"]:
                    if filepath.name not in existing_sources:
                        if verbose:
                            print(f"[watcher] Processing nuclei file: {filepath.name}")
                        try:
                            process_import_file(filepath, scanner_type="nuclei")
                            new_files += 1
                        except Exception as e:
                            print(f"[watcher] Error: {e}")

        # ── Gowitness export folders dropped directly into imports/ ────────
        # Handles e.g. imports/gowitness-march7/ containing gowitness.db + screenshots/
        # process_import_file moves db + screenshots/ → processed/gowitness-TS/;
        # the source dir is then empty and gets removed (or moved if residual files remain).
        gw_candidate_dirs = [
            d for d in Path(IMPORTS_PATH).iterdir()
            if d.is_dir()
            and not d.name.endswith(".dir")
            and d.name not in ("processed", "nuclei", "gowitness", "amass", "nmap",
                               "nmapx", "httpx", "dnsx", "whois", "ffuf")
            and "processed" not in d.parts
        ]
        for gw_dir in gw_candidate_dirs:
            try:
                db_files = [
                    f for f in gw_dir.iterdir()
                    if f.is_file() and f.suffix in (".sqlite3", ".db")
                    and f.name not in existing_sources
                ]
                if not db_files:
                    continue
                for db_file in db_files:
                    if verbose:
                        print(f"[watcher] Processing gowitness bundle folder: {gw_dir.name}/{db_file.name}")
                    try:
                        process_import_file(db_file, scanner_type="gowitness")
                        new_files += 1
                    except Exception as e:
                        print(f"[watcher] Error processing gowitness folder {gw_dir.name}: {e}")
                        traceback.print_exc()
                # db + screenshots/ were moved to processed/gowitness-TS/ by process_import_file.
                # Clean up the now-empty source dir, or move residuals to processed/.
                try:
                    remaining = list(gw_dir.iterdir())
                    if not remaining:
                        gw_dir.rmdir()
                        if verbose:
                            print(f"[watcher] ✓ Removed empty gowitness folder: {gw_dir.name}/")
                    else:
                        os.makedirs(PROCESSED_PATH, exist_ok=True)
                        dest = Path(PROCESSED_PATH) / gw_dir.name
                        if dest.exists():
                            shutil.rmtree(dest)
                        shutil.move(str(gw_dir), str(dest))
                        if verbose:
                            print(f"[watcher] ✓ Moved residual gowitness folder → processed/{gw_dir.name}/")
                except Exception as e:
                    print(f"[watcher] Could not clean up gowitness folder {gw_dir.name}: {e}")
            except Exception as e:
                print(f"[watcher] Error scanning gowitness folder {gw_dir.name}: {e}")
                traceback.print_exc()

        # ── Plain folders in imports/ containing .md files (nuclei -markdown-export) ──
        plain_dirs = [
            d for d in Path(IMPORTS_PATH).iterdir()
            if d.is_dir()
            and not d.name.endswith(".dir")
            and d.name not in ("processed", "nuclei", "amass", "nmap", "nmapx",
                               "gowitness", "httpx", "dnsx", "whois", "ffuf")
            and "processed" not in d.parts
        ]
        for plain_dir in plain_dirs:
            md_files = [
                f for f in plain_dir.iterdir()
                if f.is_file() and f.suffix.lower() == ".md"
                and f.name not in existing_sources
            ]
            if md_files:
                scan_label = plain_dir.name
                if verbose:
                    print(f"[watcher] Processing {len(md_files)} nuclei .md file(s) from folder '{scan_label}'")
                try:
                    from importers.import_nuclei import process_nuclei_md_files as _pnmd
                    _pnmd(md_files, scan_label)
                    new_files += len(md_files)
                    # Move the folder to processed/ when done
                    os.makedirs(PROCESSED_PATH, exist_ok=True)
                    dest = Path(PROCESSED_PATH) / plain_dir.name
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.move(str(plain_dir), str(dest))
                    if verbose:
                        print(f"[watcher] ✓ Moved {plain_dir.name}/ -> processed/")
                except Exception as e:
                    print(f"[watcher] Error processing .md folder '{plain_dir.name}': {e}")
                    traceback.print_exc()

    except Exception as e:
        print(f"[watcher] Scan error: {e}")
        traceback.print_exc()

    return new_files


def _import_watcher_thread():
    """Background daemon thread: re-scan imports/ every WATCHER_INTERVAL seconds."""
    print(f"[watcher] Background thread started (interval={WATCHER_INTERVAL}s)")
    while True:
        time.sleep(WATCHER_INTERVAL)
        try:
            new_files = scan_imports_dir(verbose=False)
            if new_files > 0:
                print(f"[watcher] Periodic scan: imported {new_files} new file(s)")
        except Exception as e:
            print(f"[watcher] Periodic scan error: {e}")




def process_import_file(filepath, scanner_type=None, skip_move=False):
    """Process a single import file and optionally move it to processed/"""
    filename = filepath.name
    print(f"\n{'='*70}")
    print(f"[DEBUG] Processing {filename} as {scanner_type}...")
    print(f"[DEBUG] File path: {filepath}")
    print(f"[DEBUG] File exists: {filepath.exists()}")
    print(f"[DEBUG] File size: {filepath.stat().st_size if filepath.exists() else 'N/A'}")
    
    # Skip binary/image files.
    # NOTE: .sqlite3/.db are allowed through for the gowitness handler — do NOT add them here.
    skip_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"]
    if any(filename.lower().endswith(ext) for ext in skip_extensions):
        print(f"[DEBUG] ✗ Skipping binary file: {filename}")
        return

    # SQLite databases can only be handled by the gowitness scanner; skip for anything else.
    is_sqlite = filename.lower().endswith((".sqlite3", ".db"))
    if is_sqlite and scanner_type != "gowitness":
        print(f"[DEBUG] ✗ Skipping SQLite file (not a gowitness import): {filename}")
        return
    
    # Read content — skip for binary SQLite files (gowitness handler reads DB directly)
    content = ""
    if not is_sqlite:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            print(f"[DEBUG] ✓ File read successfully, {len(content)} bytes")
            print(f"[DEBUG] First 100 chars: {content[:100]}")
        except Exception as e:
            print(f"[DEBUG] ✗ Failed to read {filename}: {e}")
            import traceback
            traceback.print_exc()
            return
    else:
        print(f"[DEBUG] SQLite file — skipping text read, will use sqlite3 module directly")
    
    # Extract scan name from filename (prefix before extension or dash)
    # Example: example-amass.json -> scan_name = "example"
    # For .dir mode (axiom output): use the parent dir name as the scan batch identifier
    # so all domains from the same run are grouped into one target.
    _parent = Path(filepath).parent.name
    if _parent.endswith(".dir"):
        scan_name = _parent  # e.g. "whois+02-26_23-34-28.dir"
    elif '-' in filename:
        scan_name = filename.split('-')[0]
    else:
        scan_name = filename.split('.')[0]
    print(f"[DEBUG] Extracted scan_name: {scan_name}")
    
    # ── Dispatch to modular importer ─────────────────────────────────────────
    scanner = scanner_type
    try:
        from importers import REGISTRY, GENERIC
        _importer = REGISTRY.get(scanner, GENERIC)
    except ImportError:
        print(f"[DEBUG] ⚠ importers package not found; falling back to legacy inline parser")
        _importer = None

    if _importer is not None:
        fmt = _importer.detect_format(scanner, filename, content)
        print(f"[DEBUG] ✓ Detected: scanner={scanner}, format={fmt}, scan_name={scan_name}")
        print(f"[DEBUG] Loading store...")
        store  = load_store()
        targets = store.get("targets", [])
        print(f"[DEBUG] Current targets in store: {len(targets)}")
        targets, changed, file_moved = _importer.parse(
            filepath, scanner, fmt, content, scan_name, targets, skip_move
        )
        if changed:
            store["targets"] = targets
            save_store(store)
            print(f"[DEBUG] ✓ Saved! Total targets: {len(targets)}")
            print(f"[watcher] ✓ Imported {filename}, total targets: {len(targets)}")
        else:
            print(f"[DEBUG] No changes detected")
            print(f"[watcher] No new targets from {filename}")
        if not skip_move and not file_moved:
            print(f"[DEBUG] Moving to processed folder...")
            os.makedirs(PROCESSED_PATH, exist_ok=True)
            dest = Path(PROCESSED_PATH) / filename
            try:
                os.rename(filepath, dest)
                print(f"[DEBUG] ✓ Moved {filename} -> processed/")
            except Exception as e:
                print(f"[DEBUG] ✗ Failed to move file: {e}")
        print(f"{'='*70}\n")
        return

    # ── Fallback: importers package not available ────────────────────────────
    print(f"[bridge] ✗ importers package unavailable — cannot process '{filename}'")


def process_dir_folder(dir_path):
    """Process all files inside a .dir output folder, then move the whole dir to processed/"""
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        print(f"[watcher] .dir path no longer exists: {dir_path}")
        return

    dir_name = dir_path.name  # e.g. "whois+02-26_23-13-50.dir"

    # Extract scanner type from folder name: "whois+timestamp.dir" -> "whois"
    base = dir_name.replace(".dir", "")
    scanner_type = base.split("+")[0].split("-")[0].lower()
    print(f"[watcher] Processing .dir folder: {dir_name}  scanner={scanner_type}")

    # Load existing sources so we can skip already-imported files
    store = load_store()
    existing_sources = set()
    for target in store.get("targets", []):
        for source in target.get("sources", []):
            existing_sources.add(source)
    print(f"[DEBUG][dir] existing_sources in store: {sorted(existing_sources) or '(empty)'}")
    print(f"[DEBUG][dir] current targets in store: {[t.get('id') for t in store.get('targets', [])]}")

    files = sorted([f for f in dir_path.iterdir() if f.is_file() and not f.name.startswith(".")])
    print(f"[watcher] Found {len(files)} file(s) in {dir_name}: {[f.name for f in files]}")

    for filepath in files:
        if filepath.name in existing_sources:
            print(f"[watcher]   skip (already imported): {filepath.name}")
            continue
        print(f"[DEBUG][dir]   → queuing {filepath.name} for processing")
        try:
            process_import_file(filepath, scanner_type=scanner_type, skip_move=True)
        except Exception as e:
            print(f"[watcher] Error processing {filepath.name}: {e}")
            import traceback
            traceback.print_exc()

    # Move entire .dir folder to processed/
    os.makedirs(PROCESSED_PATH, exist_ok=True)
    dest = Path(PROCESSED_PATH) / dir_name
    try:
        if dest.exists():
            # If a previous run already moved a dir with the same name, remove the old one
            shutil.rmtree(dest)
        shutil.move(str(dir_path), str(dest))
        print(f"[watcher] ✓ Moved {dir_name}/ -> processed/")
    except Exception as e:
        print(f"[watcher] ✗ Failed to move {dir_name}: {e}")


def load_store():
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return DEFAULT_STORE.copy()
    except Exception:
        return DEFAULT_STORE.copy()


def save_store(store):
    # Ensure data directory exists
    os.makedirs(os.path.dirname(STORE_PATH) or ".", exist_ok=True)
    tmp = STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, STORE_PATH)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "bridge": True})


@app.route("/api/axiom/config", methods=["GET"])
def get_axiom_config():
    """Return key fields from ~/.axiom/axiom.json (provisioner, provider, imageid)"""
    axiom_json = os.path.expanduser("~/.axiom/axiom.json")
    result = {"provisioner": "unknown", "provider": "unknown", "imageid": "unknown"}
    if os.path.exists(axiom_json):
        try:
            with open(axiom_json) as f:
                cfg = json.load(f)
            result["provisioner"] = cfg.get("provisioner", "unknown") or "unknown"
            result["provider"]    = cfg.get("provider", "unknown") or "unknown"
            result["imageid"]     = cfg.get("imageid", "unknown") or "unknown"
        except Exception as e:
            print(f"[config] Error reading axiom.json: {e}")
    return jsonify(result)


@app.route("/api/targets", methods=["GET"])
def get_targets():
    store = load_store()
    return jsonify(store.get("targets", []))


@app.route("/api/screenshots/<path:rel>")
def serve_screenshot(rel):
    """Serve screenshot images stored in processed/gowitness-* bundles.
    rel = gowitness-TS/screenshots/filename.jpeg
    """
    full_path = os.path.realpath(os.path.join(PROCESSED_PATH, rel))
    # Security: must stay inside PROCESSED_PATH
    if not full_path.startswith(os.path.realpath(PROCESSED_PATH)):
        abort(403)
    if not os.path.isfile(full_path):
        print(f"[gw] Screenshot 404: {full_path}")
        abort(404)
    print(f"[gw] Serving screenshot: {full_path}")
    return send_file(full_path, mimetype="image/jpeg")


@app.route("/api/gowitness-bundle/<bundle_name>/zip")
def download_gowitness_bundle(bundle_name):
    """Download a gowitness bundle (sqlite + screenshots) as a ZIP archive.
    bundle_name must be in the form gowitness-MM-DD_HH-MM-SS.
    """
    import re, io, zipfile
    # Validate to prevent path traversal — only alphanumerics, hyphens, underscores
    if not re.match(r'^gowitness-[\w-]+$', bundle_name):
        abort(400)
    real_processed = os.path.realpath(PROCESSED_PATH)
    bundle_path = os.path.realpath(os.path.join(PROCESSED_PATH, bundle_name))
    # Security: bundle must live inside PROCESSED_PATH
    if not bundle_path.startswith(real_processed + os.sep) and bundle_path != real_processed:
        abort(403)
    if not os.path.isdir(bundle_path):
        print(f"[gw] Bundle ZIP 404: {bundle_path}")
        abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(bundle_path):
            for fname in files:
                full = os.path.join(root, fname)
                arcname = os.path.relpath(full, os.path.dirname(bundle_path))
                zf.write(full, arcname)
    buf.seek(0)
    print(f"[gw] Serving bundle ZIP: {bundle_name} ({buf.getbuffer().nbytes} bytes)")
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{bundle_name}.zip",
    )


@app.route("/api/targets/<path:tid>/raw-zip")
def download_target_raw(tid):
    """Download the raw source files for a target as a ZIP.
    Looks up target.sources[] filenames anywhere inside PROCESSED_PATH.
    """
    import io, zipfile, glob
    store = load_store()
    target = next((t for t in store.get("targets", []) if t.get("id") == tid), None)
    if not target:
        abort(404)
    sources = target.get("sources", [])
    if not sources:
        abort(404)
    real_processed = os.path.realpath(PROCESSED_PATH)
    real_imports   = os.path.realpath(IMPORTS_PATH)
    buf = io.BytesIO()
    added = 0
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for src_name in sources:
            matches = glob.glob(
                os.path.join(real_processed, "**", src_name), recursive=True
            )
            if not matches:
                candidate = os.path.join(real_imports, src_name)
                if os.path.isfile(candidate):
                    matches = [candidate]
            for fpath in matches:
                real_fpath = os.path.realpath(fpath)
                if not real_fpath.startswith(real_imports):
                    continue
                arcname = os.path.relpath(real_fpath, real_processed)
                zf.write(real_fpath, arcname)
                added += 1
    if added == 0:
        abort(404)
    buf.seek(0)
    safe_id = re.sub(r'[^\w\-.]', '_', tid)[:64]
    print(f"[raw-zip] Serving {added} file(s) for '{tid}'")
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{safe_id}-raw.zip",
    )


@app.route("/api/debug/store", methods=["GET"])
def debug_store():
    """Return a diagnostic summary of the store — target IDs, domains, sources,
    and rawWhoisData keys (NOT the full content to keep the response small)."""
    store = load_store()
    targets = store.get("targets", [])
    summary = []
    for t in targets:
        rwd = t.get("rawWhoisData") or {}
        summary.append({
            "id": t.get("id"),
            "domain": t.get("domain"),
            "programName": t.get("programName"),
            "status": t.get("status"),
            "sources": t.get("sources", []),
            "subdomains": [s.get("hostname") for s in t.get("subdomains", [])],
            "rawWhoisData_keys": list(rwd.keys()),
            "rawWhoisData_sizes": {k: len(v) for k, v in rwd.items()},
        })
    return jsonify({
        "store_path": STORE_PATH,
        "target_count": len(targets),
        "targets": summary,
    })


@app.route("/api/imports/scan", methods=["GET", "POST"])
def trigger_import_scan():
    """Trigger an immediate scan of the imports/ directory."""
    try:
        new_files = scan_imports_dir(verbose=True)
        return jsonify({"ok": True, "new_files": new_files})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/imports/upload", methods=["POST"])
def upload_import_file():
    """Accept a file upload and save it to the correct imports/ subfolder.

    Supported form fields:
      file     – the file to upload (required)
      scanner  – hint: "nuclei", "amass", etc.  Auto-detected from filename if omitted.
      trigger  – if "true" (default), immediately run scan_imports_dir after saving.
    """
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No 'file' field in request"}), 400

    f        = request.files["file"]
    scanner  = (request.form.get("scanner") or "").strip().lower()
    trigger  = request.form.get("trigger", "true").lower() != "false"
    filename = f.filename or "upload.txt"
    filename = Path(filename).name  # strip any path traversal

    # Auto-detect scanner from filename if not supplied
    if not scanner:
        scanner = classify_by_filename(filename) or ""

    # Choose destination directory
    subdir_map = {
        "nuclei":     NUCLEI_PATH,
        "amass":      AMASS_PATH,
        "nmap":       NMAP_PATH,
        "nmapx":      NMAPX_PATH,
        "gowitness":  GOWITHNESS_PATH,
        "httpx":      HTTPX_PATH,
        "dnsx":       DNSX_PATH,
        "whois":      WHOIS_PATH,
        "ffuf":       FFUF_PATH,
    }
    dest_dir = subdir_map.get(scanner, IMPORTS_PATH)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = Path(dest_dir) / filename

    try:
        f.save(str(dest_path))
        print(f"[upload] Saved {filename} -> {dest_path}  (scanner={scanner or 'auto'})")
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to save file: {e}"}), 500

    new_files = 0
    if trigger:
        try:
            new_files = scan_imports_dir(verbose=True)
        except Exception as e:
            print(f"[upload] scan_imports_dir error: {e}")

    return jsonify({
        "ok":       True,
        "filename": filename,
        "scanner":  scanner or "auto",
        "dest":     str(dest_path),
        "new_files": new_files,
    })


@app.route("/api/imports/reimport", methods=["POST"])
def reimport_processed():
    """Move all .dir folders (and flat files) from imports/processed/ back to
    imports/ and trigger a fresh re-scan.  Useful after a bridge restart that
    cleared the store, or when you want to force re-parsing.
    """
    moved = []
    errors = []

    if os.path.isdir(PROCESSED_PATH):
        for item in os.listdir(PROCESSED_PATH):
            src = os.path.join(PROCESSED_PATH, item)
            dst = os.path.join(IMPORTS_PATH, item)
            try:
                if os.path.exists(dst):
                    if os.path.isdir(dst):
                        shutil.rmtree(dst)
                    else:
                        os.remove(dst)
                shutil.move(src, dst)
                print(f"[reimport] Restored {item} -> imports/")
                moved.append(item)
            except Exception as e:
                print(f"[reimport] Failed to restore {item}: {e}")
                errors.append({"file": item, "error": str(e)})

    try:
        new_files = scan_imports_dir(verbose=True)
    except Exception as e:
        return jsonify({"ok": False, "moved": moved, "error": str(e)}), 500

    return jsonify({"ok": True, "moved": moved, "new_files": new_files, "errors": errors})


@app.route("/api/fleet", methods=["GET"])
def get_fleet():
    # Query parameters for flexible filtering
    # Default to "managed" to only show Axiom-managed instances (from selected.conf or scan prefixes)
    filter_mode = request.args.get("filter", "managed")  # "all", "managed", or specific prefix
    force_refresh = request.args.get("refresh", "false").lower() == "true"  # Force cache bypass
    print(f"[bridge] Fetching fleet with filter_mode: {filter_mode}, force_refresh: {force_refresh}")
    
    # Check cache first (unless force refresh requested)
    current_time = time.time()
    cache_age = current_time - FLEET_CACHE["timestamp"]
    
    if not force_refresh and cache_age < FLEET_CACHE["ttl"] and FLEET_CACHE["data"]:
        print(f"[bridge] Returning cached fleet data (age: {cache_age:.1f}s, ttl: {FLEET_CACHE['ttl']}s)")
        return jsonify(FLEET_CACHE["data"])
    
    # Cache miss or expired - fetch fresh data from axiom-ls via zsh
    print(f"[bridge] Cache {'bypass' if force_refresh else 'miss/expired'} - fetching fleet data via axiom-ls")
    result = run_zsh_command("axiom-ls --json", timeout=180)
    
    # Load axiom instance metadata from stats.log
    instance_metadata = {}
    stats_log_path = os.path.expanduser("~/.axiom/stats.log")
    if os.path.exists(stats_log_path):
        try:
            with open(stats_log_path, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        # Extract instance info from "init" entries (deployment records)
                        if "init" in entry and "ip" in entry:
                            instance_name = entry["init"]
                            instance_metadata[instance_name] = {
                                "time": entry.get("time", ""),
                                "region": entry.get("region", ""),
                                "size": entry.get("size", ""),
                                "image": entry.get("image", ""),
                                "deploy": entry.get("deploy", "false"),
                            }
                    except json.JSONDecodeError:
                        pass
            print(f"[bridge] Loaded {len(instance_metadata)} instance metadata from stats.log")
        except Exception as e:
            print(f"[bridge] Failed to read stats.log: {e}")
    else:
        print(f"[bridge] stats.log not found at {stats_log_path}")
    
    # Load axiom-managed instance names from selected.conf
    axiom_instances = set()
    selected_conf_path = os.path.expanduser("~/.axiom/selected.conf")
    if os.path.exists(selected_conf_path):
        try:
            with open(selected_conf_path, "r") as f:
                axiom_instances = set(line.strip() for line in f if line.strip())
            print(f"[bridge] Loaded {len(axiom_instances)} instance names from selected.conf: {axiom_instances}")
        except Exception as e:
            print(f"[bridge] Failed to read selected.conf: {e}")
    else:
        print(f"[bridge] selected.conf not found at {selected_conf_path}")
    
    if result["returncode"] == 0 and result["stdout"]:
        # axiom-ls --json outputs a header line before JSON, strip it
        output = result["stdout"]
        
        # Strip ANSI color codes (e.g., [1;37m)
        import re
        output = re.sub(r'\x1b\[[0-9;]*m', '', output)
        
        # Find the first '{' or '[' to locate where JSON starts
        json_start = -1
        for i, char in enumerate(output):
            if char in ('{', '['):
                json_start = i
                break
        
        print(f"[bridge] JSON starts at position: {json_start}")
        
        if json_start >= 0:
            json_str = output[json_start:]
            print(f"[bridge] First 100 chars of JSON string: {json_str[:100]}")
            try:
                data = json.loads(json_str)
                
                # Handle AWS EC2 describe-instances format
                if isinstance(data, dict) and "Reservations" in data:
                    fleet = []
                    skipped_count = 0
                    for reservation in data.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            # Extract instance details from AWS format
                            name = None
                            for tag in instance.get("Tags", []):
                                if tag.get("Key") == "Name":
                                    name = tag.get("Value")
                                    break
                            
                            if not name:
                                print(f"[bridge] Skipping instance without Name tag")
                                skipped_count += 1
                                continue
                            
                            # Apply filtering based on filter_mode
                            is_axiom_managed = name in axiom_instances
                            
                            # Check if instance matches any active scan prefix
                            is_scan_instance = False
                            with SCAN_INSTANCES["lock"]:
                                for prefix in SCAN_INSTANCES["prefixes"]:
                                    if name.lower().startswith(prefix.lower()):
                                        is_scan_instance = True
                                        print(f"[bridge] Instance {name} matches active scan prefix: {prefix}")
                                        break
                            
                            should_include = False
                            
                            if filter_mode == "managed":
                                # Include axiom-managed instances OR instances from active scans
                                should_include = is_axiom_managed or is_scan_instance
                            elif filter_mode == "all":
                                # Include all instances
                                should_include = True
                            else:
                                # Custom prefix filter (e.g., "dvw" includes "dvw01", "dvw-prod")
                                # Also include instances from active scans
                                should_include = name.lower().startswith(filter_mode.lower()) or is_scan_instance
                            
                            if not should_include:
                                print(f"[bridge] Skipping instance {name} (filter_mode={filter_mode}, axiom_managed={is_axiom_managed}, scan_instance={is_scan_instance})")
                                skipped_count += 1
                                continue
                            
                            state = instance.get("State", {}).get("Name", "unknown")
                            public_ip = instance.get("PublicIpAddress", "")
                            instance_type = instance.get("InstanceType", "unknown")
                            placement = instance.get("Placement", {})
                            region = placement.get("AvailabilityZone", "Unknown")
                            
                            # Get metadata from stats.log if available
                            metadata = instance_metadata.get(name, {})
                            deployment_time = metadata.get("time", "")
                            stats_region = metadata.get("region", region)
                            stats_size = metadata.get("size", instance_type)
                            
                            fleet.append({
                                "id": name,
                                "name": name,
                                "provider": "AWS",
                                "ip": public_ip,
                                "region": stats_region or region,
                                "status": state,
                                "instanceType": stats_size or instance_type,
                                "currentTask": "",
                                "uptime": deployment_time,
                                "axiomManaged": is_axiom_managed,  # Tag whether it's in selected.conf
                            })
                    print(f"[bridge] axiom-ls returned {len(fleet)} filtered instances (skipped {skipped_count})")
                    
                    # Update cache
                    FLEET_CACHE["data"] = fleet
                    FLEET_CACHE["timestamp"] = time.time()
                    print(f"[bridge] Fleet cache updated with {len(fleet)} instances")
                    
                    return jsonify(fleet)
                
                # Handle axiom native format (array of instances)
                elif isinstance(data, list):
                    fleet = []
                    for instance in data:
                        fleet.append({
                            "id": instance.get("name", "unknown"),
                            "name": instance.get("name", "unknown"),
                            "provider": instance.get("provider", "Unknown"),
                            "ip": instance.get("ip", ""),
                            "region": instance.get("region", "Unknown"),
                            "status": instance.get("status", "unknown"),
                            "instanceType": instance.get("size", "unknown"),
                            "currentTask": "",
                            "uptime": "",
                        })
                    print(f"[bridge] axiom-ls returned {len(fleet)} instances")
                    
                    # Update cache
                    FLEET_CACHE["data"] = fleet
                    FLEET_CACHE["timestamp"] = time.time()
                    print(f"[bridge] Fleet cache updated with {len(fleet)} instances")
                    
                    return jsonify(fleet)
                else:
                    print(f"[bridge] axiom-ls returned unexpected data structure: {type(data)}")
            except json.JSONDecodeError as e:
                print(f"[bridge] axiom-ls output not valid JSON: {e}")
                print(f"[bridge] Attempted to parse: {json_str[:200]}")
        else:
            print(f"[bridge] Could not find JSON start in output")
            print(f"[bridge] Raw output: {output[:200]}")
    else:
        print(f"[bridge] axiom-ls failed or returned no data")
        if result["stderr"]:
            print(f"[bridge] axiom-ls stderr: {result['stderr'][:200]}")
    
    # Return empty list if axiom-ls fails (don't fall back to stale stored data)
    print(f"[bridge] No instances available from axiom-ls, returning empty fleet")
    return jsonify([])


@app.route("/api/targets/<path:tid>", methods=["GET"])
def get_target(tid):
    store = load_store()
    for t in store.get("targets", []):
        if t.get("id") == tid or t.get("domain") == tid:
            return jsonify(t)
    abort(404)


@app.route("/api/targets/<path:tid>", methods=["DELETE"])
def delete_target(tid):
    """Delete a target from the store by id."""
    store = load_store()
    before = len(store.get("targets", []))
    store["targets"] = [t for t in store.get("targets", []) if t.get("id") != tid]
    after = len(store["targets"])
    if before == after:
        abort(404)
    save_store(store)
    return jsonify({"deleted": tid, "remaining": after})


@app.route("/api/targets", methods=["DELETE"])
def delete_targets_bulk():
    """Delete multiple targets. Body: {"ids": ["id1", "id2"]}"""
    body = request.get_json(silent=True) or {}
    ids = set(body.get("ids", []))
    if not ids:
        return jsonify({"error": "no ids provided"}), 400
    store = load_store()
    store["targets"] = [t for t in store.get("targets", []) if t.get("id") not in ids]
    save_store(store)
    return jsonify({"deleted": list(ids), "remaining": len(store["targets"])})


@app.route("/run-axiom-ls", methods=["GET"])
def run_axiom_ls():
    # run the axiom-ls executable if present
    if not Path(AXIOM_LS_PATH).exists():
        return jsonify({"error": "axiom-ls not found", "path": AXIOM_LS_PATH}), 404
    try:
        print(f"[bridge] running axiom-ls: {AXIOM_LS_PATH} --json")
        res = subprocess.run([AXIOM_LS_PATH, "--json"], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            print(f"[bridge] axiom-ls failed rc={res.returncode} stderr={res.stderr[:200]}")
            return jsonify({"error": "axiom-ls failed", "stderr": res.stderr}), 500
        # try to parse stdout as json
        try:
            data = json.loads(res.stdout)
        except Exception:
            data = {"raw": res.stdout}
        print(f"[bridge] axiom-ls output size={len(res.stdout)}")
        return jsonify(data)
    except Exception as e:
        print(f"[bridge] run_axiom_ls exception: {e}")
        return jsonify({"error": str(e)}), 500


# Scan management endpoints
SCANS_STORE = os.path.join(os.path.dirname(STORE_PATH), "scans.json")

# ── Failure-pattern detection ─────────────────────────────────────────────────
# Each entry: (lowercase search pattern, human-readable label).
_LOG_FAILURE_PATTERNS = [
    ("command not found",          "command not found"),
    ("unable to find image",       "docker image not found"),
    ("pull access denied",         "docker pull access denied"),
    ("error response from daemon", "docker daemon error"),
    ("no such file or directory",  "file not found"),
    ("permission denied",          "permission denied"),
    ("exec format error",          "exec format error"),
    ("cannot find",                "binary not found"),
    ("not installed",              "tool not installed"),
    ("failed to connect",          "connection failed"),
    ("connection refused",         "connection refused"),
]

def _detect_log_failures(log_lines):
    """Scan log lines for known failure patterns.
    Returns (is_failed: bool, failure_reason: str | None, failure_lines: list[str])
    """
    matched_lines = []
    matched_reasons = []
    for raw_line in log_lines:
        line = raw_line.strip() if isinstance(raw_line, str) else ""
        line_lower = line.lower()
        for pattern, reason in _LOG_FAILURE_PATTERNS:
            if pattern in line_lower:
                if line not in matched_lines:
                    matched_lines.append(line[:200])
                if reason not in matched_reasons:
                    matched_reasons.append(reason)
                break
    if matched_reasons:
        return True, "; ".join(matched_reasons[:3]), matched_lines[:5]
    return False, None, []

def _read_logs_for_failure_check(path, max_lines=500):
    """Read log lines from a file or directory path for failure detection."""
    lines = []
    if not path or not os.path.exists(path):
        return lines
    try:
        if os.path.isfile(path):
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()[-max_lines:]
        elif os.path.isdir(path):
            for fname in sorted(os.listdir(path)):
                fpath = os.path.join(path, fname)
                if os.path.isfile(fpath):
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            lines.extend(f.readlines()[-max_lines:])
                    except Exception:
                        pass
    except Exception as e:
        print(f"[failure-check] Error reading logs at {path}: {e}")
    return lines

def load_scans_from_stats_log():
    """Load scan history from ~/.axiom/stats.log"""
    scans = []
    stats_log_path = os.path.expanduser("~/.axiom/stats.log")

    if not os.path.exists(stats_log_path):
        print(f"[scans] stats.log not found at {stats_log_path}")
        return scans

    try:
        with open(stats_log_path, "r") as f:
            lines = f.readlines()

        known_non_scan_keys = {"init", "ip", "time", "region", "size", "image", "deploy"}

        for line_num, line in enumerate(lines, 1):
            try:
                line = line.strip()
                if not line:
                    continue

                entry = json.loads(line)

                # "scan" key → actual scan record
                if "scan" in entry and isinstance(entry["scan"], dict):
                    for module_name, scan_data in entry["scan"].items():
                        scan_id = scan_data.get("id", f"{module_name}-unknown")
                        scan_obj = {
                            "id": scan_id,
                            "name": scan_id,
                            "module": module_name,
                            "status": scan_data.get("status", "completed"),
                            "date": scan_data.get("date", ""),
                            "instances": int(scan_data.get("instances", 0)),
                            "targets": int(scan_data.get("targets", 0)),
                            "results": int(scan_data.get("results", 0)),
                            "runtime": scan_data.get("runtime", ""),
                            "command": scan_data.get("command", ""),
                            "threads": int(scan_data.get("threads", 0)),
                            "local_logs": scan_data.get("local_logs", ""),
                            "remote_logs": scan_data.get("remote_logs", ""),
                            "output": scan_data.get("output", ""),
                            "extra_args": scan_data.get("extra_args", ""),
                        }
                        # If 0 results, check local logs for known failure patterns
                        if scan_obj["results"] == 0 and scan_obj.get("local_logs"):
                            _log_lines = _read_logs_for_failure_check(scan_obj["local_logs"])
                            if _log_lines:
                                _is_failed, _reason, _fail_lines = _detect_log_failures(_log_lines)
                                if _is_failed:
                                    scan_obj["status"] = "failed"
                                    scan_obj["failure_reason"] = _reason
                                    scan_obj["failure_lines"] = _fail_lines
                                    print(f"[scans] Marking {scan_id} as FAILED: {_reason}")
                        scans.append(scan_obj)

                elif not known_non_scan_keys.issuperset(entry.keys()):
                    # Only warn for truly unexpected entry shapes
                    print(f"[scans] Line {line_num}: Unrecognised entry keys: {list(entry.keys())}")

            except json.JSONDecodeError as e:
                print(f"[scans] Line {line_num}: JSON decode error: {e}")
            except Exception as e:
                print(f"[scans] Line {line_num}: Error processing: {e}")

        print(f"[scans] Loaded {len(scans)} scans from stats.log ({len(lines)} lines)")
    except Exception as e:
        print(f"[scans] Failed to read stats.log: {e}")
        import traceback
        traceback.print_exc()

    return scans

def load_scans():
    """Load scans from stats.log, fall back to store if needed"""
    try:
        scans = load_scans_from_stats_log()
        if scans:
            return scans
    except Exception as e:
        print(f"[scans] Error loading from stats.log: {e}")
    
    # Fallback to stored scans
    try:
        with open(SCANS_STORE, "r") as f:
            return json.load(f)
    except:
        return []

def save_scans(scans):
    """Save scans to store (mainly for running/pending scans not yet in stats.log)"""
    try:
        with open(SCANS_STORE, "w") as f:
            json.dump(scans, f, indent=2)
    except Exception as e:
        print(f"[scans] Failed to save scans: {e}")


def sanitize_domain(target: str) -> str:
    """Sanitize a single target string (domain, IP, CIDR, or URL).
    Strips whitespace and removes characters that are unsafe in shell contexts.
    Returns an empty string if the target is clearly invalid.
    """
    target = target.strip()
    if not target:
        return ""
    # Remove shell-unsafe characters (keep alphanumerics, dots, dashes, slashes,
    # colons for ports/IPv6, brackets for IPv6, underscores, @, %)
    sanitized = re.sub(r"[^\w.:/\-@%\[\]]+", "", target)
    return sanitized


@app.route("/api/axiom/modules", methods=["GET"])
def get_modules():
    """List available axiom scan modules that have their required tool installed"""
    import shutil
    modules_path = os.path.expanduser("~/.axiom/modules")
    available = []
    if os.path.exists(modules_path):
        for fname in sorted(os.listdir(modules_path)):
            if fname.startswith('.') or not fname.endswith('.json'):
                continue
            module_name = fname[:-5]  # strip .json
            try:
                with open(os.path.join(modules_path, fname)) as f:
                    module_data = json.load(f)
                # Get command from first entry (module JSON is a list or dict)
                command = None
                if isinstance(module_data, list) and module_data:
                    command = module_data[0].get("command", "")
                elif isinstance(module_data, dict):
                    command = module_data.get("command", "")

                if command:
                    binary = command.strip().split()[0] if command.strip() else None
                    if binary and shutil.which(binary):
                        available.append(fname)
                    else:
                        print(f"[modules] Skipping {module_name}: '{binary}' not found in PATH")
                else:
                    available.append(fname)  # no command field, include anyway
            except Exception as e:
                print(f"[modules] Error reading {fname}: {e}")
                available.append(fname)  # include on parse error

    if not available:
        # Fallback when ~/.axiom/modules doesn't exist yet
        fallback_tools = ["amass", "httpx", "dnsx", "nmap", "ffuf",
                          "nuclei", "gowitness", "subfinder", "masscan"]
        available = [f"{t}.json" for t in fallback_tools if shutil.which(t)]

    return jsonify({"modules": available})

@app.route("/api/axiom/scan", methods=["POST"])
def launch_scan():
    """Launch an axiom-scan job, optionally deploying a new fleet first"""
    data = request.json
    scan_name = data.get("scanName")
    targets = data.get("targets", [])
    module = data.get("module")
    output_file = data.get("outputFile")
    options = data.get("options", {})
    fleet_config = data.get("fleet")
    
    if not all([scan_name, targets, module, output_file]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Handle fleet deployment if requested
    deployed_fleet_name = None
    if fleet_config and fleet_config.get("deploy"):
        print(f"[scans] Fleet deployment requested: {fleet_config}")
        fleet_name = fleet_config.get("name") or f"{scan_name}-fleet"
        fleet_size = fleet_config.get("size", 5)
        fleet_region = fleet_config.get("region", "us-east-1")
        auto_destroy = fleet_config.get("autoDestroy", False)
        
        # Deploy fleet using axiom-fleet
        deploy_cmd = f"axiom-fleet {fleet_name} -i {fleet_size} --region={fleet_region}"
        print(f"[scans] Deploying fleet: {deploy_cmd}")
        
        try:
            result = run_zsh_command(deploy_cmd, timeout=600)  # 10 min timeout for fleet deployment
            if result["returncode"] == 0:
                print(f"[scans] Fleet {fleet_name} deployed successfully")
                deployed_fleet_name = fleet_name
                
                # Store fleet info for potential auto-destroy
                if auto_destroy:
                    scan_name = f"{scan_name}_AUTODESTROY_{fleet_name}"
            else:
                error_msg = f"Fleet deployment failed: {result.get('stderr', 'Unknown error')}"
                print(f"[scans] {error_msg}")
                return jsonify({"error": error_msg}), 500
        except Exception as e:
            error_msg = f"Failed to deploy fleet: {str(e)}"
            print(f"[scans] {error_msg}")
            return jsonify({"error": error_msg}), 500
    
    # Create scan record
    module_name = module.replace('.json', '')
    scan_id = f"{module_name}+{datetime.utcnow().strftime('%m-%d_%H-%M-%S-%f')[:22]}"
    
    try:
        with open(SCANS_STORE, "r") as f:
            scans = json.load(f)
    except:
        scans = []
    
    scan = {
        "id": scan_id,
        "name": scan_name,
        "module": module,
        "targets": targets,
        "outputFile": output_file,
        "options": options,
        "fleet": deployed_fleet_name,
        "autoDestroyFleet": fleet_config.get("autoDestroy") if fleet_config else False,
        "status": "running",
        "startedAt": datetime.utcnow().isoformat() + "Z",
        "completedAt": None,
        "progress": 0,
        "logs": []
    }
    
    # Save scan
    scans.append(scan)
    save_scans(scans)
    
    # Build axiom-scan command
    # Create input file in axiom tmp directory with proper naming
    axiom_tmp = AXIOM_TMP  # Use configured temp path (Docker-friendly)
    os.makedirs(axiom_tmp, exist_ok=True)
    targets_file = os.path.join(axiom_tmp, f"{scan_name}_{module}_targets.txt")
    
    # Convert targets to plain strings if they're objects
    target_lines = []
    for t in targets:
        if isinstance(t, dict):
            target_str = t.get("hostname") or t.get("domain") or t.get("host") or t.get("target") or t.get("url") or t.get("ip") or str(t)
        else:
            target_str = str(t)
        target_str = sanitize_domain(target_str)
        if target_str:
            target_lines.append(target_str)

    if not target_lines:
        print(f"[scans] ERROR: No valid targets after processing {len(targets)} input(s)")
        return jsonify({"error": "No valid targets provided"}), 400
    
    try:
        with open(targets_file, "w", encoding="utf-8") as f:
            for line in target_lines:
                f.write(line + "\n")
            f.flush()
        print(f"[scans] Input file: {targets_file} ({len(target_lines)} targets)")
    except Exception as e:
        print(f"[scans] Error creating input file: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Failed to create input file: {e}"}), 500
    
    # Create output directory in the imports folder for auto-import into dashboard
    # Most modules: output file goes directly to imports/ (module name is in filename)
    # Exception: gowitness outputs a folder of screenshots
    if module == "gowitness":
        # Gowitness outputs a directory, put it in imports/gowitness/
        output_dir = os.path.join(IMPORTS_PATH, "gowitness")
        os.makedirs(output_dir, exist_ok=True)
    else:
        # All other modules: put output file directly in imports/
        # The filename already contains the module name (e.g., example-httpx.txt, example-whois.txt)
        output_dir = IMPORTS_PATH
    
    # Auto-generate output filename as {module}+{timestamp}.{ext}
    # Avoids per-target modules (e.g. whois) creating a directory instead of a file
    ext = ".txt"
    module_json_path = os.path.expanduser(
        f"~/.axiom/modules/{module if module.endswith('.json') else module + '.json'}"
    )
    try:
        with open(module_json_path) as _mf:
            _mdata = json.load(_mf)
            if isinstance(_mdata, list) and _mdata:
                raw_ext = _mdata[0].get("ext", "txt")
                ext = raw_ext if raw_ext.startswith('.') else f".{raw_ext}"
    except Exception:
        pass
    output_filename = f"{scan_id}{ext}"
    output_file_abs = os.path.join(output_dir, output_filename)
    print(f"[scans] Output: {output_file_abs}")
    
    cmd = ["axiom-scan", targets_file, "-m", module, "-o", output_file_abs]
    
    # Track which fleet prefix/name this scan will use
    fleet_prefix_to_track = None
    
    # If we deployed a fleet, target it specifically
    if deployed_fleet_name:
        cmd.extend(["--fleet", deployed_fleet_name])
        fleet_prefix_to_track = deployed_fleet_name
    
    # Add fleet control options (from ax scan --help Fleet Control section)
    fleet_control = data.get("fleetControl", {})
    
    # If spinup is requested, ensure we have a fleet prefix to track the instances
    # Auto-generate from scan name if not provided
    if fleet_control.get("spinup"):
        cmd.extend(["--spinup", str(fleet_control["spinup"])])
        
        # Use provided fleet prefix or auto-generate from scan name
        if fleet_control.get("fleetPrefix"):
            fleet_prefix_to_track = fleet_control["fleetPrefix"]
        else:
            # Auto-generate prefix from scan name (lowercase, alphanumeric only)
            import re
            fleet_prefix_to_track = re.sub(r'[^a-z0-9]', '', scan_name.lower())[:12] or "axscan"
            print(f"[scans] Auto-generated fleet prefix from scan name: {fleet_prefix_to_track}")
        
        # Always add --fleet when spinning up to ensure consistent naming
        cmd.extend(["--fleet", fleet_prefix_to_track])
        print(f"[scans] Using fleet prefix '{fleet_prefix_to_track}' for {fleet_control['spinup']} instances")
    elif fleet_control.get("fleetPrefix"):
        cmd.extend(["--fleet", fleet_control["fleetPrefix"]])
        fleet_prefix_to_track = fleet_control["fleetPrefix"]
    if fleet_control.get("regions"):
        # regions is an array, join with commas
        regions_str = ",".join(fleet_control["regions"])
        cmd.extend(["--regions", regions_str])
    if fleet_control.get("rmWhenDone"):
        cmd.append("--rm-when-done")
    if fleet_control.get("shutdownWhenDone"):
        cmd.append("--shutdown-when-done")
    if fleet_control.get("customSsh"):
        cmd.extend(["--custom-ssh", fleet_control["customSsh"]])
    if fleet_control.get("useCache"):
        cmd.append("--cache")
    
    # Add options
    if options.get("wordlist"):
        cmd.extend(["-w", options["wordlist"]])
    if options.get("threads"):
        cmd.extend(["--threads", str(options["threads"])])
    if options.get("maxRuntime"):
        cmd.extend(["--max-runtime", options["maxRuntime"]])
    if options.get("dontShuffle"):
        cmd.append("--dont-shuffle")
    if options.get("dontSplit"):
        cmd.append("--dont-split")
    if options.get("expandCidr"):
        cmd.append("--expand-cidr")
    if options.get("anew"):
        cmd.append("--anew")
    if options.get("quiet"):
        cmd.append("--quiet")
    if options.get("unsafe"):
        cmd.append("--unsafe")
    if options.get("extraArgs"):
        cmd.extend(shlex.split(options["extraArgs"]))
    
    # Register fleet prefix so the fleet endpoint can find these instances
    if fleet_prefix_to_track:
        with SCAN_INSTANCES["lock"]:
            SCAN_INSTANCES["prefixes"].add(fleet_prefix_to_track)
            save_scan_prefixes(SCAN_INSTANCES["prefixes"])  # Persist to file
            print(f"[scans] Registered fleet prefix for tracking: {fleet_prefix_to_track}")
            print(f"[scans] Active scan prefixes: {SCAN_INSTANCES['prefixes']}")
        # Invalidate fleet cache so the dashboard refreshes and shows the new instances
        FLEET_CACHE["timestamp"] = 0
    
    # Print detailed command information
    print("\n" + "="*80)
    print("[scans] COMMAND PREVIEW")
    print("="*80)
    print(f"Scan ID: {scan_id}")
    print(f"Scan Name: {scan_name}")
    print(f"Module: {module}")
    print(f"Targets File: {targets_file}")
    print(f"Output File: {output_file_abs}")
    print(f"Output Directory: {output_dir}")
    if fleet_prefix_to_track:
        print(f"Fleet Prefix: {fleet_prefix_to_track}")
    print("\nFull Command:")
    print(' '.join(cmd))
    print("\nCommand with arguments on separate lines:")
    for i, arg in enumerate(cmd):
        print(f"  [{i}] {arg}")
    print("="*80 + "\n")
    
    # Launch in tmux session for proper detachment
    print(f"[scans] Launching scan {scan_id} in tmux session")
    
    # Create tmux session name from scan_id (replace + with _ for tmux compatibility)
    tmux_session = scan_id.replace('+', '_').replace(':', '_')
    
    # Build the command as a single shell string for tmux
    # Quote arguments that contain spaces
    cmd_str = ' '.join([f'"{arg}"' if ' ' in arg else arg for arg in cmd])

    # Persist the actual command string back to the scan record so the UI can display it
    for _s in scans:
        if _s["id"] == scan_id:
            _s["command"] = cmd_str
            break
    save_scans(scans)

    # Create tmux command that will run the scan using zsh (for proper axiom environment)
    # The zsh -l -c sources ~/.zshrc which sets up axiom PATH and functions
    log_file = os.path.join(axiom_tmp, f"{scan_id.replace('+', '_')}.log")
    
    tmux_shell_cmd = f'''zsh -l -c '
        echo "=== Axiom Scan Starting ===" | tee {log_file}
        echo "Time: $(date)" | tee -a {log_file}
        echo "Command: {cmd_str}" | tee -a {log_file}
        echo "Output: {output_file_abs}" | tee -a {log_file}
        echo "=========================" | tee -a {log_file}
        
        echo "" | tee -a {log_file}
        echo "=== Input File Check ===" | tee -a {log_file}
        if [ -f "{targets_file}" ]; then
            echo "✓ Input file: {targets_file}" | tee -a {log_file}
            echo "  Lines: $(wc -l < "{targets_file}")" | tee -a {log_file}
            echo "  Contents:" | tee -a {log_file}
            cat "{targets_file}" | tee -a {log_file}
        else
            echo "✗ ERROR: Input file does not exist!" | tee -a {log_file}
            exit 1
        fi
        echo "=========================" | tee -a {log_file}
        
        # Run the scan (output goes directly to imports/ folder)
        echo "" | tee -a {log_file}
        echo "=== Running Scan ===" | tee -a {log_file}
        {cmd_str} 2>&1 | tee -a {log_file}
        EXIT_CODE=$?
        
        echo "" | tee -a {log_file}
        echo "=== Scan Completed ===" | tee -a {log_file}
        echo "Exit code: $EXIT_CODE" | tee -a {log_file}
        echo "Time: $(date)" | tee -a {log_file}
        
        # Check output file (should be in imports/ folder for auto-import)
        echo "" | tee -a {log_file}
        if [ -f "{output_file_abs}" ]; then
            LINES=$(wc -l < "{output_file_abs}")
            SIZE=$(ls -lh "{output_file_abs}" | awk "{{print \\$5}}")
            echo "✓ Output saved to imports folder:" | tee -a {log_file}
            echo "  Path: {output_file_abs}" | tee -a {log_file}
            echo "  Lines: $LINES" | tee -a {log_file}
            echo "  Size: $SIZE" | tee -a {log_file}
            echo "" | tee -a {log_file}
            echo "=== Output Preview (first 20 lines) ===" | tee -a {log_file}
            head -20 "{output_file_abs}" | tee -a {log_file}
        elif [ -d "{output_file_abs}" ]; then
            # gowitness creates a directory
            echo "✓ Output directory created:" | tee -a {log_file}
            echo "  Path: {output_file_abs}" | tee -a {log_file}
            echo "  Contents: $(ls -1 "{output_file_abs}" | wc -l) files" | tee -a {log_file}
        else
            echo "✗ Output not found at: {output_file_abs}" | tee -a {log_file}
        fi
        
        echo "" | tee -a {log_file}
        echo "Scan finished. Keeping terminal open for 60 seconds..." | tee -a {log_file}
        echo "View full log: cat {log_file}" | tee -a {log_file}
        sleep 60
    '
    '''
    
    # Create tmux command - use send-keys so we can properly handle the zsh session
    tmux_cmd = [
        "tmux", "new-session", "-d", "-s", tmux_session,
        tmux_shell_cmd
    ]
    
    print(f"[scans] Tmux session: {tmux_session}")
    print(f"[scans] Tmux command: {' '.join(tmux_cmd)}")
    
    def run_scan():
        try:
            print(f"[scans] Background: Starting tmux session {tmux_session}")
            result = subprocess.run(tmux_cmd, capture_output=True, text=True, timeout=30)
            print(f"[scans] Background: Tmux session created with return code {result.returncode}")
            if result.stdout:
                print(f"[scans] Background stdout: {result.stdout[:500]}")
            if result.stderr:
                print(f"[scans] Background stderr: {result.stderr[:500]}")
            
            if result.returncode != 0:
                print(f"[scans] ERROR: Failed to create tmux session!")
                print(f"[scans] You can manually run: tmux attach -t {tmux_session}")
                return
            if result.returncode != 0:
                print(f"[scans] ERROR: Failed to create tmux session!")
                print(f"[scans] You can manually run: tmux attach -t {tmux_session}")
                return
            
            print(f"[scans] ✓ Scan running in tmux session: {tmux_session}")
            print(f"[scans] To view: tmux attach -t {tmux_session}")
            print(f"[scans] To list all sessions: tmux ls")
            
            # Note: We don't wait for the scan to complete here
            # The scan runs independently in tmux
            # Fleet auto-destruction would need to be handled differently
            # (e.g., via a monitoring script or cron job)
            
        except Exception as e:
            print(f"[scans] Background error: {e}")
            traceback.print_exc()
    
    import threading
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    print(f"[scans] Background thread started for scan {scan_id}")
    print(f"[scans] Scan will run in tmux session: {tmux_session}")
    print(f"[scans] Log file: {log_file}")
    print(f"[scans] Output will be saved to: {output_file_abs}")
    
    # Build response message based on whether spinup was requested
    spinup_count = fleet_control.get("spinup")
    if spinup_count:
        message = (
            f"Scan launched in tmux session '{tmux_session}'. "
            f"⚠️ Spinning up {spinup_count} new instance(s) with prefix '{fleet_prefix_to_track}' - this typically takes ~3-4 minutes. "
            f"Use 'tmux attach -t {tmux_session}' to monitor progress."
        )
        status = "initializing"
    else:
        message = f"Scan launched in tmux session '{tmux_session}'. Use 'tmux attach -t {tmux_session}' to view."
        status = "launched"
    
    return jsonify({
        "scanId": scan_id, 
        "status": status,
        "tmuxSession": tmux_session,
        "spinup": spinup_count,
        "fleetPrefix": fleet_prefix_to_track,
        "outputFile": output_file_abs,
        "logFile": log_file,
        "message": message
    })

@app.route("/api/axiom/scan/preview", methods=["POST"])
def preview_scan_command():
    """Preview the axiom-scan command that would be executed without actually running it"""
    data = request.json
    scan_name = data.get("scanName")
    targets = data.get("targets", [])
    module = data.get("module")
    output_file = data.get("outputFile")
    options = data.get("options", {})
    fleet_control = data.get("fleetControl", {})
    
    if not all([scan_name, targets, module]):
        return jsonify({"error": "Missing required fields for preview"}), 400
    
    # Build the command exactly as it would be built in launch_scan
    final_output_file = output_file or f"{scan_name}-{module}.txt"
    axiom_tmp = AXIOM_TMP  # Use configured temp path (Docker-friendly)
    targets_file = os.path.join(axiom_tmp, f"{scan_name}_{module}_targets.txt")
    
    cmd = ["axiom-scan", targets_file, "-m", module, "-o", final_output_file]
    
    # Add fleet control options
    if fleet_control.get("spinup"):
        cmd.extend(["--spinup", str(fleet_control["spinup"])])
    if fleet_control.get("fleetPrefix"):
        cmd.extend(["--fleet", fleet_control["fleetPrefix"]])
    if fleet_control.get("regions"):
        regions_str = ",".join(fleet_control["regions"])
        cmd.extend(["--regions", regions_str])
    if fleet_control.get("rmWhenDone"):
        cmd.append("--rm-when-done")
    if fleet_control.get("shutdownWhenDone"):
        cmd.append("--shutdown-when-done")
    if fleet_control.get("customSsh"):
        cmd.extend(["--custom-ssh", fleet_control["customSsh"]])
    if fleet_control.get("useCache"):
        cmd.append("--cache")
    
    # Add options
    if options.get("wordlist"):
        cmd.extend(["-w", options["wordlist"]])
    if options.get("threads"):
        cmd.extend(["--threads", str(options["threads"])])
    if options.get("maxRuntime"):
        cmd.extend(["--max-runtime", options["maxRuntime"]])
    if options.get("dontShuffle"):
        cmd.append("--dont-shuffle")
    if options.get("dontSplit"):
        cmd.append("--dont-split")
    if options.get("expandCidr"):
        cmd.append("--expand-cidr")
    if options.get("anew"):
        cmd.append("--anew")
    if options.get("quiet"):
        cmd.append("--quiet")
    if options.get("unsafe"):
        cmd.append("--unsafe")
    if options.get("extraArgs"):
        cmd.extend(shlex.split(options["extraArgs"]))
    
    return jsonify({
        "command": " ".join(cmd),
        "commandArray": cmd,
        "targetsFile": targets_file,
        "targetsCount": len(targets),
        "outputFile": final_output_file,
        "module": module,
        "scanName": scan_name
    })

@app.route("/api/axiom/scans", methods=["GET"])
def get_scans():
    """Get all scans from stats.log, sorted by most recent first"""
    print("[API /api/axiom/scans] Loading scans...")
    scans = load_scans()
    print(f"[API /api/axiom/scans] Loaded {len(scans)} scans")
    
    if scans:
        print(f"[API /api/axiom/scans] Sample scan (first): {scans[0]}")
    else:
        print("[API /api/axiom/scans] No scans loaded")
    
    # Sort by date/id in reverse order (most recent first)
    scans_sorted = sorted(scans, key=lambda x: x.get("date", x.get("id", "")), reverse=True)
    print(f"[API /api/axiom/scans] Returning {len(scans_sorted)} scans")
    return jsonify(scans_sorted)

@app.route("/api/axiom/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Get specific scan by ID - check both stats.log and filesystem"""
    print(f"[get_scan] Looking for scan: {scan_id}")
    
    # First try stats.log scans
    scans = load_scans()
    for scan in scans:
        if scan.get("id") == scan_id:
            print(f"[get_scan] Found in stats.log")
            return jsonify(scan)
    
    # If not found, try filesystem discovery
    print(f"[get_scan] Not in stats.log, checking filesystem...")
    axiom_logs = os.path.expanduser("~/.axiom/logs")
    axiom_tmp = os.path.expanduser("~/.axiom/tmp")
    
    # Check both directories for the scan folder
    for base_dir in [axiom_logs, axiom_tmp]:
        scan_path = os.path.join(base_dir, scan_id)
        if os.path.isdir(scan_path):
            print(f"[get_scan] Found in filesystem at: {scan_path}")
            
            # Parse the scan details from the folder
            parts = scan_id.rsplit('+', 1)
            module = parts[0] if parts else scan_id
            timestamp = parts[1] if len(parts) > 1 else ""
            
            output_dir = os.path.join(scan_path, "output")
            logs_dir = os.path.join(scan_path, "logs")
            log_file = os.path.join(scan_path, "axiom-scan.log")
            results_count = 0
            output_files = []
            output_content_lines = []  # actual content of per-domain files (e.g. whois)
            logs = []
            
            # Read logs - check both root axiom-scan.log and logs/ subdirectory
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        logs = f.readlines()
                        print(f"[get_scan] Read {len(logs)} log lines from axiom-scan.log")
                except Exception as e:
                    print(f"[get_scan] Error reading log: {e}")
            
            # If no root log file, collect logs from logs/ subdirectory
            if not logs and os.path.exists(logs_dir):
                try:
                    for instance_log in os.listdir(logs_dir):
                        log_path = os.path.join(logs_dir, instance_log)
                        if os.path.isfile(log_path):
                            try:
                                with open(log_path, 'r') as f:
                                    instance_logs = f.readlines()
                                    logs.extend(instance_logs)
                                    print(f"[get_scan] Read {len(instance_logs)} log lines from {instance_log}")
                            except Exception as e:
                                print(f"[get_scan] Error reading {instance_log}: {e}")
                except Exception as e:
                    print(f"[get_scan] Error reading logs directory: {e}")
            
            # Read output - output/ contains subdirectories per instance
            if os.path.exists(output_dir):
                try:
                    for item in os.listdir(output_dir):
                        item_path = os.path.join(output_dir, item)
                        
                        # If it's a file, read it directly
                        if os.path.isfile(item_path):
                            output_files.append(item)
                            try:
                                with open(item_path, 'r') as f:
                                    content = f.read()
                                    file_lines = content.splitlines()
                                    results_count += len(file_lines)
                                    print(f"[get_scan] Read {len(file_lines)} results from {item}")
                                    # Collect content for display (used when no axiom-scan.log)
                                    output_content_lines.append(f"=== {item} ===")
                                    output_content_lines.extend(file_lines)
                            except Exception as e:
                                print(f"[get_scan] Error reading file {item}: {e}")
                        
                        # If it's a directory (per-instance output), read files inside
                        elif os.path.isdir(item_path):
                            try:
                                for file_in_dir in os.listdir(item_path):
                                    file_path = os.path.join(item_path, file_in_dir)
                                    if os.path.isfile(file_path):
                                        output_files.append(f"{item}/{file_in_dir}")
                                        try:
                                            with open(file_path, 'r') as f:
                                                content = f.read()
                                                file_lines = len(content.splitlines())
                                                results_count += file_lines
                                                print(f"[get_scan] Read {file_lines} results from {item}/{file_in_dir}")
                                        except Exception as e:
                                            print(f"[get_scan] Error reading {item}/{file_in_dir}: {e}")
                            except Exception as e:
                                print(f"[get_scan] Error listing {item}: {e}")
                except Exception as e:
                    print(f"[get_scan] Error reading output: {e}")
            
            # If still no results from files, try to extract from logs
            # For running scans, results might only be in the logs, not written to output files yet
            if results_count == 0 and logs:
                print(f"[get_scan] No results in output files, extracting from logs...")
                # For modules like amass, results appear as domain names in logs
                # They typically don't start with common log prefixes and are valid domains
                domain_results = []
                for log_line in logs:
                    line = log_line.strip()
                    # Skip empty lines and common log messages
                    if not line or any(skip in line.lower() for skip in ['discovered', 'enumeration', 'error', 'warning', 'migrating', 'database', '[', 'no names']):
                        continue
                    # Basic domain validation - contains . and no spaces
                    if '.' in line and ' ' not in line and not line.startswith('/'):
                        domain_results.append(line)
                
                if domain_results:
                    results_count = len(domain_results)
                    print(f"[get_scan] Extracted {results_count} potential results from logs")
            
            # For gowitness (sqlite database), count the number of screens captured
            # GoWitness sqlite databases have a 'screenshots' table
            if module.lower() == "gowitness" and results_count == 0 and output_files:
                try:
                    import sqlite3
                    # Find the sqlite database file
                    for output_file in output_files:
                        if output_file.endswith('.db') or output_file.endswith('.sqlite3'):
                            db_path = os.path.join(output_dir, output_file)
                            try:
                                conn = sqlite3.connect(db_path)
                                cursor = conn.cursor()
                                # GoWitness stores screenshots in the screenshots table
                                cursor.execute("SELECT COUNT(*) FROM screenshots")
                                count = cursor.fetchone()[0]
                                results_count += count
                                print(f"[get_scan] GoWitness found {count} screenshots in {output_file}")
                                conn.close()
                            except Exception as e:
                                print(f"[get_scan] Error reading GoWitness database {output_file}: {e}")
                except ImportError:
                    print(f"[get_scan] sqlite3 module not available for GoWitness parsing")
            
            # Determine status based on log file modification time
            import time as time_module
            is_running = True
            check_file = log_file if os.path.exists(log_file) else None
            
            # If no root log, check logs directory for most recent file
            if not check_file and os.path.exists(logs_dir):
                try:
                    log_files = [f for f in os.listdir(logs_dir) if os.path.isfile(os.path.join(logs_dir, f))]
                    if log_files:
                        # Get the most recently modified log file
                        check_file = os.path.join(logs_dir, max(log_files, key=lambda f: os.path.getmtime(os.path.join(logs_dir, f))))
                except:
                    pass
            
            if check_file and os.path.exists(check_file):
                current_time = time_module.time()
                log_mtime = os.path.getmtime(check_file)
                time_since_update = current_time - log_mtime
                if time_since_update > 120:
                    is_running = False
                print(f"[get_scan] Log last updated {time_since_update:.0f}s ago, status={'running' if is_running else 'completed'}")
            else:
                # No log file at all (e.g. whois uses 'tee output/_target_', no axiom-scan.log)
                current_time = time_module.time()
                if output_files:
                    # Output files exist → scan ran and wrote results → completed
                    is_running = False
                    print(f"[get_scan] No log file but {len(output_files)} output file(s) found → marking as completed")
                elif os.path.exists(scan_path) and current_time - os.path.getmtime(scan_path) > 300:
                    # Folder >5 min old with no output yet → probably stalled
                    is_running = False
                    print(f"[get_scan] No log, no output, folder >5 min old → marking as completed")
                else:
                    print(f"[get_scan] No log file, no output yet — treating as still running")

            # For dir-type scans (e.g. whois) axiom-scan.log may be absent or minimal;
            # substitute actual per-domain file content so the viewer shows real data.
            if not logs and output_content_lines:
                logs = output_content_lines
                print(f"[get_scan] Using {len(output_content_lines)} output content lines as log display")

            # Detect failures via log patterns when scan is done and produced 0 results
            final_scan_status = "running" if is_running else "completed"
            scan_failure_reason = None
            scan_failure_lines_list = []
            if not is_running and results_count == 0 and logs:
                _is_failed, scan_failure_reason, scan_failure_lines_list = _detect_log_failures(logs)
                if _is_failed:
                    final_scan_status = "failed"
                    print(f"[get_scan] Marking {scan_id} as FAILED: {scan_failure_reason}")

            scan = {
                "id": scan_id,
                "name": scan_id,
                "module": module,
                "status": final_scan_status,
                "date": timestamp,
                "source": "tmp" if base_dir == axiom_tmp else "logs",
                "path": scan_path,
                "output_files": output_files,
                "output": output_dir if output_files else None,
                "local_logs": logs_dir if os.path.exists(logs_dir) else (log_file if os.path.exists(log_file) else None),
                "logs": logs,
                "results": results_count,
                "progress": min(95, (results_count // 10) if results_count else 0) if is_running else 100,
            }
            if scan_failure_reason:
                scan["failure_reason"] = scan_failure_reason
                scan["failure_lines"] = scan_failure_lines_list
            
            print(f"[get_scan] Returning filesystem scan: {results_count} results, {len(logs)} log lines, status={final_scan_status}")
            return jsonify(scan)
    
    print(f"[get_scan] Scan not found: {scan_id}")
    return jsonify({"error": "Scan not found"}), 404

@app.route("/api/axiom/scans/<scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id):
    """Cancel a running scan (if it's in the active store, not from stats.log)"""
    try:
        with open(SCANS_STORE, "r") as f:
            scans = json.load(f)
    except:
        scans = []
    
    for scan in scans:
        if scan.get("id") == scan_id:
            if scan.get("status") in ["running", "pending"]:
                scan["status"] = "cancelled"
                scan["completedAt"] = datetime.utcnow().isoformat() + "Z"
                save_scans(scans)
                return jsonify({"status": "cancelled"})
            else:
                return jsonify({"error": "Scan is not currently running"}), 400
    
    # Check if it's in stats.log (those are completed and can't be cancelled)
    stats_scans = load_scans_from_stats_log()
    for scan in stats_scans:
        if scan.get("id") == scan_id:
            return jsonify({"error": "Scan is already completed"}), 400
    
    return jsonify({"error": "Scan not found"}), 404

@app.route("/api/axiom/scans/<scan_id>/logs", methods=["GET"])
def get_scan_logs(scan_id):
    """Get logs for a specific scan from local_logs or remote_logs path"""
    scans = load_scans()
    scan = None
    for s in scans:
        if s.get("id") == scan_id:
            scan = s
            break
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    logs = []
    log_path = None
    
    # Try local_logs first, then remote_logs
    for path_key in ["local_logs", "remote_logs"]:
        path = scan.get(path_key, "")
        if path and os.path.exists(path):
            log_path = path
            print(f"[logs] Reading logs from {path_key}: {path}")
            break
    
    if not log_path:
        print(f"[logs] No log file found for scan {scan_id}")
        print(f"[logs]   local_logs: {scan.get('local_logs', 'N/A')}")
        print(f"[logs]   remote_logs: {scan.get('remote_logs', 'N/A')}")
        return jsonify({"logs": [], "error": "No log file found", "scan": scan})
    
    try:
        with open(log_path, "r") as f:
            content = f.read()
            # Split by lines and limit to last 1000 lines
            lines = content.split("\n")
            logs = lines[-1000:]
        print(f"[logs] Read {len(logs)} lines from {log_path}")
    except Exception as e:
        print(f"[logs] Failed to read log file: {e}")
        return jsonify({"logs": [], "error": str(e), "path": log_path}), 500
    
    return jsonify({
        "logs": logs,
        "scanId": scan_id,
        "logPath": log_path,
        "totalLines": len(logs)
    })

_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
_SCREENSHOT_MODULES = {"gowitness", "webscreenshot", "scrying", "aquatone"}

def _find_scan_folder(scan_id: str):
    """Return (folder_path, source) for a scan_id, checking tmp then logs."""
    for base in [os.path.expanduser("~/.axiom/tmp"), os.path.expanduser("~/.axiom/logs")]:
        path = os.path.join(base, scan_id)
        if os.path.isdir(path):
            return path, ("tmp" if "tmp" in base else "logs")
    return None, None

@app.route("/api/axiom/scans/<scan_id>/screenshots", methods=["GET"])
def list_scan_screenshots(scan_id):
    """Return a list of screenshot objects for a scan.
    Each item: {url, filename, domain}
    Works for gowitness (screenshots/ subdir) and flat image output directories.
    """
    folder, _ = _find_scan_folder(scan_id)
    if not folder:
        return jsonify([])

    output_dir = os.path.join(folder, "output")
    shots = []

    def _collect(dirpath, prefix=""):
        try:
            for entry in sorted(os.listdir(dirpath)):
                full = os.path.join(dirpath, entry)
                rel  = (prefix + "/" + entry).lstrip("/")
                if os.path.isdir(full):
                    _collect(full, rel)
                elif os.path.isfile(full):
                    ext = os.path.splitext(entry)[1].lower()
                    if ext in _IMAGE_EXTENSIONS:
                        # Build a human-readable domain label from the filename
                        stem = os.path.splitext(entry)[0]
                        # gowitness names like "https-example.com-443.png"
                        domain = stem.replace("-", ".", 1).replace("-", "/", 1) if "-" in stem else stem
                        shots.append({
                            "url":      f"/api/axiom/scans/{scan_id}/img/{rel}",
                            "filename": entry,
                            "rel":      rel,
                            "domain":   domain,
                        })
        except Exception as e:
            print(f"[screenshots] Error scanning {dirpath}: {e}")

    if os.path.isdir(output_dir):
        _collect(output_dir)

    print(f"[screenshots] Found {len(shots)} screenshots for {scan_id}")
    return jsonify(shots)


@app.route("/api/axiom/scans/<scan_id>/img/<path:rel>", methods=["GET"])
def serve_scan_image(scan_id, rel):
    """Serve a screenshot image from a scan's output directory."""
    folder, _ = _find_scan_folder(scan_id)
    if not folder:
        abort(404)

    output_dir  = os.path.realpath(os.path.join(folder, "output"))
    full_path   = os.path.realpath(os.path.join(output_dir, rel))

    # Security: must stay inside the scan's output directory
    if not full_path.startswith(output_dir + os.sep):
        abort(403)
    if not os.path.isfile(full_path):
        abort(404)

    ext = os.path.splitext(full_path)[1].lower()
    mime_map = {".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".png": "image/png",  ".webp": "image/webp", ".gif": "image/gif"}
    return send_file(full_path, mimetype=mime_map.get(ext, "image/png"))


@app.route("/api/axiom/scans/filesystem/discover", methods=["GET"])
def discover_scans_from_filesystem():
    """Discover running and completed scans from axiom's filesystem directories"""
    axiom_logs = os.path.expanduser("~/.axiom/logs")
    axiom_tmp = os.path.expanduser("~/.axiom/tmp")
    
    scans = []
    
    print(f"[filesystem-scans] Checking {axiom_logs} for completed scans")
    print(f"[filesystem-scans] Checking {axiom_tmp} for running scans")
    
    # Check ~/.axiom/logs for completed scans
    if os.path.exists(axiom_logs):
        try:
            for folder in os.listdir(axiom_logs):
                folder_path = os.path.join(axiom_logs, folder)
                if not os.path.isdir(folder_path):
                    continue
                
                # Parse folder name: module+timestamp
                parts = folder.rsplit('+', 1)
                module = parts[0] if parts else folder
                timestamp = parts[1] if len(parts) > 1 else ""
                
                # Check for output files and read their contents
                output_files = []
                logs = []
                output_dir = os.path.join(folder_path, "output")
                results_count = 0
                
                # Read log file if it exists
                log_file = os.path.join(folder_path, "axiom-scan.log")
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r') as f:
                            logs = f.readlines()[-1000:]  # Last 1000 lines
                            print(f"[filesystem-scans] Read {len(logs)} log lines from {log_file}")
                    except Exception as e:
                        print(f"[filesystem-scans] Error reading log file: {e}")
                
                # Check for output directory and read merged results
                if os.path.exists(output_dir):
                    try:
                        for f in os.listdir(output_dir):
                            file_path = os.path.join(output_dir, f)
                            output_files.append(f)
                            
                            # Read the output file to count results
                            if os.path.isfile(file_path):
                                try:
                                    with open(file_path, 'r') as outf:
                                        content = outf.read()
                                        # Count lines as results
                                        results_count += len(content.splitlines())
                                        print(f"[filesystem-scans] Read {len(content.splitlines())} results from {f}")
                                except:
                                    pass
                    except Exception as e:
                        print(f"[filesystem-scans] Error reading output directory: {e}")
                
                # Detect failures when 0 results are produced
                logs_scan_status = "completed"
                logs_failure_reason = None
                logs_failure_lines = []
                if results_count == 0 and logs:
                    _is_failed, logs_failure_reason, logs_failure_lines = _detect_log_failures(logs)
                    if _is_failed:
                        logs_scan_status = "failed"
                        print(f"[filesystem-scans] Marking {folder} as FAILED: {logs_failure_reason}")

                logs_scan_entry = {
                    "id": folder,
                    "name": folder,
                    "module": module,
                    "status": logs_scan_status,
                    "date": timestamp,
                    "source": "logs",
                    "path": folder_path,
                    "output_files": output_files,
                    "output": output_dir if output_files else None,
                    "local_logs": log_file if os.path.exists(log_file) else None,
                    "logs": logs,
                    "results": results_count,
                }
                if logs_failure_reason:
                    logs_scan_entry["failure_reason"] = logs_failure_reason
                    logs_scan_entry["failure_lines"] = logs_failure_lines
                scans.append(logs_scan_entry)
                print(f"[filesystem-scans] Discovered {logs_scan_status} scan: {folder} ({results_count} results)")
        except Exception as e:
            print(f"[filesystem-scans] Error reading logs: {e}")

    # Check ~/.axiom/tmp for running scans
    if os.path.exists(axiom_tmp):
        try:
            import time as time_module
            current_time = time_module.time()
            
            # First pass: collect all tmp scans with timestamps
            tmp_scans = []
            for folder in os.listdir(axiom_tmp):
                folder_path = os.path.join(axiom_tmp, folder)
                if not os.path.isdir(folder_path):
                    continue
                
                # Parse folder name: module+timestamp (e.g., amass+01-15_14-26-05)
                parts = folder.rsplit('+', 1)
                module = parts[0] if parts else folder
                timestamp = parts[1] if len(parts) > 1 else ""
                
                tmp_scans.append({
                    "folder": folder,
                    "folder_path": folder_path,
                    "module": module,
                    "timestamp": timestamp,
                })
            
            # Sort by timestamp (newest first) to identify old stuck scans
            tmp_scans_sorted = sorted(tmp_scans, key=lambda x: x["timestamp"], reverse=True)
            
            for idx, scan_info in enumerate(tmp_scans_sorted):
                folder = scan_info["folder"]
                folder_path = scan_info["folder_path"]
                module = scan_info["module"]
                timestamp = scan_info["timestamp"]
                
                # Check for output directory and read current results
                output_dir = os.path.join(folder_path, "output")
                results_count = 0
                output_files = []
                logs = []
                
                # Read live log file if it exists
                log_file = os.path.join(folder_path, "axiom-scan.log")
                is_running = True
                
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r') as f:
                            logs = f.readlines()[-1000:]  # Last 1000 lines
                            print(f"[filesystem-scans] Read {len(logs)} log lines from scan {folder}")
                    except Exception as e:
                        print(f"[filesystem-scans] Error reading live log: {e}")
                    
                    # Check if log file has been modified recently (within 2 minutes)
                    log_mtime = os.path.getmtime(log_file)
                    time_since_update = current_time - log_mtime
                    
                    if time_since_update > 120:  # More than 2 minutes since last update
                        is_running = False
                        print(f"[filesystem-scans] Scan {folder} appears completed (log last updated {time_since_update:.0f}s ago)")
                    else:
                        print(f"[filesystem-scans] Scan {folder} is running (log updated {time_since_update:.0f}s ago)")
                
                # Check if this scan is old and there's a newer scan for the same module (stuck scan detection)
                # If this scan is older than the first (newest) scan for the same module, mark as failed
                is_newer_scan_exists = False
                final_status = "running" if is_running else "completed"
                if idx > 0:  # Only check if there are scans after this one
                    newer_scan = tmp_scans_sorted[0]
                    if newer_scan["module"] == module and newer_scan["timestamp"] != timestamp:
                        is_newer_scan_exists = True
                        is_running = False
                        final_status = "failed"  # Mark as failed since it's stuck/stale
                        print(f"[filesystem-scans] Scan {folder} is older than {newer_scan['folder']}, marking as FAILED (stuck/stale)")
                
                # Check for live results in output directory
                if os.path.exists(output_dir):
                    try:
                        for f in os.listdir(output_dir):
                            file_path = os.path.join(output_dir, f)
                            output_files.append(f)
                            
                            if os.path.isfile(file_path):
                                try:
                                    with open(file_path, 'r') as outf:
                                        content = outf.read()
                                        results_count += len(content.splitlines())
                                except:
                                    pass
                    except Exception as e:
                        print(f"[filesystem-scans] Error reading live output: {e}")

                # No axiom-scan.log present (e.g. whois pipes directly to output files).
                # Infer completion from output files so the scan doesn't stay "running" forever.
                if not os.path.exists(log_file) and is_running:
                    if output_files:
                        is_running = False
                        final_status = "completed"
                        print(f"[filesystem-scans] No axiom-scan.log but {len(output_files)} output file(s) — marking {folder} as completed")
                    elif current_time - os.path.getmtime(folder_path) > 300:
                        is_running = False
                        final_status = "completed"
                        print(f"[filesystem-scans] No log, no output, folder >5 min old — marking {folder} as completed")

                # Detect failures via log patterns when scan is done and produced 0 results
                tmp_failure_reason = None
                tmp_failure_lines = []
                if not is_running and results_count == 0 and logs and final_status != "failed":
                    _is_failed, tmp_failure_reason, tmp_failure_lines = _detect_log_failures(logs)
                    if _is_failed:
                        final_status = "failed"
                        print(f"[filesystem-scans] Marking {folder} as FAILED: {tmp_failure_reason}")

                tmp_entry = {
                    "id": folder,
                    "name": folder,
                    "module": module,
                    "status": final_status,
                    "date": timestamp,
                    "source": "tmp",
                    "path": folder_path,
                    "output_files": output_files,
                    "output": output_dir if output_files else None,
                    "local_logs": log_file if os.path.exists(log_file) else None,
                    "logs": logs,
                    "results": results_count,
                    "progress": min(95, (results_count // 10) if results_count else 0) if is_running else 100,  # 100% if completed
                }
                if tmp_failure_reason:
                    tmp_entry["failure_reason"] = tmp_failure_reason
                    tmp_entry["failure_lines"] = tmp_failure_lines
                scans.append(tmp_entry)
                status_str = "running" if is_running else final_status
                stuck_note = " (stuck - newer scan exists)" if is_newer_scan_exists else ""
                print(f"[filesystem-scans] Discovered {status_str} scan: {folder} ({results_count} results){stuck_note}")
        except Exception as e:
            print(f"[filesystem-scans] Error reading tmp: {e}")
    
    print(f"[filesystem-scans] Found {len(scans)} total scans")
    return jsonify(scans)

# Fleet control endpoints
def run_zsh_command(cmd_str: str, timeout: int = 180):
    """Run a command via zsh login shell so ~/.zshrc is sourced and ~/.axiom path is available.
    Returns CompletedProcess-like dict.
    """
    print(f"[fleet] Running command via zsh: {cmd_str}")
    try:
        # Use zsh -lc to run in a login shell context
        result = subprocess.run([
            "/bin/zsh", "-lc", cmd_str
        ], capture_output=True, text=True, timeout=timeout)
        
        print(f"[fleet] Command completed with return code: {result.returncode}")
        if result.stdout:
            print(f"[fleet] STDOUT: {result.stdout[:500]}")
        if result.stderr:
            print(f"[fleet] STDERR: {result.stderr[:500]}")
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired as e:
        error_msg = f"Command timed out after {timeout}s"
        print(f"[fleet] ERROR: {error_msg}")
        return {"stdout": "", "stderr": error_msg, "returncode": -1}
    except Exception as e:
        error_msg = f"Exception running command: {str(e)}"
        print(f"[fleet] ERROR: {error_msg}")
        import traceback
        traceback.print_exc()
        return {"stdout": "", "stderr": error_msg, "returncode": -1}

@app.route("/api/axiom/fleet/prefixes", methods=["GET", "POST", "DELETE"])
def fleet_prefixes():
    """Manage tracked fleet prefixes for instance discovery"""
    if request.method == "GET":
        # Return current tracked prefixes
        with SCAN_INSTANCES["lock"]:
            return jsonify({"prefixes": list(SCAN_INSTANCES["prefixes"])})
    
    elif request.method == "POST":
        # Add a new prefix
        data = request.json or {}
        prefix = data.get("prefix", "").strip()
        if not prefix:
            return jsonify({"error": "prefix is required"}), 400
        
        with SCAN_INSTANCES["lock"]:
            SCAN_INSTANCES["prefixes"].add(prefix)
            save_scan_prefixes(SCAN_INSTANCES["prefixes"])
            print(f"[fleet] Added prefix: {prefix}")
        
        # Invalidate cache
        FLEET_CACHE["timestamp"] = 0
        return jsonify({"success": True, "prefix": prefix, "prefixes": list(SCAN_INSTANCES["prefixes"])})
    
    elif request.method == "DELETE":
        # Remove a prefix
        data = request.json or {}
        prefix = data.get("prefix", "").strip()
        if not prefix:
            return jsonify({"error": "prefix is required"}), 400
        
        with SCAN_INSTANCES["lock"]:
            SCAN_INSTANCES["prefixes"].discard(prefix)
            save_scan_prefixes(SCAN_INSTANCES["prefixes"])
            print(f"[fleet] Removed prefix: {prefix}")
        
        return jsonify({"success": True, "prefix": prefix, "prefixes": list(SCAN_INSTANCES["prefixes"])})


@app.route("/api/axiom/fleet/power", methods=["POST"])
def fleet_power():
    """Power on/off instances - only for axiom-managed instances"""
    data = request.json
    action = data.get("action")  # "on" or "off"
    pattern = data.get("pattern")
    
    if not action or not pattern:
        return jsonify({"error": "Missing action or pattern"}), 400
    
    # Load axiom-managed instance names from selected.conf
    axiom_instances = set()
    selected_conf_path = os.path.expanduser("~/.axiom/selected.conf")
    if os.path.exists(selected_conf_path):
        try:
            with open(selected_conf_path, "r") as f:
                axiom_instances = set(line.strip() for line in f if line.strip())
        except Exception as e:
            return jsonify({"error": f"Failed to read selected.conf: {e}"}), 500
    
    # Validate pattern matches only axiom instances
    if pattern == "*":
        # Allow wildcard only if there are axiom instances
        if not axiom_instances:
            return jsonify({"error": "No axiom instances configured"}), 400
    else:
        # Validate specific instance is in axiom's managed list
        if pattern not in axiom_instances:
            return jsonify({"error": f"Instance '{pattern}' is not managed by axiom"}), 403
    
    print(f"[fleet] Power {action} request for pattern: {pattern}")
    cmd_str = f"axiom-power {action} {pattern}"
    result = run_zsh_command(cmd_str, timeout=300)
    return jsonify({
        "output": result["stdout"], 
        "stderr": result["stderr"], 
        "returncode": result["returncode"],
        "command": cmd_str
    })

@app.route("/api/axiom/fleet/ssh", methods=["POST"])
def fleet_ssh():
    """Get SSH command for instance"""
    data = request.json
    instance = data.get("instance")
    
    if not instance:
        return jsonify({"error": "Missing instance name"}), 400
    
    return jsonify({"command": f"axiom-ssh {instance}"})

@app.route("/api/axiom/fleet/exec", methods=["POST"])
def fleet_exec():
    """Execute command on instances - only for axiom-managed instances"""
    data = request.json
    command = data.get("command")
    pattern = data.get("pattern", "*")
    
    if not command:
        return jsonify({"error": "Missing command"}), 400
    
    # Load axiom-managed instance names from selected.conf
    axiom_instances = set()
    selected_conf_path = os.path.expanduser("~/.axiom/selected.conf")
    if os.path.exists(selected_conf_path):
        try:
            with open(selected_conf_path, "r") as f:
                axiom_instances = set(line.strip() for line in f if line.strip())
        except Exception as e:
            return jsonify({"error": f"Failed to read selected.conf: {e}"}), 500
    
    # Validate pattern matches only axiom instances
    if pattern == "*":
        # Allow wildcard only if there are axiom instances
        if not axiom_instances:
            return jsonify({"error": "No axiom instances configured"}), 400
    else:
        # Validate specific instance is in axiom's managed list
        if pattern not in axiom_instances:
            return jsonify({"error": f"Instance '{pattern}' is not managed by axiom"}), 403
    
    print(f"[fleet] Execute command '{command}' on pattern: {pattern}")
    # Select instances and execute via zsh login shell
    sel = run_zsh_command(f"axiom-select {pattern}", timeout=180)
    exe = run_zsh_command(f"axiom-exec '{command}'", timeout=600)
    return jsonify({
        "output": exe["stdout"], 
        "stderr": sel["stderr"] + "\n" + exe["stderr"], 
        "returncode": exe["returncode"],
        "command": f"axiom-select {pattern} && axiom-exec '{command}'"
    })

@app.route("/api/axiom/fleet/rm", methods=["POST"])
def fleet_rm():
    """Terminate instances - only for axiom-managed instances"""
    data = request.json
    pattern = data.get("pattern")
    
    if not pattern:
        return jsonify({"error": "Missing pattern"}), 400
    
    # Load axiom-managed instance names from selected.conf
    axiom_instances = set()
    selected_conf_path = os.path.expanduser("~/.axiom/selected.conf")
    if os.path.exists(selected_conf_path):
        try:
            with open(selected_conf_path, "r") as f:
                axiom_instances = set(line.strip() for line in f if line.strip())
        except Exception as e:
            return jsonify({"error": f"Failed to read selected.conf: {e}"}), 500
    
    # Validate pattern matches only axiom instances
    if pattern == "*":
        # Allow wildcard only if there are axiom instances
        if not axiom_instances:
            return jsonify({"error": "No axiom instances configured"}), 400
    else:
        # Validate specific instance is in axiom's managed list
        if pattern not in axiom_instances:
            return jsonify({"error": f"Instance '{pattern}' is not managed by axiom"}), 403
    
    print(f"[fleet] Terminate instances matching: {pattern}")
    cmd_str = f"axiom-rm {pattern} -f"
    result = run_zsh_command(cmd_str, timeout=300)
    return jsonify({
        "output": result["stdout"], 
        "stderr": result["stderr"], 
        "returncode": result["returncode"],
        "command": cmd_str
    })


# ---------------------------------------------------------------------------
# Ax framework update  —  GET /api/axiom/update
# ---------------------------------------------------------------------------
_AX_FRAMEWORK_PATH = Path.home() / ".axiom"


@app.route("/api/axiom/update", methods=["GET"])
def ax_update():
    """Stream 'ax update' output to keep the Ax framework up to date.

    Uses the built-in `ax update` command (axiom-update) via a zsh login
    shell so ~/.axiom/interact is on PATH, just like every other Ax command.

    Yields newline-delimited JSON objects:
      {"type": "info",    "line": "Running ax update…"}
      {"type": "stdout",  "line": "…"}
      {"type": "success", "line": "Update complete"}
      {"type": "error",   "line": "…"}
      {"type": "done",    "commit": "abc1234", "ok": true}
    """
    def _stream():
        ax_path = str(_AX_FRAMEWORK_PATH)

        def _emit(t, line):
            return json.dumps({"type": t, "line": line}) + "\n"

        if not _AX_FRAMEWORK_PATH.is_dir():
            yield _emit("error", f"{ax_path} not found — run the installer first.")
            yield json.dumps({"type": "done", "commit": None, "ok": False}) + "\n"
            return

        # Snapshot commit before update so we can report what changed
        try:
            cur = subprocess.check_output(
                ["git", "-C", ax_path, "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL, text=True).strip()
            branch = subprocess.check_output(
                ["git", "-C", ax_path, "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL, text=True).strip()
            yield _emit("info", f"Current: {branch} @ {cur}")
        except Exception:
            cur = "unknown"

        yield _emit("info", "Running: ax update")
        try:
            proc = subprocess.Popen(
                ["/bin/zsh", "-lc", "ax update"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            for line in proc.stdout:
                yield _emit("stdout", line.rstrip())
            proc.wait()
        except Exception as exc:
            yield _emit("error", f"ax update failed: {exc}")
            yield json.dumps({"type": "done", "commit": None, "ok": False}) + "\n"
            return

        ok = proc.returncode == 0

        try:
            new_commit = subprocess.check_output(
                ["git", "-C", ax_path, "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL, text=True).strip()
        except Exception:
            new_commit = "unknown"

        if ok:
            if new_commit != cur:
                yield _emit("success", f"Updated: {cur} → {new_commit}")
            else:
                yield _emit("success", "Already up to date.")
        else:
            yield _emit("error", f"ax update exited with code {proc.returncode}")

        yield json.dumps({"type": "done", "commit": new_commit, "ok": ok}) + "\n"

    return Response(
        _stream(),
        mimetype="application/x-ndjson",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@app.route("/api/axiom/version", methods=["GET"])
def ax_version():
    """Return current Ax commit hash, branch, and module count."""
    ax_path = str(_AX_FRAMEWORK_PATH)
    if not (_AX_FRAMEWORK_PATH / ".git").is_dir():
        return jsonify({"installed": False, "path": ax_path})

    try:
        commit = subprocess.check_output(
            ["git", "-C", ax_path, "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL, text=True).strip()
        branch = subprocess.check_output(
            ["git", "-C", ax_path, "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL, text=True).strip()
        date_str = subprocess.check_output(
            ["git", "-C", ax_path, "log", "-1", "--format=%ci"],
            stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        commit = branch = date_str = "unknown"

    modules_dir = _AX_FRAMEWORK_PATH / "modules"
    module_count = len(list(modules_dir.glob("*.json"))) if modules_dir.is_dir() else 0

    return jsonify({
        "installed": True,
        "path": ax_path,
        "commit": commit,
        "branch": branch,
        "date": date_str,
        "module_count": module_count,
    })


if __name__ == "__main__":
    os.makedirs(IMPORTS_PATH, exist_ok=True)
    os.makedirs(PROCESSED_PATH, exist_ok=True)
    os.makedirs(os.path.dirname(STORE_PATH) or ".", exist_ok=True)
    # gowitness outputs a directory of screenshots — keep its subdir
    os.makedirs(GOWITHNESS_PATH, exist_ok=True)
    print(f"[bridge] Import folder: {IMPORTS_PATH}  (drop any scan output file here)")
    print(f"[bridge] Scanner type is detected from the filename (e.g. example-amass.txt -> amass)")

    if not Path(STORE_PATH).exists():
        save_store(DEFAULT_STORE.copy())

    # ── Initial scan of imports/ ──────────────────────────────────────────
    print(f"\n[watcher] Initial scan of: {IMPORTS_PATH}")
    startup_count = scan_imports_dir(verbose=True)
    if startup_count:
        print(f"[watcher] Startup scan: imported {startup_count} file(s)")
    else:
        print(f"[watcher] Startup scan: no new files found")

    # ── Start periodic background scanner ────────────────────────────────
    # Replaces the watchdog Observer so we never poll at the 1-second default
    # rate that PollingObserver uses on Docker/NFS volumes.
    watcher_thread = threading.Thread(target=_import_watcher_thread, daemon=True)
    watcher_thread.start()
    print(f"[watcher] Periodic import scan every {WATCHER_INTERVAL}s "
          f"(set WATCHER_INTERVAL env to change)  "
          f"— or call GET /api/imports/scan to trigger immediately")

    print(f"\nAxiom bridge running on port {PORT}")
    print(f"  AXIOM_LS_PATH: {AXIOM_LS_PATH}")
    print(f"  AXIOM_TMP:     {AXIOM_TMP}")
    print(f"  STORE:         {STORE_PATH}")
    print(f"  IMPORTS:       {IMPORTS_PATH}")
    print(f"\n[watcher] ✓ Drop scan output files into imports/ — they will be picked up within {WATCHER_INTERVAL}s")
    print(f"{'='*70}\n")

    app.run(host="127.0.0.1", port=PORT)
