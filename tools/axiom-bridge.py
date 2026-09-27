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
import importlib as _importlib
from pathlib import Path as _Path
# Ensure tools/ is on sys.path so "import importers" resolves correctly.
_tools_dir = str(_Path(__file__).resolve().parent)
if _tools_dir not in _sys.path:
    _sys.path.insert(0, _tools_dir)

def _fresh_import(module_name: str, attr: str):
    """Import attr from module_name, forcing a reload if the cached module
    doesn't have it (handles stale sys.modules from a previous process start)."""
    import importlib, sys
    mod = sys.modules.get(module_name)
    if mod is not None and not hasattr(mod, attr):
        # Cached module is stale — reload from disk
        mod = importlib.reload(mod)
    elif mod is None:
        mod = importlib.import_module(module_name)
    return getattr(mod, attr)

from flask import Flask, jsonify, request, abort, send_file, Response
from flask_cors import CORS
import os
import re
import json
import subprocess
import signal
import traceback
import secrets
from pathlib import Path
from datetime import datetime, timezone
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
CORS(app, supports_credentials=True)

# ── Auth configuration ─────────────────────────────────────────────────────────
# Set GUI_AX_PASSWORD to enable login gate.  Leave empty to disable auth.
# Set GUI_AX_USERNAME to change the username (default: admin).
# Set GUI_AX_SECRET_KEY for a stable session key across restarts.
AUTH_USERNAME = os.environ.get("GUI_AX_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("GUI_AX_PASSWORD", "")       # empty = auth OFF
app.secret_key = os.environ.get("GUI_AX_SECRET_KEY") or secrets.token_hex(32)

from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=7)

# store format: { "targets": [ {id, domain, sources, created_at} ], "fleet": [...] }
DEFAULT_STORE = {"targets": [], "fleet": []}

# Fleet cache with TTL to avoid hammering AWS
FLEET_CACHE = {
    "data": [],
    "timestamp": 0,
    "ttl": 30  # Cache for 30 seconds (configurable via FLEET_CACHE_TTL env var)
}
FLEET_CACHE["ttl"] = int(os.environ.get("FLEET_CACHE_TTL", "30"))

# Guard so only one axiom-ls can be in flight at a time. Without this, the UI
# polling /api/fleet (every 30s, with refresh=true) would spawn a fresh
# axiom-ls -> aws call on every poll even while the previous one is still
# running/hung — stacking up processes and starving the container's CPU.
# Concurrent callers instead get served the last cached data immediately.
FLEET_FETCH_LOCK = threading.Lock()

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
    #   amass-out.txt              -> amass
    #   dnsx-out-full-2.txt        -> dnsx
    #   httpx+01-16_09-39-08       -> httpx (single module)
    #   httpx+nuclei+09-05_14-50   -> nuclei (multi-module: use LAST module)
    #
    # For bridge multi-module filenames (module1+module2+timestamp), split on "+"
    # and collect non-timestamp parts.  The last module in the chain is the one
    # whose output format ends up in the file (modules pipe into each other).
    if "+" in name_without_ext:
        plus_parts = name_without_ext.split("+")
        # A timestamp part looks like "09-05_14-50-33-606960" (digits + dashes)
        import re as _re
        module_parts = [
            p for p in plus_parts
            if p and not _re.match(r'^\d', p)
        ]
        module = module_parts[-1].lower() if module_parts else plus_parts[0].lower()
    elif "-" in name_without_ext:
        module = name_without_ext.split("-")[0].lower()
    else:
        module = name_without_ext.lower()

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
                else:
                    # No DB file — check for JPEG/PNG screenshots only
                    jpeg_files = [
                        f for f in subdir.iterdir()
                        if f.is_file() and f.suffix.lower() in ('.jpeg', '.jpg', '.png')
                        and subdir.name not in existing_sources
                    ]
                    if jpeg_files:
                        if verbose:
                            print(f"[watcher] Processing JPEG-only gowitness folder: {subdir.name} ({len(jpeg_files)} images)")
                        try:
                            parse_jpeg_folder = _fresh_import("importers.import_gowitness", "parse_jpeg_folder")
                            # Use the full folder name as unique scan ID (not just the prefix)
                            _jpeg_key = subdir.name.rstrip('.')
                            try:
                                with open(SCANS_STORE, "r") as _sf:
                                    _jpeg_stored = json.load(_sf)
                                _jpeg_nm = {s["id"]: s.get("name", "") for s in _jpeg_stored if s.get("id") and s.get("name")}
                                _jpeg_display = _jpeg_nm.get(_jpeg_key) or _jpeg_nm.get(subdir.name) or None
                            except Exception:
                                _jpeg_display = None
                            sn = subdir.name  # full folder name — unique per scan
                            store = load_store()
                            t = store.get("targets", [])
                            t, _changed = parse_jpeg_folder(subdir, sn, t, display_name=_jpeg_display)
                            if _changed:
                                store["targets"] = t
                                save_store(store)
                                new_files += 1
                        except Exception as e:
                            print(f"[watcher] Error processing JPEG-only gowitness folder: {e}")
                            traceback.print_exc()

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
                    # No DB — check for JPEG/PNG screenshot-only folders (axiom-scan gowitness output)
                    jpeg_files = [
                        f for f in gw_dir.iterdir()
                        if f.is_file() and f.suffix.lower() in ('.jpeg', '.jpg', '.png')
                        and gw_dir.name not in existing_sources
                    ]
                    if jpeg_files:
                        if verbose:
                            print(f"[watcher] Processing JPEG-only gowitness folder in imports/: {gw_dir.name} ({len(jpeg_files)} images)")
                        try:
                            parse_jpeg_folder = _fresh_import("importers.import_gowitness", "parse_jpeg_folder")
                            _jpeg_key = gw_dir.name.rstrip('.')
                            try:
                                with open(SCANS_STORE, "r") as _sf:
                                    _jpeg_stored = json.load(_sf)
                                _jpeg_nm = {s["id"]: s.get("name", "") for s in _jpeg_stored if s.get("id") and s.get("name")}
                                _jpeg_display = _jpeg_nm.get(_jpeg_key) or _jpeg_nm.get(gw_dir.name) or None
                            except Exception:
                                _jpeg_display = None
                            store = load_store()
                            t = store.get("targets", [])
                            t, _changed = parse_jpeg_folder(gw_dir, gw_dir.name, t, display_name=_jpeg_display)
                            if _changed:
                                store["targets"] = t
                                save_store(store)
                                new_files += 1
                        except Exception as e:
                            print(f"[watcher] Error processing JPEG-only folder {gw_dir.name}: {e}")
                            traceback.print_exc()
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
    _gw_display = None  # human-readable display name (gowitness only)
    if _parent.endswith(".dir"):
        scan_name = _parent  # e.g. "whois+02-26_23-34-28.dir"
    elif scanner_type == "gowitness" and _parent and _parent not in ("gowitness", "imports"):
        # Use the bundle folder name as the unique target ID so each gowitness scan
        # gets its own row instead of merging everything under "gowitness".
        # Strip trailing dot from truncated folder names (filesystem limit)
        _gw_key = _parent.rstrip('.')
        try:
            with open(SCANS_STORE, "r") as _sf:
                _stored_scans = json.load(_sf)
            _gw_nm = {s["id"]: s.get("name", "") for s in _stored_scans if s.get("id") and s.get("name")}
            _gw_display = _gw_nm.get(_gw_key) or _gw_nm.get(_parent) or None
        except Exception:
            pass
        scan_name = _parent  # unique ID = bundle folder name (e.g. "gowitness-03-14_15-04-01")
    else:
        # For axiom-generated output files (stem = bridge scan_id like
        # "httpx+nuclei+09-05_14-50-33-606960"), look up the human-readable
        # name in SCANS_STORE first so targets get the correct programName
        # (e.g. "gw-acme-5") and the project filter can match them.
        file_stem = filename.rsplit('.', 1)[0]
        try:
            with open(SCANS_STORE, "r") as _sf:
                _stored_scans = json.load(_sf)
            _id_to_name = {
                s["id"]: s.get("name", "")
                for s in _stored_scans
                if s.get("id") and s.get("name")
            }
            _looked_up = _id_to_name.get(file_stem, "")
        except Exception:
            _looked_up = ""

        if _looked_up:
            scan_name = _looked_up
        elif '-' in filename:
            scan_name = filename.split('-')[0]
        else:
            scan_name = file_stem
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
        # For gowitness: update domain / programName to the human-readable scan name
        # when we resolved one from scans.json (so the UI shows e.g. "mycompany-scan"
        # rather than the raw bundle folder timestamp).
        if changed and scanner == "gowitness" and _gw_display:
            for _t in targets:
                if _t.get("id") == scan_name:
                    _t["domain"] = _gw_display          # e.g. "xwz"
                    _t["programName"] = "GoWitness Scan"
                    break
        if changed:
            # Opportunistically geolocate freshly-imported subdomains that already
            # carry an IP — offline + cached, so it's cheap. The slower pass that
            # DNS-resolves hosts without an IP is on-demand via POST /api/geo/enrich.
            try:
                _enrich = _fresh_import("importers.base", "enrich_targets_geo")
                _gstats = _enrich(targets, do_dns=False)
                if _gstats.get("located"):
                    print(f"[geo] auto-located {_gstats['located']} subdomain(s) by IP")
            except Exception as _ge:
                print(f"[geo] auto-enrich skipped: {_ge}")
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


# ── Auth gate (Bearer token — works across origins) ───────────────────────────
# Tokens are kept in memory. They survive bridge restarts only if
# GUI_AX_STATIC_TOKEN is set; otherwise each restart issues new tokens.
_active_tokens: set = set()
if os.environ.get("GUI_AX_STATIC_TOKEN"):
    _active_tokens.add(os.environ["GUI_AX_STATIC_TOKEN"])


def _token_from_request() -> str:
    """Extract Bearer token from the Authorization header."""
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        return hdr[7:].strip()
    return ""


@app.before_request
def _require_auth():
    """Block all /api/* requests unless the caller has a valid Bearer token.
    Auth is disabled entirely when GUI_AX_PASSWORD is not set."""
    if not AUTH_PASSWORD:
        return  # auth disabled globally
    if request.method == "OPTIONS":
        return  # CORS preflight — never block
    path = request.path
    if path.startswith("/api/auth/"):
        return  # login / logout / status are always public
    # Screenshot images are served via <img> tags which can't send auth headers
    if path.startswith("/api/screenshots/") or path.startswith("/api/gowitness-bundle/"):
        return
    if not path.startswith("/api/"):
        return  # static files, /, /health
    token = _token_from_request()
    if not token:
        return jsonify({"error": "unauthorized", "authRequired": True}), 401
    # Static env-var token is always valid (survives restarts without re-login)
    static = os.environ.get("GUI_AX_STATIC_TOKEN", "")
    if static and secrets.compare_digest(token, static):
        return  # static token always passes
    if token in _active_tokens:
        return  # dynamic login / generated token
    return jsonify({"error": "unauthorized", "authRequired": True}), 401


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Return auth state for the current caller, including their role."""
    if not AUTH_PASSWORD:
        return jsonify({"authRequired": False, "authenticated": True, "username": None, "role": None})
    token = _token_from_request()
    # Static env-var token is always authenticated as admin
    _static = os.environ.get("GUI_AX_STATIC_TOKEN", "")
    if _static and token and secrets.compare_digest(token, _static):
        return jsonify({"authRequired": True, "authenticated": True, "username": AUTH_USERNAME, "role": "admin", "projects": None})
    is_auth = bool(token and token in _active_tokens)

    if not is_auth:
        return jsonify({"authRequired": True, "authenticated": False, "username": None, "role": None})

    # Look up the user record by token to return their real username + role
    store = load_store()
    user = next(
        (u for u in _get_users(store) if u.get("token") == token),
        None,
    )
    if user:
        role = user.get("role", "user")
        # Admin gets null (all projects); regular users get their project list
        projects = None if role == "admin" else user.get("projects", [])
        return jsonify({
            "authRequired":  True,
            "authenticated": True,
            "username":      user["username"],
            "role":          role,
            "projects":      projects,
        })

    # Legacy single-user mode (store has no user records yet)
    return jsonify({
        "authRequired":  True,
        "authenticated": True,
        "username":      AUTH_USERNAME,
        "role":          "admin",
        "projects":      None,
    })


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Validate credentials and return a Bearer token.
    Checks the multi-user store first; falls back to env-var single-user."""
    if not AUTH_PASSWORD:
        return jsonify({"ok": True, "authRequired": False, "token": None})

    data     = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # ── Multi-user store check ─────────────────────────────────────────────
    store = load_store()
    users = _get_users(store)
    if users:
        matched = next((u for u in users if u.get("username") == username), None)
        if matched and _check_pw(password, matched.get("passwordHash", "")):
            token = secrets.token_hex(32)
            _active_tokens.add(token)
            # Persist token + last-login on the user record
            matched["token"]     = token
            matched["lastLogin"] = datetime.now(timezone.utc).isoformat()
            store["users"] = users
            save_store(store)
            role     = matched.get("role", "user")
            projects = None if role == "admin" else matched.get("projects", [])
            return jsonify({
                "ok":       True,
                "token":    token,
                "username": matched["username"],
                "role":     role,
                "projects": projects,
            })
        return jsonify({"error": "Invalid username or password"}), 401

    # ── Legacy single-user env-var fallback ───────────────────────────────
    username_ok = secrets.compare_digest(username, AUTH_USERNAME)
    password_ok = secrets.compare_digest(password, AUTH_PASSWORD)

    if username_ok and password_ok:
        token = secrets.token_hex(32)
        _active_tokens.add(token)
        return jsonify({"ok": True, "token": token, "username": AUTH_USERNAME, "role": "admin", "projects": None})

    return jsonify({"error": "Invalid username or password"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Revoke the caller's token."""
    token = _token_from_request()
    if token:
        _active_tokens.discard(token)
    return jsonify({"ok": True})


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


def _get_linked_scan_names(project_token: str) -> set:
    """Return the set of programNames linked to a project (case-insensitive)."""
    projects = load_projects()
    proj = projects.get(project_token)
    if not proj:
        return set()
    return {n.lower() for n in proj.get("linked_scans", []) if n}


@app.route("/api/targets", methods=["GET"])
def get_targets():
    store = load_store()
    all_targets = store.get("targets", [])
    project_token = request.args.get("projectToken", "").strip()
    if project_token:
        linked = _get_linked_scan_names(project_token)
        if linked:
            all_targets = [
                t for t in all_targets
                if (t.get("programName") or "").lower() in linked
            ]
        else:
            all_targets = []
    return jsonify(all_targets)


@app.route("/api/screenshots/<path:rel>")
def serve_screenshot(rel):
    """Serve screenshot images stored in processed/gowitness-* bundles.

    Handles both formats produced by the importer:
      DB-based:   gowitness-TS/screenshots/filename.jpeg
      JPEG-only:  gowitness-TS/filename.jpeg  (no screenshots/ subdir)

    Also tries PNG variant when a .jpeg path is not found (newer gowitness
    versions produce PNG instead of JPEG).
    """
    processed_root = os.path.realpath(PROCESSED_PATH)
    full_path = os.path.realpath(os.path.join(PROCESSED_PATH, rel))
    if not full_path.startswith(processed_root):
        abort(403)

    candidates = [full_path]
    base, ext = os.path.splitext(full_path)
    if ext.lower() in (".jpeg", ".jpg"):
        candidates.append(base + ".png")
    elif ext.lower() == ".png":
        candidates.extend([base + ".jpeg", base + ".jpg"])

    # Also try without the `screenshots/` subdirectory in case the bundle
    # stores images flat (JPEG-only import path).
    for c in list(candidates):
        flat = c.replace(os.sep + "screenshots" + os.sep, os.sep)
        if flat != c:
            candidates.append(flat)

    for candidate in candidates:
        candidate = os.path.realpath(candidate)
        if not candidate.startswith(processed_root):
            continue
        if os.path.isfile(candidate):
            ext_lc = os.path.splitext(candidate)[1].lower()
            mime = "image/png" if ext_lc == ".png" else "image/jpeg"
            print(f"[gw] Serving screenshot: {candidate}")
            return send_file(candidate, mimetype=mime)

    # Bundle path not found — search all gowitness bundles for a screenshot
    # matching the same hostname. Handles the case where the original bundle
    # was deleted or gowitness changed its filename format between runs.
    # Hostname extraction: "http---hostname-443.jpeg" or "https:__hostname.png"
    import re as _re
    fname_only = os.path.basename(full_path)
    fname_stem = os.path.splitext(fname_only)[0]

    # Try to extract hostname from known gowitness filename formats
    _hostname = None
    _m = _re.match(r"^https?---(.+?)-\d+$", fname_stem)
    if _m:
        _hostname = _m.group(1)
    else:
        _m2 = _re.match(r"^https?---(.+)$", fname_stem)
        if _m2:
            _hostname = _m2.group(1)
        else:
            _m3 = _re.match(r"^https?[:_]{1,2}[_]{1,2}(.+)$", fname_stem, _re.I)
            if _m3:
                _hostname = _m3.group(1)

    try:
        bundles = sorted(
            [d for d in os.listdir(PROCESSED_PATH)
             if d.startswith("gowitness-") and os.path.isdir(os.path.join(PROCESSED_PATH, d))],
            reverse=True  # newest first
        )
        image_exts = {".jpeg", ".jpg", ".png"}
        for bundle in bundles:
            for sub in ("", "screenshots"):
                bd = os.path.join(PROCESSED_PATH, bundle, sub) if sub else os.path.join(PROCESSED_PATH, bundle)
                if not os.path.isdir(bd):
                    continue
                for f in os.listdir(bd):
                    fbase = os.path.splitext(f)[0]
                    if os.path.splitext(f)[1].lower() not in image_exts:
                        continue
                    # Match by exact filename (same format) or by hostname substring
                    if fbase == fname_stem or (_hostname and _hostname in fbase):
                        p = os.path.realpath(os.path.join(bd, f))
                        if p.startswith(processed_root) and os.path.isfile(p):
                            ext_lc = os.path.splitext(p)[1].lower()
                            mime = "image/png" if ext_lc == ".png" else "image/jpeg"
                            print(f"[gw] Serving screenshot (fallback {bundle}): {p}")
                            return send_file(p, mimetype=mime)
    except Exception:
        pass

    print(f"[gw] Screenshot 404: {full_path}")
    abort(404)


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
        patch_gowitness_names()
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
    
    # Only let one axiom-ls run at a time. If another request is already
    # fetching, don't pile on a second axiom-ls (which under this container's
    # emulated AWS CLI can busy-loop) — serve the current cache instead.
    if not FLEET_FETCH_LOCK.acquire(blocking=False):
        print(f"[bridge] axiom-ls already in flight — serving cached fleet ({len(FLEET_CACHE['data'])} instances) instead of stacking another call")
        return jsonify(FLEET_CACHE["data"])

    # Cache miss or expired - fetch fresh data from axiom-ls via zsh
    # Short timeout: this endpoint is polled by the UI, so we'd rather fail
    # fast and fall back to the last known-good data than block a page load
    # for minutes on a hung/slow AWS region call. Lock is held only around the
    # subprocess call (the part that spawns axiom-ls); the parsing below is
    # cheap and process-free, so we release right after.
    print(f"[bridge] Cache {'bypass' if force_refresh else 'miss/expired'} - fetching fleet data via axiom-ls")
    try:
        result = run_zsh_command("axiom-ls --json", timeout=25)
    finally:
        FLEET_FETCH_LOCK.release()
    
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

    # axiom-ls failed/timed out this round (e.g. a slow/unreachable AWS
    # region). Serve the last known-good fleet instead of blanking the list —
    # returning [] here made instances that are actually up (including ones
    # a workflow just provisioned) disappear from the UI for as long as the
    # underlying AWS call keeps failing.
    if FLEET_CACHE["data"]:
        print(f"[bridge] axiom-ls unavailable, serving stale cached fleet (age: {time.time() - FLEET_CACHE['timestamp']:.1f}s)")
        return jsonify(FLEET_CACHE["data"])

    print(f"[bridge] No instances available from axiom-ls and no cache to fall back to, returning empty fleet")
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


@app.route("/api/geo/status", methods=["GET"])
def geo_status():
    """Report which IP-geolocation providers the map can use.
      offlineAvailable — MaxMind GeoLite2 present (private, local).
      onlineAvailable  — ip-api.com fallback (no key/signup; needs internet)."""
    try:
        geo_available = _fresh_import("importers.base", "geo_available")
        geoip_db_path = _fresh_import("importers.base", "geoip_db_path")
        offline = bool(geo_available())
        return jsonify({
            "available": offline,            # kept for backwards-compat
            "offlineAvailable": offline,
            "onlineAvailable": True,         # no key needed; assumed reachable
            "dbPath": geoip_db_path(),
        })
    except Exception as e:
        return jsonify({"available": False, "offlineAvailable": False,
                        "onlineAvailable": True, "dbPath": None, "error": str(e)})


@app.route("/api/geo/enrich", methods=["POST"])
def geo_enrich():
    """Populate subdomain geo via IP geolocation (second map source alongside
    WHOIS). Body:
      {"doDns": bool}      — resolve hosts lacking an IP first (default true)
      {"provider": str}    — "offline" (GeoLite2, default) or "online" (ip-api.com)"""
    body     = request.get_json(silent=True) or {}
    do_dns   = bool(body.get("doDns", True))
    provider = body.get("provider", "offline")
    if provider not in ("offline", "online"):
        provider = "offline"
    try:
        enrich = _fresh_import("importers.base", "enrich_targets_geo")
    except Exception as e:
        return jsonify({"error": f"geo module unavailable: {e}"}), 500
    store   = load_store()
    targets = store.get("targets", [])
    stats   = enrich(targets, do_dns=do_dns, provider=provider)
    if not stats.get("available"):
        return jsonify({
            "error": "Offline GeoLite2 database/geoip2 library not available — "
                     "add GeoLite2-City.mmdb, or use the online provider (see README)",
            **stats,
        }), 400
    if stats.get("located") or stats.get("resolved"):
        store["targets"] = targets
        save_store(store)
    return jsonify(stats)


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
    """Load scan history from ~/.axiom/stats.log

    Multi-module scans (e.g. axiom-scan -m httpx -m nuclei) produce one stats.log
    entry per module, each pointing to the same output file. We group by the output
    filename — which encodes our bridge scan_id — so they collapse into one record.
    """
    stats_log_path = os.path.expanduser("~/.axiom/stats.log")
    if not os.path.exists(stats_log_path):
        print(f"[scans] stats.log not found at {stats_log_path}")
        return []

    # Ordered dict: bridge_id → merged scan_obj
    by_bridge_id = {}
    bridge_id_order = []

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

                if "scan" in entry and isinstance(entry["scan"], dict):
                    for module_name, scan_data in entry["scan"].items():
                        axiom_id = scan_data.get("id", f"{module_name}-unknown")
                        output_path = scan_data.get("output", "")
                        # The output filename encodes our bridge scan_id; use it as
                        # the dedup key so multi-module entries collapse into one record.
                        if output_path:
                            bridge_id = os.path.splitext(os.path.basename(output_path))[0]
                        else:
                            bridge_id = axiom_id

                        if bridge_id not in by_bridge_id:
                            bridge_id_order.append(bridge_id)
                            scan_obj = {
                                "id": bridge_id,
                                "name": bridge_id,
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
                                "output": output_path,
                                "extra_args": scan_data.get("extra_args", ""),
                            }
                            by_bridge_id[bridge_id] = scan_obj
                        else:
                            # Merge additional module into the existing record
                            existing = by_bridge_id[bridge_id]
                            existing_mods = [m.strip() for m in existing["module"].split(",")]
                            if module_name not in existing_mods:
                                existing_mods.append(module_name)
                                existing["module"] = ", ".join(existing_mods)
                            existing["results"] = max(existing["results"], int(scan_data.get("results", 0)))
                            existing["targets"] = max(existing["targets"], int(scan_data.get("targets", 0)))

                        # Failure detection for zero-result scans
                        scan_obj = by_bridge_id[bridge_id]
                        if scan_obj["results"] == 0 and scan_obj.get("local_logs"):
                            _log_lines = _read_logs_for_failure_check(scan_obj["local_logs"])
                            if _log_lines:
                                _is_failed, _reason, _fail_lines = _detect_log_failures(_log_lines)
                                if _is_failed:
                                    scan_obj["status"] = "failed"
                                    scan_obj["failure_reason"] = _reason
                                    scan_obj["failure_lines"] = _fail_lines
                                    print(f"[scans] Marking {bridge_id} as FAILED: {_reason}")

                elif not known_non_scan_keys.issuperset(entry.keys()):
                    print(f"[scans] Line {line_num}: Unrecognised entry keys: {list(entry.keys())}")

            except json.JSONDecodeError as e:
                print(f"[scans] Line {line_num}: JSON decode error: {e}")
            except Exception as e:
                print(f"[scans] Line {line_num}: Error processing: {e}")

        scans = [by_bridge_id[bid] for bid in bridge_id_order]
        print(f"[scans] Loaded {len(scans)} scans from stats.log ({len(lines)} lines)")
    except Exception as e:
        print(f"[scans] Failed to read stats.log: {e}")
        import traceback
        traceback.print_exc()
        scans = []

    return scans

def _resolve_inflight_status(scan):
    """For a scan still marked running/initializing/launched in SCANS_STORE,
    inspect its wrapper log to see if it actually finished or died.

    The wrapper shell (see launch_scan) always emits '=== Scan Completed ==='
    once axiom-scan returns, then either '✓ Output saved'/'✓ Output directory'
    or '✗ Output not found'. Until stats.log gets an entry, that log is the only
    signal — so a scan that aborts in seconds (missing tool, bad input) would
    otherwise sit at 'running' forever both in the UI and for workflow-runner.

    Returns a (possibly mutated) copy of the scan dict with an updated status,
    and — when failed — 'failure_reason' / 'failure_lines' for display.
    """
    status = (scan.get("status") or "").lower()
    if status not in ("running", "initializing", "launched", "pending", ""):
        return scan

    log_path = scan.get("logFile")
    if not log_path:
        sid = scan.get("id") or ""
        if sid:
            log_path = os.path.join(
                os.path.expanduser("~/.axiom/tmp"),
                f"{sid.replace('+', '_')}.log"
            )
    if not log_path or not os.path.isfile(log_path):
        return scan  # not started writing yet → genuinely still spinning up

    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return scan

    text = "".join(lines)
    if "=== Scan Completed ===" not in text:
        return scan  # axiom-scan still running → leave as-is

    # The wrapper has finished. Decide completed vs failed.
    updated = dict(scan)
    is_failed, reason, fail_lines = _detect_log_failures(lines)
    output_missing = "✗ Output not found" in text
    output_ok = ("✓ Output saved" in text) or ("✓ Output directory" in text)

    if is_failed or (output_missing and not output_ok):
        updated["status"] = "failed"
        updated["failure_reason"] = reason or "scan finished but produced no output"
        if fail_lines:
            updated["failure_lines"] = fail_lines
    elif output_ok:
        updated["status"] = "completed"
    # else: completed marker present but ambiguous → leave running for now
    return updated


def load_scans():
    """Load scans from stats.log AND merge any running scans from SCANS_STORE.

    stats.log only contains scans after axiom-scan finishes writing to it, so
    just-launched / in-flight scans need to come from SCANS_STORE. We dedupe by
    id/name (stats.log entry wins for completed scans).

    stats.log entries set name=id (the raw scan ID), losing the human-readable
    label (e.g. "gw-nike-5") stored in SCANS_STORE. We restore it so the
    project filter in the UI (which matches on name prefix) can still find them.
    """
    stats_scans = []
    try:
        stats_scans = load_scans_from_stats_log()
    except Exception as e:
        print(f"[scans] Error loading from stats.log: {e}")

    store_scans = []
    try:
        with open(SCANS_STORE, "r") as f:
            store_scans = json.load(f) or []
    except Exception:
        store_scans = []

    if not stats_scans and not store_scans:
        return []

    # Build id → human-readable name from SCANS_STORE so we can restore labels
    # that stats.log drops (it uses the raw scan ID as name).
    store_name_by_id = {
        s["id"]: s["name"]
        for s in store_scans
        if s.get("id") and s.get("name") and s["id"] != s["name"]
    }

    # Dedupe — prefer stats.log entry (it has runtime/results/etc.), but
    # restore the label name from SCANS_STORE if stats.log only has the raw ID.
    seen = set()
    merged = []
    for s in stats_scans:
        sid = s.get("id") or s.get("name")
        if sid:
            seen.add(sid)
        # stats.log sets name == id; restore human-readable label if available
        if s.get("name") == s.get("id") and sid in store_name_by_id:
            s = {**s, "name": store_name_by_id[sid]}
        merged.append(s)

    store_changed = False
    for s in store_scans:
        sid = s.get("id") or s.get("name")
        if sid and sid not in seen:
            # Ensure running scans expose a status field the UI can poll on
            if not s.get("status"):
                s["status"] = "running"
            # Reconcile against the wrapper log so a scan that already finished
            # or died (before landing in stats.log) doesn't linger as 'running'.
            resolved = _resolve_inflight_status(s)
            if resolved.get("status") != s.get("status"):
                # Status changed — write back so it doesn't linger as 'running'
                store_changed = True
                s = resolved
            merged.append(s)

    if store_changed:
        # Persist only the store entries (not stats.log-sourced ones)
        updated_store = [s for s in merged if s.get("id") not in
                         {ss.get("id") for ss in stats_scans}]
        # Keep any store entries that were deduped out too
        all_store_ids = {s.get("id") or s.get("name") for s in updated_store}
        for s in store_scans:
            sid = s.get("id") or s.get("name")
            if sid and sid not in all_store_ids:
                updated_store.append(s)
        try:
            save_scans(updated_store)
        except Exception:
            pass

    return merged

def save_scans(scans):
    """Save scans to store (mainly for running/pending scans not yet in stats.log)"""
    try:
        with open(SCANS_STORE, "w") as f:
            json.dump(scans, f, indent=2)
    except Exception as e:
        print(f"[scans] Failed to save scans: {e}")


def patch_gowitness_names():
    """Back-fill human-readable scan names onto gowitness targets in the store.

    Reads data/scans.json and for every gowitness scan entry looks up the
    matching target in the bridge store (by id == scan["id"]) and sets
    ``domain`` = scan["name"] and ``programName`` = "GoWitness Scan".
    Also handles the legacy merged target with id="gowitness" by leaving it
    untouched (it won't have a matching scan entry).
    """
    try:
        with open(SCANS_STORE, "r") as f:
            scans = json.load(f)
    except Exception:
        return  # nothing to do

    # Build id -> name map for gowitness scans only
    gw_name_map = {
        s["id"]: s["name"]
        for s in scans
        if s.get("id") and s.get("name")
        and "gowitness" in s.get("module", "").lower()
    }
    if not gw_name_map:
        return

    store = load_store()
    changed = False
    for t in store.get("targets", []):
        tid = t.get("id", "")
        # Match on exact id OR the id with trailing dot stripped
        match_name = gw_name_map.get(tid) or gw_name_map.get(tid.rstrip('.'))
        if match_name and t.get("domain") != match_name:
            print(f"[bridge] patch_gowitness_names: '{tid}' -> '{match_name}'")
            t["domain"] = match_name
            t["programName"] = "GoWitness Scan"
            changed = True

    if changed:
        save_store(store)
        print(f"[bridge] patch_gowitness_names: store updated")


def sanitize_domain(target: str) -> str:
    """Sanitize a single target string (domain, IP, CIDR, or URL).
    Strips HTML tags (Ghostwriter rich-text scopes wrap lines in <p> tags),
    then removes characters that are unsafe in shell contexts.
    Returns an empty string if the target is clearly invalid.
    """
    target = target.strip()
    if not target:
        return ""
    # Strip HTML tags before any other processing
    target = re.sub(r"<[^>]+>", "", target).strip()
    if not target:
        return ""
    # Remove shell-unsafe characters (keep alphanumerics, dots, dashes, slashes,
    # colons for ports/IPv6, brackets for IPv6, underscores, @, %)
    sanitized = re.sub(r"[^\w.:/\-@%\[\]]+", "", target)
    return sanitized


@app.route("/api/axiom/modules", methods=["GET"])
def get_modules():
    """List all axiom scan modules from ~/.axiom/modules.
    No local binary check — tools run on remote Axiom instances, not locally."""
    modules_path = os.path.expanduser("~/.axiom/modules")
    available = []
    if os.path.exists(modules_path):
        for fname in sorted(os.listdir(modules_path)):
            if fname.startswith('.') or not fname.endswith('.json'):
                continue
            available.append(fname)

    if not available:
        # Fallback when ~/.axiom/modules doesn't exist yet
        fallback_tools = ["amass", "httpx", "dnsx", "nmap", "ffuf",
                          "nuclei", "gowitness", "subfinder", "masscan",
                          "nuclei", "gowitness", "ffuf", "httpx", "dnsx",
                          "subfinder", "amass", "nmap", "masscan", "rustscan",
                          "whois", "katana", "waybackurls", "gospider"]
        available = [f"{t}.json" for t in dict.fromkeys(fallback_tools)]

    return jsonify({"modules": available})


def _build_scan_shell(cmd_str: str, targets_file: str, output_file_abs: str, log_file: str) -> str:
    """Return the zsh shell script that wraps one axiom-scan invocation in a tmux session."""
    return f'''zsh -l -c '
        echo "=== Axiom Scan Starting ===" | tee {log_file}
        echo "Time: $(date)" | tee -a {log_file}
        echo "Command: {cmd_str}" | tee -a {log_file}
        echo "=========================" | tee -a {log_file}
        echo "" | tee -a {log_file}
        if [ -f "{targets_file}" ]; then
            echo "✓ Input: $(wc -l < "{targets_file}") targets" | tee -a {log_file}
        else
            echo "✗ ERROR: Input file missing!" | tee -a {log_file}
            exit 1
        fi
        echo "" | tee -a {log_file}
        echo "=== Waiting 10s for instances to initialise... ===" | tee -a {log_file}
        sleep 10
        echo "=== Running Scan ===" | tee -a {log_file}
        {cmd_str} 2>&1 | tee -a {log_file}
        EXIT_CODE=$?
        echo "" | tee -a {log_file}
        echo "=== Scan Completed (exit $EXIT_CODE) ===" | tee -a {log_file}
        if [ -f "{output_file_abs}" ]; then
            echo "✓ Output: $(wc -l < "{output_file_abs}") lines saved to {output_file_abs}" | tee -a {log_file}
        elif [ -d "{output_file_abs}" ]; then
            echo "✓ Output dir: $(ls -1 "{output_file_abs}" | wc -l) files" | tee -a {log_file}
        else
            echo "✗ Output not found at {output_file_abs}" | tee -a {log_file}
        fi
        echo "Keeping terminal open 60s..." | tee -a {log_file}
        sleep 60
    \''''


def _launch_split_mode(scan_name, targets, module_list, fleet_control, options, deployed_fleet_name):
    """Split mode: one axiom-scan per module, each on dedicated instance(s).

    Unlike the default chained mode (where modules pipe into each other and share
    all fleet instances), split mode gives every module its own instance(s) and
    feeds all modules the original raw target list independently.

    Fleet size is divided equally: fleet_size=4 with 2 modules → 2 instances each.
    """
    spinup = int(fleet_control.get("spinup") or 0)
    instances_per_module = max(1, spinup // len(module_list)) if spinup else 0

    # Sanitize targets once; reuse the same list for all modules
    target_lines = []
    for t in targets:
        if isinstance(t, dict):
            target_str = (t.get("hostname") or t.get("domain") or t.get("host")
                          or t.get("target") or t.get("url") or t.get("ip") or str(t))
        else:
            target_str = str(t)
        target_str = sanitize_domain(target_str)
        if target_str:
            target_lines.append(target_str)

    if not target_lines:
        return jsonify({"error": "No valid targets provided"}), 400

    try:
        with open(SCANS_STORE, "r") as f:
            scans = json.load(f)
    except Exception:
        scans = []

    timestamp = datetime.now(timezone.utc).strftime('%m-%d_%H-%M-%S-%f')[:22]
    axiom_tmp = AXIOM_TMP
    os.makedirs(axiom_tmp, exist_ok=True)
    safe_name = re.sub(r'[^a-z0-9]', '', scan_name.lower())[:10]

    sub_scan_ids = []

    for m in module_list:
        m_scan_id = f"{m}+{timestamp}"
        m_targets_file = os.path.join(axiom_tmp, f"{scan_name}_{m}_targets.txt")
        os.makedirs(os.path.dirname(m_targets_file), exist_ok=True)

        with open(m_targets_file, "w", encoding="utf-8") as f:
            f.write("\n".join(target_lines) + "\n")

        # Determine file extension from module JSON (e.g. nuclei → .txt)
        ext = ".txt"
        m_json_path = os.path.expanduser(f"~/.axiom/modules/{m}.json")
        try:
            with open(m_json_path) as _mf:
                _mdata = json.load(_mf)
                if isinstance(_mdata, list) and _mdata:
                    raw_ext = _mdata[0].get("ext", "txt")
                    ext = raw_ext if raw_ext.startswith('.') else f".{raw_ext}"
        except Exception:
            pass

        m_output_file = os.path.join(IMPORTS_PATH, f"{m_scan_id}{ext}")
        # Fleet prefix unique per module to prevent instance-name collisions
        m_fleet_prefix = f"{safe_name}{m[:4]}" if instances_per_module else None

        m_cmd = ["axiom-scan", m_targets_file, "-m", m, "-o", m_output_file]
        if deployed_fleet_name:
            m_cmd.extend(["--fleet", deployed_fleet_name])
        elif instances_per_module and m_fleet_prefix:
            m_cmd.extend(["--spinup", str(instances_per_module), "--fleet", m_fleet_prefix])
        if fleet_control.get("rmWhenDone"):
            m_cmd.append("--rm-when-done")
        if fleet_control.get("regions"):
            m_cmd.extend(["--regions", ",".join(fleet_control["regions"])])
        if options.get("extraArgs"):
            m_cmd.extend(shlex.split(options["extraArgs"]))

        m_cmd_str = ' '.join([f'"{a}"' if ' ' in a else a for a in m_cmd])
        m_log_file = os.path.join(axiom_tmp, f"{m_scan_id.replace('+', '_')}.log")
        m_tmux_session = m_scan_id.replace('+', '_').replace(':', '_')

        m_scan = {
            "id": m_scan_id,
            "name": scan_name,
            "module": m,
            "targets": targets,
            "targetsFile": m_targets_file,
            "outputFile": m_output_file,
            "status": "running",
            "startedAt": datetime.now(timezone.utc).isoformat() + "Z",
            "completedAt": None,
            "progress": 0,
            "logFile": m_log_file,
            "logs": [],
            "splitMode": True,
        }
        scans.append(m_scan)

        m_shell = _build_scan_shell(m_cmd_str, m_targets_file, m_output_file, m_log_file)
        m_tmux_cmd = ["tmux", "new-session", "-d", "-s", m_tmux_session, m_shell]

        def _launch(session=m_tmux_session, cmd=m_tmux_cmd, sid=m_scan_id):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                print(f"[scans][split] {session} rc={r.returncode}")
                if r.returncode != 0 and r.stderr:
                    print(f"[scans][split] stderr: {r.stderr[:300]}")
            except Exception as exc:
                print(f"[scans][split] error launching {session}: {exc}")

        threading.Thread(target=_launch, daemon=True).start()
        print(f"[scans][split] Queued: {m_scan_id} (fleet={m_fleet_prefix}, instances={instances_per_module})")

        if m_fleet_prefix:
            with SCAN_INSTANCES["lock"]:
                SCAN_INSTANCES["prefixes"].add(m_fleet_prefix)
                save_scan_prefixes(SCAN_INSTANCES["prefixes"])

        sub_scan_ids.append(m_scan_id)

    save_scans(scans)
    FLEET_CACHE["timestamp"] = 0

    return jsonify({
        "scanId":            sub_scan_ids[0],
        "scanIds":           sub_scan_ids,
        "status":            "initializing" if instances_per_module else "launched",
        "mode":              "split",
        "modulesLaunched":   len(sub_scan_ids),
        "instancesPerModule": instances_per_module,
        "message": (
            f"Split mode: {len(sub_scan_ids)} parallel scan(s) launched — "
            f"{instances_per_module} instance(s) per module. "
            f"Modules: {', '.join(module_list)}"
        ),
    })


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
    # Split comma-separated modules ("httpx,nuclei" → ["httpx", "nuclei"])
    module_list = [m.strip().replace('.json', '') for m in module.split(",") if m.strip()]
    module_name = "+".join(module_list)  # safe for filenames: "httpx+nuclei"

    # ── Split mode: one axiom-scan per module on dedicated instances ──────────
    if data.get("splitModulesPerInstance") and len(module_list) > 1:
        return _launch_split_mode(
            scan_name=scan_name,
            targets=targets,
            module_list=module_list,
            fleet_control=data.get("fleetControl", {}),
            options=data.get("options", {}),
            deployed_fleet_name=deployed_fleet_name,
        )
    # ─────────────────────────────────────────────────────────────────────────

    scan_id = f"{module_name}+{datetime.now(timezone.utc).strftime('%m-%d_%H-%M-%S-%f')[:22]}"

    # Define targets_file path BEFORE building the scan record
    axiom_tmp = AXIOM_TMP  # Use configured temp path (Docker-friendly)
    os.makedirs(axiom_tmp, exist_ok=True)
    targets_file = os.path.join(axiom_tmp, f"{scan_name}_{module_name}_targets.txt")
    # scan_name may contain a team-prefix slash (e.g. "team/name") which
    # produces a subdirectory — make sure it exists before writing the file.
    os.makedirs(os.path.dirname(targets_file), exist_ok=True)

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
        "targetsFile": targets_file,
        "outputFile": output_file,
        "options": options,
        "fleet": deployed_fleet_name,
        "autoDestroyFleet": fleet_config.get("autoDestroy") if fleet_config else False,
        "status": "running",
        "startedAt": datetime.now(timezone.utc).isoformat() + "Z",
        "completedAt": None,
        "progress": 0,
        # Project association — set when the scan is launched from a project context.
        "project_token": data.get("projectToken") or None,
        # Path to the per-scan wrapper log (written by the tmux shell below).
        # load_scans() watches this to detect a scan that finished/failed before
        # ever reaching stats.log (e.g. a missing tool aborts axiom-scan in <10s).
        "logFile": os.path.join(
            os.path.expanduser("~/.axiom/tmp"),
            f"{scan_id.replace('+', '_')}.log"
        ),
        "logs": []
    }
    
    # Save scan
    scans.append(scan)
    save_scans(scans)
    
    # Build axiom-scan command (targets_file already defined above)
    
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
    if module_list == ["gowitness"]:
        # Gowitness outputs a directory, put it in imports/gowitness/
        output_dir = os.path.join(IMPORTS_PATH, "gowitness")
        os.makedirs(output_dir, exist_ok=True)
    else:
        # All other modules: put output file directly in imports/
        output_dir = IMPORTS_PATH

    # Auto-generate output filename as {module_name}+{timestamp}.{ext}
    # Use the first module's JSON to determine extension
    ext = ".txt"
    first_module = module_list[0] if module_list else "scan"
    module_json_path = os.path.expanduser(
        f"~/.axiom/modules/{first_module if first_module.endswith('.json') else first_module + '.json'}"
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

    # Build axiom-scan -m flags: one per module (comma list → repeated -m)
    m_flags = []
    for m in module_list:
        m_flags.extend(["-m", m])
    cmd = ["axiom-scan", targets_file] + m_flags + ["-o", output_file_abs]
    
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

    # Gowitness cold-start note: the 10s sleep injected in the tmux shell handles
    # the "websocket url timeout" issue on fresh instances.  No extra flags needed
    # here — --chrome-timeout is not a valid gowitness flag.

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
        echo "=== Waiting 10s for instances to fully initialise... ===" | tee -a {log_file}
        sleep 10
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

@app.route("/api/axiom/scans/<path:scan_id>/project", methods=["PUT", "DELETE"])
def link_scan_project(scan_id):
    """Link (PUT) or unlink (DELETE) a scan/programName to/from a project.

    PUT  body: {"projectToken": "<token>"}  — adds scan_id as a linked programName on the project
    DELETE                                  — removes scan_id from all projects' linked_scans
    """
    body = request.json or {}
    projects = load_projects()

    if request.method == "PUT":
        token = body.get("projectToken")
        if not token:
            return jsonify({"error": "projectToken required"}), 400
        proj = projects.get(token)
        if proj is None:
            return jsonify({"error": "project not found"}), 404
        linked = proj.setdefault("linked_scans", [])
        if scan_id not in linked:
            linked.append(scan_id)
        save_projects(projects)
        return jsonify({"ok": True, "scan_id": scan_id, "project": token})

    # DELETE — remove from whichever project has it
    changed = False
    for proj in projects.values():
        ls = proj.get("linked_scans", [])
        if scan_id in ls:
            proj["linked_scans"] = [x for x in ls if x != scan_id]
            changed = True
    if changed:
        save_projects(projects)
    return jsonify({"ok": True, "scan_id": scan_id})


@app.route("/api/projects/<token>/linked-scans", methods=["GET"])
def get_project_linked_scans(token):
    """Return linked_scans for a project and the available programNames."""
    projects = load_projects()
    proj = projects.get(token)
    if proj is None:
        return jsonify({"error": "project not found"}), 404

    # Collect all unique programNames from the targets store
    try:
        store = load_store()
        all_program_names = sorted({
            t.get("programName", "").strip()
            for t in store.get("targets", [])
            if t.get("programName", "").strip()
        })
    except Exception:
        all_program_names = []

    return jsonify({
        "linked_scans": proj.get("linked_scans", []),
        "available_program_names": all_program_names,
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
    preview_module_list = [m.strip().replace('.json', '') for m in module.split(",") if m.strip()]
    preview_module_name = "+".join(preview_module_list)
    final_output_file = output_file or f"{scan_name}-{preview_module_name}.txt"
    axiom_tmp = AXIOM_TMP  # Use configured temp path (Docker-friendly)
    targets_file = os.path.join(axiom_tmp, f"{scan_name}_{preview_module_name}_targets.txt")
    os.makedirs(os.path.dirname(targets_file), exist_ok=True)

    preview_m_flags = []
    for m in preview_module_list:
        preview_m_flags.extend(["-m", m])
    cmd = ["axiom-scan", targets_file] + preview_m_flags + ["-o", final_output_file]
    
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
    """Get scans from stats.log, sorted by most recent first.

    Admins receive all scans. Regular users only see:
      - Scans whose name starts with gw-<client-slug>- for any of their projects.
      - Scans whose name does NOT start with 'gw-' (personal / workflow scans).
    """
    project_tokens = _get_caller_project_tokens(load_store())
    scans = load_scans()

    if project_tokens is not None:
        projects = load_projects()
        # Build allowed gw- prefixes from the user's project client slugs
        allowed_prefixes = []
        for tok in project_tokens:
            proj = projects.get(tok)
            if proj:
                client = proj.get("client", "")
                slug = re.sub(r"[^a-z0-9]+", "-", client.lower()).strip("-")[:24]
                allowed_prefixes.append(f"gw-{slug}-")

        def _scan_allowed(s):
            name = (s.get("name") or "").lower()
            if not name.startswith("gw-"):
                return True  # personal / workflow scans visible to all
            return any(name.startswith(p) for p in allowed_prefixes)

        scans = [s for s in scans if _scan_allowed(s)]

    scans_sorted = sorted(scans, key=lambda x: x.get("date", x.get("id", "")), reverse=True)
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

            # Prefer the human-readable scan name from scans.json over the raw folder id
            _stored_name = next(
                (s.get("name") for s in load_scans() if s.get("id") == scan_id and s.get("name")),
                scan_id,
            )
            scan = {
                "id": scan_id,
                "name": _stored_name,
                "module": module,
                "status": final_scan_status,
                "date": timestamp,
                "source": "tmp" if base_dir == axiom_tmp else "logs",
                "path": scan_path,
                "output_files": output_files,
                "output": output_dir if output_files else None,
                "local_logs": logs_dir if os.path.exists(logs_dir) else (log_file if os.path.exists(log_file) else None),
                # "logs": logs,  # Removed: logs will be fetched separately via /logs endpoint
                "results": results_count,
                "progress": min(95, (results_count // 10) if results_count else 0) if is_running else 100,
            }
            # Read the input (targets) file from the scan folder
            input_file = os.path.join(scan_path, "input")
            if os.path.isfile(input_file):
                try:
                    with open(input_file, "r", encoding="utf-8") as _f:
                        scan["targetList"] = [l.strip() for l in _f if l.strip()]
                    print(f"[get_scan] Read {len(scan['targetList'])} targets from input file")
                except Exception as _e:
                    print(f"[get_scan] Could not read input file: {_e}")
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
                scan["completedAt"] = datetime.now(timezone.utc).isoformat() + "Z"
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

@app.route("/api/axiom/scans/<scan_id>/complete", methods=["POST"])
def complete_scan(scan_id):
    """Mark a scan as completed (called by workflow-runner after filesystem detection)."""
    data = request.get_json(silent=True) or {}
    result_count = int(data.get("resultCount", 0))
    output_path  = data.get("outputPath", "")
    try:
        with open(SCANS_STORE, "r") as f:
            scans = json.load(f)
    except Exception:
        scans = []

    for scan in scans:
        if scan.get("id") == scan_id:
            scan["status"]      = "completed"
            scan["completedAt"] = datetime.now(timezone.utc).isoformat() + "Z"
            scan["resultCount"] = result_count
            scan["results"]     = result_count
            if output_path:
                scan["output"] = output_path
            save_scans(scans)
            return jsonify({"ok": True, "resultCount": result_count})

    # Not in store (e.g. gowitness which had no SCANS_STORE entry) — add it.
    scans.append({
        "id":          scan_id,
        "name":        scan_id,
        "status":      "completed",
        "completedAt": datetime.now(timezone.utc).isoformat() + "Z",
        "resultCount": result_count,
        "results":     result_count,
        "output":      output_path,
    })
    save_scans(scans)
    return jsonify({"ok": True, "resultCount": result_count, "created": True})


@app.route("/api/axiom/scans/<scan_id>/targets", methods=["GET"])
def get_scan_targets(scan_id):
    """Return the list of targets used for a specific scan.

    Sources (in priority order):
      1. targetsFile path stored in scans.json → read the txt file
      2. targets[] array stored in scans.json (dashboard-launched scans)
      3. input file inside the axiom log scan folder (~/.axiom/logs/<scan_id>/input)
    """
    # 1 + 2: check stored scan record
    scans = load_scans()
    for scan in scans:
        if scan.get("id") == scan_id:
            # Prefer the targets file on disk (most accurate after sanitisation)
            tf = scan.get("targetsFile")
            if tf and os.path.isfile(tf):
                try:
                    with open(tf, "r", encoding="utf-8") as f:
                        lines = [l.strip() for l in f if l.strip()]
                    return jsonify({"targets": lines, "count": len(lines), "source": "file"})
                except Exception as e:
                    print(f"[targets] Could not read targetsFile: {e}")
            # Fall back to the in-memory array
            stored = scan.get("targets", [])
            if stored:
                if isinstance(stored, list):
                    lines = [str(t) for t in stored if t]
                else:
                    lines = []
                return jsonify({"targets": lines, "count": len(lines), "source": "store"})

    # 3: filesystem scan folder
    for base_dir in [os.path.expanduser("~/.axiom/logs"), os.path.expanduser("~/.axiom/tmp"), AXIOM_TMP]:
        input_file = os.path.join(base_dir, scan_id, "input")
        if os.path.isfile(input_file):
            try:
                with open(input_file, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                return jsonify({"targets": lines, "count": len(lines), "source": "input_file"})
            except Exception as e:
                print(f"[targets] Could not read input file: {e}")

    return jsonify({"targets": [], "count": 0, "source": "none"})


@app.route("/api/axiom/scans/<scan_id>/logs", methods=["GET"])
def get_scan_logs(scan_id):
    """Get logs for a specific scan from ~/.axiom/logs/{scan_id}/logs/ directory"""
    logs = []
    
    # Find the scan folder
    folder, _ = _find_scan_folder(scan_id)
    if not folder:
        return jsonify({"logs": [], "error": "Scan folder not found"}), 404
    
    # Look for logs in the logs/ subdirectory
    logs_dir = os.path.join(folder, "logs")
    if not os.path.isdir(logs_dir):
        return jsonify({"logs": [], "error": "Logs directory not found", "path": logs_dir}), 404
    
    # Find all files in the logs directory
    try:
        entries = [f for f in os.listdir(logs_dir) if os.path.isfile(os.path.join(logs_dir, f))]
        if not entries:
            return jsonify({"logs": [], "error": "No log files in directory", "path": logs_dir}), 404
        
        # Use the most recent file (by modification time)
        latest_file = max(entries, key=lambda f: os.path.getmtime(os.path.join(logs_dir, f)))
        log_path = os.path.join(logs_dir, latest_file)
        
        print(f"[logs] Reading log file: {log_path}")
        
        with open(log_path, "r") as f:
            content = f.read()
            logs = content.split("\n")
        
        # Keep only the last 1000 lines
        logs = logs[-1000:]
        print(f"[logs] Read {len(logs)} lines from {log_path}")
    except Exception as e:
        print(f"[logs] Failed to read log file: {e}")
        return jsonify({"logs": [], "error": str(e), "path": logs_dir}), 500

    return jsonify({
        "logs": logs,
        "scanId": scan_id,
        "logPath": log_path,
        "totalLines": len(logs)
    })

_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
_SCREENSHOT_MODULES = {"gowitness", "webscreenshot", "scrying", "aquatone"}

def _find_scan_folder(scan_id: str):
    """Return (folder_path, source) for a scan_id, checking tmp then logs.

    Tries exact match first, then falls back to a prefix match on the module
    name (the part before '+') so that the bridge-assigned scan_id (timestamped
    at request time) still finds the axiom log directory (timestamped when
    axiom-scan actually ran, which may be several seconds later).
    """
    for base in [os.path.expanduser("~/.axiom/tmp"), os.path.expanduser("~/.axiom/logs")]:
        # Exact match
        path = os.path.join(base, scan_id)
        if os.path.isdir(path):
            return path, ("tmp" if "tmp" in base else "logs")

    # Fuzzy fallback: match directories whose name starts with the module
    # prefix (e.g. "httprobe") extracted from scan_id "httprobe+06-18_..."
    module_prefix = scan_id.split("+")[0] if "+" in scan_id else scan_id
    for base in [os.path.expanduser("~/.axiom/tmp"), os.path.expanduser("~/.axiom/logs")]:
        if not os.path.isdir(base):
            continue
        try:
            candidates = sorted(
                [d for d in os.listdir(base)
                 if d.startswith(module_prefix + "+") and os.path.isdir(os.path.join(base, d))],
                key=lambda d: os.path.getmtime(os.path.join(base, d)),
                reverse=True,  # most recent first
            )
            if candidates:
                return os.path.join(base, candidates[0]), ("tmp" if "tmp" in base else "logs")
        except OSError:
            pass
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

    # Build a name lookup from stored scan records so filesystem scan IDs
    # are mapped to the human-readable name given at launch time.
    # We build two indexes:
    #   _name_map        — exact id match
    #   _prefix_name_map — module+MM-DD_HH-MM-SS prefix match (strips the last
    #                      counter/microsecond suffix so bridge IDs like
    #                      httprobe+07-02_21-10-09-653016 map to axiom folder
    #                      names like httprobe+07-02_21-10-09-5)
    _stored   = load_scans()
    _name_map = {s["id"]: s["name"] for s in _stored if s.get("id") and s.get("name")}
    _prefix_name_map: dict = {}
    # Minute-level map: "module+MM-DD_HH-MM" → {id, name}
    # Bridges the gap between the bridge scan_id timestamp (at launch) and the
    # axiom internal folder timestamp (slightly later when axiom actually starts).
    _minute_map: dict = {}
    for _s in _stored:
        _sid  = _s.get("id", "")
        _name = _s.get("name", "")
        if "+" in _sid and "-" in _sid and _name:
            # prefix = everything up to (but not including) the last dash-segment
            _pfx = _sid.rsplit("-", 1)[0]
            if _pfx and _pfx not in _prefix_name_map:
                _prefix_name_map[_pfx] = _name
            # Minute-level key: module+MM-DD_HH-MM (first 11 chars of timestamp)
            _s_parts = _sid.rsplit("+", 1)
            _s_ts = _s_parts[1] if len(_s_parts) > 1 else ""
            _min_key = _s_parts[0] + "+" + _s_ts[:11] if _s_ts else ""
            if _min_key and _min_key not in _minute_map:
                _minute_map[_min_key] = {"id": _sid, "name": _name}

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

                # Resolve folder → bridge scan entry: exact, second-prefix, minute-prefix
                _logs_id = folder
                _logs_name = _name_map.get(folder) or _prefix_name_map.get(folder.rsplit("-", 1)[0])
                if not _logs_name:
                    _f_parts = folder.rsplit("+", 1)
                    _f_ts = _f_parts[1] if len(_f_parts) > 1 else ""
                    _f_min_key = _f_parts[0] + "+" + _f_ts[:11] if _f_ts else ""
                    _matched = _minute_map.get(_f_min_key)
                    if _matched:
                        _logs_id   = _matched["id"]    # use bridge id so frontend dedup works
                        _logs_name = _matched["name"]
                _logs_name = _logs_name or folder

                logs_scan_entry = {
                    "id": _logs_id,
                    "name": _logs_name,
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

                # Resolve folder → bridge scan entry: exact, second-prefix, minute-prefix
                _tmp_id = folder
                _tmp_name = _name_map.get(folder) or _prefix_name_map.get(folder.rsplit("-", 1)[0])
                if not _tmp_name:
                    _tf_parts = folder.rsplit("+", 1)
                    _tf_ts = _tf_parts[1] if len(_tf_parts) > 1 else ""
                    _tf_min_key = _tf_parts[0] + "+" + _tf_ts[:11] if _tf_ts else ""
                    _t_matched = _minute_map.get(_tf_min_key)
                    if _t_matched:
                        _tmp_id   = _t_matched["id"]
                        _tmp_name = _t_matched["name"]
                _tmp_name = _tmp_name or folder

                tmp_entry = {
                    "id": _tmp_id,
                    "name": _tmp_name,
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

    Runs in its own process group (start_new_session=True) so that on timeout
    we can kill the whole tree (zsh + any nested children it spawns, e.g.
    axiom-ls -> aws ec2 describe-regions) via os.killpg. subprocess.run()'s
    built-in timeout only kills the direct zsh child — any grandchildren it
    forked keep running as orphans, which is how a single hung AWS region
    call turns into a pile of stuck processes that never go away and starve
    the container's CPU.
    """
    print(f"[fleet] Running command via zsh: {cmd_str}")
    proc = None
    try:
        proc = subprocess.Popen(
            ["/bin/zsh", "-lc", cmd_str],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stdout, stderr = proc.communicate(timeout=timeout)

        print(f"[fleet] Command completed with return code: {proc.returncode}")
        if stdout:
            print(f"[fleet] STDOUT: {stdout[:500]}")
        if stderr:
            print(f"[fleet] STDERR: {stderr[:500]}")

        return {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {timeout}s"
        print(f"[fleet] ERROR: {error_msg} - killing process group to avoid orphaned children")
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
        return {"stdout": "", "stderr": error_msg, "returncode": -1}
    except Exception as e:
        error_msg = f"Exception running command: {str(e)}"
        print(f"[fleet] ERROR: {error_msg}")
        traceback.print_exc()
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
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


# ─── Workflow runner endpoints ────────────────────────────────────────────────
# These replace the browser-side Promise scheduler with a reliable Python
# subprocess that writes verbose per-run logs and a JSON status file.
# Log/status files live in /tmp/workflow-logs/<run-id>.{log,status.json}.

WF_LOG_DIR = os.environ.get("WF_LOG_DIR", "/tmp/workflow-logs")
os.makedirs(WF_LOG_DIR, exist_ok=True)

# Map run_id → Popen object so we can abort and properly reap the child.
_wf_procs: dict = {}  # run_id → subprocess.Popen


def _supervise_wf(run_id: str, proc: subprocess.Popen, log_fd) -> None:
    """Wait for the runner to exit (prevents zombie) and clean up."""
    try:
        proc.wait()
    finally:
        try:
            log_fd.close()
        except Exception:
            pass
        _wf_procs.pop(run_id, None)
        print(f"[workflow] Run {run_id} exited  rc={proc.returncode}")


@app.route("/api/workflow/run", methods=["POST"])
def start_workflow_run():
    """
    POST { name, steps, config, initialTargets }
    Saves the workflow to a temp JSON file, launches workflow-runner.py as a
    background subprocess, and returns { runId, logFile, statusFile }.
    """
    data = request.json or {}
    if not data.get("steps"):
        return jsonify({"error": "no steps provided"}), 400

    import uuid as _uuid
    run_id    = f"wf-{datetime.now(timezone.utc).strftime('%m%d-%H%M%S')}-{_uuid.uuid4().hex[:6]}"
    wf_file   = os.path.join(WF_LOG_DIR, f"{run_id}.workflow.json")
    log_file  = os.path.join(WF_LOG_DIR, f"{run_id}.log")
    stat_file = os.path.join(WF_LOG_DIR, f"{run_id}.status.json")

    os.makedirs(WF_LOG_DIR, exist_ok=True)
    with open(wf_file, "w") as f:
        json.dump(data, f, indent=2)

    # Determine path to workflow-runner.py (same directory as this script)
    runner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "workflow-runner.py")
    if not os.path.isfile(runner_path):
        return jsonify({"error": f"workflow-runner.py not found at {runner_path}"}), 500

    # Pass the static token so the runner can authenticate against the bridge.
    env = os.environ.copy()
    _static_tok = os.environ.get("GUI_AX_STATIC_TOKEN", "")
    if _static_tok:
        env["WF_BRIDGE_TOKEN"] = _static_tok
    elif _active_tokens:
        env["WF_BRIDGE_TOKEN"] = next(iter(_active_tokens))

    print(f"[workflow] Starting run {run_id}  log={log_file}")
    try:
        log_fd = open(log_file, "wb")
        proc = subprocess.Popen(
            ["python3", runner_path,
             "--run-id", run_id,
             "--workflow-file", wf_file],
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            env=env,
        )
        # Don't close log_fd here — _supervise_wf does it after proc exits.
        _wf_procs[run_id] = proc
        # Supervisor thread: calls proc.wait() so the child is properly reaped
        # and never becomes a zombie (container PID 1 is tail -f /dev/null).
        threading.Thread(
            target=_supervise_wf,
            args=(run_id, proc, log_fd),
            daemon=True,
        ).start()
    except Exception as e:
        print(f"[workflow] failed to start runner: {e}")
        return jsonify({"error": f"failed to start workflow runner: {e}"}), 500

    print(f"[workflow] Run {run_id} started  pid={proc.pid}")
    return jsonify({
        "runId":      run_id,
        "pid":        proc.pid,
        "logFile":    log_file,
        "statusFile": stat_file,
        "message":    f"Workflow started (pid {proc.pid}).  Tail logs: tail -f {log_file}",
    })


@app.route("/api/workflow/<run_id>/status", methods=["GET"])
def get_workflow_status(run_id: str):
    """
    Returns the current status JSON for a workflow run plus the last N log lines.
    { runId, status, startedAt, endedAt, steps: { id: {...} }, recentLog: [...] }
    """
    # Sanitise run_id to prevent path traversal
    if not re.match(r'^[a-zA-Z0-9_\-]+$', run_id):
        abort(400)

    stat_file = os.path.join(WF_LOG_DIR, f"{run_id}.status.json")
    log_file  = os.path.join(WF_LOG_DIR, f"{run_id}.log")

    if not os.path.isfile(stat_file):
        return jsonify({"error": "run not found", "runId": run_id}), 404

    try:
        with open(stat_file) as f:
            status_data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"could not read status: {e}"}), 500

    # Append recent log lines (last 100)
    recent_log = []
    if os.path.isfile(log_file):
        try:
            with open(log_file) as f:
                lines = f.readlines()
            recent_log = [l.rstrip("\n") for l in lines[-100:]]
        except Exception:
            pass

    status_data["recentLog"] = recent_log
    return jsonify(status_data)


@app.route("/api/workflow/<run_id>/log", methods=["GET"])
def get_workflow_log(run_id: str):
    """Returns the full log for a workflow run as plain text."""
    if not re.match(r'^[a-zA-Z0-9_\-]+$', run_id):
        abort(400)
    log_file = os.path.join(WF_LOG_DIR, f"{run_id}.log")
    if not os.path.isfile(log_file):
        abort(404)
    return send_file(log_file, mimetype="text/plain")


@app.route("/api/workflow/<run_id>/abort", methods=["POST"])
def abort_workflow_run(run_id: str):
    """Kill the workflow runner process for this run."""
    if not re.match(r'^[a-zA-Z0-9_\-]+$', run_id):
        abort(400)
    proc = _wf_procs.get(run_id)
    killed = False
    if proc:
        try:
            proc.terminate()
            killed = True
        except Exception as e:
            print(f"[workflow] Abort run={run_id}  pid={proc.pid}  error={e}")
    # Mark as aborted in status file
    stat_file = os.path.join(WF_LOG_DIR, f"{run_id}.status.json")
    if os.path.isfile(stat_file):
        try:
            with open(stat_file) as f:
                d = json.load(f)
            d["status"]  = "aborted"
            d["endedAt"] = datetime.now(timezone.utc).isoformat() + "Z"
            with open(stat_file, "w") as f:
                json.dump(d, f, indent=2)
        except Exception:
            pass
    pid = proc.pid if proc else None
    print(f"[workflow] Abort run={run_id}  pid={pid}  killed={killed}")
    return jsonify({"runId": run_id, "killed": killed})


# ── MCP server process management ─────────────────────────────────────────────
# The MCP server (tools/mcp-server.py) is a separate long-running process that
# exposes the bridge to AI/reporting tools over the Model Context Protocol.
# These endpoints let the dashboard start/stop it (Settings → MCP Server) and
# read its status, so operators can turn the integration on or off at will.
# Only the network transports (streamable-http / sse) are launchable from here —
# stdio needs a client attached to its stdin and is used via `python3
# tools/mcp-server.py` directly (e.g. Claude Desktop).
_mcp_proc = None                 # subprocess.Popen | None
_mcp_meta: dict = {}             # {transport, host, port, startedAt, actingAs}
_mcp_log_file = os.path.join(WF_LOG_DIR, "mcp-server.log")
_mcp_lock = threading.Lock()


def _mcp_server_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-server.py")


def _mcp_running() -> bool:
    return _mcp_proc is not None and _mcp_proc.poll() is None


def _supervise_mcp(proc, log_fd) -> None:
    """Reap the MCP process when it exits (avoids zombies) and close its log."""
    try:
        proc.wait()
    finally:
        try:
            log_fd.close()
        except Exception:
            pass
        print(f"[mcp] server exited  rc={proc.returncode}")


def _mcp_status_payload() -> dict:
    tail = []
    if os.path.isfile(_mcp_log_file):
        try:
            with open(_mcp_log_file, errors="replace") as f:
                tail = [l.rstrip("\n") for l in f.readlines()[-40:]]
        except Exception:
            pass
    running = _mcp_running()
    host = _mcp_meta.get("host")
    port = _mcp_meta.get("port")
    transport = _mcp_meta.get("transport")
    endpoint = None
    if running and host and port:
        # streamable-http serves at /mcp; sse serves at /sse
        path = "/mcp" if transport == "streamable-http" else "/sse"
        shown_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        endpoint = f"http://{shown_host}:{port}{path}"
    return {
        "running":   running,
        "available": os.path.isfile(_mcp_server_path()),
        "pid":       _mcp_proc.pid if running else None,
        "transport": transport,
        "host":      host,
        "port":      port,
        "endpoint":  endpoint,
        "actingAs":  _mcp_meta.get("actingAs"),
        "startedAt": _mcp_meta.get("startedAt"),
        "logTail":   tail,
    }


@app.route("/api/mcp/status", methods=["GET"])
def mcp_status():
    """Report whether the MCP server subprocess is running, plus its endpoint
    and the tail of its log."""
    return jsonify(_mcp_status_payload())


@app.route("/api/mcp/start", methods=["POST"])
def mcp_start():
    """Start the MCP server as a background subprocess (network transport only).
    Body: { transport?: "streamable-http"|"sse", host?, port? }.
    It is pointed back at this bridge and authenticated as the calling account."""
    err = _require_admin()
    if err:
        return err
    global _mcp_proc, _mcp_meta
    data = request.json or {}
    transport = data.get("transport") or "streamable-http"
    if transport not in ("streamable-http", "sse"):
        return jsonify({"error": "transport must be 'streamable-http' or 'sse' "
                                 "(stdio is launched directly, not from the UI)"}), 400
    host = data.get("host") or "0.0.0.0"
    try:
        port = int(data.get("port") or 8787)
    except (TypeError, ValueError):
        return jsonify({"error": "port must be a number"}), 400

    server_path = _mcp_server_path()
    if not os.path.isfile(server_path):
        return jsonify({"error": f"mcp-server.py not found at {server_path}"}), 500

    with _mcp_lock:
        if _mcp_running():
            return jsonify({"error": "MCP server already running",
                            **_mcp_status_payload()}), 409

        # Point the MCP server back at this bridge and hand it a token so it acts
        # as the calling account (falls back to the static token / any active one).
        env = os.environ.copy()
        env["GUIAX_BRIDGE_URL"] = f"http://127.0.0.1:{os.environ.get('PORT', '5000')}"
        tok = _token_from_request() or os.environ.get("GUI_AX_STATIC_TOKEN", "")
        if not tok and _active_tokens:
            tok = next(iter(_active_tokens))
        if tok:
            env["GUIAX_TOKEN"] = tok

        acting_as = None
        store = load_store()
        caller = _caller_user(store)
        if caller:
            acting_as = caller.get("username")

        os.makedirs(WF_LOG_DIR, exist_ok=True)
        try:
            log_fd = open(_mcp_log_file, "wb")
            proc = subprocess.Popen(
                ["python3", server_path,
                 "--transport", transport, "--host", host, "--port", str(port)],
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                close_fds=True,
                env=env,
            )
        except Exception as e:
            return jsonify({"error": f"failed to start MCP server: {e}"}), 500

        _mcp_proc = proc
        _mcp_meta = {
            "transport": transport,
            "host":      host,
            "port":      port,
            "actingAs":  acting_as,
            "startedAt": datetime.now(timezone.utc).isoformat() + "Z",
        }
        threading.Thread(target=_supervise_mcp, args=(proc, log_fd), daemon=True).start()
        print(f"[mcp] started  pid={proc.pid}  transport={transport}  {host}:{port}")

    return jsonify({"message": f"MCP server started (pid {proc.pid}).",
                    **_mcp_status_payload()})


@app.route("/api/mcp/stop", methods=["POST"])
def mcp_stop():
    """Stop the running MCP server subprocess."""
    err = _require_admin()
    if err:
        return err
    global _mcp_proc
    with _mcp_lock:
        if not _mcp_running():
            _mcp_proc = None
            return jsonify({"message": "MCP server was not running",
                            **_mcp_status_payload()})
        pid = _mcp_proc.pid
        try:
            _mcp_proc.terminate()
            try:
                _mcp_proc.wait(timeout=5)
            except Exception:
                _mcp_proc.kill()
        except Exception as e:
            return jsonify({"error": f"failed to stop MCP server: {e}"}), 500
        _mcp_proc = None
        _mcp_meta.clear()
        print(f"[mcp] stopped  pid={pid}")
    return jsonify({"message": "MCP server stopped", **_mcp_status_payload()})


# ── User / Team / Invite management ──────────────────────────────────────────
# Data is stored inside the existing JSON store under keys:
#   store["users"]   — list of user dicts
#   store["teams"]   — list of team dicts
#   store["invites"] — list of invite dicts
#
# Passwords are stored as SHA-256 hex digests.  Not bcrypt, but fine for a
# single-instance recon dashboard where the real security boundary is the
# network perimeter.

import hashlib

def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def _check_pw(password: str, hashed: str) -> bool:
    return secrets.compare_digest(_hash_pw(password), hashed)

# Alias for instructions compatibility
def _verify_pw(pw: str, hashed: str) -> bool:
    return _check_pw(pw, hashed)

# ── Persistent side-car stores (users.json, projects.json, user_workflows.json) ─
# DATA_DIR is the directory that also holds the main store.
DATA_DIR = os.path.dirname(os.path.abspath(STORE_PATH))

USERS_STORE          = os.path.join(DATA_DIR, "users.json")
PROJECTS_STORE       = os.path.join(DATA_DIR, "projects.json")
USER_WORKFLOWS_STORE = os.path.join(DATA_DIR, "user_workflows.json")


def _load_json_file(path: str, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _save_json_file(path: str, data) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_users():
    """Load the users sidecar file (dict keyed by username)."""
    return _load_json_file(USERS_STORE, {})


def save_users(users: dict) -> None:
    _save_json_file(USERS_STORE, users)


def load_projects():
    """Load the projects sidecar file (dict keyed by token)."""
    return _load_json_file(PROJECTS_STORE, {})


def save_projects(projects: dict) -> None:
    _save_json_file(PROJECTS_STORE, projects)


def load_user_workflows():
    """Load per-user workflows (dict keyed by username -> list of workflow dicts)."""
    return _load_json_file(USER_WORKFLOWS_STORE, {})


def save_user_workflows(wf: dict) -> None:
    _save_json_file(USER_WORKFLOWS_STORE, wf)

def _get_users(store):
    return store.setdefault("users", [])

def _get_teams(store):
    return store.setdefault("teams", [])

def _get_invites(store):
    return store.setdefault("invites", [])

def _require_admin():
    """Return 403 if the caller is not an admin.  Returns None when OK."""
    store = load_store()
    token = _token_from_request()

    # The static env-var token is always admin-level regardless of user records
    static = os.environ.get("GUI_AX_STATIC_TOKEN", "")
    if static and token and secrets.compare_digest(token, static):
        return None

    # Find the user associated with this token
    caller = next(
        (u for u in _get_users(store) if u.get("token") == token),
        None,
    )
    if caller is None:
        # Fall back: if no users exist yet the legacy single-user admin is caller
        if not _get_users(store):
            return None
        return jsonify({"error": "forbidden"}), 403
    if caller.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    return None

def _caller_user(store):
    """Return the AppUser dict for the current request's token, or None."""
    token = _token_from_request()
    return next((u for u in _get_users(store) if u.get("token") == token), None)


def _get_caller_project_tokens(store):
    """Return None for admin/legacy (sees all), or a set of allowed project tokens.

    An empty set means the caller is a regular user with no projects assigned.
    """
    # Static env-var token is always admin-level
    static = os.environ.get("GUI_AX_STATIC_TOKEN", "")
    token = _token_from_request()
    if static and token and secrets.compare_digest(token, static):
        return None

    caller = _caller_user(store)
    if caller is None:
        return None  # no user record = legacy single-user mode

    if caller.get("role") == "admin":
        return None  # admin sees everything

    # Merge project tokens from both the store list and the users.json sidecar
    allowed = set(caller.get("projects") or [])
    sidecar = load_users().get(caller.get("username", ""), {})
    allowed.update(sidecar.get("projects") or [])
    return allowed


def _ensure_admin_user():
    """Bootstrap the admin user from env-vars if the users list is empty.
    Also re-registers any persisted user tokens into _active_tokens so
    existing sessions survive a bridge restart."""
    store = load_store()
    users = _get_users(store)

    # Re-hydrate active tokens from persisted user records
    for u in users:
        t = u.get("token")
        if t:
            _active_tokens.add(t)

    if users:
        return  # already bootstrapped

    if not AUTH_PASSWORD:
        return

    admin = {
        "id":           secrets.token_hex(8),
        "username":     AUTH_USERNAME,
        "email":        "",
        "role":         "admin",
        "teams":        [],
        "createdAt":    datetime.now(timezone.utc).isoformat(),
        "lastLogin":    None,
        "active":       True,
        "passwordHash": _hash_pw(AUTH_PASSWORD),
        "token":        None,
    }
    users.append(admin)
    store["users"] = users
    save_store(store)


# ── Patch auth_login to also issue/persist token on the user record ────────────

_original_auth_login = None  # will be set after the existing route is defined

def _update_user_token_and_last_login(username: str, token: str):
    """After a successful login, store the token on the matching user record."""
    store = load_store()
    users = _get_users(store)
    changed = False
    for u in users:
        if u.get("username") == username:
            u["token"] = token
            u["lastLogin"] = datetime.now(timezone.utc).isoformat()
            changed = True
            break
    if changed:
        store["users"] = users
        save_store(store)


# ── /api/users ────────────────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
def list_users():
    err = _require_admin()
    if err:
        return err
    store = load_store()
    # Strip passwordHash and token before sending
    safe = [{k: v for k, v in u.items() if k not in ("passwordHash", "token")}
            for u in _get_users(store)]
    return jsonify(safe)


@app.route("/api/users", methods=["POST"])
def create_user():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")
    email    = (data.get("email") or "").strip()
    role     = data.get("role", "user")

    if not username:
        return jsonify({"error": "username is required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if role not in ("admin", "user"):
        role = "user"

    store = load_store()
    users = _get_users(store)
    if any(u["username"] == username for u in users):
        return jsonify({"error": "username already exists"}), 409

    new_user = {
        "id":           secrets.token_hex(8),
        "username":     username,
        "email":        email,
        "role":         role,
        "teams":        [],
        "createdAt":    datetime.now(timezone.utc).isoformat(),
        "lastLogin":    None,
        "active":       True,
        "passwordHash": _hash_pw(password),
        "token":        None,
    }
    users.append(new_user)
    store["users"] = users
    save_store(store)
    safe = {k: v for k, v in new_user.items() if k not in ("passwordHash", "token")}
    return jsonify(safe), 201


@app.route("/api/users/me", methods=["GET"])
def get_me():
    store = load_store()
    user = _caller_user(store)
    if user is None:
        # Legacy single-user mode — synthesise a response
        return jsonify({
            "id": "admin",
            "username": AUTH_USERNAME,
            "email": "",
            "role": "admin",
            "teams": [],
            "createdAt": None,
            "lastLogin": None,
            "active": True,
        })
    safe = {k: v for k, v in user.items() if k not in ("passwordHash", "token")}
    return jsonify(safe)


@app.route("/api/users/me/prefs", methods=["GET"])
def get_my_prefs():
    store = load_store()
    user = _caller_user(store)
    username = user["username"] if user else AUTH_USERNAME
    users_file = load_users()
    prefs = users_file.get(username, {}).get("prefs", {})
    return jsonify(prefs)


@app.route("/api/users/me/prefs", methods=["PATCH"])
def patch_my_prefs():
    store = load_store()
    user = _caller_user(store)
    username = user["username"] if user else AUTH_USERNAME
    data = request.get_json(silent=True) or {}
    users_file = load_users()
    rec = users_file.setdefault(username, {})
    prefs = rec.setdefault("prefs", {})
    prefs.update(data)
    save_users(users_file)
    return jsonify({"ok": True, "prefs": prefs})


@app.route("/api/users/me/password", methods=["PUT"])
def change_my_password():
    store = load_store()
    data = request.get_json(silent=True) or {}
    current_pw = data.get("currentPassword", "")
    new_pw     = data.get("newPassword", "")

    if len(new_pw) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    user = _caller_user(store)
    if user is None:
        # Legacy mode — compare against env var password
        if not AUTH_PASSWORD or not secrets.compare_digest(current_pw, AUTH_PASSWORD):
            return jsonify({"error": "Current password is incorrect"}), 403
        return jsonify({"ok": True, "note": "legacy mode — restart bridge to apply env password change"})

    if not _check_pw(current_pw, user.get("passwordHash", "")):
        return jsonify({"error": "Current password is incorrect"}), 403

    users = _get_users(store)
    for u in users:
        if u["id"] == user["id"]:
            u["passwordHash"] = _hash_pw(new_pw)
            break
    store["users"] = users
    save_store(store)
    return jsonify({"ok": True})


@app.route("/api/users/<user_id>", methods=["PATCH"])
def update_user(user_id):
    err = _require_admin()
    if err:
        return err
    store = load_store()
    users = _get_users(store)
    user = next((u for u in users if u["id"] == user_id), None)
    if user is None:
        return jsonify({"error": "user not found"}), 404

    data = request.get_json(silent=True) or {}
    if "role" in data and data["role"] in ("admin", "user"):
        user["role"] = data["role"]
    if "teams" in data and isinstance(data["teams"], list):
        user["teams"] = data["teams"]
    if "email" in data:
        user["email"] = (data["email"] or "").strip()
    if "active" in data:
        user["active"] = bool(data["active"])

    store["users"] = users
    save_store(store)
    safe = {k: v for k, v in user.items() if k not in ("passwordHash", "token")}
    return jsonify(safe)


@app.route("/api/users/<user_id>/password", methods=["PUT"])
def reset_user_password(user_id):
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    new_pw = data.get("newPassword", "")
    if len(new_pw) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    store = load_store()
    users = _get_users(store)
    user = next((u for u in users if u["id"] == user_id), None)
    if user is None:
        return jsonify({"error": "user not found"}), 404

    user["passwordHash"] = _hash_pw(new_pw)
    # Invalidate existing token so the user must log in again
    user["token"] = None
    store["users"] = users
    save_store(store)
    return jsonify({"ok": True})


@app.route("/api/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    err = _require_admin()
    if err:
        return err
    store = load_store()
    users = _get_users(store)
    before = len(users)
    store["users"] = [u for u in users if u["id"] != user_id]
    if len(store["users"]) == before:
        return jsonify({"error": "user not found"}), 404
    save_store(store)
    return jsonify({"ok": True})


# ── /api/teams ────────────────────────────────────────────────────────────────

@app.route("/api/teams", methods=["GET"])
def list_teams():
    store = load_store()
    return jsonify(_get_teams(store))


@app.route("/api/teams", methods=["POST"])
def create_team():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    store = load_store()
    teams = _get_teams(store)
    if any(t["name"] == name for t in teams):
        return jsonify({"error": "team name already exists"}), 409

    team = {
        "id":          secrets.token_hex(8),
        "name":        name,
        "description": (data.get("description") or "").strip(),
        "targetIds":   [],
        "memberIds":   [],
        "createdAt":   datetime.now(timezone.utc).isoformat(),
    }
    teams.append(team)
    store["teams"] = teams
    save_store(store)
    return jsonify(team), 201


@app.route("/api/teams/<team_id>", methods=["DELETE"])
def delete_team(team_id):
    err = _require_admin()
    if err:
        return err
    store = load_store()
    teams = _get_teams(store)
    before = len(teams)
    store["teams"] = [t for t in teams if t["id"] != team_id]
    if len(store["teams"]) == before:
        return jsonify({"error": "team not found"}), 404
    save_store(store)
    return jsonify({"ok": True})


# ── /api/invites ──────────────────────────────────────────────────────────────

@app.route("/api/invites", methods=["GET"])
def list_invites():
    err = _require_admin()
    if err:
        return err
    store = load_store()
    return jsonify(_get_invites(store))


@app.route("/api/invites/my", methods=["GET"])
def my_invites():
    """Return invites visible to the current user (admin sees all, user sees none by default)."""
    store = load_store()
    user = _caller_user(store)
    if user and user.get("role") == "admin":
        return jsonify(_get_invites(store))
    return jsonify([])


@app.route("/api/invites", methods=["POST"])
def create_invite():
    err = _require_admin()
    if err:
        return err
    data     = request.get_json(silent=True) or {}
    team_id  = data.get("teamId", "")
    max_uses = int(data.get("maxUses", 5))
    expiry_d = int(data.get("expiryDays", 7))

    store = load_store()
    team  = next((t for t in _get_teams(store) if t["id"] == team_id), None)
    if team is None:
        return jsonify({"error": "team not found"}), 404

    caller = _caller_user(store)
    created_by = caller["username"] if caller else AUTH_USERNAME

    from datetime import timedelta
    invite = {
        "id":         secrets.token_hex(8),
        "token":      secrets.token_urlsafe(24),
        "teamId":     team_id,
        "teamName":   team["name"],
        "createdBy":  created_by,
        "expiresAt":  (datetime.now(timezone.utc) + timedelta(days=expiry_d)).isoformat(),
        "usedBy":     None,
        "usedAt":     None,
        "maxUses":    max_uses,
        "useCount":   0,
    }
    invites = _get_invites(store)
    invites.append(invite)
    store["invites"] = invites
    save_store(store)
    return jsonify(invite), 201


@app.route("/api/invites/accept", methods=["POST"])
def accept_invite():
    data  = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    # Strip full URL down to just the token
    if "/" in token:
        token = token.rstrip("/").split("/")[-1]

    if not token:
        return jsonify({"error": "token is required"}), 400

    store   = load_store()
    invites = _get_invites(store)
    invite  = next((i for i in invites if i["token"] == token), None)

    if invite is None:
        return jsonify({"error": "invite not found"}), 404
    if invite["expiresAt"]:
        try:
            exp = datetime.fromisoformat(invite["expiresAt"].replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return jsonify({"error": "invite has expired"}), 410
        except Exception:
            pass  # malformed date — allow through rather than blocking
    if invite["useCount"] >= invite["maxUses"]:
        return jsonify({"error": "invite has reached its maximum uses"}), 410

    # Add caller to the team
    teams = _get_teams(store)
    for t in teams:
        if t["id"] == invite["teamId"]:
            if _caller_user(store) and _caller_user(store)["id"] not in t["memberIds"]:
                t["memberIds"].append(_caller_user(store)["id"])
            break

    # Update invite counters
    invite["useCount"] += 1
    caller = _caller_user(store)
    if caller:
        invite["usedBy"] = caller["username"]
        invite["usedAt"] = datetime.now(timezone.utc).isoformat()
        # Also add team to user's teams list
        users = _get_users(store)
        for u in users:
            if u["id"] == caller["id"] and invite["teamId"] not in u["teams"]:
                u["teams"].append(invite["teamId"])
        store["users"] = users

    store["teams"]   = teams
    store["invites"] = invites
    save_store(store)
    return jsonify({"ok": True, "teamName": invite["teamName"]})


@app.route("/api/invites/<invite_id>", methods=["DELETE"])
def revoke_invite(invite_id):
    err = _require_admin()
    if err:
        return err
    store = load_store()
    invites = _get_invites(store)
    before = len(invites)
    store["invites"] = [i for i in invites if i["id"] != invite_id]
    if len(store["invites"]) == before:
        return jsonify({"error": "invite not found"}), 404
    save_store(store)
    return jsonify({"ok": True})


# ── Patch login to persist token on user record ───────────────────────────────
# We wrap app.view_functions["auth_login"] after it's been registered so we can
# call the original handler and then side-effect the user store.

_orig_login = app.view_functions.get("auth_login")

def _patched_login():
    resp = _orig_login()
    # Flask can return (response, status) or just response
    body = resp[0] if isinstance(resp, tuple) else resp
    try:
        payload = body.get_json()
        if payload and payload.get("ok") and payload.get("token"):
            _update_user_token_and_last_login(
                request.get_json(silent=True).get("username", ""),
                payload["token"],
            )
    except Exception:
        pass
    return resp

if _orig_login:
    app.view_functions["auth_login"] = _patched_login


# ── Target enrichment: notes + tags ──────────────────────────────────────────

@app.route("/api/targets/<path:tid>", methods=["PATCH"])
def patch_target(tid):
    """Update mutable target fields: notes, tags, falsePositiveVulnIds."""
    store = load_store()
    target = next((t for t in store.get("targets", []) if t.get("id") == tid), None)
    if not target:
        abort(404)
    body = request.get_json(silent=True) or {}
    for field in ("notes", "tags", "falsePositiveVulnIds"):
        if field in body:
            target[field] = body[field]
    save_store(store)
    return jsonify(target)


# ── CVE enrichment (NVD API v2 + CVEProject/cvelistV5) ────────────────────────

_CVE_CACHE: dict = {}           # in-memory: cve_id → result dict
_CVE_DISK_CACHE_FILE = os.path.join(DATA_DIR, "cve_cache.json")
_CVE_DISK_TTL = 7 * 24 * 3600  # 7 days on disk

import urllib.request as _ureq
import urllib.error as _uerr


def _cve_disk_load():
    try:
        with open(_CVE_DISK_CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _cve_disk_save(cache: dict):
    try:
        with open(_CVE_DISK_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass


def _cvelistv5_path(cve_id: str) -> str:
    """Return the raw GitHub URL for the CVE JSON in CVEProject/cvelistV5."""
    parts = cve_id.split("-")
    year = parts[1]
    num = int(parts[2])
    dir_name = f"{num // 1000}xxx"
    return (
        f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
        f"/cves/{year}/{dir_name}/{cve_id}.json"
    )


def _fetch_cvelistv5(cve_id: str) -> dict:
    """Fetch raw CVE JSON from CVEProject/cvelistV5 on GitHub. Returns {} on failure."""
    try:
        url = _cvelistv5_path(cve_id)
        req = _ureq.Request(url, headers={"User-Agent": "gui-ax/1.0"})
        with _ureq.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def _parse_cvelistv5(raw: dict) -> dict:
    """Extract PoC refs, KEV status, affected products from a cvelistV5 JSON."""
    if not raw:
        return {}

    containers = raw.get("containers", {})
    cna = containers.get("cna", {})
    adp_list = containers.get("adp", []) or []

    # Description (prefer English)
    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            desc = d.get("value", "")
            break

    # CVSS — try v3.1 first, then v3.0, then v4.0
    cvss = None
    for metric in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if key in metric:
                m = metric[key]
                cvss = {
                    "baseScore":    m.get("baseScore"),
                    "baseSeverity": m.get("baseSeverity"),
                    "vectorString": m.get("vectorString"),
                }
                break
        if cvss:
            break

    # References — keep all but tag the interesting ones
    all_refs = []
    poc_refs = []
    exploit_tags = {"exploit", "exploit-code", "exploit_code", "proof-of-concept", "poc", "technical-description"}
    for ref in cna.get("references", []):
        url = ref.get("url", "")
        tags = [t.lower() for t in (ref.get("tags") or [])]
        entry = {"url": url, "tags": tags, "name": ref.get("name", "")}
        all_refs.append(entry)
        # Mark as PoC if tagged or URL pattern matches GitHub PoC repos
        if any(t in exploit_tags for t in tags):
            poc_refs.append(entry)
        elif "github.com" in url.lower() and any(k in url.lower() for k in ["poc", "exploit", "cve-"]):
            poc_refs.append(entry)

    # Affected products (limit for UI)
    affected = []
    for a in cna.get("affected", [])[:6]:
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        versions = [
            v.get("version", "")
            for v in (a.get("versions") or [])
            if v.get("status") == "affected"
        ][:5]
        affected.append({"vendor": vendor, "product": product, "versions": versions})

    # CISA KEV / ADP enrichment
    kev = False
    exploitation = None
    for adp in adp_list:
        title = adp.get("title", "")
        for metric in adp.get("metrics", []) or []:
            other = metric.get("other", {})
            if other.get("type", "").lower() == "kev":
                kev = True
            if other.get("type", "").lower() == "ssvc":
                for opt in other.get("content", {}).get("options", []):
                    if "Exploitation" in opt:
                        exploitation = opt["Exploitation"]
        # Also collect ADP references for PoC
        for ref in adp.get("references", []) or []:
            url = ref.get("url", "")
            tags = [t.lower() for t in (ref.get("tags") or [])]
            entry = {"url": url, "tags": tags, "name": ref.get("name", "")}
            if any(t in exploit_tags for t in tags):
                if entry not in poc_refs:
                    poc_refs.append(entry)

    return {
        "description":   desc,
        "cvss":          cvss,
        "references":    all_refs,
        "pocRefs":       poc_refs,
        "affected":      affected,
        "kev":           kev,
        "exploitation":  exploitation,
        "published":     raw.get("cveMetadata", {}).get("datePublished", ""),
    }


def _build_cve_result(cve_id: str) -> dict:
    """Fetch from NVD (CVSS/description) and cvelistV5 (PoC refs/KEV), merge."""
    result: dict = {"id": cve_id}

    # ── NVD for CVSS + base description ──────────────────────────────────────
    try:
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = _ureq.Request(nvd_url, headers={"User-Agent": "gui-ax/1.0"})
        with _ureq.urlopen(req, timeout=10) as resp:
            nvd_data = json.loads(resp.read())
        items = nvd_data.get("vulnerabilities", [])
        if items:
            cve_data = items[0].get("cve", {})
            metrics = cve_data.get("metrics", {})
            cvss_v3 = None
            for m in metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []):
                cvss_v3 = m.get("cvssData", {})
                break
            result["description"]    = next(
                (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), "")
            result["cvssV3Score"]    = cvss_v3.get("baseScore")    if cvss_v3 else None
            result["cvssV3Severity"] = cvss_v3.get("baseSeverity") if cvss_v3 else None
            result["cvssV3Vector"]   = cvss_v3.get("vectorString") if cvss_v3 else None
            result["published"]      = cve_data.get("published", "")
            result["lastModified"]   = cve_data.get("lastModified", "")
            result["references"]     = [r.get("url") for r in cve_data.get("references", [])[:8]]
    except Exception:
        pass

    # ── CVEProject/cvelistV5 for PoC refs, KEV, affected, richer description ─
    v5_raw = _fetch_cvelistv5(cve_id)
    v5 = _parse_cvelistv5(v5_raw)
    if v5:
        # Prefer v5 description if we got nothing from NVD
        if not result.get("description") and v5.get("description"):
            result["description"] = v5["description"]
        # Prefer v5 CVSS if NVD gave nothing
        if not result.get("cvssV3Score") and v5.get("cvss"):
            c = v5["cvss"]
            result["cvssV3Score"]    = c.get("baseScore")
            result["cvssV3Severity"] = c.get("baseSeverity")
            result["cvssV3Vector"]   = c.get("vectorString")
        result["pocRefs"]      = v5.get("pocRefs", [])
        result["kev"]          = v5.get("kev", False)
        result["exploitation"] = v5.get("exploitation")
        result["affected"]     = v5.get("affected", [])
        # Merge v5 references (tags) with NVD plain URLs
        v5_urls = {r["url"] for r in v5.get("references", [])}
        existing_urls = set(result.get("references", []))
        extra_refs = [
            r for r in v5.get("references", [])
            if r["url"] not in existing_urls
        ]
        result["referencesTagged"] = v5.get("references", [])
        # Add any URLs that weren't in NVD
        for r in extra_refs:
            if r["url"] not in existing_urls:
                result.setdefault("references", []).append(r["url"])
    else:
        result.setdefault("pocRefs", [])
        result.setdefault("kev", False)
        result.setdefault("affected", [])
        result.setdefault("referencesTagged", [])

    return result


@app.route("/api/cve/<cve_id>", methods=["GET"])
def get_cve(cve_id):
    """Fetch CVE details from NVD + CVEProject/cvelistV5, merged. Persistent disk cache."""
    cve_id = cve_id.upper().strip()
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        return jsonify({"error": "invalid CVE id"}), 400

    # In-memory cache hit
    if cve_id in _CVE_CACHE:
        return jsonify(_CVE_CACHE[cve_id])

    # Disk cache hit (survives restarts)
    import time as _time
    disk = _cve_disk_load()
    entry = disk.get(cve_id, {})
    if entry and _time.time() - entry.get("_ts", 0) < _CVE_DISK_TTL:
        _CVE_CACHE[cve_id] = entry["data"]
        return jsonify(entry["data"])

    try:
        result = _build_cve_result(cve_id)
        if not result.get("description") and not result.get("cvssV3Score"):
            return jsonify({"error": "CVE not found in NVD or cvelistV5"}), 404
        _CVE_CACHE[cve_id] = result
        disk[cve_id] = {"_ts": _time.time(), "data": result}
        _cve_disk_save(disk)
        return jsonify(result)
    except _uerr.URLError as e:
        return jsonify({"error": f"Network unreachable: {e}"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cve/batch", methods=["POST"])
def get_cve_batch():
    """Fetch multiple CVEs at once (max 30). Used by inventory cards."""
    import time as _time
    import concurrent.futures as _cf

    body = request.get_json(silent=True) or {}
    ids = [c.upper().strip() for c in body.get("ids", [])
           if re.match(r'^CVE-\d{4}-\d+$', c.strip(), re.IGNORECASE)]
    ids = list(dict.fromkeys(ids))[:30]  # dedup + limit

    disk = _cve_disk_load()
    now = _time.time()
    results: dict = {}
    to_fetch: list = []

    for cid in ids:
        if cid in _CVE_CACHE:
            results[cid] = _CVE_CACHE[cid]
            continue
        entry = disk.get(cid, {})
        if entry and now - entry.get("_ts", 0) < _CVE_DISK_TTL:
            _CVE_CACHE[cid] = entry["data"]
            results[cid] = entry["data"]
        else:
            to_fetch.append(cid)

    def _fetch_one(cid):
        try:
            return cid, _build_cve_result(cid)
        except Exception:
            return cid, None

    if to_fetch:
        with _cf.ThreadPoolExecutor(max_workers=5) as pool:
            for cid, data in pool.map(_fetch_one, to_fetch):
                if data and (data.get("description") or data.get("cvssV3Score")):
                    _CVE_CACHE[cid] = data
                    disk[cid] = {"_ts": now, "data": data}
                    results[cid] = data
        _cve_disk_save(disk)

    return jsonify(results)


# ── SearchSploit (offline Exploit-DB search) ──────────────────────────────────

_SEARCHSPLOIT_CACHE: dict = {}  # query → parsed results, in-memory


@app.route("/api/searchsploit/<path:query>", methods=["GET"])
def get_searchsploit(query):
    """Look up public exploits for a query (CVE id, product name, ...) via the
    local searchsploit CLI (offline Exploit-DB database). Results cached
    in-memory for the bridge lifetime."""
    query = query.strip()
    if not query:
        return jsonify({"error": "empty query"}), 400
    if query in _SEARCHSPLOIT_CACHE:
        return jsonify(_SEARCHSPLOIT_CACHE[query])
    binary = shutil.which("searchsploit")
    if not binary:
        return jsonify({"error": "searchsploit is not installed on the bridge host"}), 503
    try:
        proc = subprocess.run(
            [binary, "--json", query],
            capture_output=True, text=True, timeout=15,
        )
        data = json.loads(proc.stdout or "{}")
        results = [
            {
                "title":    r.get("Title", ""),
                "path":     r.get("Path", ""),
                "type":     r.get("Type", ""),
                "platform": r.get("Platform", ""),
                "date":     r.get("Date_Published", ""),
                "codes":    r.get("Codes", ""),
            }
            for r in data.get("RESULTS_EXPLOIT", [])[:10]
        ]
        result = {"query": query, "results": results}
        _SEARCHSPLOIT_CACHE[query] = result
        return jsonify(result)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "searchsploit timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AI analysis (Ollama / Claude) ─────────────────────────────────────────────

def _ollama_url() -> str:
    # Default: Mac Ollama accessed from inside Docker via host.docker.internal.
    # Override with OLLAMA_URL env var to point at LiteLLM or a remote Ollama.
    return os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434").rstrip("/")


def _ollama_reachable() -> bool:
    import urllib.request as _ureq
    try:
        with _ureq.urlopen(f"{_ollama_url()}/api/tags", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


@app.route("/api/ai/status", methods=["GET"])
def ai_status():
    """Return which AI providers are configured / reachable.
    Does NOT require auth so the Settings tab can show status before login."""
    return jsonify({
        "claude": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
        "claudeModel": os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001"),
        "ollama": _ollama_reachable(),
        "ollamaUrl": _ollama_url(),
        "ollamaModel": os.environ.get("OLLAMA_MODEL", "llama3.2"),
    })


@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    """Call an LLM to analyze security data.

    Body: { "prompt": str, "provider": "auto"|"ollama"|"claude" }
    Returns: { "response": str, "provider": str, "model": str }

    "auto" prefers Ollama (local, private) then Claude, then 400.
    """
    import urllib.request as _ureq
    import urllib.error as _uerr

    data = request.get_json(force=True) or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400

    provider = (data.get("provider") or "auto").lower()
    claude_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    if provider == "auto":
        if _ollama_reachable():
            provider = "ollama"
        elif claude_key:
            provider = "claude"
        else:
            return jsonify({
                "error": "No AI provider available. Start Ollama or set ANTHROPIC_API_KEY."
            }), 400

    # ── Ollama (local) ─────────────────────────────────────────────────────────
    if provider == "ollama":
        model = os.environ.get("OLLAMA_MODEL", "llama3.2")
        url = f"{_ollama_url()}/api/generate"
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
        }).encode()
        req = _ureq.Request(
            url, data=payload,
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with _ureq.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read())
            return jsonify({
                "response": result.get("response", ""),
                "provider": "ollama",
                "model": model,
            })
        except _uerr.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return jsonify({"error": f"Ollama error {e.code}: {body}"}), 502
        except Exception as e:
            return jsonify({"error": f"Ollama request failed: {e}"}), 502

    # ── Claude (Anthropic API) ─────────────────────────────────────────────────
    if provider == "claude":
        if not claude_key:
            return jsonify({"error": "ANTHROPIC_API_KEY is not set"}), 400
        model = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
        payload = json.dumps({
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = _ureq.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key": claude_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            method="POST",
        )
        try:
            with _ureq.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
            return jsonify({
                "response": result["content"][0]["text"],
                "provider": "claude",
                "model": model,
            })
        except _uerr.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return jsonify({"error": f"Claude API error {e.code}: {body}"}), 502
        except Exception as e:
            return jsonify({"error": f"Claude request failed: {e}"}), 502

    return jsonify({"error": f"Unknown provider: {provider}"}), 400


# ── Cross-target findings / triage ────────────────────────────────────────────

@app.route("/api/findings", methods=["GET"])
def list_findings():
    """Aggregate vulnerabilities across all targets with dedup + filtering.

    Query params:
      severity        — filter: critical/high/medium/low/info
      target          — filter by target id
      projectToken    — filter to scans explicitly linked to this project token
                        (preferred over programPrefix; returns linkedScansCount in meta)
      programPrefix   — legacy: filter by programName prefix (e.g. "gw-acme-")
                        used as fallback when projectToken has no linked scans
      q               — free-text search in name or description
      fp              — include false positives: true/false (default false)
      limit           — max results to return (default 100, max 1000)
      offset          — skip this many results (for pagination)
    """
    from collections import defaultdict
    store            = load_store()
    severity_filter  = (request.args.get("severity") or "").lower()
    target_filter    = request.args.get("target", "")
    project_token    = (request.args.get("projectToken") or "").strip()
    program_prefix   = (request.args.get("programPrefix") or "").lower()
    q                = (request.args.get("q") or "").lower()
    include_fp       = request.args.get("fp", "false").lower() == "true"
    limit            = min(int(request.args.get("limit", 100)), 5000)
    offset           = max(int(request.args.get("offset", 0)), 0)

    all_targets = store.get("targets", [])
    linked_scans_count = None  # None = filter not by project; 0 = project set but no linked scans

    # Project-token filter: match targets whose programName is in the project's
    # linked_scans list (stored on the project record, not on scan records).
    if project_token:
        linked_scan_names = _get_linked_scan_names(project_token)
        linked_scans_count = len(linked_scan_names)
        if linked_scan_names:
            all_targets = [
                t for t in all_targets
                if (t.get("programName") or "").lower() in linked_scan_names
            ]
        else:
            # No scans linked yet — return empty so the UI can show a message
            all_targets = []
    elif program_prefix:
        # Legacy fallback: match by client-slug prefix
        all_targets = [
            t for t in all_targets
            if (t.get("programName") or "").lower().startswith(program_prefix)
        ]

    # First pass: for each finding key collect every unique domain that has it,
    # so we can show "multiple (N)" in the UI.  Use domain as the dedup key
    # (not targetId) so that targets sharing an id but having different domains
    # — like the multi-domain nuclei_targets entries — are all counted.
    key_domains: dict = defaultdict(list)
    for t in all_targets:
        domain = t.get("domain", t.get("id", ""))
        for v in (t.get("vulnerabilities") or []):
            sev = (v.get("severity") or "").upper()
            dk = f"{(v.get('name') or '').lower()}|{sev}"
            if domain not in key_domains[dk]:
                key_domains[dk].append(domain)

    findings: list = []
    seen_hashes: set = set()

    for t in all_targets:
        tid = t.get("id", "")
        if target_filter and tid != target_filter:
            continue
        fp_ids = set(t.get("falsePositiveVulnIds", []))
        prog = t.get("programName", "")
        for v in (t.get("vulnerabilities") or []):
            vid = v.get("id", "")
            if not include_fp and vid in fp_ids:
                continue
            sev = (v.get("severity") or "").upper()
            if severity_filter and sev.lower() != severity_filter:
                continue
            name = (v.get("name") or "").lower()
            desc = (v.get("description") or "").lower()
            if q and q not in name and q not in desc:
                continue
            dedup_key = f"{name}|{sev}"
            is_dupe = dedup_key in seen_hashes
            seen_hashes.add(dedup_key)
            findings.append({
                **v,
                "targetId":        tid,
                "targetDomain":    t.get("domain", tid),
                "programName":     prog,
                "affectedDomains": key_domains.get(dedup_key, []),
                "isFalsePositive": vid in fp_ids,
                "isDuplicate":     is_dupe,
            })

    total = len(findings)
    page_slice = findings[offset:offset + limit]
    resp = {"findings": page_slice, "total": total}
    if linked_scans_count is not None:
        resp["linkedScansCount"] = linked_scans_count
    return jsonify(resp)


@app.route("/api/findings/mark-fp", methods=["POST"])
def mark_finding_fp():
    """Mark or unmark a vulnerability as a false positive on a specific target."""
    body  = request.get_json(silent=True) or {}
    tid   = body.get("targetId")
    vid   = body.get("vulnId")
    is_fp = bool(body.get("isFalsePositive", True))
    if not tid or not vid:
        return jsonify({"error": "targetId and vulnId are required"}), 400
    store  = load_store()
    target = next((t for t in store.get("targets", []) if t.get("id") == tid), None)
    if not target:
        abort(404)
    fp_ids = set(target.get("falsePositiveVulnIds", []))
    if is_fp:
        fp_ids.add(vid)
    else:
        fp_ids.discard(vid)
    target["falsePositiveVulnIds"] = list(fp_ids)
    save_store(store)
    return jsonify({"ok": True, "falsePositiveVulnIds": target["falsePositiveVulnIds"]})


# ── Wordlist catalog ──────────────────────────────────────────────────────────

def _classify_wordlist(fname: str, dirpath: str) -> str:
    needle = (fname + " " + dirpath).lower()
    if any(k in needle for k in ("subdomain", "dns", "sublist", "resolvers", "alterations")):
        return "subdomains"
    if any(k in needle for k in ("director", "/dir", "path", "content", "web", "raft", "dirbuster")):
        return "directories"
    if any(k in needle for k in ("username", "user", "login", "account")):
        return "usernames"
    if any(k in needle for k in ("password", "pass", "rockyou", "credential", "common-credential")):
        return "passwords"
    if any(k in needle for k in ("fuzz", "param", "payload", "xss", "sqli", "lfi")):
        return "fuzzing"
    if any(k in needle for k in ("api", "endpoint", "route", "swagger", "graphql")):
        return "api"
    return "general"


@app.route("/api/wordlists", methods=["GET"])
def list_wordlists():
    """Scan common wordlist locations on the host and return a catalog."""
    common_paths = [
        "/usr/share/wordlists",
        "/usr/share/seclists",
        os.path.expanduser("~/wordlists"),
        os.path.expanduser("~/SecLists"),
        os.path.expanduser("~/.axiom/wordlists"),
        "/opt/wordlists",
        "/opt/SecLists",
    ]
    result: list = []
    max_files = int(request.args.get("limit", "300"))

    for base in common_paths:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if len(result) >= max_files:
                    break
                if fname.startswith("."):
                    continue
                ext = os.path.splitext(fname)[1].lower()
                if ext not in (".txt", ".lst", ".list", ""):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    sz = os.path.getsize(fpath)
                    line_count = 0
                    if sz < 30 * 1024 * 1024:  # skip line count for files > 30 MB
                        with open(fpath, "r", errors="ignore") as f:
                            for _ in f:
                                line_count += 1
                    result.append({
                        "path":      fpath,
                        "name":      fname,
                        "category":  _classify_wordlist(fname, root),
                        "size":      sz,
                        "lineCount": line_count,
                        "relPath":   os.path.relpath(fpath, base),
                    })
                except Exception:
                    pass

    result.sort(key=lambda x: (x["category"], x["name"]))
    return jsonify({"wordlists": result, "total": len(result)})


# ── Risk scoring ──────────────────────────────────────────────────────────────

@app.route("/api/targets/<path:tid>/risk", methods=["GET"])
def get_target_risk(tid):
    """Compute a risk score (0-100) for a target based on its vulnerability profile."""
    store  = load_store()
    target = next((t for t in store.get("targets", []) if t.get("id") == tid), None)
    if not target:
        abort(404)
    vulns   = target.get("vulnerabilities") or []
    fp_ids  = set(target.get("falsePositiveVulnIds", []))
    # Severity weights (Rekono-inspired)
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
    raw = sum(
        weights.get((v.get("severity") or "").upper(), 0)
        for v in vulns if v.get("id") not in fp_ids
    )
    # Open ports add marginal weight
    port_count = sum(
        len(s.get("ports", []))
        for s in (target.get("subdomains") or [])
    )
    raw += port_count * 0.1
    score = min(100, round(raw, 1))
    if score >= 75:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"
    return jsonify({"targetId": tid, "score": score, "level": level,
                    "vulnCount": len(vulns), "portCount": port_count})


# ── /api/admin — project-aware user management ───────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    """Admin-only: list all users in the sidecar users.json (not the env-var admin)."""
    err = _require_admin()
    if err:
        return err
    users = load_users()
    # Strip password hashes; return list of safe dicts
    safe = [
        {k: v for k, v in u.items() if k != "passwordHash"}
        for u in users.values()
    ]
    return jsonify(safe)


@app.route("/api/admin/users", methods=["POST"])
def admin_create_update_user():
    """Admin-only: create or update a user in users.json."""
    err = _require_admin()
    if err:
        return err
    data         = request.get_json(silent=True) or {}
    username     = (data.get("username") or "").strip()
    password     = data.get("password")  # optional — omit to keep existing
    role         = data.get("role", "user")
    projects     = data.get("projects", [])
    display_name = (data.get("display_name") or "").strip()

    if not username:
        return jsonify({"error": "username is required"}), 400
    if role not in ("admin", "user"):
        role = "user"

    users = load_users()
    existing = users.get(username, {})

    pw_hash = existing.get("passwordHash")
    if password:
        pw_hash = _hash_pw(password)
    elif not pw_hash:
        return jsonify({"error": "password is required for new users"}), 400

    users[username] = {
        "username":     username,
        "display_name": display_name or existing.get("display_name", ""),
        "role":         role,
        "projects":     projects,
        "passwordHash": pw_hash,
        "createdAt":    existing.get("createdAt", datetime.now(timezone.utc).isoformat()),
    }
    save_users(users)
    safe = {k: v for k, v in users[username].items() if k != "passwordHash"}
    status = 200 if existing else 201
    return jsonify(safe), status


@app.route("/api/admin/users/<username>", methods=["DELETE"])
def admin_delete_user(username):
    """Admin-only: delete a user from users.json."""
    err = _require_admin()
    if err:
        return err
    users = load_users()
    if username not in users:
        return jsonify({"error": "user not found"}), 404
    del users[username]
    save_users(users)
    return jsonify({"ok": True})


@app.route("/api/admin/users/<username>/token", methods=["POST"])
def admin_get_user_token(username):
    """Admin-only: generate (or refresh) an active auth token for a named user.

    Used by Ghostwriter to obtain a per-user token for iframe autoauth so each
    consultant sees their own data instead of the shared admin account.
    auth_status resolves identity via store["users"], so we mirror the user
    there from users.json if needed so the token resolves to the right person.
    """
    err = _require_admin()
    if err:
        return err

    store = load_store()
    users = _get_users(store)
    user = next((u for u in users if u.get("username") == username), None)

    if user is None:
        # Fall back to users.json (populated by admin_create_update_user / Ghostwriter sync)
        users_file = load_users()
        if username in users_file:
            file_rec = users_file[username]
            user = {
                "username":     username,
                "role":         file_rec.get("role", "user"),
                "projects":     file_rec.get("projects", []),
                "display_name": file_rec.get("display_name", username),
            }
            users.append(user)
            store["users"] = users
        else:
            return jsonify({"error": f"user '{username}' not found"}), 404

    token = secrets.token_hex(32)
    _active_tokens.add(token)
    user["token"] = token
    store["users"] = users
    save_store(store)

    return jsonify({"ok": True, "token": token, "username": username})


@app.route("/api/admin/projects", methods=["POST"])
def admin_register_project():
    """Admin-only: register a project in projects.json."""
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    token         = (data.get("token") or "").strip()
    name          = (data.get("name") or "").strip()
    client        = (data.get("client") or "").strip()
    project_type  = (data.get("project_type") or "").strip()
    ghostwriter_id = data.get("ghostwriter_id")

    if not token:
        return jsonify({"error": "token is required"}), 400
    if not name:
        return jsonify({"error": "name is required"}), 400

    projects = load_projects()
    projects[token] = {
        "token":          token,
        "name":           name,
        "client":         client,
        "project_type":   project_type,
        "ghostwriter_id": ghostwriter_id,
        "createdAt":      datetime.now(timezone.utc).isoformat(),
    }
    save_projects(projects)
    return jsonify(projects[token]), 201


@app.route("/api/admin/projects", methods=["GET"])
def admin_list_projects():
    """Admin-only: list all registered projects."""
    err = _require_admin()
    if err:
        return err
    projects = load_projects()
    return jsonify(list(projects.values()))


@app.route("/api/projects/mine", methods=["GET"])
def my_projects():
    """Authenticated: return projects the current user can access.
    Admin → all projects; regular user → only their assigned project tokens."""
    store = load_store()
    caller = _caller_user(store)

    projects = load_projects()

    if caller is None or caller.get("role") == "admin":
        # Legacy admin or env-var admin: return all projects
        return jsonify(list(projects.values()))

    # Regular user: filter to their assigned tokens
    allowed_tokens = set(caller.get("projects") or [])

    # Also check the sidecar users.json (admin may manage users there)
    sidecar_users = load_users()
    sidecar_record = sidecar_users.get(caller.get("username", ""), {})
    allowed_tokens.update(sidecar_record.get("projects", []))

    result = [p for token, p in projects.items() if token in allowed_tokens]
    return jsonify(result)


@app.route("/api/projects", methods=["POST"])
def create_project():
    """Authenticated: create a project and auto-assign it to the caller."""
    store = load_store()
    caller = _caller_user(store)

    data = request.get_json(silent=True) or {}
    name         = (data.get("name") or "").strip()
    client       = (data.get("client") or "").strip()
    project_type = (data.get("project_type") or "").strip()

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not client:
        return jsonify({"error": "client is required"}), 400

    slug  = re.sub(r"[^a-z0-9]+", "-", f"{client}-{name}".lower()).strip("-")[:28]
    token = f"{slug}-{secrets.token_hex(3)}"

    projects = load_projects()
    if token in projects:
        token = f"{slug}-{secrets.token_hex(4)}"

    username = caller.get("username") if caller else AUTH_USERNAME
    is_admin = (caller is None) or caller.get("role") == "admin"

    projects[token] = {
        "token":        token,
        "name":         name,
        "client":       client,
        "project_type": project_type,
        "ghostwriter_id": None,
        "createdAt":    datetime.now(timezone.utc).isoformat(),
        "createdBy":    username,
    }
    save_projects(projects)

    # Assign the new project token to the creating user (non-admins only)
    if not is_admin:
        sidecar = load_users()
        rec = sidecar.setdefault(username, {})
        if token not in rec.get("projects", []):
            rec.setdefault("projects", []).append(token)
            save_users(sidecar)

    return jsonify(projects[token]), 201


@app.route("/api/projects/<token>", methods=["DELETE"])
def delete_project(token):
    """Admin or project creator: delete a project."""
    store = load_store()
    caller = _caller_user(store)

    projects = load_projects()
    if token not in projects:
        return jsonify({"error": "not found"}), 404

    proj = projects[token]
    is_admin = (caller is None) or caller.get("role") == "admin"
    is_creator = caller and caller.get("username") == proj.get("createdBy")

    if not (is_admin or is_creator):
        return jsonify({"error": "forbidden"}), 403

    del projects[token]
    save_projects(projects)

    # Remove the token from all user assignments
    sidecar = load_users()
    changed = False
    for _u, rec in sidecar.items():
        if token in rec.get("projects", []):
            rec["projects"] = [t for t in rec["projects"] if t != token]
            changed = True
    if changed:
        save_users(sidecar)

    return jsonify({"ok": True})


@app.route("/api/projects/<token>", methods=["PATCH"])
def update_project(token):
    """Admin or project creator: update project name/client/type."""
    store = load_store()
    caller = _caller_user(store)

    projects = load_projects()
    if token not in projects:
        return jsonify({"error": "not found"}), 404

    proj = projects[token]
    is_admin = (caller is None) or caller.get("role") == "admin"
    is_creator = caller and caller.get("username") == proj.get("createdBy")

    if not (is_admin or is_creator):
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    if "name"         in data: proj["name"]         = (data["name"] or "").strip()
    if "client"       in data: proj["client"]       = (data["client"] or "").strip()
    if "project_type" in data: proj["project_type"] = (data["project_type"] or "").strip()

    projects[token] = proj
    save_projects(projects)
    return jsonify(proj)


@app.route("/api/projects/<token>/retag-targets", methods=["POST"])
def retag_project_targets(token):
    """Retag historical targets that were imported without a gw- programName.

    When a scan is launched from Ghostwriter the bridge labels the output file
    with the scan label (e.g. "gw-acme-c3-5").  If the scan completed while
    scans.json was empty (bridge restart) the importer falls back to the module
    name ("nuclei"), breaking the project filter.  This endpoint retroactively
    updates programName for those targets.

    Body:
      - domains: list of root domains that belong to this project
      - label:   the gw- label to assign (e.g. "gw-acme-c3-3")
    Only touches targets whose domain is in the list AND whose programName does
    NOT already start with "gw-".
    """
    projects = load_projects()
    if token not in projects:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(silent=True) or {}
    domains = [d.lower().strip() for d in (data.get("domains") or []) if d]
    label = (data.get("label") or "").strip()

    if not domains or not label:
        return jsonify({"error": "domains and label are required"}), 400

    domain_set = set(domains)
    store = load_store()
    targets = store.get("targets", [])

    updated = 0
    for t in targets:
        t_domain = (t.get("domain") or "").lower().strip()
        if t_domain in domain_set and not (t.get("programName") or "").startswith("gw-"):
            t["programName"] = label
            updated += 1

    if updated:
        store["targets"] = targets
        save_store(store)

    print(f"[retag-targets] token={token} label={label} updated={updated}")
    return jsonify({"updated": updated, "label": label})


# ── /api/workflows/user — per-user saved workflows ────────────────────────────

@app.route("/api/workflows/user", methods=["GET"])
def list_user_workflows():
    """Return workflows saved by the currently logged-in user."""
    store = load_store()
    caller = _caller_user(store)
    if caller is None:
        username = AUTH_USERNAME  # legacy single-user
    else:
        username = caller.get("username", "")

    wf_store = load_user_workflows()
    return jsonify(wf_store.get(username, []))


@app.route("/api/workflows/user", methods=["POST"])
def save_user_workflow():
    """Save a workflow for the current user.
    Body: {name, description, steps}
    Auto-generates id and sets owner to current username."""
    import uuid as _uuid
    store = load_store()
    caller = _caller_user(store)
    if caller is None:
        username = AUTH_USERNAME
    else:
        username = caller.get("username", "")

    data        = request.get_json(silent=True) or {}
    name        = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    steps       = data.get("steps", [])

    if not name:
        return jsonify({"error": "name is required"}), 400

    wf_store = load_user_workflows()
    user_wfs = wf_store.setdefault(username, [])

    new_wf = {
        "id":          str(_uuid.uuid4()),
        "name":        name,
        "description": description,
        "steps":       steps,
        "inputType":   data.get("inputType", "domains"),
        "tags":        data.get("tags", []),
        "difficulty":  data.get("difficulty", "medium"),
        "owner":       username,
        "created_at":  datetime.now(timezone.utc).isoformat(),
    }
    user_wfs.append(new_wf)
    save_user_workflows(wf_store)
    return jsonify(new_wf), 201


@app.route("/api/workflows/user/<wf_id>", methods=["DELETE"])
def delete_user_workflow(wf_id):
    """Delete a workflow owned by the current user."""
    store = load_store()
    caller = _caller_user(store)
    if caller is None:
        username = AUTH_USERNAME
    else:
        username = caller.get("username", "")

    wf_store = load_user_workflows()
    user_wfs = wf_store.get(username, [])
    before   = len(user_wfs)
    wf_store[username] = [w for w in user_wfs if w.get("id") != wf_id]
    if len(wf_store[username]) == before:
        return jsonify({"error": "workflow not found"}), 404
    save_user_workflows(wf_store)
    return jsonify({"ok": True})


# ── CVE Inventory Monitor ──────────────────────────────────────────────────────

INVENTORY_PATH = os.path.join(os.path.dirname(STORE_PATH), "inventory.json")

_inventory_lock   = threading.Lock()
_inventory_thread = None          # running background refresh thread
_inventory_progress = {"done": 0, "total": 0}


def _load_inventory() -> dict:
    try:
        with open(INVENTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"last_full_scan": None, "technologies": []}
    except Exception:
        return {"last_full_scan": None, "technologies": []}


def _save_inventory(inv: dict):
    os.makedirs(os.path.dirname(INVENTORY_PATH) or ".", exist_ok=True)
    tmp = INVENTORY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=2)
    os.replace(tmp, INVENTORY_PATH)


def _extract_technologies(store: dict) -> dict:
    """Extract product/version pairs from nuclei vulnerability findings.

    Returns {(product, version): {hostnames: set, programs: set}}.
    Only entries where a version can be determined are included, since
    versionless entries produce too many false positives in NVD queries.
    """
    import re as _re

    tech_map: dict = {}

    # Template ID prefixes/exact IDs that carry no useful version information
    _SKIP_PREFIXES = (
        "dns-", "rdap-", "internal-ip", "missing-sri",
        "waf-detect:", "dns-waf-detect:",
    )
    _SKIP_EXACT = {
        "waf-detect", "akamai-detect", "akamai-cache-detect", "bigip-detect",
        "spring-detect", "graphql-detect", "oauth2-detect", "oidc-detect",
        "smtp-detect", "dns-rebinding", "bigip-detect",
    }

    def _normalize_product(tid: str) -> str:
        t = tid.lower()
        if ":" in t:
            prefix, suffix = t.split(":", 1)
            if suffix == "version":
                # e.g. grafana-detect:version → grafana
                return _re.sub(r"[-_](detect|version|check|info)$", "", prefix).strip("-_")
            # e.g. waf-detect:nginxgeneric → nginx
            product = _re.sub(r"generic$", "", suffix)
            return _re.sub(r"[-_](waf|cdn|lb|firewall)$", "", product).strip("-_")
        return _re.sub(
            r"[-_](detect|version[-_]disclosure|disclosure|panel|"
            r"login|check|fingerprint|banner|info|identify).*$",
            "", t,
        ).strip("-_") or t

    def _extract_version(tid: str, raw: str) -> str:
        t = tid.lower()

        # OpenSSH banner: SSH-2.0-OpenSSH_7.4
        if "openssh" in t:
            m = _re.search(r"OpenSSH[_/](\d+\.\d+[\d.p]*)", raw, _re.IGNORECASE)
            if m:
                return m.group(1)

        # TLS: tls10 → 1.0, tls12 → 1.2, tls13 → 1.3
        if t == "tls-version":
            m = _re.search(r"tls(\d)(\d*)", raw, _re.IGNORECASE)
            if m:
                return f"{m.group(1)}.{m.group(2) or '0'}"

        # Generic: quoted brackets ["x.y.z"] at the end of rawContent
        for b in _re.findall(r'\["([^"]+)"\]', raw):
            if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", b):
                continue  # skip IPs
            if b.startswith("http") and "/" in b:
                continue  # skip URLs
            m = _re.search(r"^v?(\d+\.\d+[\.\d]*)", b)
            if m:
                return m.group(1)

        # Fallback: unquoted brackets [x.y.z] ignoring type/severity tokens
        _IGNORE = {"http", "tcp", "ssl", "dns", "info", "low", "medium",
                   "high", "critical", "unknown", tid.lower()}
        for b in _re.findall(r"\[([^\[\]\"]+)\]", raw):
            if b.lower() in _IGNORE:
                continue
            m = _re.search(r"^v?(\d+\.\d+[\.\d]*)", b)
            if m:
                return m.group(1)

        return ""

    for target in store.get("targets", []):
        prog = target.get("programName", "")
        domain = target.get("domain", target.get("id", ""))

        for v in (target.get("vulnerabilities") or []):
            vid = v.get("id", "")
            raw = v.get("rawContent", "")

            if any(vid.startswith(p) for p in _SKIP_PREFIXES):
                continue
            if vid in _SKIP_EXACT:
                continue

            product = _normalize_product(vid)
            version = _extract_version(vid, raw)
            if not version:
                continue

            # Clean host: strip protocol and path
            host = v.get("path", "") or domain
            host = _re.sub(r"^https?://", "", host).split("/")[0].split("?")[0]

            key = (product, version)
            if key not in tech_map:
                tech_map[key] = {"hostnames": set(), "programs": set()}
            tech_map[key]["hostnames"].add(host)
            if prog:
                tech_map[key]["programs"].add(prog)

    return tech_map


def _query_nvd(product: str, version: str, api_key: str = "") -> list:
    """Query the NVD CVE 2.0 API for a product/version combo.

    Paginates through all results (cap 500) so no CVEs are silently dropped.
    Rate limit: 5 req/30 s without key → 1.5 s inter-page; 50/30 s with key → 0.3 s.
    """
    import urllib.request, urllib.parse, urllib.error

    headers = {"User-Agent": "gui-ax-inventory/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    inter_page_delay = 0.3 if api_key else 1.5
    per_page         = 100
    all_cves         = []
    start_index      = 0

    def _parse_page(items, prev_scan=""):
        parsed = []
        for item in items:
            cve      = item.get("cve", {})
            cve_id   = cve.get("id", "")
            published = (cve.get("published") or "")[:10]
            desc_list = (cve.get("descriptions") or [])
            description = next(
                (d["value"] for d in desc_list if d.get("lang") == "en"), ""
            )[:400]

            metrics = cve.get("metrics", {})
            score, severity = 0.0, "UNKNOWN"
            for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if mkey in metrics and metrics[mkey]:
                    m = metrics[mkey][0].get("cvssData", {})
                    score    = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", m.get("vectorString", "UNKNOWN"))
                    break

            # CPE version check — flag unverified when no CPE match found
            cpe_match = False
            for cfg_node in cve.get("configurations", [{}]):
                for node in (
                    [cfg_node] if "cpeMatch" in cfg_node
                    else cfg_node.get("nodes", [])
                ):
                    for cpe_m in node.get("cpeMatch", []):
                        if version in cpe_m.get("criteria", ""):
                            cpe_match = True
                            break

            parsed.append({
                "id":          cve_id,
                "published":   published,
                "severity":    severity.upper() if isinstance(severity, str) else "UNKNOWN",
                "score":       round(float(score), 1),
                "description": description,
                "verified":    cpe_match,
            })
        return parsed

    while len(all_cves) < 500:
        params = urllib.parse.urlencode({
            "keywordSearch":  f"{product} {version}",
            "resultsPerPage": per_page,
            "startIndex":     start_index,
        })
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            print(f"[inventory] NVD query failed for {product}/{version}"
                  f" (startIndex={start_index}): {exc}")
            break

        items         = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        all_cves.extend(_parse_page(items))
        start_index += len(items)

        if not items or start_index >= total_results:
            break

        time.sleep(inter_page_delay)

    return all_cves


def _run_inventory_refresh():
    """Background thread: extract technologies, query NVD, persist inventory."""
    global _inventory_thread, _inventory_progress
    api_key = os.environ.get("NVD_API_KEY", "")
    delay   = 0.3 if api_key else 1.2    # conservative rate limiting

    try:
        prev_inv    = _load_inventory()
        prev_scan   = prev_inv.get("last_full_scan") or ""
        store       = load_store()
        tech_map    = _extract_technologies(store)
        items       = list(tech_map.items())

        _inventory_progress = {"done": 0, "total": len(items)}
        print(f"[inventory] Starting refresh: {len(items)} unique tech/version combos")

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        results = []

        for i, ((product, version), meta) in enumerate(items):
            cves = _query_nvd(product, version, api_key)
            for c in cves:
                c["is_new"] = prev_scan and c["published"] > prev_scan[:10]

            results.append({
                "product":      product,
                "version":      version,
                "hostnames":    sorted(meta["hostnames"]),
                "programs":     sorted(meta["programs"]),
                "cve_count":    len(cves),
                "max_severity": max((c["score"] for c in cves), default=0.0),
                "cves":         sorted(cves, key=lambda c: -c["score"]),
                "last_checked": now_iso,
            })
            _inventory_progress["done"] = i + 1
            time.sleep(delay)

        inventory = {
            "last_full_scan": now_iso,
            "technologies":   sorted(results, key=lambda r: -r["max_severity"]),
        }
        _save_inventory(inventory)
        print(f"[inventory] Refresh complete: {len(results)} entries saved")
    except Exception as exc:
        print(f"[inventory] Refresh failed: {exc}")
        import traceback as _tb
        _tb.print_exc()
    finally:
        _inventory_thread = None


@app.route("/api/inventory", methods=["GET"])
def get_inventory():
    """Return the full persisted inventory with optional project filter.

    ?projectToken=<token>    filter to technologies whose programs include
                              a scan name explicitly linked to this project.
    ?programPrefix=gw-acme- legacy fallback: match by programName prefix.
    """
    inv = _load_inventory()
    project_token = request.args.get("projectToken", "").strip()
    prefix = request.args.get("programPrefix", "").strip()
    linked_scans_count = None

    techs = inv.get("technologies", [])

    if project_token:
        linked_scan_names = _get_linked_scan_names(project_token)
        linked_scans_count = len(linked_scan_names)
        if linked_scan_names:
            techs = [
                t for t in techs
                if any(p.lower() in linked_scan_names for p in (t.get("programs") or []))
            ]
        else:
            techs = []
    elif prefix:
        techs = [
            t for t in techs
            if any(p.startswith(prefix) for p in (t.get("programs") or []))
        ]

    # Attach project labels so the frontend can show human-readable names
    try:
        all_projects = list(load_projects().values())
    except Exception:
        all_projects = []

    resp = {
        "last_full_scan": inv.get("last_full_scan"),
        "technologies": techs,
        "projects": [
            {"token": p.get("token"), "name": p.get("name"),
             "client": p.get("client")}
            for p in all_projects
        ],
    }
    if linked_scans_count is not None:
        resp["linkedScansCount"] = linked_scans_count
    return jsonify(resp)


@app.route("/api/inventory/refresh", methods=["POST"])
def start_inventory_refresh():
    """Trigger a background CVE refresh. Returns immediately."""
    global _inventory_thread
    with _inventory_lock:
        if _inventory_thread and _inventory_thread.is_alive():
            return jsonify({"status": "already_running"})
        _inventory_thread = threading.Thread(target=_run_inventory_refresh, daemon=True)
        _inventory_thread.start()
    return jsonify({"status": "started"})


@app.route("/api/inventory/status", methods=["GET"])
def get_inventory_status():
    """Return refresh status: running flag, progress, and last scan timestamp."""
    running = bool(_inventory_thread and _inventory_thread.is_alive())
    inv     = _load_inventory()
    prog    = _inventory_progress
    return jsonify({
        "running":        running,
        "last_full_scan": inv.get("last_full_scan"),
        "progress":       f"{prog['done']}/{prog['total']}" if running else None,
        "total_entries":  len(inv.get("technologies", [])),
    })


@app.route("/api/inventory/ai-analyze", methods=["POST"])
def inventory_ai_analyze():
    """Proxy a chunk of inventory data to an AI provider for analysis.

    Expects JSON body:
      {provider, api_key, model, base_url, system, messages, max_tokens}

    Returns {text} on success or {error} on failure.
    Supports providers: anthropic, openai, ollama.
    """
    import urllib.request as _urlreq
    import urllib.error   as _urlerr

    body      = request.json or {}
    provider  = body.get("provider", "anthropic")
    api_key   = body.get("api_key", "")
    model     = body.get("model", "")
    base_url  = body.get("base_url", "").rstrip("/")
    system    = body.get("system", "")
    messages  = body.get("messages", [])
    max_tok   = int(body.get("max_tokens", 1500))

    if not messages:
        return jsonify({"error": "no messages provided"}), 400

    try:
        if provider == "anthropic":
            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
            payload = {
                "model": model or "claude-opus-4-8",
                "max_tokens": max_tok,
                "system": system,
                "messages": messages,
            }
        elif provider == "openai":
            url = (base_url or "https://api.openai.com") + "/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            }
            msgs = ([{"role": "system", "content": system}] if system else []) + messages
            payload = {"model": model or "gpt-4o", "messages": msgs, "max_tokens": max_tok}
        elif provider == "ollama":
            url = (base_url or "http://localhost:11434") + "/api/chat"
            headers = {"Content-Type": "application/json"}
            msgs = ([{"role": "system", "content": system}] if system else []) + messages
            payload = {"model": model or "llama3", "messages": msgs, "stream": False}
        else:
            return jsonify({"error": f"unknown provider: {provider}"}), 400

        data = json.dumps(payload).encode()
        req  = _urlreq.Request(url, data=data, headers=headers, method="POST")
        with _urlreq.urlopen(req, timeout=90) as resp:
            result = json.loads(resp.read().decode())

        if provider == "anthropic":
            text = (result.get("content") or [{}])[0].get("text", "")
        elif provider == "openai":
            text = (result.get("choices") or [{}])[0].get("message", {}).get("content", "")
        elif provider == "ollama":
            text = result.get("message", {}).get("content", "")
        else:
            text = str(result)

        return jsonify({"text": text})

    except _urlerr.HTTPError as exc:
        err_body = exc.read().decode()
        return jsonify({"error": f"HTTP {exc.code}: {err_body}"}), 502
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


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

    # Back-fill human-readable scan names onto any existing gowitness targets
    patch_gowitness_names()

    # Bootstrap admin user from env-vars on first run
    _ensure_admin_user()

    # ── Start periodic background scanner ────────────────────────────────
    # Replaces the watchdog Observer so we never poll at the 1-second default
    # rate that PollingObserver uses on Docker/NFS volumes.
    watcher_thread = threading.Thread(target=_import_watcher_thread, daemon=True)
    watcher_thread.start()
    print(f"[watcher] Periodic import scan every {WATCHER_INTERVAL}s \n (set WATCHER_INTERVAL env to change) \n— or call GET /api/imports/scan to trigger immediately")

    print(f"Axiom bridge running on port {PORT}")
    print(f"  AXIOM_LS_PATH: {AXIOM_LS_PATH}")
    print(f"  AXIOM_TMP:     {AXIOM_TMP}")
    print(f"  STORE:         {STORE_PATH}")
    print(f"  IMPORTS:       {IMPORTS_PATH}")
    print(f"\n[watcher] ✓ Drop scan output files into imports/ — they will be picked up within {WATCHER_INTERVAL}s")
    print(f"{'='*70}\n")

    app.run(host="0.0.0.0", port=PORT)
