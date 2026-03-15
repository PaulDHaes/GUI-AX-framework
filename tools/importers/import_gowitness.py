"""
importers/import_gowitness.py — parser for GoWitness screenshots / web-probe tool.

Handles:
  gowitness — sqlite3 database (with optional screenshots/ folder) + json/jsonl/txt

Special behaviour:
  - For sqlite format: performs its own bundle move to processed/gowitness-<TS>/
    and returns file_moved=True so the bridge skips the default move.
  - Screenshots are served via /api/screenshots/<bundle_name>/ by the bridge.

Interface:
    HANDLES, detect_format, parse  (see base.py for contract)
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .base import extract_root_domain, load_store, save_store, PROCESSED_PATH

HANDLES: list[str] = ["gowitness"]


def detect_format(scanner: str, filename: str, content: str) -> str:
    fn = filename.lower()
    if fn.endswith(".sqlite3") or fn.endswith(".db"):
        return "sqlite"
    if fn.endswith(".jsonl") or fn.endswith(".ndjson"):
        return "jsonl"
    if fn.endswith(".json"):
        return "json"
    return "txt"


def parse(filepath, scanner: str, fmt: str, content: str, scan_name: str,
          targets: list, skip_move: bool = False) -> tuple[list, bool, bool]:
    filename = Path(filepath).name

    if fmt == "sqlite":
        return _parse_sqlite(filepath, filename, scan_name, targets, skip_move)
    else:
        return _parse_text(filepath, filename, fmt, content, scan_name, targets)


# ── SQLite bundle ─────────────────────────────────────────────────────────────

def _parse_sqlite(filepath, filename: str, scan_name: str,
                  targets: list, skip_move: bool) -> tuple[list, bool, bool]:
    import sqlite3
    import os, shutil

    print(f"[gowitness] Processing SQLITE database — {filename}")

    fp = Path(filepath)
    screenshots_src = fp.parent / "screenshots"
    has_screenshots = screenshots_src.is_dir()
    sc_count = len([f for f in screenshots_src.iterdir() if f.is_file()]) if has_screenshots else 0
    print(f"[gowitness] screenshots dir: {screenshots_src} (exists={has_screenshots}, count={sc_count})")

    ts          = datetime.utcnow().strftime("%m-%d_%H-%M-%S")
    bundle_name = f"gowitness-{ts}"
    bundle_dest = Path(PROCESSED_PATH) / bundle_name
    screenshots_dest = bundle_dest / "screenshots"

    def _candidate_fnames(raw_url):
        try:
            p = urlparse(raw_url)
            scheme = p.scheme or "http"
            host   = p.hostname or ""
            port   = p.port
            dflt   = 443 if scheme == "https" else 80
            eport  = port or dflt
            return [
                f"{scheme}---{host}-{eport}.jpeg",
                f"{scheme}---{host}.jpeg",
            ]
        except Exception:
            return []

    def _screenshot_url(raw_url):
        if not has_screenshots:
            return None
        for fname in _candidate_fnames(raw_url):
            if (screenshots_src / fname).exists():
                return f"/api/screenshots/{bundle_name}/screenshots/{fname}"
        return None

    # ── Read database ─────────────────────────────────────────────────────
    rows_data: list[dict] = []
    try:
        conn = sqlite3.connect(str(filepath))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        all_tables = [r[0] for r in cur.fetchall()]
        print(f"[gowitness] Tables: {all_tables}")

        data_table = next(
            (t for t in ("results", "urls", "screenshots") if t in all_tables), None
        )
        if not data_table:
            print(f"[gowitness] ✗ No recognised results table found")
            conn.close()
            return [], False, False

        cur.execute(f"PRAGMA table_info({data_table})")
        avail = {r[1] for r in cur.fetchall()}
        print(f"[gowitness] Using '{data_table}', columns: {sorted(avail)}")

        def _pick(*candidates):
            return next((c for c in candidates if c in avail), None)

        url_col    = _pick("url", "final_url")
        title_col  = _pick("title")
        code_col   = _pick("response_code", "status_code", "status")
        tech_col   = _pick("technologies")
        failed_col = _pick("failed")

        if not url_col:
            print(f"[gowitness] ✗ No URL column found in '{data_table}'")
            conn.close()
            return [], False, False

        select_cols = [c for c in [url_col, title_col, code_col, tech_col, failed_col] if c]
        cur.execute(f"SELECT {', '.join(select_cols)} FROM {data_table}")
        raw_rows = cur.fetchall()
        conn.close()
        print(f"[gowitness] Fetched {len(raw_rows)} rows")

        seen_hosts: set = set()
        for row in raw_rows:
            row = dict(zip(select_cols, row))
            raw_url = row.get(url_col) or ""
            if not raw_url:
                continue
            if failed_col and row.get(failed_col):
                continue
            p = urlparse(raw_url)
            host = p.netloc or raw_url
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)

            scheme   = (p.scheme or "http").lower()
            port_num = p.port or (443 if scheme == "https" else 80)

            techs = []
            if tech_col and row.get(tech_col):
                try:
                    tv = row[tech_col]
                    pt = json.loads(tv) if isinstance(tv, str) else tv
                    if isinstance(pt, list):
                        techs = [
                            (t.get("name") or str(t)) if isinstance(t, dict) else str(t)
                            for t in pt
                        ]
                except Exception:
                    pass

            rows_data.append({
                "hostname":   host,
                "url":        raw_url,
                "title":      (row.get(title_col) or "").strip() if title_col else "",
                "statusCode": int(row.get(code_col) or 0) if code_col else 0,
                "technologies": techs,
                "port":       port_num,
                "scheme":     scheme,
                "screenshot": _screenshot_url(raw_url),
            })

    except Exception as e:
        import traceback
        print(f"[gowitness] ✗ SQLite error: {e}")
        traceback.print_exc()
        return targets, False, False

    sc_linked = sum(1 for r in rows_data if r["screenshot"])
    print(f"[gowitness] Parsed {len(rows_data)} unique hosts, {sc_linked} with screenshots")

    # ── Find or create target ─────────────────────────────────────────────
    target_id = scan_name
    target = next((t for t in targets if t.get("id") == target_id), None)
    changed = False
    if not target:
        target = {
            "id":              target_id,
            "domain":          scan_name,
            "programName":     "GoWitness Scan",
            "status":          "COMPLETED",
            "subdomains":      [],
            "vulnerabilities": [],
            "totalPorts":      0,
            "sources":         [filename],
            "lastScanDate":    datetime.utcnow().isoformat() + "Z",
        }
        targets.append(target)
        changed = True
    else:
        if filename not in target.get("sources", []):
            target.setdefault("sources", []).append(filename)
            changed = True

    existing_subs = {s.get("hostname") for s in target.get("subdomains", [])}
    added = 0
    for r in rows_data:
        host = r["hostname"]
        if host in existing_subs:
            continue
        entry = {
            "id":           host,
            "hostname":     host,
            "url":          r["url"],
            "ip":           host.rsplit(":", 1)[0] if ":" in host else host,
            "ports":        [{"port": r["port"], "service": r["scheme"],
                               "banner": "", "isOpen": True}],
            "technologies": r["technologies"],
            "location":     "",
            "asn":          "",
        }
        if r["title"]:
            entry["title"] = r["title"]
        if r["statusCode"]:
            entry["statusCode"] = r["statusCode"]
        if r["screenshot"]:
            entry["screenshot"] = r["screenshot"]
        target.setdefault("subdomains", []).append(entry)
        changed = True
        added += 1

    print(f"[gowitness] ✓ Added {added} subdomain entries")

    # ── Bundle move: sqlite3 + screenshots/ → processed/gowitness-TS/ ────
    file_moved = False
    if not skip_move:
        try:
            os.makedirs(bundle_dest, exist_ok=True)
            db_dest = bundle_dest / filename
            shutil.move(str(filepath), str(db_dest))
            print(f"[gowitness] ✓ {filename} → {db_dest}")
            if has_screenshots:
                shutil.move(str(screenshots_src), str(screenshots_dest))
                moved = len([f for f in screenshots_dest.iterdir() if f.is_file()]) \
                        if screenshots_dest.exists() else 0
                print(f"[gowitness] ✓ screenshots/ → {screenshots_dest} ({moved} files)")
            file_moved = True
        except Exception as e:
            import traceback
            print(f"[gowitness] ✗ Bundle move error: {e}")
            traceback.print_exc()

    return targets, changed, file_moved


# ── JPEG-only folder (no sqlite DB) ──────────────────────────────────────────

def parse_jpeg_folder(folder_path, scan_name: str, targets: list, display_name: str = None) -> tuple[list, bool]:
    """Import a gowitness output folder that contains only JPEG/PNG screenshots
    (no sqlite DB).  Parses filenames like ``scheme---host-port.jpeg`` to
    reconstruct URLs and creates/updates a target record.

    ``scan_name`` is used as the unique target ID (should be the folder name so
    each scan gets its own row).  ``display_name`` is the human-readable label
    shown in the UI (e.g. the scan name from scans.json); falls back to
    ``scan_name`` if not provided.

    Moves the folder to processed/ when done.
    Returns (targets, changed).
    """
    import os, shutil

    folder_path = Path(folder_path)
    image_exts  = {".jpeg", ".jpg", ".png"}
    jpeg_files  = [f for f in folder_path.iterdir()
                   if f.is_file() and f.suffix.lower() in image_exts]

    if not jpeg_files:
        print(f"[gowitness] JPEG folder {folder_path.name} has no image files — skipping")
        return targets, False

    ts          = datetime.now(timezone.utc).strftime("%m-%d_%H-%M-%S")
    bundle_name = f"gowitness-{ts}"
    bundle_dest = Path(PROCESSED_PATH) / bundle_name
    bundle_dest.mkdir(parents=True, exist_ok=True)

    rows_data: list[dict] = []
    for jf in jpeg_files:
        stem = jf.stem  # e.g. "https---apple.com-443"
        m = re.match(r"^(https?)---(.+?)-(\d+)$", stem)
        if m:
            scheme, host, port = m.group(1), m.group(2), int(m.group(3))
        else:
            m2 = re.match(r"^(https?)---(.+)$", stem)
            if m2:
                scheme, host = m2.group(1), m2.group(2)
                port = 443 if scheme == "https" else 80
            else:
                # Unknown format — just copy the file and skip
                shutil.copy2(str(jf), str(bundle_dest / jf.name))
                continue

        dest_fname = jf.name
        shutil.copy2(str(jf), str(bundle_dest / dest_fname))

        rows_data.append({
            "hostname":     host,
            "url":          f"{scheme}://{host}",
            "title":        "",
            "statusCode":   0,
            "technologies": [],
            "port":         port,
            "scheme":       scheme,
            "screenshot":   f"/api/screenshots/{bundle_name}/{dest_fname}",
        })

    if not rows_data:
        print(f"[gowitness] JPEG folder {folder_path.name}: no parseable filenames")
        return targets, False

    # Upsert target record
    # scan_name is the unique bundle ID (full folder name); display_name is the
    # human-readable label (from scans.json) shown in the UI.
    _label = display_name or scan_name
    target_id = scan_name
    target    = next((t for t in targets if t.get("id") == target_id), None)
    changed   = False

    if not target:
        target = {
            "id":              target_id,
            "domain":          _label,
            "programName":     "GoWitness Scan",
            "status":          "COMPLETED",
            "subdomains":      [],
            "vulnerabilities": [],
            "totalPorts":      0,
            "sources":         [folder_path.name],
            "lastScanDate":    datetime.now(timezone.utc).isoformat(),
        }
        targets.append(target)
        changed = True
    else:
        if folder_path.name not in target.get("sources", []):
            target.setdefault("sources", []).append(folder_path.name)
            changed = True

    existing_hosts = {s.get("hostname") for s in target.get("subdomains", [])}
    added = 0
    for r in rows_data:
        if r["hostname"] in existing_hosts:
            continue
        target["subdomains"].append({
            "id":           r["hostname"],
            "hostname":     r["hostname"],
            "url":          r["url"],
            "ip":           "",
            "ports":        [{"port": r["port"], "service": r["scheme"],
                               "banner": "", "isOpen": True}],
            "technologies": [],
            "location":     "",
            "asn":          "",
            "screenshot":   r["screenshot"],
            "statusCode":   r["statusCode"],
            "title":        r["title"],
        })
        existing_hosts.add(r["hostname"])
        changed = True
        added += 1

    print(f"[gowitness] JPEG folder {folder_path.name}: added {added} entries → bundle {bundle_name}/")

    # Save store
    if changed:
        store = load_store()
        store_targets = store.get("targets", [])
        store_targets = [t for t in store_targets if t.get("id") != target_id]
        store_targets.append(target)
        store["targets"] = store_targets
        save_store(store)

    # Move source folder to processed/
    try:
        dest = Path(PROCESSED_PATH) / folder_path.name
        if dest.exists():
            import shutil as _sh
            _sh.rmtree(str(dest))
        shutil.move(str(folder_path), str(dest))
        print(f"[gowitness] ✓ Moved {folder_path.name}/ → processed/")
    except Exception as e:
        print(f"[gowitness] ✗ Could not move {folder_path.name}: {e}")

    return targets, changed


# ── JSON / JSONL / TXT ────────────────────────────────────────────────────────

def _parse_text(filepath, filename: str, fmt: str, content: str,
                scan_name: str, targets: list) -> tuple[list, bool, bool]:
    print(f"[gowitness] Processing {fmt.upper()} — {filename}")
    screenshot_data: list = []

    if fmt == "json":
        try:
            results = json.loads(content)
            if isinstance(results, list):
                screenshot_data = results
            elif isinstance(results, dict):
                screenshot_data = results.get("screenshots", [results])
        except json.JSONDecodeError:
            print(f"[gowitness] ✗ Failed to parse JSON")
            return targets, False, False

    elif fmt == "jsonl":
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                screenshot_data.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    else:  # txt — one URL per line
        for line in content.splitlines():
            line = line.strip()
            if line:
                screenshot_data.append({"url": line})

    print(f"[gowitness] Parsed {len(screenshot_data)} entries")

    subdomains_list: list[str] = []
    for entry in screenshot_data:
        if isinstance(entry, dict):
            url = entry.get("url") or entry.get("final_url") or entry.get("input") or ""
            if url:
                parsed = urlparse(url)
                host = parsed.netloc or url
                if host:
                    subdomains_list.append(host)
        elif isinstance(entry, str):
            subdomains_list.append(entry)

    # Upsert target
    target_id = scan_name
    target = next((t for t in targets if t.get("id") == target_id), None)
    changed = False

    root_domain = extract_root_domain(subdomains_list[0]) if subdomains_list else None
    if not target:
        target = {
            "id":              target_id,
            "domain":          root_domain or target_id,
            "programName":     "GoWitness Scan",
            "status":          "COMPLETED",
            "subdomains":      [],
            "vulnerabilities": [],
            "totalPorts":      0,
            "sources":         [filename],
            "lastScanDate":    datetime.utcnow().isoformat() + "Z",
        }
        targets.append(target)
        changed = True
    else:
        if filename not in target.get("sources", []):
            target.setdefault("sources", []).append(filename)
            changed = True

    existing_subs = {s.get("hostname") for s in target.get("subdomains", [])}
    added = 0
    for sub in subdomains_list:
        if sub not in existing_subs:
            target.setdefault("subdomains", []).append({
                "id": sub, "hostname": sub, "ip": "",
                "ports": [], "technologies": [], "location": "", "asn": "",
            })
            changed = True
            added += 1

    print(f"[gowitness] ✓ Added {added} subdomains")
    return targets, changed, False


# ── Standalone CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <gowitness.db|results.json> [scanner_type]")
        sys.exit(1)

    fp = Path(sys.argv[1])
    sc = "gowitness"

    if fp.suffix.lower() in (".db", ".sqlite3"):
        cont = b""
        fmt  = "sqlite"
    else:
        cont = fp.read_text(encoding="utf-8", errors="replace")
        fmt  = detect_format(sc, fp.name, cont)

    sn    = fp.stem.split("-")[0] if "-" in fp.stem else fp.stem
    store = load_store()
    tgts  = store.get("targets", [])
    tgts, changed, file_moved = parse(fp, sc, fmt, cont, sn, tgts)

    if changed:
        store["targets"] = tgts
        save_store(store)
        print(f"[gowitness] ✓ Saved store")
    if not file_moved and changed:
        os.makedirs(PROCESSED_PATH, exist_ok=True)
        shutil.move(str(fp), str(Path(PROCESSED_PATH) / fp.name))
        print(f"[gowitness] ✓ Moved {fp.name} to processed/")
    if not changed:
        print(f"[gowitness] No new data")
