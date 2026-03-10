"""
importers/import_ffuf.py — parser for ffuf directory fuzzer output.

Handles:
  ffuf, ffuf_base, ffuz  — csv / json / jsonl / txt
  Results are stored as vulnerabilities with severity INFO.

Interface:
    HANDLES, detect_format, parse  (see base.py for contract)
"""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .base import extract_root_domain, load_store, save_store, PROCESSED_PATH

HANDLES: list[str] = ["ffuf", "ffuf_base", "ffuz"]


def detect_format(scanner: str, filename: str, content: str) -> str:
    fn = filename.lower()
    if fn.endswith(".csv"):
        return "csv"
    if fn.endswith(".jsonl") or fn.endswith(".ndjson"):
        return "jsonl"
    if fn.endswith(".json"):
        return "json"
    return "txt"


def parse(filepath, scanner: str, fmt: str, content: str, scan_name: str,
          targets: list, skip_move: bool = False) -> tuple[list, bool, bool]:
    filename = Path(filepath).name
    print(f"[ffuf] Processing '{scanner}' ({fmt.upper()}) — {filename}")

    found: list[dict] = _extract_results(fmt, content)
    print(f"[ffuf]   → {len(found)} results extracted")

    # Resolve target
    target_id   = scan_name
    target      = next((t for t in targets if t.get("id") == target_id), None)
    first_host  = next((f["host"] for f in found if f.get("host")), target_id)
    root_domain = extract_root_domain(first_host) if first_host != target_id else target_id
    changed     = False

    if not target:
        target = {
            "id":              target_id,
            "domain":          root_domain or target_id,
            "programName":     "ffuf Directory Scan",
            "status":          "COMPLETED",
            "subdomains":      [],
            "vulnerabilities": [],
            "totalPorts":      0,
            "sources":         [filename],
            "lastScanDate":    datetime.now(timezone.utc).isoformat(),
        }
        targets.append(target)
        changed = True
    else:
        if filename not in target.get("sources", []):
            target.setdefault("sources", []).append(filename)
            changed = True

    existing_paths = {v.get("path") for v in target.get("vulnerabilities", [])}
    added = 0
    for f in found:
        path = f.get("url") or ""
        if not path or path in existing_paths:
            continue
        target.setdefault("vulnerabilities", []).append({
            "id":          f"ffuf-{f.get('status', '200')}-{len(target.get('vulnerabilities', []))}",
            "name":        f"Directory Found: {path}",
            "description": f"Status: {f.get('status', '')}  Length: {f.get('length', '')}",
            "severity":    "INFO",
            "path":        path,
            "matched":     path,
            "type":        "directory-fuzzing",
        })
        changed = True
        existing_paths.add(path)
        added += 1

    print(f"[ffuf] ✓ {added} new findings")
    return targets, changed, False


# ── Format parsers ────────────────────────────────────────────────────────────

def _extract_results(fmt: str, content: str) -> list[dict]:
    results: list[dict] = []

    if fmt == "csv":
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                url    = row.get("url") or row.get("URL") or ""
                status = row.get("status_code") or row.get("status") or ""
                length = row.get("content_length") or row.get("length") or ""
                if url and "://" in url:
                    host = urlparse(url).netloc.split(":")[0]
                    results.append({"host": host, "url": url,
                                    "status": status, "length": length})
        except Exception as e:
            print(f"[ffuf] CSV parse error: {e}")

    elif fmt in ("json", "jsonl"):
        raw = content.strip()
        # Accept both jsonl and single-doc JSON (detect by first char)
        lines = raw.splitlines() if (fmt == "jsonl" or (raw.startswith("{") and "\n" in raw)) else [raw]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    url  = obj.get("url") or ""
                    host = obj.get("host") or ""
                    if url and "://" in url and not host:
                        host = urlparse(url).netloc.split(":")[0]
                    if host or url:
                        results.append({"host": host, "url": url,
                                        "status": str(obj.get("status", "")),
                                        "length": str(obj.get("length", ""))})
            except json.JSONDecodeError:
                continue

    else:  # txt
        for line in content.splitlines():
            line = line.strip()
            if line and "://" in line:
                host = urlparse(line).netloc.split(":")[0]
                results.append({"host": host, "url": line,
                                 "status": "", "length": ""})

    return results


# ── Standalone CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <ffuf_output_file> [scanner_type]")
        sys.exit(1)

    fp   = Path(sys.argv[1])
    sc   = sys.argv[2] if len(sys.argv) > 2 else "ffuf"
    cont = fp.read_text(encoding="utf-8", errors="replace")
    fmt  = detect_format(sc, fp.name, cont)
    sn   = fp.stem.split("-")[0] if "-" in fp.stem else fp.stem

    store = load_store()
    tgts  = store.get("targets", [])
    tgts, changed, _ = parse(fp, sc, fmt, cont, sn, tgts)

    if changed:
        store["targets"] = tgts
        save_store(store)
        os.makedirs(PROCESSED_PATH, exist_ok=True)
        shutil.move(str(fp), str(Path(PROCESSED_PATH) / fp.name))
        print(f"[ffuf] ✓ Saved and moved {fp.name}")
    else:
        print(f"[ffuf] No new data")
