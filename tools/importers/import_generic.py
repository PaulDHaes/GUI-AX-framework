"""
importers/import_generic.py — catch-all parser for unrecognised scanner output.

This module is NOT in HANDLES (it is never registered by name).
The importers registry falls back to it when no specific importer matches.

Tries to extract host/hostname/domain/ip/url/target/name fields from
JSON, JSONL, or plain-text lines.

Interface:
    detect_format, parse  (no HANDLES — used as fallback)
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .base import (extract_root_domain, load_store, save_store,
                   sanitize_domain, _find_target_for_host, PROCESSED_PATH)

# No HANDLES — this is the fallback module, not registered by scanner name.
HANDLES: list[str] = []


def detect_format(scanner: str, filename: str, content: str) -> str:
    fn = filename.lower()
    if fn.endswith(".jsonl") or fn.endswith(".ndjson"):
        return "jsonl"
    if fn.endswith(".json"):
        return "json"
    return "txt"


def parse(filepath, scanner: str, fmt: str, content: str, scan_name: str,
          targets: list, skip_move: bool = False) -> tuple[list, bool, bool]:
    filename = Path(filepath).name
    print(f"[generic] Processing '{scanner}' ({fmt.upper()}) — {filename}")

    items: list = _load_items(fmt, content)
    print(f"[generic] {len(items)} items parsed")

    if not items:
        return targets, False, False

    hosts: set[str] = set()
    for item in items:
        h = _extract_host(item)
        if h:
            hosts.add(h)

    hosts = {h for h in hosts if h and '.' in h and len(h) < 253}
    print(f"[generic] {len(hosts)} unique hosts extracted")
    if not hosts:
        return targets, False, False

    changed = False
    for host in sorted(hosts):
        root = extract_root_domain(host)
        target = _find_target_for_host(targets, host, root)
        if not target:
            target = {
                "id":              scan_name,
                "domain":          root or host,
                "programName":     scanner,
                "status":          "COMPLETED",
                "subdomains":      [],
                "vulnerabilities": [],
                "totalPorts":      0,
                "sources":         [filename],
                "lastScanDate":    datetime.now(timezone.utc).isoformat(),
            }
            targets.append(target)
            changed = True

        if filename not in target.get("sources", []):
            target.setdefault("sources", []).append(filename)
            changed = True

        existing = {s.get("hostname") for s in target.get("subdomains", [])}
        if host not in existing:
            target.setdefault("subdomains", []).append({
                "id": host, "hostname": host, "ip": "",
                "ports": [], "technologies": [], "location": "", "asn": "",
            })
            changed = True

    print(f"[generic] ✓ '{scanner}': {len(hosts)} hosts")
    return targets, changed, False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_items(fmt: str, content: str) -> list:
    items: list = []
    if fmt == "json":
        try:
            data = json.loads(content)
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("results", data.get("items", data.get("hosts", [data])))
        except json.JSONDecodeError:
            items = [l.strip() for l in content.splitlines() if l.strip()]
    elif fmt == "jsonl":
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                items.append(line)
    else:
        items = [l.strip() for l in content.splitlines() if l.strip()]
    return items


def _extract_host(item) -> str:
    if isinstance(item, dict):
        raw = (item.get("host") or item.get("hostname") or
               item.get("domain") or item.get("ip") or
               item.get("url") or item.get("target") or
               item.get("name") or "")
        if raw and "://" in raw:
            parsed = urlparse(raw)
            raw = parsed.netloc or raw
        return sanitize_domain(raw)
    elif isinstance(item, str):
        line = item.strip()
        if "://" in line:
            parsed = urlparse(line)
            line = parsed.netloc or line
        return sanitize_domain(line)
    return ""


# ── Standalone CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <scan_output_file> [scanner_name]")
        sys.exit(1)

    fp   = Path(sys.argv[1])
    sc   = sys.argv[2] if len(sys.argv) > 2 else "generic"
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
        print(f"[generic] ✓ Saved and moved {fp.name}")
    else:
        print(f"[generic] No new data")
