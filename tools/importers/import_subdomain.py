"""
importers/import_subdomain.py — parser for all subdomain-enumeration tools.

Handles tools that produce a plain list of hostnames / subdomains:
  amass, dnsx, assetfinder, subfinder, findomain, shuffledns, puredns,
  massdns, dnsgen, crobat, ctfr, gobuster, github-subdomains,
  github-endpoints, cero, cngo, hakrevdns, dnsvalidator, dnscewl,
  sublist3r, chaos, knockpy, aiodnsbrute, altdns, altdns, anubis,
  bbot (subdomain mode), … and amass JSON format.

Interface (same for every importer):
    HANDLES   : list[str]  — scanner names routed here
    detect_format(scanner, filename, content) -> str
    parse(filepath, scanner, fmt, content, scan_name, targets,
          skip_move=False) -> (targets, changed, file_moved)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .base import (
    extract_root_domain,
    load_store,
    make_subdomain_entry,
    save_store,
    sanitize_domain,
    PROCESSED_PATH,
)

# ── Scanner names handled here ───────────────────────────────────────────────

HANDLES: list[str] = [
    "amass", "dnsx", "assetfinder", "subfinder", "findomain",
    "shuffledns", "puredns", "massdns", "dnsgen", "crobat", "ctfr",
    "gobuster", "github-subdomains", "github-endpoints", "cero", "cngo",
    "hakrevdns", "dnsvalidator", "dnscewl", "sublist3r", "chaos",
    "knockpy", "aiodnsbrute", "altdns", "anubis", "bbot",
]


# ── Format detection ─────────────────────────────────────────────────────────

def detect_format(scanner: str, filename: str, content: str) -> str:
    fn = filename.lower()
    if fn.endswith(".jsonl") or fn.endswith(".ndjson"):
        return "jsonl"
    if fn.endswith(".json"):
        return "json"
    return "txt"


# ── Parser ───────────────────────────────────────────────────────────────────

def parse(filepath, scanner: str, fmt: str, content: str, scan_name: str,
          targets: list, skip_move: bool = False) -> tuple[list, bool, bool]:
    """Extract subdomains and upsert into targets list.

    Returns (targets, changed, file_moved=False).
    """
    filename = Path(filepath).name
    print(f"[subdomain] Processing '{scanner}' ({fmt.upper()}) — {filename}")

    subdomains_list: list[str] = _extract(scanner, fmt, content)
    print(f"[subdomain] Extracted {len(subdomains_list)} subdomains")

    if not subdomains_list:
        return targets, False, False

    root_domain = extract_root_domain(subdomains_list[0])
    target_id   = scan_name

    # Find or create target
    target = next(
        (t for t in targets if t.get("id") == target_id or t.get("domain") == target_id),
        None,
    )
    changed = False
    if not target:
        target = {
            "id":            target_id,
            "domain":        root_domain or target_id,
            "programName":   f"{scanner.capitalize()} Scan",
            "status":        "COMPLETED",
            "subdomains":    [],
            "vulnerabilities": [],
            "totalPorts":    0,
            "sources":       [filename],
            "lastScanDate":  datetime.now(timezone.utc).isoformat(),
        }
        targets.append(target)
        changed = True
        print(f"[subdomain] ✓ Created target '{target_id}'")
    else:
        if filename not in target.get("sources", []):
            target.setdefault("sources", []).append(filename)
            changed = True

    existing = {s.get("hostname") for s in target.get("subdomains", [])}
    added = 0
    for sub in subdomains_list:
        if sub not in existing:
            target.setdefault("subdomains", []).append(make_subdomain_entry(sub))
            existing.add(sub)
            changed = True
            added += 1
    print(f"[subdomain] ✓ Added {added} new subdomains to '{target_id}'")

    return targets, changed, False


# ── Internal extraction helpers ──────────────────────────────────────────────

def _extract(scanner: str, fmt: str, content: str) -> list[str]:
    """Return a deduplicated list of valid hostnames from file content."""
    raw: list[str] = []

    if fmt == "json":
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    raw.append(_item_to_domain(item))
            elif isinstance(data, dict):
                # amass JSON: list of objects with "name" key
                domains = data.get("results") or data.get("domains") or list(data.values())
                for item in (domains if isinstance(domains, list) else [domains]):
                    raw.append(_item_to_domain(item))
        except json.JSONDecodeError:
            pass

    elif fmt == "jsonl":
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                raw.append(_item_to_domain(obj))
            except json.JSONDecodeError:
                raw.append(sanitize_domain(line))

    else:  # txt
        for line in content.splitlines():
            raw.append(sanitize_domain(line))

    # Deduplicate and validate
    seen: set[str] = set()
    result: list[str] = []
    for d in raw:
        if d and d not in seen:
            seen.add(d)
            result.append(d)
    return result


def _item_to_domain(item) -> str:
    if isinstance(item, dict):
        d = (item.get("name") or item.get("host") or item.get("domain") or
             item.get("subdomain") or item.get("hostname") or "")
        return sanitize_domain(str(d))
    if isinstance(item, str):
        return sanitize_domain(item)
    return ""


# ── Standalone CLI ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    import shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <scan_output_file> [scanner_type]")
        sys.exit(1)

    fp    = Path(sys.argv[1])
    sc    = sys.argv[2] if len(sys.argv) > 2 else fp.stem.split("-")[0].lower()
    cont  = fp.read_text(encoding="utf-8", errors="replace")
    fmt   = detect_format(sc, fp.name, cont)
    sname = fp.stem.split("-")[0] if "-" in fp.stem else fp.stem

    store   = load_store()
    tgts    = store.get("targets", [])
    tgts, changed, _ = parse(fp, sc, fmt, cont, sname, tgts)

    if changed:
        store["targets"] = tgts
        save_store(store)
        print(f"[subdomain] ✓ Store saved")
        os.makedirs(PROCESSED_PATH, exist_ok=True)
        dest = Path(PROCESSED_PATH) / fp.name
        shutil.move(str(fp), str(dest))
        print(f"[subdomain] ✓ Moved {fp.name} → processed/")
    else:
        print(f"[subdomain] No new data")
