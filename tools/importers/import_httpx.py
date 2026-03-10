"""
importers/import_httpx.py — parser for HTTP probing tools.

Handles:
  httpx    — full-featured HTTP probe output (json / jsonl / txt)
  tlsx     — TLS cert scanner (json / jsonl / txt)
  tlscout  — similar to tlsx

Interface:
    HANDLES, detect_format, parse  (see base.py for contract)
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from .base import (extract_root_domain, load_store, save_store,
                   sanitize_domain, _find_target_for_host, PROCESSED_PATH)

HANDLES: list[str] = ["httpx", "tlsx", "tlscout"]


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
    print(f"[httpx] Processing '{scanner}' ({fmt.upper()}) — {filename}")

    changed = False
    rows = _parse_rows(scanner, fmt, content)
    print(f"[httpx]   → {len(rows)} entries parsed")

    for row in rows:
        host       = row.get("host", "")
        url        = row.get("url", "")
        ip         = row.get("ip", "")
        title      = row.get("title", "")
        status     = row.get("status", 0)
        techs      = row.get("technologies", [])
        webserver  = row.get("webserver", "")
        tls_cn     = row.get("tls_cn", "")

        if not host and url:
            m = re.match(r'https?://([^/:]+)', url)
            host = m.group(1) if m else ""
        host = sanitize_domain(host)
        if not host:
            continue

        root = extract_root_domain(host)
        target = _find_target_for_host(targets, host, root)

        if not target:
            target = {
                "id":              scan_name,
                "domain":          root or host,
                "programName":     f"{scanner.capitalize()} Probe",
                "status":          "COMPLETED",
                "subdomains":      [],
                "vulnerabilities": [],
                "ports":           [],
                "totalPorts":      0,
                "sources":         [filename],
                "lastScanDate":    datetime.now(timezone.utc).isoformat(),
            }
            targets.append(target)
            changed = True

        if filename not in target.get("sources", []):
            target.setdefault("sources", []).append(filename)
            changed = True

        # Upsert subdomain entry
        subs = target.setdefault("subdomains", [])
        existing = next((s for s in subs if s.get("hostname") == host), None)
        if existing:
            if ip and not existing.get("ip"):
                existing["ip"] = ip
                changed = True
            if title and not existing.get("title"):
                existing["title"] = title
                changed = True
            if techs:
                known_techs = {t.get("name") if isinstance(t, dict) else str(t)
                               for t in existing.get("technologies", [])}
                for t in techs:
                    tname = t.get("name") if isinstance(t, dict) else str(t)
                    if tname and tname not in known_techs:
                        existing.setdefault("technologies", []).append(
                            {"name": tname, "version": t.get("version", "") if isinstance(t, dict) else ""}
                        )
                        changed = True
            if status and not existing.get("statusCode"):
                existing["statusCode"] = status
                changed = True
        else:
            tech_list = []
            for t in techs:
                if isinstance(t, dict):
                    tech_list.append({"name": t.get("name", ""), "version": t.get("version", "")})
                else:
                    tech_list.append({"name": str(t), "version": ""})
            if webserver and not any(t["name"] == webserver for t in tech_list):
                tech_list.append({"name": webserver, "version": ""})

            subs.append({
                "id":           host,
                "hostname":     host,
                "ip":           ip,
                "title":        title,
                "statusCode":   status,
                "url":          url,
                "tlsCN":        tls_cn,
                "ports":        [],
                "technologies": tech_list,
                "location":     "",
                "asn":          "",
            })
            changed = True

    print(f"[httpx] ✓ '{scanner}': {len(rows)} HTTP entries processed")
    return targets, changed, False


# ── Row parsers ───────────────────────────────────────────────────────────────

def _parse_rows(scanner: str, fmt: str, content: str) -> list[dict]:
    rows: list[dict] = []

    if fmt in ("json", "jsonl"):
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, list):
                    rows.extend(_norm(scanner, item) for item in obj if isinstance(item, dict))
                elif isinstance(obj, dict):
                    rows.append(_norm(scanner, obj))
            except json.JSONDecodeError:
                pass
    else:
        # Plain text — one URL / host per line
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rows.append(_norm_txt(scanner, line))

    return [r for r in rows if r.get("host") or r.get("url")]


def _norm(scanner: str, obj: dict) -> dict:
    """Normalise a JSON object to a common row schema."""
    # httpx / tlsx field names
    host    = (obj.get("input") or obj.get("host") or obj.get("hostname") or "").strip()
    url     = (obj.get("url") or "").strip()
    ip      = (obj.get("a") or obj.get("host-ip") or obj.get("ip") or "")
    if isinstance(ip, list):
        ip = ip[0] if ip else ""
    title   = (obj.get("title") or obj.get("page-title") or "").strip()
    status  = int(obj.get("status-code") or obj.get("status") or 0)

    # Technologies — httpx returns list of strings, tlsx may differ
    techs = obj.get("tech") or obj.get("technologies") or obj.get("technology") or []
    if isinstance(techs, str):
        techs = [techs]
    techs = [{"name": (t.get("name") if isinstance(t, dict) else str(t)), "version":
               (t.get("version", "") if isinstance(t, dict) else "")} for t in techs]

    webserver = (obj.get("webserver") or "").strip()

    # TLS CN / subject
    tls_cn = ""
    tls = obj.get("tls") or {}
    if isinstance(tls, dict):
        tls_cn = tls.get("subject-cn") or tls.get("cn") or ""
    elif isinstance(tls, str):
        tls_cn = tls

    # If url is not set but host is
    if not url and host:
        scheme = "https" if (443 in str(obj) or "tls" in obj) else "http"
        url = f"{scheme}://{host}"

    if not host and url:
        m = re.match(r'https?://([^/:]+)', url)
        host = m.group(1) if m else ""

    return {"host": host, "url": url, "ip": ip, "title": title,
            "status": status, "technologies": techs,
            "webserver": webserver, "tls_cn": tls_cn}


def _norm_txt(scanner: str, line: str) -> dict:
    """Parse a plain-text output line (e.g. 'https://example.com [200] [nginx]')."""
    url = ""
    host = ""
    status = 0
    techs = []
    title = ""

    # httpx -silent: just URL  |  httpx verbose: URL [status] [tech,tech] [Title]
    url_match = re.match(r'(https?://\S+)', line)
    if url_match:
        url = url_match.group(1)
        rest = line[len(url):].strip()
        # brackets after URL: [200] [nginx] [My Title]
        for bm in re.finditer(r'\[([^\]]+)\]', rest):
            val = bm.group(1)
            if val.isdigit():
                status = int(val)
            else:
                techs.append({"name": val, "version": ""})
        mh = re.match(r'https?://([^/:]+)', url)
        host = mh.group(1) if mh else ""
    else:
        # bare host or host:port
        host = sanitize_domain(line.split()[0])

    return {"host": host, "url": url, "ip": "", "title": title,
            "status": status, "technologies": techs,
            "webserver": "", "tls_cn": ""}


# ── Standalone CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <scan_output_file> [scanner_type]")
        sys.exit(1)

    fp   = Path(sys.argv[1])
    sc   = sys.argv[2] if len(sys.argv) > 2 else "httpx"
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
        print(f"[httpx] ✓ Saved and moved {fp.name}")
    else:
        print(f"[httpx] No new data")
