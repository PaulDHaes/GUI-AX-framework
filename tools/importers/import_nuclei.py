"""
importers/import_nuclei.py — parser for Nuclei vulnerability scanner.

Handles:
  nuclei   — json / jsonl / txt output
  nuclei-md — markdown export directory (via process_nuclei_md_files)

Interface:
    HANDLES, detect_format, parse  (see base.py for contract)
    
Also exports:
    parse_nuclei_md_content(content, filename)  -> (host, vuln_info)
    process_nuclei_md_files(md_files, scan_name) -> (added, vulns)
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .base import extract_root_domain, load_store, save_store, _find_target_for_host, PROCESSED_PATH

HANDLES: list[str] = ["nuclei"]


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
    print(f"[nuclei] Processing '{scanner}' ({fmt.upper()}) — {filename}")
    added_count = 0
    vuln_count  = 0
    changed     = False

    if fmt in ("json", "jsonl"):
        lines = content.strip().splitlines()
        if fmt == "json":
            # entire file is one JSON doc (array or single object)
            try:
                doc = json.loads(content)
                lines = [json.dumps(item) for item in (doc if isinstance(doc, list) else [doc])]
            except json.JSONDecodeError:
                pass

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                vuln = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = vuln.get("host") or vuln.get("url") or vuln.get("matched-at") or ""
            if not host:
                continue

            parsed = urlparse(host)
            domain = parsed.netloc or parsed.path
            if ":" in domain and not domain.startswith("["):
                h, p = domain.rsplit(":", 1)
                if p.isdigit():
                    domain = h
            if not domain:
                continue

            root_domain = extract_root_domain(domain)
            if not root_domain:
                continue

            target = _find_target_for_host(targets, domain, root_domain)
            if not target:
                target = {
                    "id":              f"{scan_name}-{root_domain}",
                    "domain":          root_domain,
                    "programName":     scanner,
                    "status":          "COMPLETED",
                    "lastScanDate":    datetime.now(timezone.utc).isoformat(),
                    "sources":         [scan_name],
                    "totalPorts":      0,
                    "subdomains":      [],
                    "vulnerabilities": [],
                    "created_at":      datetime.now(timezone.utc).isoformat(),
                }
                targets.append(target)
                changed = True
                added_count += 1
            elif scan_name not in target.get("sources", []):
                target.setdefault("sources", []).append(scan_name)

            vuln_info = {
                "id":          vuln.get("template-id", f"vuln-{len(target['vulnerabilities'])}"),
                "name":        vuln.get("info", {}).get("name",
                               vuln.get("template-id", "Unknown Vulnerability")),
                "description": vuln.get("info", {}).get("description", ""),
                "severity":    vuln.get("info", {}).get("severity", "INFO").upper(),
                "path":        host,
                "matched":     vuln.get("matched-at", host),
                "type":        vuln.get("type", "unknown"),
                "rawContent":  line,
            }
            if not any(v.get("id") == vuln_info["id"] and v.get("path") == vuln_info["path"]
                       for v in target["vulnerabilities"]):
                target["vulnerabilities"].append(vuln_info)
                changed = True
                vuln_count += 1

    elif fmt == "txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # canonical nuclei stdout: [template-id] [protocol] [severity] url
            m = re.match(r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s+(\S+)', line)
            if m:
                template_id = m.group(1).strip()
                protocol    = m.group(2).strip()
                severity    = m.group(3).strip().upper()
                url         = m.group(4).strip()
            else:
                parts = line.split()
                if not parts:
                    continue
                url         = parts[-1]
                template_id = parts[0].strip("[]") if parts else "unknown"
                severity    = "INFO"
                protocol    = "http"

            parsed = urlparse(url if "://" in url else "http://" + url)
            domain = parsed.netloc or parsed.path.split("/")[0]
            if ":" in domain and not domain.startswith("["):
                h, p = domain.rsplit(":", 1)
                if p.isdigit():
                    domain = h
            if not domain:
                continue

            root_domain = extract_root_domain(domain)
            if not root_domain:
                continue

            target = _find_target_for_host(targets, domain, root_domain)
            if not target:
                target = {
                    "id":              f"{scan_name}-{root_domain}",
                    "domain":          root_domain,
                    "programName":     scanner,
                    "status":          "COMPLETED",
                    "lastScanDate":    datetime.now(timezone.utc).isoformat(),
                    "sources":         [scan_name],
                    "totalPorts":      0,
                    "subdomains":      [],
                    "vulnerabilities": [],
                    "created_at":      datetime.now(timezone.utc).isoformat(),
                }
                targets.append(target)
                changed = True
                added_count += 1
            elif scan_name not in target.get("sources", []):
                target.setdefault("sources", []).append(scan_name)

            vuln_info = {
                "id":          template_id,
                "name":        template_id.replace("-", " ").title(),
                "description": "",
                "severity":    severity,
                "path":        url,
                "matched":     url,
                "type":        protocol,
                "rawContent":  line,
            }
            if not any(v.get("id") == vuln_info["id"] and v.get("path") == vuln_info["path"]
                       for v in target["vulnerabilities"]):
                target["vulnerabilities"].append(vuln_info)
                changed = True
                vuln_count += 1

    print(f"[nuclei] ✓ {added_count} new targets, {vuln_count} vulnerabilities")
    return targets, changed, False


# ── Nuclei markdown export helpers ───────────────────────────────────────────

def parse_nuclei_md_content(content: str, filename: str):
    """Parse one nuclei -markdown-export .md file.
    Returns (target_host, vuln_info) or (None, None).
    """
    def _table_val(key):
        m = re.search(rf'\|\s*{re.escape(key)}\s*\|\s*(.+?)\s*\|', content, re.IGNORECASE)
        return m.group(1).strip() if m else None

    name        = _table_val("Name")
    severity    = (_table_val("Severity") or "info").upper()
    description = _table_val("Description") or ""
    description = re.sub(r'<[^>]+>', '', description)

    # CVE / template-id
    template_id = None
    cve_m = re.search(r'\|\s*CVE-ID\s*\|\s*\[?([A-Z]+-\d+-\d+)', content)
    if cve_m:
        template_id = cve_m.group(1).strip()
    if not template_id:
        m2 = re.search(r'\(([A-Z]+-\d+-\d+)', content)
        if m2:
            template_id = m2.group(1)
    if not template_id:
        stem  = Path(filename).stem
        parts = stem.split('-')
        id_parts = []
        for part in parts:
            if '.' in part:
                break
            id_parts.append(part)
        template_id = '-'.join(id_parts) if id_parts else stem[:60]

    # CVSS fallback for severity
    if severity == "INFO":
        sc_m = re.search(r'CVSS-Score\s*\|\s*([\d.]+)', content)
        if sc_m:
            score = float(sc_m.group(1))
            if score >= 9.0:   severity = "CRITICAL"
            elif score >= 7.0: severity = "HIGH"
            elif score >= 4.0: severity = "MEDIUM"
            elif score > 0:    severity = "LOW"

    # Target URL
    url = None
    url_m = re.search(r'\*\*Full URL\*\*[:\s]+([^\s]+)', content)
    if url_m:
        url = url_m.group(1).strip()

    target_host = None
    det_m = re.search(r'\*\*Details\*\*[^:]*:\s*\*\*[^*]+\*\*\s+matched at\s+(\S+)', content)
    if det_m:
        target_host = det_m.group(1).strip()
    elif url:
        parsed = urlparse(url if '://' in url else 'tcp://' + url)
        target_host = parsed.netloc or parsed.path.split('/')[0]
        if ':' in target_host and not target_host.startswith('['):
            h, p = target_host.rsplit(':', 1)
            if p.isdigit():
                target_host = h

    if not target_host:
        return None, None

    if ':' in target_host and not target_host.startswith('['):
        h, p = target_host.rsplit(':', 1)
        if p.isdigit():
            target_host = h

    vuln_info = {
        "id":          template_id or "unknown",
        "name":        name or (template_id.replace("-", " ").title() if template_id else "Unknown"),
        "description": description,
        "severity":    severity,
        "path":        url or target_host,
        "matched":     url or target_host,
        "type":        "nuclei-md",
        "rawContent":  content,
    }
    return target_host, vuln_info


def process_nuclei_md_files(md_files, scan_name: str) -> tuple[int, int]:
    """Ingest a list of nuclei -markdown-export .md files into the store."""
    store   = load_store()
    targets = store.setdefault("targets", [])
    changed = False
    added   = 0
    vulns   = 0

    for filepath in md_files:
        filepath = Path(filepath)
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[nuclei-md] Cannot read {filepath.name}: {e}")
            continue

        target_host, vuln_info = parse_nuclei_md_content(content, filepath.name)
        if not target_host or not vuln_info:
            print(f"[nuclei-md] Skipping (no target): {filepath.name}")
            continue

        root_domain = extract_root_domain(target_host)
        if not root_domain:
            print(f"[nuclei-md] Skipping (no root domain from '{target_host}'): {filepath.name}")
            continue

        target = next((t for t in targets if t.get("domain") == root_domain), None)
        if not target:
            target = {
                "id":              f"{scan_name}-{root_domain}",
                "domain":          root_domain,
                "programName":     "nuclei",
                "status":          "COMPLETED",
                "lastScanDate":    datetime.now(timezone.utc).isoformat(),
                "sources":         [scan_name],
                "totalPorts":      0,
                "subdomains":      [],
                "vulnerabilities": [],
                "created_at":      datetime.now(timezone.utc).isoformat(),
            }
            targets.append(target)
            changed = True
            added  += 1
        elif scan_name not in target.get("sources", []):
            target.setdefault("sources", []).append(scan_name)

        if not any(v.get("id") == vuln_info["id"] and v.get("path") == vuln_info["path"]
                   for v in target["vulnerabilities"]):
            target["vulnerabilities"].append(vuln_info)
            changed = True
            vulns  += 1

        if filepath.name not in target.get("sources", []):
            target.setdefault("sources", []).append(filepath.name)

    if changed:
        save_store(store)
    print(f"[nuclei-md] ✓ {len(md_files)} files → {added} new targets, {vulns} vulnerabilities")
    return added, vulns


# ── Standalone CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <scan_output_file_or_md_dir> [scanner_type]")
        sys.exit(1)

    fp = Path(sys.argv[1])
    sc = sys.argv[2] if len(sys.argv) > 2 else "nuclei"

    if fp.is_dir():
        md_files = list(fp.glob("*.md"))
        print(f"[nuclei] Found {len(md_files)} .md files in '{fp}'")
        process_nuclei_md_files(md_files, fp.name)
    else:
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
            print(f"[nuclei] ✓ Saved and moved {fp.name}")
        else:
            print(f"[nuclei] No new data")
