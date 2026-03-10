"""
importers/import_ports.py — parser for port-scanning tools.

Handles:
  nmap, nmapx   — XML (-oX), normal (-oN .txt), grepable (-oG .gnmap)
  naabu         — host:port lines or JSON
  rustscan      — "ip -> [22, 80, 443]" lines
  masscan       — list format (-oL) or discovery format
  unimap        — JSON / host:port

Interface:
    HANDLES, detect_format, parse  (see base.py for contract)
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from .base import extract_root_domain, load_store, save_store, sanitize_domain, PROCESSED_PATH

HANDLES: list[str] = [
    "nmap", "nmapx",
    "naabu", "naabu-nmap",
    "rustscan",
    "masscan",
    "unimap",
]


def detect_format(scanner: str, filename: str, content: str) -> str:
    fn = filename.lower()
    if scanner in ("nmap", "nmapx"):
        if fn.endswith(".xml"):
            return "xml" if ("<nmaprun" in content[:400] or "<!DOCTYPE nmaprun" in content[:200]) else "txt"
        if fn.lower().endswith((".og", ".gnmap")):
            return "grepable"
        return "txt"
    if fn.endswith(".xml"):
        return "xml"
    if fn.endswith((".og", ".gnmap")):
        return "grepable"
    if fn.endswith(".jsonl") or fn.endswith(".ndjson"):
        return "jsonl"
    if fn.endswith(".json"):
        return "json"
    return "txt"


def parse(filepath, scanner: str, fmt: str, content: str, scan_name: str,
          targets: list, skip_move: bool = False) -> tuple[list, bool, bool]:
    filename = Path(filepath).name
    print(f"[ports] Processing '{scanner}' ({fmt.upper()}) — {filename}")

    target_id = scan_name
    target = next((t for t in targets if t.get("id") == target_id), None)
    changed = False
    if not target:
        target = {
            "id":            target_id,
            "domain":        target_id,
            "programName":   f"{scanner.capitalize()} Port Scan",
            "status":        "COMPLETED",
            "subdomains":    [],
            "vulnerabilities": [],
            "ports":         [],
            "totalPorts":    0,
            "sources":       [filename],
            "lastScanDate":  datetime.now(timezone.utc).isoformat(),
        }
        targets.append(target)
        changed = True
    if filename not in target.get("sources", []):
        target.setdefault("sources", []).append(filename)
        changed = True

    if scanner in ("nmap", "nmapx"):
        changed = _parse_nmap(target, fmt, content, filename) or changed
    elif scanner == "rustscan":
        changed = _parse_rustscan(target, content) or changed
    elif scanner == "masscan":
        changed = _parse_masscan(target, fmt, content) or changed
    else:
        # naabu, naabu-nmap, unimap — generic host:port / JSON
        changed = _parse_host_port(target, fmt, content) or changed

    # Update totalPorts
    target["totalPorts"] = sum(len(s.get("ports", [])) for s in target.get("subdomains", []))
    # Update domain label from scanned hosts
    host_names = [s.get("hostname", "") for s in target.get("subdomains", []) if s.get("hostname")]
    if host_names:
        joined = ", ".join(host_names)
        target["domain"] = joined[:75] + ("…" if len(joined) > 75 else "")
        changed = True

    print(f"[ports] ✓ '{scanner}': {target['totalPorts']} total port entries")
    return targets, changed, False


# ── nmap XML / normal / grepable ─────────────────────────────────────────────

def _parse_nmap(target: dict, fmt: str, content: str, filename: str) -> bool:
    import xml.etree.ElementTree as ET
    changed = False

    if fmt == "xml":
        try:
            tree = ET.fromstring(content)
        except ET.ParseError as e:
            print(f"[ports] nmap XML parse error: {e}")
            return False
        for host_el in tree.findall(".//host"):
            state_el = host_el.find("status")
            if state_el is None or state_el.get("state") != "up":
                continue
            ip = None
            hostname = None
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv4":
                    ip = addr_el.get("addr")
            for hn_el in host_el.findall(".//hostname"):
                hostname = hn_el.get("name")
                break
            display = hostname or ip
            if not display:
                continue
            open_ports = _nmap_ports_from_el(host_el)
            changed = _upsert_host(target, display, ip or "", open_ports) or changed

    elif fmt == "txt":
        # nmap -oN normal output
        blocks = re.split(r'(?m)^(?=Nmap scan report for )', content)
        for block in blocks:
            if not block.strip() or not block.startswith("Nmap scan report for "):
                continue
            lines = block.splitlines()
            m = re.match(r'^Nmap scan report for (.+?)(?:\s+\((\d[\d.]+)\))?$', lines[0])
            if not m:
                continue
            display = m.group(1).strip()
            ip      = m.group(2) or ""
            open_ports = []
            for ln in lines[1:]:
                mp = re.match(r'^(\d+)/(tcp|udp)\s+open\s*(\S*)', ln.strip())
                if mp:
                    svc = mp.group(3) or mp.group(2)
                    open_ports.append({"port": int(mp.group(1)), "service": svc,
                                        "banner": "", "isOpen": True})
            changed = _upsert_host(target, display, ip, open_ports) or changed

    elif fmt == "grepable":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            mh = re.search(r'Host:\s+(\S+)\s+\(([^)]*)\)', line)
            mp = re.search(r'Ports:\s+(.+?)(?:\t|$)', line)
            if not mh:
                continue
            ip       = mh.group(1)
            hostname = mh.group(2) or ip
            open_ports = []
            if mp:
                for token in mp.group(1).split(','):
                    parts = token.strip().split('/')
                    if len(parts) >= 2 and parts[1] == 'open':
                        pnum  = int(parts[0])
                        proto = parts[2] if len(parts) > 2 else "tcp"
                        svc   = parts[4] if len(parts) > 4 and parts[4] else proto
                        open_ports.append({"port": pnum, "service": svc,
                                            "banner": "", "isOpen": True})
            changed = _upsert_host(target, hostname, ip, open_ports) or changed

    return changed


def _nmap_ports_from_el(host_el) -> list:
    ports = []
    for port_el in host_el.findall(".//port"):
        st = port_el.find("state")
        if st is not None and st.get("state") == "open":
            pnum = int(port_el.get("portid", "0"))
            svc_el = port_el.find("service")
            svc = (svc_el.get("name") if svc_el is not None else None) or port_el.get("protocol", "tcp")
            ports.append({"port": pnum, "service": svc, "banner": "", "isOpen": True})
    return ports


# ── rustscan ─────────────────────────────────────────────────────────────────

def _parse_rustscan(target: dict, content: str) -> bool:
    changed = False
    for line in content.splitlines():
        m = re.match(r'^(\S+)\s*->\s*\[([^\]]+)\]', line.strip())
        if m:
            host  = m.group(1)
            ports = [{"port": int(p.strip()), "service": "tcp", "banner": "", "isOpen": True}
                     for p in m.group(2).split(',') if p.strip().isdigit()]
        else:
            line = sanitize_domain(line)
            if ':' not in line:
                continue
            h, p = line.rsplit(':', 1)
            if not p.isdigit():
                continue
            host  = h
            ports = [{"port": int(p), "service": "tcp", "banner": "", "isOpen": True}]
        changed = _upsert_host(target, host, host, ports) or changed
    return changed


# ── masscan ──────────────────────────────────────────────────────────────────

def _parse_masscan(target: dict, fmt: str, content: str) -> bool:
    changed = False
    svc_map: dict = {}  # host -> {port_str: service}
    host_ports: dict = {}

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # List format: Timestamp: ... Host: IP () Ports: port/state/proto//svc//
        m_list = re.match(r'^Timestamp:\s+\S+\s+Host:\s+(\S+)\s.*?Ports:\s+(.+)', line)
        if m_list:
            host = m_list.group(1)
            for pe in m_list.group(2).split(","):
                pm = re.match(r'^(\d+)/open/(\w+)//(\w*)/', pe.strip())
                if pm:
                    ps, proto, svc = pm.group(1), pm.group(2), pm.group(3) or pm.group(2)
                    host_ports.setdefault(host, []).append(ps)
                    svc_map.setdefault(host, {})[ps] = svc
            continue
        # Discovery format: Discovered open port PORT/proto on IP
        m_disc = re.match(r'Discovered open port (\d+)/(\w+) on (\S+)', line)
        if m_disc:
            ps, proto, host = m_disc.group(1), m_disc.group(2), m_disc.group(3)
            host_ports.setdefault(host, []).append(ps)
            svc_map.setdefault(host, {})[ps] = proto

    for host, ports in host_ports.items():
        seen: set = set()
        port_objs = []
        for ps in ports:
            pnum = int(ps)
            if pnum not in seen:
                seen.add(pnum)
                svc = svc_map.get(host, {}).get(ps, "tcp")
                port_objs.append({"port": pnum, "service": svc, "banner": "", "isOpen": True})
        changed = _upsert_host(target, host, host, port_objs) or changed
    return changed


# ── Generic host:port / JSON (naabu, unimap, …) ──────────────────────────────

def _parse_host_port(target: dict, fmt: str, content: str) -> bool:
    changed = False
    host_ports: dict = {}

    if fmt in ("json", "jsonl"):
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = obj.get("host") or obj.get("ip") or ""
                port = str(obj.get("port") or obj.get("portid") or "")
                if host and port:
                    host_ports.setdefault(host, []).append(port)
            except json.JSONDecodeError:
                pass
    else:
        # host:port one per line
        for line in content.splitlines():
            line = sanitize_domain(line)
            if ':' in line:
                h, p = line.rsplit(':', 1)
                if p.isdigit():
                    host_ports.setdefault(h, []).append(p)

    for host, ports in host_ports.items():
        seen: set = set()
        port_objs = []
        for ps in ports:
            pnum = int(ps)
            if pnum not in seen:
                seen.add(pnum)
                port_objs.append({"port": pnum, "service": "tcp", "banner": "", "isOpen": True})
        changed = _upsert_host(target, host, host, port_objs) or changed
    return changed


# ── Host upsert helper ────────────────────────────────────────────────────────

def _upsert_host(target: dict, display: str, ip: str, open_ports: list) -> bool:
    """Add or merge a host entry into target['subdomains']. Returns True if changed."""
    existing_subs = {s.get("hostname") for s in target.get("subdomains", [])}
    if display not in existing_subs:
        target.setdefault("subdomains", []).append({
            "id": display, "hostname": display, "ip": ip,
            "ports": open_ports, "technologies": [], "location": "", "asn": "",
        })
        _sync_port_list(target, open_ports)
        return True

    # Merge ports into existing sub
    changed = False
    for s in target["subdomains"]:
        if s.get("hostname") == display:
            existing_pnums = {p["port"] if isinstance(p, dict) else int(p)
                              for p in s.get("ports", [])}
            for po in open_ports:
                if po["port"] not in existing_pnums:
                    s.setdefault("ports", []).append(po)
                    changed = True
            break
    if changed:
        _sync_port_list(target, open_ports)
    return changed


def _sync_port_list(target: dict, open_ports: list) -> None:
    """Keep legacy target['ports'] list of unique port strings up to date."""
    tracked = target.setdefault("ports", [])
    for po in open_ports:
        ps = str(po["port"])
        if ps not in tracked:
            tracked.append(ps)


# ── Standalone CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <scan_output_file> [scanner_type]")
        sys.exit(1)

    fp   = Path(sys.argv[1])
    sc   = sys.argv[2] if len(sys.argv) > 2 else fp.stem.split("-")[0].lower()
    cont = fp.read_text(encoding="utf-8", errors="replace")
    fmt  = detect_format(sc, fp.name, cont)
    sn   = fp.stem.split("-")[0] if "-" in fp.stem else fp.stem

    store  = load_store()
    tgts   = store.get("targets", [])
    tgts, changed, _ = parse(fp, sc, fmt, cont, sn, tgts)

    if changed:
        store["targets"] = tgts
        save_store(store)
        os.makedirs(PROCESSED_PATH, exist_ok=True)
        shutil.move(str(fp), str(Path(PROCESSED_PATH) / fp.name))
        print(f"[ports] ✓ Saved and moved {fp.name}")
    else:
        print(f"[ports] No new data")
