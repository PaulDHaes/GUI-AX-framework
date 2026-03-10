"""
importers/import_whois.py — parser for WHOIS lookups.

Handles:
  whois  — txt / json / csv / xml
           plus .dir-mode (one file per queried domain, folder name = scan batch)

Interface:
    HANDLES, detect_format, parse  (see base.py for contract)
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from .base import (COUNTRY_COORDS, extract_root_domain, load_store, save_store,
                   sanitize_domain, PROCESSED_PATH)

HANDLES: list[str] = ["whois"]

# ccTLD → ISO 3166-1 alpha-2 (used when WHOIS output omits country field)
_CCTLD_MAP: dict[str, str] = {
    "ac":"SH","ad":"AD","ae":"AE","af":"AF","ag":"AG","ai":"AI",
    "al":"AL","am":"AM","ao":"AO","aq":"AQ","ar":"AR","as":"AS",
    "at":"AT","au":"AU","aw":"AW","ax":"FI","az":"AZ",
    "ba":"BA","bb":"BB","bd":"BD","be":"BE","bf":"BF","bg":"BG",
    "bh":"BH","bi":"BI","bj":"BJ","bm":"BM","bn":"BN","bo":"BO",
    "br":"BR","bs":"BS","bt":"BT","bw":"BW","by":"BY","bz":"BZ",
    "ca":"CA","cc":"CC","cd":"CD","cf":"CF","cg":"CG","ch":"CH",
    "ci":"CI","ck":"CK","cl":"CL","cm":"CM","cn":"CN","co":"CO",
    "cr":"CR","cu":"CU","cv":"CV","cx":"CX","cy":"CY","cz":"CZ",
    "de":"DE","dj":"DJ","dk":"DK","dm":"DM","do":"DO","dz":"DZ",
    "ec":"EC","ee":"EE","eg":"EG","er":"ER","es":"ES","et":"ET",
    "fi":"FI","fj":"FJ","fk":"FK","fm":"FM","fo":"FO","fr":"FR",
    "ga":"GA","gb":"GB","gd":"GD","ge":"GE","gf":"GF","gg":"GG",
    "gh":"GH","gi":"GI","gl":"GL","gm":"GM","gn":"GN","gp":"GP",
    "gq":"GQ","gr":"GR","gs":"GS","gt":"GT","gu":"GU","gw":"GW",
    "gy":"GY","hk":"HK","hm":"HM","hn":"HN","hr":"HR","ht":"HT",
    "hu":"HU","id":"ID","ie":"IE","il":"IL","im":"IM","in":"IN",
    "io":"IO","iq":"IQ","ir":"IR","is":"IS","it":"IT","je":"JE",
    "jm":"JM","jo":"JO","jp":"JP","ke":"KE","kg":"KG","kh":"KH",
    "ki":"KI","km":"KM","kn":"KN","kp":"KP","kr":"KR","kw":"KW",
    "ky":"KY","kz":"KZ","la":"LA","lb":"LB","lc":"LC","li":"LI",
    "lk":"LK","lr":"LR","ls":"LS","lt":"LT","lu":"LU","lv":"LV",
    "ly":"LY","ma":"MA","mc":"MC","md":"MD","me":"ME","mg":"MG",
    "mh":"MH","mk":"MK","ml":"ML","mm":"MM","mn":"MN","mo":"MO",
    "mp":"MP","mq":"MQ","mr":"MR","ms":"MS","mt":"MT","mu":"MU",
    "mv":"MV","mw":"MW","mx":"MX","my":"MY","mz":"MZ","na":"NA",
    "nc":"NC","ne":"NE","nf":"NF","ng":"NG","ni":"NI","nl":"NL",
    "no":"NO","np":"NP","nr":"NR","nu":"NU","nz":"NZ","om":"OM",
    "pa":"PA","pe":"PE","pf":"PF","pg":"PG","ph":"PH","pk":"PK",
    "pl":"PL","pm":"PM","pn":"PN","pr":"PR","ps":"PS","pt":"PT",
    "pw":"PW","py":"PY","qa":"QA","re":"RE","ro":"RO","rs":"RS",
    "ru":"RU","rw":"RW","sa":"SA","sb":"SB","sc":"SC","sd":"SD",
    "se":"SE","sg":"SG","sh":"SH","si":"SI","sk":"SK","sl":"SL",
    "sm":"SM","sn":"SN","so":"SO","sr":"SR","ss":"SS","st":"ST",
    "sv":"SV","sx":"SX","sy":"SY","sz":"SZ","tc":"TC","td":"TD",
    "tf":"TF","tg":"TG","th":"TH","tj":"TJ","tk":"TK","tl":"TL",
    "tm":"TM","tn":"TN","to":"TO","tr":"TR","tt":"TT","tv":"TV",
    "tw":"TW","tz":"TZ","ua":"UA","ug":"UG","uk":"GB","us":"US",
    "uy":"UY","uz":"UZ","va":"VA","vc":"VC","ve":"VE","vg":"VG",
    "vi":"VI","vn":"VN","vu":"VU","wf":"WF","ws":"WS","ye":"YE",
    "yt":"YT","za":"ZA","zm":"ZM","zw":"ZW",
}


def detect_format(scanner: str, filename: str, content: str) -> str:
    fn = filename.lower()
    if fn.endswith(".json") or fn.endswith(".jsonl"):
        return "json"
    if fn.endswith(".xml"):
        return "xml"
    if fn.endswith(".csv"):
        return "csv"
    return "txt"


def parse(filepath, scanner: str, fmt: str, content: str, scan_name: str,
          targets: list, skip_move: bool = False) -> tuple[list, bool, bool]:
    filename = Path(filepath).name
    print(f"[whois] Processing '{scanner}' ({fmt.upper()}) — {filename}")
    print(f"[whois] content[:200]: {content[:200]!r}")

    # Skip no-match responses
    no_match = re.search(r'No match for|NOT FOUND|No Data Found|Object does not exist',
                         content, re.IGNORECASE)
    if no_match:
        print(f"[whois] ✗ Skipping: no-match ('{no_match.group()}')")
        return targets, False, False

    # Detect .dir-mode (filename is the queried domain, parent dir ends in .dir)
    fp = Path(filepath)
    parent_dir   = fp.parent.name
    is_dir_mode  = parent_dir.endswith(".dir") or ".dir" in parent_dir
    if is_dir_mode:
        raw = fp.name.lower()
        filename_domain = raw[4:] if raw.startswith("www.") else raw
    else:
        filename_domain = None
    print(f"[whois] is_dir_mode={is_dir_mode}, filename_domain={filename_domain}")

    # Build entry helper
    def _make_entry(domain_str: str, cc: str | None) -> dict:
        entry = {
            "id": domain_str, "hostname": domain_str, "ip": "",
            "ports": [], "technologies": [],
            "location": cc or "", "asn": "",
        }
        if cc and cc in COUNTRY_COORDS:
            lat, lng = COUNTRY_COORDS[cc]
            entry["geo"] = {"lat": lat, "lng": lng,
                            "country": cc, "countryCode": cc}
        return entry

    subdomains_entries: list[tuple[str, dict]] = []

    if fmt == "txt":
        country_match = re.search(
            r'^(?:Registrant\s+Country|country)\s*:\s*([A-Z]{2})\s*$',
            content, re.IGNORECASE | re.MULTILINE
        )
        country_code = country_match.group(1).strip().upper() if country_match else None

        # Fallback: infer from ccTLD
        if not country_code and filename_domain and '.' in filename_domain:
            tld = filename_domain.rsplit('.', 1)[-1].lower()
            country_code = _CCTLD_MAP.get(tld)
            if country_code:
                print(f"[whois] Inferred country '{country_code}' from ccTLD '.{tld}'")

        if is_dir_mode and filename_domain:
            subdomains_entries.append((filename_domain, _make_entry(filename_domain, country_code)))
        else:
            blocks = re.split(r'\n\s*\n', content.strip())
            for block in blocks:
                if not block.strip():
                    continue
                dm = re.search(r'^(?:Domain Name|domain)\s*:\s*(\S+)',
                               block, re.IGNORECASE | re.MULTILINE)
                if not dm:
                    continue
                domain_str = dm.group(1).strip().lower().rstrip('.')
                if not domain_str or '.' not in domain_str:
                    continue
                blk_cc = re.search(
                    r'^(?:Registrant\s+Country|country)\s*:\s*([A-Z]{2})\s*$',
                    block, re.IGNORECASE | re.MULTILINE
                )
                cc = blk_cc.group(1).strip().upper() if blk_cc else country_code
                subdomains_entries.append((domain_str, _make_entry(domain_str, cc)))
    else:
        # Non-txt: treat each non-empty sanitised line as a hostname
        for line in content.splitlines():
            line = sanitize_domain(line)
            if line and '.' in line and len(line) < 253:
                subdomains_entries.append((line, {
                    "id": line, "hostname": line, "ip": "",
                    "ports": [], "technologies": [], "location": "", "asn": "",
                }))

    print(f"[whois] Extracted {len(subdomains_entries)} entries")
    if not subdomains_entries:
        print(f"[whois] ✗ No usable records, skipping")
        return targets, False, False

    # Find / create target
    target_id     = scan_name
    friendly_name = scan_name.replace(".dir", "")
    target = next((t for t in targets if t.get("id") == target_id), None)
    queried_domains = [d for d, _ in subdomains_entries]
    display_domain  = (
        ", ".join(queried_domains)
        if is_dir_mode and queried_domains
        else (extract_root_domain(queried_domains[0]) or friendly_name)
    )
    changed = False

    if not target:
        target = {
            "id":              target_id,
            "domain":          display_domain,
            "programName":     "WHOIS Scan",
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
        # Keep domain label up to date as more files arrive in .dir mode
        if is_dir_mode and queried_domains:
            existing_hosts = {s.get("hostname") for s in target.get("subdomains", [])}
            new_domains = [d for d in queried_domains if d not in existing_hosts]
            if new_domains:
                current    = target.get("domain", "")
                all_set    = set(current.split(", ")) if current else set()
                all_set.update(new_domains)
                target["domain"] = ", ".join(sorted(all_set))
                changed = True

    existing_subs = {s.get("hostname") for s in target.get("subdomains", [])}
    added = 0
    for domain_str, entry in subdomains_entries:
        if domain_str not in existing_subs:
            target.setdefault("subdomains", []).append(entry)
            changed = True
            added  += 1

    # Store raw WHOIS text so UI can render full output
    raw_key = filename_domain if (is_dir_mode and filename_domain) else target_id
    target.setdefault("rawWhoisData", {})[raw_key] = content
    changed = True

    print(f"[whois] ✓ Added {added} entries, rawWhoisData['{raw_key}'] ({len(content)} bytes)")
    return targets, changed, False


# ── Standalone CLI ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, shutil

    if len(sys.argv) < 2:
        print(f"Usage: python {Path(__file__).name} <whois_output_file>")
        sys.exit(1)

    fp   = Path(sys.argv[1])
    sc   = "whois"
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
        print(f"[whois] ✓ Saved and moved {fp.name}")
    else:
        print(f"[whois] No new data")
