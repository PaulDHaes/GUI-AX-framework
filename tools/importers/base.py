"""
importers/base.py — shared helpers for all importer modules.

Every importer imports from here so path / store logic stays in one place.
When run standalone the importers resolve paths relative to this file:
  tools/importers/base.py  →  ../  = tools/  →  ../../ = project root
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

# ── Path resolution ──────────────────────────────────────────────────────────
# tools/importers/base.py → parent = importers/ → parent = tools/ → parent = project root
_TOOLS_DIR   = Path(__file__).parent.parent          # tools/
_PROJECT_DIR = _TOOLS_DIR.parent                     # project root

STORE_PATH     = os.environ.get("AXIOM_STORE",
                                str(_PROJECT_DIR / "data" / "axiom_bridge_store.json"))
IMPORTS_PATH   = os.environ.get("AXIOM_IMPORTS",
                                str(_PROJECT_DIR / "imports"))
PROCESSED_PATH = str(Path(IMPORTS_PATH) / "processed")

# ── Store I/O ────────────────────────────────────────────────────────────────

def load_store() -> dict:
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"targets": []}


def save_store(store: dict) -> None:
    os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
    with open(STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, default=str)


# ── Domain helpers ───────────────────────────────────────────────────────────

_TLDS2 = {
    "co.uk", "co.nz", "co.za", "co.jp", "co.in", "com.au", "com.br",
    "com.mx", "com.sg", "com.ar", "org.uk", "net.uk", "gov.uk",
}


def extract_root_domain(domain: str) -> str:
    """Return eTLD+1 for a domain string. Handles common two-part TLDs."""
    if not domain:
        return ""
    # Strip protocol / path junk
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    # Strip port
    if ':' in domain and not domain.startswith('['):
        h, p = domain.rsplit(':', 1)
        if p.isdigit():
            domain = h
    domain = domain.strip().lower()
    if not domain or '.' not in domain:
        return domain
    parts = domain.split('.')
    if len(parts) >= 3:
        two_part = f"{parts[-2]}.{parts[-1]}"
        if two_part in _TLDS2:
            return '.'.join(parts[-3:]) if len(parts) >= 3 else domain
    return '.'.join(parts[-2:])


def sanitize_domain(s: str) -> str:
    """Strip whitespace, protocol prefixes and trailing junk from a domain string."""
    s = s.strip()
    s = re.sub(r'^https?://', '', s)
    s = s.split('/')[0].split('?')[0].split('#')[0]
    s = s.strip()
    return s if '.' in s and len(s) > 3 else ''


def _find_target_for_host(targets: list, host_domain: str, root_domain: str):
    """Find the best-matching existing target for a given host.

    Priority:
      1. Exact match on full hostname
      2. Exact match on root domain
      3. host_domain is a sub-domain of an existing target's domain
    Returns None if no match.
    """
    t = next((t for t in targets if t.get("domain") == host_domain), None)
    if t:
        return t
    t = next((t for t in targets if t.get("domain") == root_domain), None)
    if t:
        return t
    return next(
        (t for t in targets if host_domain.endswith("." + t.get("domain", ""))),
        None,
    )


def make_subdomain_entry(hostname: str, ip: str = "", ports: list | None = None,
                          technologies: list | None = None) -> dict:
    """Return a minimal subdomain dict ready to be appended to target['subdomains']."""
    return {
        "id":           hostname,
        "hostname":     hostname,
        "ip":           ip,
        "ports":        ports or [],
        "technologies": technologies or [],
        "location":     "",
        "asn":          "",
    }


# ── Country → lat/lng ────────────────────────────────────────────────────────

COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    "AF": (33.93, 67.71), "AL": (41.15, 20.17), "DZ": (28.03, 1.66),
    "AR": (-38.42, -63.62), "AU": (-25.27, 133.78), "AT": (47.52, 14.55),
    "AZ": (40.14, 47.58), "BE": (50.50, 4.47),  "BR": (-14.24, -51.93),
    "BG": (42.73, 25.49),  "CA": (56.13, -106.35), "CL": (-35.68, -71.54),
    "CN": (35.86, 104.20), "CO": (4.57, -74.30),  "HR": (45.10, 15.20),
    "CZ": (49.82, 15.47),  "DK": (56.26, 9.50),   "EG": (26.82, 30.80),
    "FI": (61.92, 25.75),  "FR": (46.23, 2.21),   "DE": (51.17, 10.45),
    "GR": (39.07, 21.82),  "HU": (47.16, 19.50),  "IN": (20.59, 78.96),
    "ID": (-0.79, 113.92), "IR": (32.43, 53.69),  "IE": (53.41, -8.24),
    "IL": (31.05, 34.85),  "IT": (41.87, 12.57),  "JP": (36.20, 138.25),
    "KZ": (48.02, 66.92),  "KR": (35.91, 127.77), "KW": (29.31, 47.48),
    "LV": (56.88, 24.60),  "LB": (33.85, 35.86),  "LT": (55.17, 23.88),
    "MY": (4.21, 108.00),  "MX": (23.63, -102.55), "MA": (31.79, -7.09),
    "NL": (52.13, 5.29),   "NZ": (-40.90, 174.89), "NG": (9.08, 8.68),
    "NO": (60.47, 8.47),   "PK": (30.38, 69.35),  "PH": (12.88, 121.77),
    "PL": (51.92, 19.15),  "PT": (39.40, -8.22),  "RO": (45.94, 24.97),
    "RU": (61.52, 105.32), "SA": (23.89, 45.08),  "SN": (14.50, -14.45),
    "RS": (44.02, 21.01),  "SG": (1.35, 103.82),  "SK": (48.67, 19.70),
    "SI": (46.15, 14.99),  "ZA": (-30.56, 22.94), "ES": (40.46, -3.75),
    "LK": (7.87, 80.77),   "SE": (60.13, 18.64),  "CH": (46.82, 8.23),
    "SY": (34.80, 38.99),  "TW": (23.70, 121.00), "TZ": (-6.37, 34.89),
    "TH": (15.87, 100.99), "TR": (38.96, 35.24),  "UA": (48.38, 31.17),
    "AE": (23.42, 53.85),  "GB": (55.38, -3.44),  "UK": (55.38, -3.44),
    "US": (37.09, -95.71), "UY": (-32.52, -55.77), "UZ": (41.38, 64.59),
    "VE": (6.42, -66.59),  "VN": (14.06, 108.28), "YE": (15.55, 48.52),
    "ZW": (-19.02, 29.15),
}


# ── IP geolocation (offline MaxMind GeoLite2) ──────────────────────────────────
# A second geo source for the map: resolve host → IP → lat/lng/city entirely
# offline, so no target IPs ever leave the machine. Requires the geoip2 lib and
# a GeoLite2-City.mmdb database (free MaxMind account). Everything degrades
# gracefully to "unavailable" if either is missing — WHOIS geo still works.

# Search order for the .mmdb: env override, then a few conventional locations.
_GEOIP_DB_CANDIDATES = [
    os.environ.get("GEOIP_DB_PATH", ""),
    str(_PROJECT_DIR / "data" / "GeoLite2-City.mmdb"),
    str(Path(os.path.expanduser("~")) / ".axiom" / "GeoLite2-City.mmdb"),
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
]

_geoip_reader = None          # cached geoip2.database.Reader (or False if unavailable)
_geoip_cache: dict[str, dict | None] = {}   # ip → geo dict (or None for a miss)


def geoip_db_path() -> str | None:
    """Return the first existing GeoLite2 database path, or None."""
    for p in _GEOIP_DB_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    return None


def _get_geoip_reader():
    """Lazily open the GeoLite2 reader. Returns the reader, or None if the
    geoip2 lib or the .mmdb file is missing."""
    global _geoip_reader
    if _geoip_reader is not None:
        return _geoip_reader or None
    db = geoip_db_path()
    if not db:
        _geoip_reader = False
        return None
    try:
        import geoip2.database  # type: ignore
        _geoip_reader = geoip2.database.Reader(db)
    except Exception as e:                                   # lib missing / bad DB
        print(f"[geo] GeoLite2 reader unavailable: {e}")
        _geoip_reader = False
        return None
    return _geoip_reader


def geo_available() -> bool:
    """True when both the geoip2 lib and a database are present."""
    return _get_geoip_reader() is not None


def geolocate_ip(ip: str) -> dict | None:
    """Look up an IP in GeoLite2-City. Returns a geo dict shaped like the
    WHOIS geo (lat/lng/city/country/countryCode) with source='ip', or None
    for private/unroutable IPs, misses, or when the DB is unavailable."""
    if not ip:
        return None
    if ip in _geoip_cache:
        return _geoip_cache[ip]

    import ipaddress
    try:
        if not ipaddress.ip_address(ip).is_global:          # skip RFC1918 / loopback / CGNAT
            _geoip_cache[ip] = None
            return None
    except ValueError:
        _geoip_cache[ip] = None
        return None

    reader = _get_geoip_reader()
    if reader is None:
        return None
    try:
        import geoip2.errors  # type: ignore
        resp = reader.city(ip)
        if resp.location.latitude is None or resp.location.longitude is None:
            _geoip_cache[ip] = None
            return None
        geo = {
            "lat":         resp.location.latitude,
            "lng":         resp.location.longitude,
            "city":        resp.city.name or "",
            "country":     resp.country.name or resp.country.iso_code or "",
            "countryCode": resp.country.iso_code or "",
            "source":      "ip",
        }
        _geoip_cache[ip] = geo
        return geo
    except Exception:                                        # AddressNotFoundError etc.
        _geoip_cache[ip] = None
        return None


def resolve_hostname(host: str, timeout: float = 3.0) -> str:
    """Forward-resolve a hostname to an IPv4 address, or '' on failure."""
    if not host:
        return ""
    import socket
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(host)
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def geolocate_ips_online(ips: list) -> dict:
    """Batch-geolocate public IPs via ip-api.com — a free service that needs no
    account or API key. Returns {ip: geo}. Requires internet, and sends the IPs
    to a third party (unlike the offline GeoLite2 path). Uses only the stdlib.
    Free tier: HTTP, batches of 100, ~15 req/min."""
    import ipaddress, json as _json, urllib.request

    # Dedupe + keep only routable IPs
    pub: list[str] = []
    for ip in dict.fromkeys(ips):
        try:
            if ip and ipaddress.ip_address(ip).is_global:
                pub.append(ip)
        except ValueError:
            pass

    result: dict[str, dict] = {}
    fields = "status,country,countryCode,city,lat,lon,query"
    for i in range(0, len(pub), 100):                        # 100 IPs/batch
        chunk = pub[i:i + 100]
        body = _json.dumps(
            [{"query": ip, "fields": fields} for ip in chunk]
        ).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                arr = _json.loads(resp.read().decode())
        except Exception as e:
            print(f"[geo] online lookup failed: {e}")
            break
        for entry in arr:
            if entry.get("status") == "success" and entry.get("lat") is not None:
                result[entry["query"]] = {
                    "lat":         entry["lat"],
                    "lng":         entry["lon"],
                    "city":        entry.get("city") or "",
                    "country":     entry.get("country") or entry.get("countryCode") or "",
                    "countryCode": entry.get("countryCode") or "",
                    "source":      "ip",
                }
    return result


def enrich_targets_geo(targets: list, do_dns: bool = False,
                       provider: str = "offline") -> dict:
    """Populate subdomain['geo'] for any subdomain lacking it, via IP geolocation.

    provider:
      "offline" — MaxMind GeoLite2 lookup, fully local (default).
      "online"  — ip-api.com batch lookup; no key/signup but IPs leave the box.

    When do_dns is True, hosts without a resolved IP are forward-resolved first.
    Mutates `targets` in place. Returns stats:
      {available, provider, located, resolved, skipped, checked}.
    """
    stats = {"available": True, "provider": provider, "located": 0,
             "resolved": 0, "skipped": 0, "checked": 0}
    if provider == "offline" and not geo_available():
        stats["available"] = False
        return stats

    # Pass 1 — collect subdomains needing geo, resolving IPs on the way.
    pending: list[tuple[dict, str]] = []
    for t in targets:
        for s in t.get("subdomains", []) or []:
            g = s.get("geo")
            if g and g.get("lat") is not None:               # already placed — leave it
                continue
            stats["checked"] += 1
            ip = (s.get("ip") or "").strip()
            if not ip and do_dns:
                ip = resolve_hostname(s.get("hostname", ""))
                if ip:
                    s["ip"] = ip
                    stats["resolved"] += 1
            if not ip:
                stats["skipped"] += 1
                continue
            pending.append((s, ip))

    # Pass 2 — resolve coordinates via the chosen provider.
    if provider == "online":
        geo_by_ip = geolocate_ips_online([ip for _, ip in pending])
        lookup = lambda ip: geo_by_ip.get(ip)               # noqa: E731
    else:
        lookup = geolocate_ip

    for s, ip in pending:
        geo = lookup(ip)
        if geo:
            s["geo"] = geo
            if not s.get("location"):
                s["location"] = ", ".join(
                    x for x in (geo.get("city"), geo.get("country")) if x
                )
            stats["located"] += 1
        else:
            stats["skipped"] += 1
    return stats
