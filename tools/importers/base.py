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
