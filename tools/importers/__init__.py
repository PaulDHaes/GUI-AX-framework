"""
tools/importers/__init__.py

Auto-discovery registry.  Each importer module exposes:
  HANDLES : list[str]  — scanner names it covers
  detect_format(scanner, filename, content) -> str
  parse(filepath, scanner, fmt, content, scan_name, targets, skip_move) -> (targets, changed, file_moved)

Usage in axiom-bridge.py:
    from importers import REGISTRY, GENERIC

    mod = REGISTRY.get(scanner, GENERIC)
    fmt = mod.detect_format(scanner, filename, content)
    targets, changed, file_moved = mod.parse(
        filepath, scanner, fmt, content, scan_name, targets, skip_move
    )
"""

from __future__ import annotations

from . import (
    import_subdomain,
    import_ports,
    import_httpx,
    import_nuclei,
    import_gowitness,
    import_whois,
    import_ffuf,
    import_generic,
)

# Build scanner-name → module mapping from each module's HANDLES list
REGISTRY: dict = {}
for _mod in (
    import_subdomain,
    import_ports,
    import_httpx,
    import_nuclei,
    import_gowitness,
    import_whois,
    import_ffuf,
):
    for _name in _mod.HANDLES:
        REGISTRY[_name] = _mod

# Fallback for unknown scanners
GENERIC = import_generic

__all__ = ["REGISTRY", "GENERIC"]
