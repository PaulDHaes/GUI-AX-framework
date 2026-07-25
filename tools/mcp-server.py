#!/usr/bin/env python3
"""
GUI-AX MCP server — Model Context Protocol interface to the Ax recon dashboard.

Exposes the Flask bridge's capabilities as MCP tools so any MCP client — Claude
Desktop, an agent, or a reporting workflow such as Ghostwriter — can drive the
platform as a specific logged-in account: launch scans and workflows, read
vulnerabilities and scan data, and manage users / teams.

Design notes
------------
* Thin adapter. Every tool calls the existing bridge REST API over HTTP, so all
  business logic, validation and multi-user auth stay in one place (the bridge).
* **Auto-terminate is enforced.** Every scan or workflow launched through MCP
  spins up a fresh fleet and tears it down when done — MCP callers can never
  leave cloud instances running.
* Runs as ONE configured account. Point it at a bridge and give it a token or
  username/password; all actions are attributed to that user. For per-user
  isolation, run one server instance per account.

Configuration (environment variables)
--------------------------------------
  GUIAX_BRIDGE_URL      Bridge base URL           (default http://localhost:5000)
  GUIAX_TOKEN           Bearer token (skips login)
  GUIAX_USERNAME        Username to log in with   (if no token)
  GUIAX_PASSWORD        Password to log in with
  GUIAX_DEFAULT_REGION  Fleet region for new scans (default: bridge/axiom default)
  GUIAX_MAX_INSTANCES   Hard cap on fleet size per scan (default 5)

Run
---
  python3 tools/mcp-server.py                              # stdio (Claude Desktop)
  python3 tools/mcp-server.py --transport streamable-http --host 0.0.0.0 --port 8787
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

# ── Configuration ──────────────────────────────────────────────────────────────
BRIDGE_URL     = os.environ.get("GUIAX_BRIDGE_URL", "http://localhost:5000").rstrip("/")
STATIC_TOKEN   = os.environ.get("GUIAX_TOKEN", "")
USERNAME       = os.environ.get("GUIAX_USERNAME", "")
PASSWORD       = os.environ.get("GUIAX_PASSWORD", "")
DEFAULT_REGION = os.environ.get("GUIAX_DEFAULT_REGION", "")
MAX_INSTANCES  = int(os.environ.get("GUIAX_MAX_INSTANCES", "5"))

# Full-scan recon chain (each entry runs after the previous one). Override by
# building a custom workflow with build_workflow().
FULL_SCAN_CHAIN = ["subfinder", "httpx", "nuclei", "gowitness"]

_token: Optional[str] = STATIC_TOKEN or None


# ── HTTP helper ──────────────────────────────────────────────────────────────
def _headers() -> dict:
    return {"Authorization": f"Bearer {_token}"} if _token else {}


def _req(method: str, path: str, *, json: Any = None, params: dict | None = None) -> Any:
    """Call the bridge. Returns parsed JSON (dict/list) or raises with a clean
    message the model can act on."""
    url = f"{BRIDGE_URL}{path}"
    try:
        resp = httpx.request(method, url, json=json, params=params,
                             headers=_headers(), timeout=120.0)
    except httpx.HTTPError as e:
        raise RuntimeError(f"cannot reach bridge at {url}: {e}") from e
    if resp.status_code >= 400:
        detail = ""
        try:
            detail = resp.json().get("error") or resp.text
        except Exception:
            detail = resp.text
        raise RuntimeError(f"bridge {resp.status_code} on {method} {path}: {detail}")
    if not resp.content:
        return {}
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}


def _login() -> None:
    """Acquire a bearer token from username/password if no static token given."""
    global _token
    if _token or not (USERNAME and PASSWORD):
        return
    try:
        data = _req("POST", "/api/auth/login",
                    json={"username": USERNAME, "password": PASSWORD})
        _token = data.get("token")
        if _token:
            print(f"[mcp] logged in as {USERNAME!r}", file=sys.stderr)
        elif data.get("authRequired") is False:
            print("[mcp] bridge auth disabled — running unauthenticated", file=sys.stderr)
    except Exception as e:
        print(f"[mcp] login failed ({e}); continuing unauthenticated", file=sys.stderr)


def _clamp_instances(n: Optional[int]) -> int:
    if not n or n < 1:
        n = min(3, MAX_INSTANCES)
    return max(1, min(int(n), MAX_INSTANCES))


def _resolve_user_id(user: str, users: list) -> Optional[dict]:
    return next((u for u in users
                 if u.get("id") == user or u.get("username") == user), None)


def _resolve_team_id(team: str, teams: list) -> Optional[dict]:
    return next((t for t in teams
                 if t.get("id") == team or t.get("name") == team), None)


# ── MCP server ─────────────────────────────────────────────────────────────────
mcp = FastMCP(
    "gui-ax",
    instructions=(
        "Drive the GUI-AX distributed recon dashboard: launch scans and workflows, "
        "read vulnerabilities and scan results for reporting (e.g. Ghostwriter), and "
        "manage users and teams. All scans launched here auto-terminate their cloud "
        "fleet when finished."
    ),
)


# ── Scans ────────────────────────────────────────────────────────────────────
@mcp.tool()
def start_scan(module: str, targets: list[str],
               instances: Optional[int] = None,
               region: Optional[str] = None,
               extra_args: Optional[str] = None) -> dict:
    """Launch a single-module scan against targets on a fresh fleet that
    AUTO-TERMINATES when the scan finishes.

    Args:
        module: Ax module name, e.g. "httpx", "nuclei", "nmap", "subfinder".
        targets: list of domains / IPs / CIDRs to scan.
        instances: fleet size (clamped to the server's max; default 3).
        region: cloud region (default: bridge/axiom default).
        extra_args: raw extra CLI args passed to the module.
    Returns the created scan record (includes its id and status).
    """
    if not targets:
        raise ValueError("targets must not be empty")
    n = _clamp_instances(instances)
    scan_name = f"mcp-{module}"
    fleet_control: dict = {"spinup": n, "rmWhenDone": True}
    reg = region or DEFAULT_REGION
    if reg:
        fleet_control["regions"] = [reg]
    payload = {
        "scanName":   scan_name,
        "targets":    targets,
        "module":     module,
        "outputFile": f"{scan_name}.txt",
        "fleetControl": fleet_control,
        "options":    {"extraArgs": extra_args} if extra_args else {},
    }
    return _req("POST", "/api/axiom/scan", json=payload)


@mcp.tool()
def start_full_scan(targets: list[str],
                    name: Optional[str] = None,
                    instances: Optional[int] = None,
                    region: Optional[str] = None) -> dict:
    """Launch a FULL recon pipeline (subfinder → httpx → nuclei → gowitness) as a
    workflow whose fleet AUTO-TERMINATES after each step. Output of each step
    feeds the next. Returns the workflow run info (includes runId).

    Args:
        targets: seed domains / IPs.
        name: optional workflow name.
        instances: max fleet size per step (clamped; default 3).
        region: cloud region.
    """
    steps = [{"module": m, "after": ([i - 1] if i else [])}
             for i, m in enumerate(FULL_SCAN_CHAIN)]
    return build_workflow(name=name or "mcp-full-scan", steps=steps,
                          initial_targets=targets, instances=instances,
                          region=region)


@mcp.tool()
def build_workflow(name: str, steps: list[dict], initial_targets: list[str],
                   instances: Optional[int] = None,
                   region: Optional[str] = None) -> dict:
    """Build and launch a custom multi-step workflow (DAG). Fleets
    AUTO-TERMINATE per step. Returns the run info (includes runId).

    Args:
        name: workflow name.
        steps: ordered list of step specs. Each: {
                  "module": "httpx",              # required Ax module name
                  "after": [0, 2],                # optional 0-based indices of
                                                  #   parent steps (omit/empty =
                                                  #   parallel root fed by
                                                  #   initial_targets)
                  "args": "--extra flags"         # optional raw module args
               }
        initial_targets: seed targets for the root step(s).
        instances: max fleet size per step (clamped; default 3).
        region: cloud region.
    """
    if not steps:
        raise ValueError("steps must not be empty")
    n = _clamp_instances(instances)
    # Assign a stable id per step, then map "after" indices → parent ids.
    ids = [f"s{i}-{os.urandom(3).hex()}" for i in range(len(steps))]
    wf_steps = []
    for i, spec in enumerate(steps):
        module = spec.get("module")
        if not module:
            raise ValueError(f"step {i} is missing 'module'")
        parents = [ids[j] for j in spec.get("after", []) if 0 <= j < len(ids) and j != i]
        wf_steps.append({
            "id":        ids[i],
            "module":    {"name": module},
            "parentIds": parents,
            "customArgs": spec.get("args") or "",
        })
    config = {
        "minInstances":       1,
        "maxInstances":       n,
        "autoTerminateFleet": True,     # enforced — never leave instances running
    }
    if (region or DEFAULT_REGION):
        config["regions"] = [region or DEFAULT_REGION]
    payload = {
        "name":           name,
        "steps":          wf_steps,
        "config":         config,
        "initialTargets": initial_targets,
    }
    return _req("POST", "/api/workflow/run", json=payload)


@mcp.tool()
def list_scans() -> list:
    """List all scans (running and completed) with status and metadata."""
    data = _req("GET", "/api/axiom/scans")
    return data if isinstance(data, list) else data.get("scans", data)


@mcp.tool()
def get_scan(scan_id: str) -> dict:
    """Get full details for one scan, including status and any failure reason."""
    return _req("GET", f"/api/axiom/scans/{scan_id}")


@mcp.tool()
def get_scan_output(scan_id: str) -> dict:
    """Get the raw log output for a scan (useful for report evidence)."""
    return _req("GET", f"/api/axiom/scans/{scan_id}/output")


@mcp.tool()
def get_workflow_status(run_id: str) -> dict:
    """Get a workflow run's status and per-step progress."""
    return _req("GET", f"/api/workflow/{run_id}/status")


# ── Vulnerabilities & targets (reporting) ──────────────────────────────────────
@mcp.tool()
def list_vulnerabilities(severity: Optional[str] = None,
                         target: Optional[str] = None) -> list:
    """List vulnerabilities across all targets — flattened and report-ready.

    Args:
        severity: optional filter, one of critical/high/medium/low/info.
        target: optional filter by target domain or id (substring match).
    Returns a list of findings: {target, severity, name, matched, type, description}.
    """
    targets = _req("GET", "/api/axiom/targets")
    if isinstance(targets, dict):
        targets = targets.get("targets", [])
    out: list[dict] = []
    for t in targets:
        dom = t.get("domain", "")
        if target and target.lower() not in (dom.lower() + " " + t.get("id", "").lower()):
            continue
        for v in t.get("vulnerabilities", []) or []:
            sev = (v.get("severity") or "").lower()
            if severity and sev != severity.lower():
                continue
            out.append({
                "target":      dom,
                "severity":    sev,
                "name":        v.get("name"),
                "matched":     v.get("matched") or v.get("path"),
                "type":        v.get("type"),
                "description": v.get("description"),
            })
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: sev_rank.get(f["severity"], 9))
    return out


@mcp.tool()
def list_targets() -> list:
    """List all targets with summary counts (subdomains, ports, vulns)."""
    targets = _req("GET", "/api/axiom/targets")
    if isinstance(targets, dict):
        targets = targets.get("targets", [])
    return [{
        "id":          t.get("id"),
        "domain":      t.get("domain"),
        "programName": t.get("programName"),
        "subdomains":  len(t.get("subdomains", []) or []),
        "ports":       t.get("totalPorts", 0),
        "vulns":       len(t.get("vulnerabilities", []) or []),
        "lastScan":    t.get("lastScanDate"),
    } for t in targets]


@mcp.tool()
def get_target(target_id: str) -> dict:
    """Get one target's full record: subdomains, ports, vulnerabilities, whois."""
    return _req("GET", f"/api/axiom/targets/{target_id}")


# ── Users, teams & invites (admin) ──────────────────────────────────────────────
@mcp.tool()
def list_users() -> list:
    """List all users (admin). Passwords/tokens are never returned."""
    return _req("GET", "/api/users")


@mcp.tool()
def add_user(username: str, password: str,
             email: Optional[str] = None, role: str = "user") -> dict:
    """Create a new user (admin). role is "user" or "admin". Password ≥ 8 chars."""
    return _req("POST", "/api/users", json={
        "username": username, "password": password,
        "email": email or "", "role": role,
    })


@mcp.tool()
def list_teams() -> list:
    """List all project teams."""
    return _req("GET", "/api/teams")


@mcp.tool()
def create_team(name: str, description: Optional[str] = None) -> dict:
    """Create a new project team (admin)."""
    return _req("POST", "/api/teams", json={
        "name": name, "description": description or "",
    })


@mcp.tool()
def add_user_to_team(user: str, team: str) -> dict:
    """Add a user to a team (admin). Accepts username or user-id, and team name
    or team-id. Returns the updated user record."""
    users = _req("GET", "/api/users")
    teams = _req("GET", "/api/teams")
    u = _resolve_user_id(user, users if isinstance(users, list) else [])
    t = _resolve_team_id(team, teams if isinstance(teams, list) else [])
    if not u:
        raise ValueError(f"user not found: {user!r}")
    if not t:
        raise ValueError(f"team not found: {team!r}")
    new_teams = list(dict.fromkeys((u.get("teams") or []) + [t["id"]]))
    return _req("PATCH", f"/api/users/{u['id']}", json={"teams": new_teams})


@mcp.tool()
def create_invite(team: str, max_uses: int = 5, expiry_days: int = 7) -> dict:
    """Create a team invite (admin). Accepts team name or id. Returns the invite
    (including its token) that a new user can redeem to join the team."""
    teams = _req("GET", "/api/teams")
    t = _resolve_team_id(team, teams if isinstance(teams, list) else [])
    if not t:
        raise ValueError(f"team not found: {team!r}")
    return _req("POST", "/api/invites", json={
        "teamId": t["id"], "maxUses": max_uses, "expiryDays": expiry_days,
    })


# ── Fleet (visibility & safety) ─────────────────────────────────────────────────
@mcp.tool()
def list_fleet() -> Any:
    """List every live cloud instance (provider, region, IP, status, cost)."""
    return _req("GET", "/api/fleet")


@mcp.tool()
def terminate_fleet(prefix: str) -> dict:
    """Terminate all instances whose name starts with `prefix` (cleanup / cost
    safety). Auto-terminating scans normally handle this for you."""
    return _req("POST", "/api/axiom/fleet/rm", json={"prefix": prefix})


@mcp.tool()
def whoami() -> dict:
    """Return the account this MCP server is acting as (username, role, teams)."""
    return _req("GET", "/api/users/me")


# ── Entrypoint ───────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="GUI-AX MCP server")
    ap.add_argument("--transport", default="stdio",
                    choices=["stdio", "sse", "streamable-http"],
                    help="MCP transport (default stdio)")
    ap.add_argument("--host", default=os.environ.get("GUIAX_MCP_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("GUIAX_MCP_PORT", "8787")))
    args = ap.parse_args()

    _login()
    print(f"[mcp] bridge={BRIDGE_URL} transport={args.transport} "
          f"auth={'yes' if _token else 'no'}", file=sys.stderr)

    if args.transport in ("sse", "streamable-http"):
        mcp.settings.host = args.host
        mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
