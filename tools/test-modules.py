#!/usr/bin/env python3
"""
GUI-AX Module Health Tester
============================
Simulates the dashboard calling the bridge API to verify every installed
reconftw/axiom module against a known target (example.com / 104.20.23.154).

• Runs up to 3 modules concurrently — each gets its own instance (--spinup 1)
  that auto-destroys when its scan finishes (--rm-when-done).
• Polls every 5 minutes; records log snapshots and notable events as notes.
• No hard timeout — waits until the bridge marks the scan completed/failed.
• Saves a timestamped JSON report to data/ and prints a summary table.

Usage (from outside the container, or inside via docker exec):
  python3 tools/test-modules.py
  python3 tools/test-modules.py --bridge http://localhost:5000
  python3 tools/test-modules.py --username admin --password secret
  python3 tools/test-modules.py --token mystatictoken
  python3 tools/test-modules.py --modules nmap,httpx,nuclei   # subset
  python3 tools/test-modules.py --output /tmp/results.json
"""

import argparse
import datetime
import json
import os
import re
import sys
import threading
import time
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed — run:  pip3 install requests")
    sys.exit(1)

# ─── Targets ──────────────────────────────────────────────────────────────────
TARGET_DOMAIN = "example.com"
TARGET_IP     = "104.20.23.154"

# Modules that operate primarily on an IP (port scanners)
IP_MODULES = {"nmap", "masscan", "rustscan"}

# ─── Per-module extra args ────────────────────────────────────────────────────
# Only added where the tool genuinely needs flags to work in a container env
# or to complete in a reasonable time.
MODULE_EXTRA_ARGS: dict[str, str] = {
    # nmap — TCP connect scan (no raw sockets / root needed), skip ICMP ping,
    #         service version detect, limit to top 50 ports for speed
    "nmap":     "-sT -sV -Pn --top-ports 50",

    # masscan — raw socket scanner; needs an explicit rate cap + port list
    #           otherwise it floods and gets blocked immediately
    "masscan":  "--rate 100 -p80,443,22,8080,8443,3306,3389",

    # rustscan — raise file-descriptor limit; pass -sT -Pn to its nmap backend
    #            (rustscan calls nmap internally, needs same workarounds)
    "rustscan": "--ulimit 5000 -- -sT -Pn",

    # nuclei — without a template filter it runs 8000+ templates and takes hours;
    #           two lightweight http template directories are enough to confirm the tool works
    "nuclei":   "-severity info,low,medium,high,critical -t http/technologies/ -t http/miscellaneous/ -no-interactsh",

    # amass — without a timeout it can run for many hours on a large domain
    "amass":    "-timeout 3",

    # nikto — prevent interactive prompts; hard cap per-request time
    "nikto":    "-timeout 10 -nointeractive",

    # testssl — fast profile skips low-priority handshake checks; still covers the basics
    "testssl":  "--fast",

    # wpscan — skip the update banner and enumeration so it finishes in seconds
    "wpscan":   "--no-banner --enumerate none",

    # gospider / katana — limit crawl depth so they don't index the whole internet
    "gospider": "-d 1 -t 2",
    "katana":   "-d 2 -timeout 10",
}

# ─── Log analysis ─────────────────────────────────────────────────────────────
# Patterns that mean the tool itself failed to run
_FAIL_PATTERNS: list[re.Pattern] = [
    # ── Binary / script missing ───────────────────────────────────────────────
    re.compile(r"No such file or directory",                re.I),  # bash & zsh & python
    re.compile(r"command not found",                        re.I),
    re.compile(r"bash:.*not found",                         re.I),
    re.compile(r"exec:.*executable file not found",         re.I),
    # ── Docker image unavailable ──────────────────────────────────────────────
    re.compile(r"pull access denied",                       re.I),
    re.compile(r"repository does not exist",                re.I),
    # ── Runtime / invocation errors ───────────────────────────────────────────
    re.compile(r"\[FATAL\]|^FATAL\b",                       re.I | re.M),
    re.compile(r"panic: runtime error",                      re.I),
    re.compile(r"\bpermission denied\b",                    re.I),
    re.compile(r"cannot connect to Docker daemon",           re.I),
    re.compile(r"failed to initialize chrome context",       re.I),  # gowitness / headless
    re.compile(r"puredns error:",                            re.I),  # missing wordlist etc.
    # ── Auth / credential missing ─────────────────────────────────────────────
    re.compile(r"\btoken not found\b",                      re.I),  # github-endpoints etc.
    re.compile(r"error: argument \w+: invalid choice",      re.I),  # CLI version mismatch (e.g. s3scanner v2)
    # ── axiom-scan infra failure ──────────────────────────────────────────────
    re.compile(r"Unable to reach any instance",             re.I),
    re.compile(r"No target provided, or empty target list", re.I),
]

# Patterns that add an informational note without failing the result
_NOTE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"apt-get (update|install)",           re.I), "Package update/install ran (outdated image — expected on first run)"),
    (re.compile(r"go: downloading",                    re.I), "Go module download detected (missing dependency)"),
    (re.compile(r"pip (install|download)",             re.I), "Python dependency install detected"),
    (re.compile(r"\bupgrading\b|\bupdating\b",         re.I), "Tool self-update/upgrade detected in log"),
    (re.compile(r"rate.?limit",                        re.I), "Rate limit encountered"),
    (re.compile(r"\b403 Forbidden\b",                  re.I), "Target returned 403 (tool reached host OK)"),
    (re.compile(r"\b429 Too Many\b",                   re.I), "Target rate-limited the request (Cloudflare)"),
    (re.compile(r"\bcloudflare\b",                     re.I), "Cloudflare WAF/CDN detected on target"),
    (re.compile(r"\bWAF\b"),                                  "WAF detected"),
    # AWS IAM region-blocking noise — informational, not a scan failure
    (re.compile(r"UnauthorizedOperation.*DescribeInstances", re.I),
     "AWS DescribeInstances denied for some regions (blocked by IAM policy) — use --regions to restrict"),
    # axiom SSH preflight errors — will be a FAIL too, but add a note with context
    (re.compile(r"cannot stat.*\.sshconfig",            re.I), "axiom .sshconfig missing — SSH config not built; try --regions <your-region>"),
]

MAX_CONCURRENT = 3
FIRST_POLL_S   = 90    # wait before first status check (instance spin-up takes time)
POLL_INTERVAL  = 300   # seconds between subsequent log snapshots (5 min)


# ─── Bridge client (mirrors what the dashboard does) ─────────────────────────
class BridgeClient:
    def __init__(self, base_url: str, token: str = "",
                 username: str = "", password: str = ""):
        self.base = base_url.rstrip("/")
        self.s    = requests.Session()
        self.s.headers["Content-Type"] = "application/json"
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"
        elif username:
            r = self.s.post(
                f"{self.base}/api/auth/login",
                json={"username": username, "password": password},
                timeout=15,
            )
            r.raise_for_status()
            # Session cookie is stored automatically by requests.Session

    def get_modules(self) -> list[str]:
        r = self.s.get(f"{self.base}/api/axiom/modules", timeout=15)
        r.raise_for_status()
        data = r.json()
        # Bridge returns {"modules": ["amass.json", "httpx.json", ...]}
        if isinstance(data, dict):
            raw = data.get("modules", [])
        elif isinstance(data, list):
            raw = data
        else:
            return []
        result = []
        for m in raw:
            if isinstance(m, dict):
                name = m.get("name", "")
            else:
                name = str(m)
            # Strip .json extension from filenames
            if name.endswith(".json"):
                name = name[:-5]
            if name:
                result.append(name)
        return result

    def _raise_with_body(self, r: requests.Response) -> None:
        """Raise an exception that includes the response body, not just the status line."""
        try:
            body = r.json()
            msg  = body.get("error") or body.get("message") or str(body)
        except Exception:
            msg = r.text[:300] or r.reason
        raise requests.HTTPError(
            f"{r.status_code} {r.reason} — {msg}",
            response=r,
        )

    def launch_scan(self, module: str, target: str,
                    extra_args: str, fleet_prefix: str,
                    regions: list[str] | None = None) -> dict:
        fleet_ctrl: dict = {
            "spinup":      1,
            "fleetPrefix": fleet_prefix,
            "rmWhenDone":  True,   # auto-destroy instance when done
            # useCache intentionally omitted: --cache skips generate_sshconfig,
            # which breaks fresh --spinup instances that aren't in .sshconfig yet.
        }
        if regions:
            fleet_ctrl["regions"] = regions
        payload: dict = {
            "scanName":   f"modtest-{module}",
            "targets":    [target],
            "module":     module,
            "outputFile": f"modtest-{module}.txt",   # required by bridge validation
            # Same fields the Scans page sends when you click "New Scan"
            "fleetControl": fleet_ctrl,
            "options": {
                "threads":     2,
                "quiet":       True,
                "dontShuffle": True,
            },
        }
        if extra_args:
            payload["options"]["extraArgs"] = extra_args
        r = self.s.post(f"{self.base}/api/axiom/scan", json=payload, timeout=30)
        if not r.ok:
            self._raise_with_body(r)
        return r.json()

    def scan_status(self, scan_id: str) -> dict:
        r = self.s.get(f"{self.base}/api/axiom/scans/{scan_id}", timeout=15)
        if r.status_code == 404:
            return {"status": "running"}  # bridge registers the scan async; retry
        if not r.ok:
            self._raise_with_body(r)
        return r.json()

    def scan_logs(self, scan_id: str) -> list[str]:
        r = self.s.get(f"{self.base}/api/axiom/scans/{scan_id}/logs", timeout=15)
        if r.status_code in (404, 204):
            return []
        r.raise_for_status()
        return r.json().get("logs", [])


# ─── Log helpers ──────────────────────────────────────────────────────────────
def _analyse_logs(lines: list[str]) -> tuple[bool, str, list[str]]:
    """Return (is_failed, fail_reason, notes) based on log content."""
    text   = "\n".join(lines)
    failed = False
    reason = ""
    for p in _FAIL_PATTERNS:
        m = p.search(text)
        if m:
            failed = True
            reason = f"Log contains: {m.group(0)!r}"
            break
    notes: list[str] = []
    seen:  set[str]  = set()
    for pat, note in _NOTE_PATTERNS:
        if pat.search(text) and note not in seen:
            notes.append(note)
            seen.add(note)
    return failed, reason, notes


# ─── Per-module runner ────────────────────────────────────────────────────────
class ModuleTester:
    def __init__(self, client: BridgeClient, run_id: str,
                 regions: list[str] | None = None):
        self.client  = client
        self.run_id  = run_id
        self.regions = regions or []
        self.results: list[dict] = []
        self._lock   = threading.Lock()

    def _run_one(self, module: str) -> None:
        target = TARGET_IP if module in IP_MODULES else TARGET_DOMAIN
        extra  = MODULE_EXTRA_ARGS.get(module, "")
        # Fleet prefix: short, alphanumeric + hyphens, unique per run
        safe_mod = re.sub(r"[^a-z0-9]", "", module)[:8]
        prefix   = f"mt{safe_mod}{self.run_id}"    # e.g.  mtnmap3a7f

        started = time.monotonic()

        result: dict = {
            "module":        module,
            "target":        target,
            "extra_args":    extra,
            "status":        "UNKNOWN",
            "results_count": 0,
            "duration_min":  0.0,
            "notes":         [],
            "snapshots":     [],
            "scan_id":       None,
            "error":         None,
        }

        def _p(msg: str) -> None:
            print(f"  [{module}] {msg}", flush=True)

        _p(f"launching → {target}" + (f"  extra={extra!r}" if extra else ""))

        # ── Launch ────────────────────────────────────────────────────────────
        try:
            resp    = self.client.launch_scan(module, target, extra, prefix,
                                              regions=self.regions or None)
            scan_id = resp.get("scanId") or resp.get("id", "")
            if not scan_id:
                raise ValueError(f"No scanId in response: {resp}")
        except Exception as exc:
            result.update(status="FAIL", error=f"Launch failed: {exc}")
            _p(f"✗ FAIL — {exc}")
            self._save(result)
            return

        result["scan_id"] = scan_id
        _p(f"scanId={scan_id}  prefix={prefix}")

        # Give the instance time to come up before first poll
        time.sleep(FIRST_POLL_S)

        # ── Poll loop (no hard timeout — wait for bridge to mark done/failed) ─
        all_notes:  set[str] = set()
        poll_count: int      = 0

        while True:
            poll_count += 1
            elapsed = round((time.monotonic() - started) / 60, 1)

            # Status
            try:
                st_data = self.client.scan_status(scan_id)
            except Exception as exc:
                _p(f"·poll#{poll_count} +{elapsed}m — status error: {exc}")
                time.sleep(POLL_INTERVAL)
                continue

            status      = st_data.get("status", "running")
            progress    = st_data.get("progress", 0)
            num_results = st_data.get("results", 0)

            # Logs
            try:
                log_lines = self.client.scan_logs(scan_id)
            except Exception:
                log_lines = []

            is_failed, fail_reason, notes_now = _analyse_logs(log_lines)
            for n in notes_now:
                all_notes.add(n)

            # Record snapshot for JSON report
            result["snapshots"].append({
                "elapsed_min": elapsed,
                "status":      status,
                "progress":    progress,
                "results":     num_results,
                "log_tail":    log_lines[-25:] if log_lines else [],
                "notes":       notes_now,
            })

            extra_info = f"  ⚠ {fail_reason}" if is_failed else ""
            _p(f"·poll#{poll_count} +{elapsed}m  status={status}  "
               f"progress={progress}%  results={num_results}{extra_info}")

            # ── Definite failure detected in log ──────────────────────────────
            if is_failed:
                result.update(
                    status="FAIL", error=fail_reason,
                    results_count=num_results, duration_min=elapsed,
                    notes=sorted(all_notes),
                )
                _p(f"✗ FAIL — {fail_reason}")
                self._save(result)
                return

            # ── Bridge says scan is done ──────────────────────────────────────
            if status in ("completed", "done", "finished"):
                if num_results == 0:
                    all_notes.add(
                        "Completed with 0 results against example.com "
                        "(expected for some modules on a hardened/proxied target)"
                    )
                result.update(
                    status="PASS", results_count=num_results,
                    duration_min=elapsed, notes=sorted(all_notes),
                )
                _p(f"✓ PASS  results={num_results}  time={elapsed}m")
                self._save(result)
                return

            # ── Bridge explicitly marked as failed ────────────────────────────
            if status == "failed":
                fr = (st_data.get("failure_reason")
                      or "; ".join(st_data.get("failure_lines", []))[:200]
                      or "Bridge marked scan as failed")
                result.update(
                    status="FAIL", error=fr,
                    results_count=num_results, duration_min=elapsed,
                    notes=sorted(all_notes),
                )
                _p(f"✗ FAIL — {fr}")
                self._save(result)
                return

            # Still running — wait for next poll window
            time.sleep(POLL_INTERVAL)

    def _save(self, result: dict) -> None:
        with self._lock:
            self.results.append(result)

    def run_all(self, modules: list[str]) -> None:
        sem = threading.Semaphore(MAX_CONCURRENT)

        def go(mod: str) -> None:
            with sem:
                self._run_one(mod)

        threads = [threading.Thread(target=go, args=(m,), daemon=True) for m in modules]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


# ─── Report ───────────────────────────────────────────────────────────────────
_ICONS = {"PASS": "✓ PASS", "FAIL": "✗ FAIL", "UNKNOWN": "? UNKNOWN"}

def _print_report(results: list[dict]) -> None:
    W = 105
    counts: dict[str, int] = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0}

    print()
    print("═" * W)
    print("  GUI-AX MODULE HEALTH REPORT — " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("═" * W)
    print(f"  {'Module':<16} {'Result':<12} {'Target':<22} "
          f"{'Res':>5} {'Time':>6}  Notes")
    print("─" * W)

    for r in sorted(results, key=lambda x: (x["status"] != "FAIL", x["module"])):
        st   = r["status"]
        icon = _ICONS.get(st, st)
        counts[st] = counts.get(st, 0) + 1

        # Build notes string — failure reason takes priority if present
        note_parts = list(r["notes"])
        if r["error"] and r["error"] not in note_parts:
            note_parts.insert(0, r["error"])
        notes_str = "; ".join(note_parts) if note_parts else "—"
        if len(notes_str) > 65:
            notes_str = notes_str[:62] + "…"

        print(
            f"  {r['module']:<16} {icon:<12} {r['target']:<22} "
            f"{r['results_count']:>5} {r['duration_min']:>5.1f}m  {notes_str}"
        )

    print("─" * W)
    print(f"  ✓ PASS: {counts.get('PASS', 0)}   "
          f"✗ FAIL: {counts.get('FAIL', 0)}   "
          f"? UNKNOWN: {counts.get('UNKNOWN', 0)}   "
          f"Total: {len(results)}")
    print("═" * W)


# ─── Entry point ──────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(
        description="GUI-AX Module Health Tester — verifies every installed module works",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--bridge",   default="http://localhost:5000",
                    help="Bridge base URL (default: http://localhost:5000)")
    ap.add_argument("--token",    default="",
                    help="Static bearer token (Settings → Static Token)")
    ap.add_argument("--username", default="",
                    help="Username (if login is enabled)")
    ap.add_argument("--password", default="",
                    help="Password")
    ap.add_argument("--modules",  default="",
                    help="Comma-separated list of modules to test (default: all installed)")
    ap.add_argument("--output",   default="",
                    help="JSON output path (default: data/module-test-<timestamp>.json)")
    ap.add_argument("--skip",     default="",
                    help="Comma-separated list of modules to skip")
    ap.add_argument("--regions",  default="",
                    help="Comma-separated AWS regions to use (e.g. eu-west-3). "
                         "Restricts axiom to only these regions so blocked "
                         "regions don't break SSH config generation. "
                         "Matches your axiom account's configured region.")
    args = ap.parse_args()

    # Unique 4-char run ID so fleet prefixes don't collide across runs
    run_id = f"{int(time.time()) % 65536:04x}"

    print(f"\n→ Connecting to bridge at {args.bridge} …")
    try:
        client = BridgeClient(
            args.bridge,
            token    = args.token    or "",
            username = args.username or "",
            password = args.password or "",
        )
    except requests.HTTPError as exc:
        print(f"ERROR: Authentication failed — {exc}")
        sys.exit(1)
    except requests.ConnectionError:
        print(f"ERROR: Cannot reach bridge at {args.bridge}\n"
              "       Is the container running?  docker compose up")
        sys.exit(1)

    print("→ Fetching installed modules from bridge …")
    try:
        installed = client.get_modules()
    except requests.HTTPError as exc:
        print(f"ERROR: Modules endpoint returned HTTP error — {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR fetching modules ({type(exc).__name__}): {exc}")
        sys.exit(1)

    # Build module list
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    else:
        modules = installed

    if args.skip:
        skip_set = {m.strip() for m in args.skip.split(",")}
        modules  = [m for m in modules if m not in skip_set]

    if not modules:
        print("ERROR: No modules to test. Is Axiom configured inside the container?")
        sys.exit(1)

    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    # Print plan before launching anything
    reg_str = f" · regions={','.join(regions)}" if regions else " · ⚠ no --regions set (may hit IAM-blocked regions)"
    print(f"\n→ {len(modules)} module(s) queued  "
          f"[max {MAX_CONCURRENT} concurrent · polling every {POLL_INTERVAL // 60} min · "
          f"run-id {run_id}{reg_str}]\n")
    col = 16
    for m in modules:
        tgt  = TARGET_IP if m in IP_MODULES else TARGET_DOMAIN
        xtra = MODULE_EXTRA_ARGS.get(m, "")
        xstr = f"  extra={xtra!r}" if xtra else ""
        print(f"    {m:<{col}} → {tgt}{xstr}")
    print()

    tester = ModuleTester(client, run_id, regions=regions)
    tester.run_all(modules)

    _print_report(tester.results)

    # Save JSON report
    ts       = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.output or f"data/module-test-{ts}.json"
    try:
        out_dir = os.path.dirname(out_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        report = {
            "generated":     datetime.datetime.now().isoformat(),
            "bridge":        args.bridge,
            "run_id":        run_id,
            "target_domain": TARGET_DOMAIN,
            "target_ip":     TARGET_IP,
            "modules_total": len(modules),
            "results":       tester.results,
        }
        with open(out_path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n→ Full JSON report (with log snapshots) saved to: {out_path}\n")
    except Exception as exc:
        print(f"\nWARN: Could not save JSON report: {exc}\n")


if __name__ == "__main__":
    main()
