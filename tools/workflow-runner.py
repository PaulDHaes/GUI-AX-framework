#!/usr/bin/env python3
"""
GUI-AX Workflow Runner
======================
Backend step sequencer for GUI-AX workflows.  Replaces the browser-side
Promise scheduler so execution continues even if the tab is closed, and
produces a persistent verbose log for debugging step ordering issues.

Usage (called by axiom-bridge.py, not directly):
  python3 tools/workflow-runner.py --run-id <id> --workflow-file <path.json>

Logs written to:  /tmp/workflow-logs/<run-id>.log
Status written to: /tmp/workflow-logs/<run-id>.status.json
"""

import argparse
import json
import os
import subprocess
import sys
import time
import threading
import traceback
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ─── Config ────────────────────────────────────────────────────────────────────
BRIDGE_URL    = os.environ.get("BRIDGE_URL",      "http://localhost:5000")
BRIDGE_TOKEN  = os.environ.get("WF_BRIDGE_TOKEN", "")   # Bearer token for bridge auth
LOG_DIR       = os.environ.get("WF_LOG_DIR",      "/tmp/workflow-logs")
POLL_INTERVAL = int(os.environ.get("WF_POLL_INTERVAL", "8"))   # seconds
SCAN_TIMEOUT  = int(os.environ.get("WF_SCAN_TIMEOUT",  "1800")) # 30 min


# ─── Utilities ─────────────────────────────────────────────────────────────────
def _ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]

def _utciso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Logger:
    def __init__(self, run_id: str):
        os.makedirs(LOG_DIR, exist_ok=True)
        self.log_path = os.path.join(LOG_DIR, f"{run_id}.log")

    def _w(self, level: str, msg: str):
        line = f"[{_ts()}] [{level:<5}] {msg}"
        print(line, flush=True)
        with open(self.log_path, "a") as f:
            f.write(line + "\n")

    def info(self,  msg): self._w("INFO",  msg)
    def warn(self,  msg): self._w("WARN",  msg)
    def error(self, msg): self._w("ERROR", msg)
    def debug(self, msg): self._w("DEBUG", msg)
    def sep(self):        self._w("INFO",  "─" * 60)


class StatusTracker:
    """Thread-safe JSON status file written alongside the log."""
    def __init__(self, run_id: str):
        os.makedirs(LOG_DIR, exist_ok=True)
        self.path = os.path.join(LOG_DIR, f"{run_id}.status.json")
        self._lock = threading.Lock()
        self.data: dict = {
            "runId":     run_id,
            "status":    "running",
            "startedAt": _utciso(),
            "endedAt":   None,
            "steps":     {},
        }
        self._save()

    def step(self, step_id: str, **kwargs):
        with self._lock:
            if step_id not in self.data["steps"]:
                self.data["steps"][step_id] = {}
            self.data["steps"][step_id].update(kwargs)
            self._save()

    def finish(self, status: str):
        with self._lock:
            self.data["status"]  = status
            self.data["endedAt"] = _utciso()
            self._save()

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        os.replace(tmp, self.path)  # atomic write


# ─── HTTP helpers ───────────────────────────────────────────────────────────────
def _post(url: str, payload: dict, log: Logger) -> dict:
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if BRIDGE_TOKEN:
        headers["Authorization"] = f"Bearer {BRIDGE_TOKEN}"
    req = urllib.request.Request(
        url, data=data,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _get(url: str, log: Logger, timeout: int = 15) -> dict:
    headers = {}
    if BRIDGE_TOKEN:
        headers["Authorization"] = f"Bearer {BRIDGE_TOKEN}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


# ─── DAG helpers ───────────────────────────────────────────────────────────────
def topo_sort(steps: list) -> list:
    """Return steps in topological order (all parents before any child)."""
    id_map   = {s["id"]: s for s in steps}
    visited  = set()
    order    = []

    def visit(sid):
        if sid in visited:
            return
        visited.add(sid)
        for pid in (id_map.get(sid, {}).get("parentIds") or []):
            if pid in id_map:
                visit(pid)
        order.append(id_map[sid])

    for s in steps:
        visit(s["id"])
    return order


def build_waves(ordered: list, enabled_ids: set) -> list[list]:
    """
    Group ordered steps into execution waves.
    Steps in the same wave have no dependency on each other and can run
    in parallel (true siblings).  Each wave must fully complete before the
    next wave starts.
    """
    waves = []
    assigned: set = set()

    while len(assigned) < len(ordered):
        wave = []
        for s in ordered:
            if s["id"] in assigned:
                continue
            live_parents = [
                p for p in (s.get("parentIds") or [])
                if p in enabled_ids
            ]
            if all(p in assigned for p in live_parents):
                wave.append(s)
        if not wave:
            # Cycle guard — shouldn't happen with a valid DAG
            break
        for s in wave:
            assigned.add(s["id"])
        waves.append(wave)

    return waves


# ─── Axiom filesystem helpers ──────────────────────────────────────────────────
AXIOM_TMP_DIR  = os.path.expanduser("~/.axiom/tmp")
AXIOM_LOGS_DIR = os.path.expanduser("~/.axiom/logs")
IMPORTS_DIR    = os.environ.get("IMPORTS_PATH", "/app/imports")


def _find_axiom_folder(module_name: str, min_mtime: float) -> tuple:
    """
    Return (folder_path, scan_id, location) for the most recent axiom scan
    folder for *module_name* that was created/modified after *min_mtime*.

    location is 'logs' (completed) or 'tmp' (still running).
    Looks in logs first so a completed scan is preferred over a running one.
    """
    best = None  # (mtime, folder, scan_id, location)
    for base, loc in [(AXIOM_LOGS_DIR, "logs"), (AXIOM_TMP_DIR, "tmp")]:
        if not os.path.isdir(base):
            continue
        for d in os.listdir(base):
            if not d.startswith(module_name + "+"):
                continue
            folder = os.path.join(base, d)
            if not os.path.isdir(folder):
                continue
            try:
                mtime = os.path.getmtime(folder)
            except OSError:
                continue
            if mtime < min_mtime:
                continue
            if best is None or mtime > best[0]:
                best = (mtime, folder, d, loc)
    if best:
        return best[1], best[2], best[3]
    return None, None, None


def _read_stats_entry(axiom_scan_id: str) -> dict:
    """Return the stats.log dict entry for a given axiom scan ID, or {}."""
    stats_path = os.path.expanduser("~/.axiom/stats.log")
    if not os.path.exists(stats_path):
        return {}
    try:
        with open(stats_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        # Scan backwards so the most recent entry wins
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if "scan" not in entry:
                    continue
                for _module, scan_data in entry["scan"].items():
                    if scan_data.get("id") == axiom_scan_id:
                        return scan_data
            except json.JSONDecodeError:
                continue
    except Exception:
        pass
    return {}


def _notify_bridge_complete(bridge_scan_id: str, result_count: int, output_path: str, log: Logger):
    """Tell the bridge to mark a scan as completed with its result count."""
    try:
        _post(f"{BRIDGE_URL}/api/axiom/scans/{bridge_scan_id}/complete",
              {"resultCount": result_count, "outputPath": output_path}, log)
        log.info(f"    bridge notified: scan {bridge_scan_id!r} → completed  results={result_count}")
    except Exception as e:
        log.warn(f"    bridge notify failed (non-fatal): {e}")


def _read_axiom_output(folder_path: str, log: Logger) -> list:
    """Read all non-empty lines from the axiom scan's output/ directory."""
    out_dir = os.path.join(folder_path, "output")
    if not os.path.isdir(out_dir):
        log.debug(f"    no output/ dir in {folder_path}")
        return []
    lines = []
    for fname in sorted(os.listdir(out_dir)):
        fp = os.path.join(out_dir, fname)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        lines.append(line)
        except Exception as e:
            log.warn(f"    could not read output file {fp}: {e}")
    seen = set()
    deduped = [x for x in lines if not (x in seen or seen.add(x))]  # type: ignore
    log.info(f"    read {len(deduped)} unique line(s) from axiom output/")
    return deduped


def _read_imports_file(scan_id: str, log: Logger) -> list:
    """Read the bridge's imports file for this scan (fallback output source).
    
    Searches both IMPORTS_DIR itself and one level of subdirectories
    (e.g. /app/imports/gowitness/<scan_id>/).
    Binary-output modules (gowitness, aquatone) whose directories contain
    only non-text files return a synthetic list of file paths so downstream
    steps and result counts stay meaningful.
    """
    # Candidate flat files
    for ext in (".txt", ".json", ".csv", ""):
        fp = os.path.join(IMPORTS_DIR, f"{scan_id}{ext}")
        if os.path.isfile(fp):
            try:
                lines = []
                with open(fp, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            lines.append(line)
                log.info(f"    read {len(lines)} line(s) from imports file {fp}")
                return lines
            except Exception as e:
                log.warn(f"    could not read imports file {fp}: {e}")

    # Candidate subdirectory: /app/imports/<module>/<scan_id> or /app/imports/<scan_id>
    module_hint = scan_id.split("+")[0] if "+" in scan_id else ""
    candidate_dirs = []
    if module_hint:
        candidate_dirs.append(os.path.join(IMPORTS_DIR, module_hint, scan_id))
        candidate_dirs.append(os.path.join(IMPORTS_DIR, module_hint, scan_id + "."))
    candidate_dirs.append(os.path.join(IMPORTS_DIR, scan_id))

    for dpath in candidate_dirs:
        if not os.path.isdir(dpath):
            continue
        # Try to read text files first
        text_lines: list = []
        binary_files: list = []
        for fname in sorted(os.listdir(dpath)):
            fp = os.path.join(dpath, fname)
            if not os.path.isfile(fp):
                continue
            _, ext = os.path.splitext(fname.lower())
            if ext in (".jpeg", ".jpg", ".png", ".gif", ".webp", ".sqlite3", ".db"):
                binary_files.append(fp)
            else:
                try:
                    with open(fp, encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                text_lines.append(line)
                except Exception:
                    binary_files.append(fp)
        if text_lines:
            seen = set()
            deduped = [x for x in text_lines if not (x in seen or seen.add(x))]  # type: ignore
            log.info(f"    read {len(deduped)} line(s) from subdir {dpath}")
            return deduped
        if binary_files:
            log.info(f"    found {len(binary_files)} binary output file(s) in {dpath} — using file paths as result list")
            return binary_files
    return []


# ─── Scan polling (filesystem-first) ───────────────────────────────────────────
def wait_for_scan(
    scan_id: str,
    launch_time: float,
    log: Logger,
    abort_event: threading.Event,
    timeout: int = SCAN_TIMEOUT,
) -> dict:
    """
    Wait for an axiom scan to complete.

    Strategy (in priority order each poll tick):
    1. Check ~/.axiom/logs/ for a folder matching {module}+* newer than
       launch_time that has a completion marker  → completed.
    2. Check ~/.axiom/tmp/  for the same pattern → still running (log only).
    3. Ask the bridge API for exact scan_id match → completed/failed.

    The bridge API is used as a fallback only and the module-prefix fuzzy
    match is restricted to scans whose folder mtime >= launch_time, which
    prevents old completed scans from triggering a false positive.
    """
    deadline      = time.time() + timeout
    module_name   = scan_id.split("+")[0] if "+" in scan_id else scan_id
    # Allow 60 s before launch in case the axiom folder was created slightly
    # before the bridge returned the scan_id to us.
    min_mtime     = launch_time - 60
    last_fs_log   = None
    last_api_log  = None
    axiom_folder  = None   # filled once we find the folder
    axiom_scan_id = None

    log.info(f"    wait_for_scan: module={module_name}  min_mtime={min_mtime:.0f}  timeout={timeout}s")

    while time.time() < deadline:
        if abort_event.is_set():
            raise RuntimeError("workflow aborted")

        # ── 1 & 2: Filesystem check ─────────────────────────────────────────
        folder, fsid, loc = _find_axiom_folder(module_name, min_mtime)
        if folder:
            axiom_folder  = folder
            axiom_scan_id = fsid
            if loc == "logs":
                # Axiom only moves a folder to logs/ when the scan is fully done.
                # No further completion marker check needed.
                log.info(f"    poll → COMPLETED on filesystem: {fsid}  ({folder})")
                return {"id": fsid, "status": "completed",
                        "axiomFolder": folder, "axiomScanId": fsid}
            else:
                msg = f"running in axiom {loc}/: {fsid}"
                if msg != last_fs_log:
                    log.debug(f"    poll → {msg}")
                    last_fs_log = msg
        else:
            if last_fs_log != "not_found":
                log.debug(f"    poll → no {module_name}+* folder yet (min_mtime={min_mtime:.0f})")
                last_fs_log = "not_found"

        # ── 3: Bridge API (exact match only, no old-scan prefix match) ──────
        try:
            scans = _get(f"{BRIDGE_URL}/api/axiom/scans", log, timeout=10)
            for s in scans:
                sid = s.get("id", "")
                # Exact match on the bridge's scan_id
                if sid != scan_id:
                    continue
                status = (s.get("status") or "").lower()
                msg = f"bridge status={status!r} ({sid})"
                if msg != last_api_log:
                    log.info(f"    poll → {msg}")
                    last_api_log = msg
                if status in ("completed", "done", "finished", "success"):
                    return s
                if status in ("failed", "error", "aborted"):
                    raise RuntimeError(f"scan {status}: {s.get('error', '')}")
        except RuntimeError:
            raise
        except Exception as e:
            log.debug(f"    poll → bridge API error (non-fatal): {e}")

        time.sleep(POLL_INTERVAL)

    raise RuntimeError(
        f"scan timed out after {timeout}s  "
        f"(last axiom folder: {axiom_scan_id or 'none found'})"
    )


def extract_outputs(scan_result: dict, output_type: str, log: Logger) -> list:
    """
    Extract output lines from a completed scan.

    Priority:
    1. Stats.log output path  (set directly by axiom-scan, most reliable)
    2. Axiom logs output/     (text results in the axiom logs folder)
    3. Bridge imports file    ({scan_id}.txt or subdirectory in /app/imports)
    4. Bridge /targets API    (parsed store — often empty for new scans)
    """
    # 1. Stats.log output path — most reliable, set directly by axiom-scan
    stats_output = scan_result.get("statsOutputPath", "")
    if stats_output:
        # Could be a directory (gowitness) or a file (subfinder)
        if os.path.isfile(stats_output):
            try:
                lines = []
                with open(stats_output, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            lines.append(line)
                if lines:
                    seen = set()
                    deduped = [x for x in lines if not (x in seen or seen.add(x))]  # type: ignore
                    log.info(f"    read {len(deduped)} line(s) from stats output file {stats_output}")
                    return deduped
            except Exception as e:
                log.warn(f"    could not read stats output file {stats_output}: {e}")
        elif os.path.isdir(stats_output):
            lines = _read_axiom_output(stats_output, log) or \
                    _read_imports_file(os.path.basename(stats_output.rstrip(".")), log)
            if lines:
                return lines

    # 2. Axiom logs output folder
    axiom_folder = scan_result.get("axiomFolder")
    if axiom_folder and os.path.isdir(axiom_folder):
        lines = _read_axiom_output(axiom_folder, log)
        if lines:
            return lines

    # 3. Bridge imports file — try the bridge scan_id first (it matches
    #    the -o filename), then fall back to the axiom folder name.
    tried_ids: list = []
    for sid in [
        scan_result.get("bridgeScanId"),
        scan_result.get("id"),
        scan_result.get("axiomScanId"),
    ]:
        if sid and sid not in tried_ids:
            tried_ids.append(sid)
            lines = _read_imports_file(sid, log)
            if lines:
                return lines

    # 4. Bridge API fallback
    fallback_id = scan_result.get("bridgeScanId") or scan_result.get("id") or scan_result.get("axiomScanId", "")
    if fallback_id:
        try:
            result = _get(f"{BRIDGE_URL}/api/axiom/scans/{fallback_id}/targets", log)
            items  = result.get("targets") or result.get("items") or []
            if items:
                log.info(f"    extracted {len(items)} item(s) from bridge /targets")
                return [str(i) for i in items]
        except Exception as e:
            log.warn(f"    bridge /targets failed: {e}")

    log.warn("    all output extraction methods returned 0 results")
    return []


# ─── Fleet termination ─────────────────────────────────────────────────────────
def _terminate_fleet_instances(fleet_prefix: str, count: int, log: Logger):
    """
    Delete axiom fleet instances that were spun up for a step.
    Tries both zero-padded (recon01) and plain (recon1) name formats.
    """
    if not fleet_prefix:
        log.warn("    autoTerminate: no fleet prefix set, cannot terminate instances")
        return
    terminated = 0
    for i in range(1, count + 1):
        candidates = [f"{fleet_prefix}{i:02d}", f"{fleet_prefix}{i}"]
        for name in candidates:
            try:
                result = subprocess.run(
                    ["axiom", "rm", name, "--force"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    log.info(f"    ✓ terminated: {name}")
                    terminated += 1
                    break
                else:
                    log.debug(f"    axiom rm {name}: {result.stderr.strip()}")
            except FileNotFoundError:
                log.warn("    autoTerminate: 'axiom' not found in PATH")
                return
            except Exception as exc:
                log.debug(f"    could not terminate {name}: {exc}")
    log.info(f"    autoTerminate: {terminated}/{count} instance(s) terminated")


# ─── Step executor ──────────────────────────────────────────────────────────────
def compute_fleet_size(weight: int, min_i: int, max_i: int, target_count: int) -> int:
    lo  = max(1, min(min_i, max_i))
    hi  = max(lo, max_i)
    t   = max(0.0, min(1.0, (weight - 1) / 4.0))
    raw = round(lo + (hi - lo) * t)
    # Never spin up more instances than there are targets
    return max(1, min(raw, target_count))


def run_step(
    step: dict,
    outputs: dict,          # mutated in-place: step_id → [str]
    initial_targets: list,
    enabled_ids: set,
    safe_name: str,
    config: dict,
    log: Logger,
    status: StatusTracker,
    abort_event: threading.Event,
    all_steps: list,
):
    step_id     = step["id"]
    module_name = step["module"]["name"]
    short_id    = step_id[-6:]
    parent_ids  = [p for p in (step.get("parentIds") or []) if p in enabled_ids]

    log.sep()
    log.info(f"STEP  module={module_name}  id={short_id}  parents={[p[-6:] for p in parent_ids]}")
    status.step(step_id, status="running", startedAt=_utciso(), module=module_name)

    # ── 1. Resolve input targets ────────────────────────────────────────────────
    if not parent_ids:
        input_targets = list(initial_targets)
        log.info(f"  ← root step  →  {len(input_targets)} initial target(s)")
    else:
        merged = []
        for pid in parent_ids:
            parent_out = outputs.get(pid, [])
            log.info(f"  ← parent [{pid[-6:]}] → {len(parent_out)} target(s): {parent_out[:5]}")
            merged.extend(parent_out)
        # Deduplicate while preserving order
        seen = set()
        input_targets = [x for x in merged if not (x in seen or seen.add(x))]  # type: ignore[func-returns-value]
        if not input_targets:
            log.warn("  ← parents returned 0 targets, falling back to initial targets")
            input_targets = list(initial_targets)
        log.info(f"  ← merged {len(input_targets)} unique target(s) from {len(parent_ids)} parent(s)")

    if not input_targets:
        log.warn("  ← 0 targets — marking as skipped")
        status.step(step_id, status="skipped", error="no targets", endedAt=_utciso())
        outputs[step_id] = []
        return

    # ── 2. Compute fleet size ───────────────────────────────────────────────────
    weight    = step["module"].get("weight", 3)
    min_inst  = config.get("minInstances", 1)
    max_inst  = config.get("maxInstances", 5)
    fleet_sz  = compute_fleet_size(weight, min_inst, max_inst, len(input_targets))
    scan_name = f"wf-{safe_name}-{short_id}-{module_name}"
    # Per-step fleet prefix: use global prefix as base, append step short_id to
    # make it unique so we know exactly which instances to terminate afterwards.
    global_prefix = config.get("fleetPrefix") or ""
    step_fleet_prefix = f"{global_prefix}{short_id[:4]}" if global_prefix else f"wf{short_id[:4]}"
    log.info(f"  → scan_name={scan_name}  fleet={fleet_sz}  step_fleet_prefix={step_fleet_prefix!r}  targets={len(input_targets)}")

    # ── 3. Launch scan via bridge ───────────────────────────────────────────────
    payload = {
        "scanName":    scan_name,
        "targets":     input_targets,
        "module":      module_name,
        "outputFile":  f"{scan_name}.txt",
        "fleetControl": {
            "fleetPrefix": step_fleet_prefix,
            "spinup":      fleet_sz,
        },
        "options": {"extraArgs": step.get("customArgs") or None},
    }

    try:
        log.info("  → POSTing to bridge /api/axiom/scan …")
        launch_time = time.time()  # record BEFORE the call so we don't miss fast scans
        launched    = _post(f"{BRIDGE_URL}/api/axiom/scan", payload, log)
        scan_id     = launched.get("scanId") or scan_name
        tmux_sess   = launched.get("tmuxSession", "?")
        log.info(f"  → scan_id={scan_id!r}  tmux={tmux_sess}  launch_time={launch_time:.0f}")
        status.step(step_id, scanId=scan_id)
    except Exception as e:
        log.error(f"  ✗ failed to launch scan: {e}")
        status.step(step_id, status="failed", error=str(e), endedAt=_utciso())
        outputs[step_id] = []
        return

    # ── 4. Wait for completion (filesystem-first) ───────────────────────────────
    try:
        log.info("  → waiting for scan to complete …")
        completed = wait_for_scan(scan_id, launch_time, log, abort_event)
        # Preserve the bridge's scan_id so extract_outputs can find the
        # imports file (named after the bridge ID, not the axiom folder name).
        completed["bridgeScanId"] = scan_id

        # Read the real result count + output path from stats.log (the axiom
        # folder ID is the key used there, not the bridge scan_id).
        axiom_scan_id = completed.get("axiomScanId", "")
        stats_entry   = _read_stats_entry(axiom_scan_id) if axiom_scan_id else {}
        result_count  = int(stats_entry.get("results", 0)) or \
                        completed.get("resultCount") or completed.get("results") or 0
        output_path   = stats_entry.get("output", "")
        if output_path:
            completed["statsOutputPath"] = output_path

        # Notify the bridge so the scan record flips from "running" → "completed"
        _notify_bridge_complete(scan_id, result_count, output_path, log)

        log.info(f"  → scan completed!  resultCount={result_count}")
    except RuntimeError as e:
        log.error(f"  ✗ scan wait failed: {e}")
        status.step(step_id, status="failed", error=str(e), endedAt=_utciso())
        outputs[step_id] = []
        return

    # ── 5. Extract outputs for downstream steps ─────────────────────────────────
    has_downstream = any(
        step_id in (s.get("parentIds") or [])
        for s in all_steps
    )
    if has_downstream:
        log.info("  → extracting outputs for downstream step(s) …")
        step_out = extract_outputs(completed, step["module"].get("outputType", "domains"), log)
        if not step_out:
            log.warn("  → 0 outputs extracted, passing input targets downstream")
            step_out = input_targets
    else:
        step_out = []
        log.info("  → leaf step — no output extraction needed")

    outputs[step_id] = step_out
    status.step(step_id, status="completed", resultCount=result_count,
                outputCount=len(step_out), endedAt=_utciso())
    log.info(f"  ✓ DONE  module={module_name}  results={result_count}  outputs_for_downstream={len(step_out)}")

    # ── 6. Auto-terminate fleet instances ───────────────────────────────────────
    if config.get("autoTerminateFleet"):
        log.info(f"  → auto-terminating {fleet_sz} instance(s) with prefix {step_fleet_prefix!r} …")
        _terminate_fleet_instances(step_fleet_prefix, fleet_sz, log)


# ─── Main runner ────────────────────────────────────────────────────────────────
def run_workflow(run_id: str, workflow: dict, log: Logger, status: StatusTracker):
    steps_raw       = workflow.get("steps", [])
    config          = workflow.get("config", {})
    initial_targets = workflow.get("initialTargets", [])
    workflow_name   = workflow.get("name", run_id)
    safe_name       = "".join(c if c.isalnum() or c in "-_" else "-" for c in workflow_name)[:24]

    enabled_steps = [s for s in steps_raw if s.get("enabled", True)]
    enabled_ids   = {s["id"] for s in enabled_steps}

    log.sep()
    log.info(f"WORKFLOW      : {workflow_name}")
    log.info(f"RUN ID        : {run_id}")
    log.info(f"ENABLED STEPS : {len(enabled_steps)} / {len(steps_raw)}")
    log.info(f"INITIAL TARGETS: {len(initial_targets)}")
    log.info(f"CONFIG        : minInstances={config.get('minInstances',1)}  "
             f"maxInstances={config.get('maxInstances',5)}  "
             f"fleetPrefix={config.get('fleetPrefix','(none)')}")
    log.sep()

    # Topological order + wave grouping
    ordered = topo_sort(enabled_steps)
    waves   = build_waves(ordered, enabled_ids)

    log.info(f"EXECUTION PLAN ({len(waves)} wave(s)):")
    for wi, wave in enumerate(waves):
        for s in wave:
            pids = [p for p in (s.get("parentIds") or []) if p in enabled_ids]
            log.info(
                f"  Wave {wi+1}  {s['module']['name']:<20} id={s['id'][-6:]}  "
                f"parents=[{', '.join(p[-6:] for p in pids)}]"
            )
    log.sep()

    # Validate parentIds — warn about any step whose parentId points to a disabled or missing step
    all_ids = {s["id"] for s in steps_raw}
    for s in enabled_steps:
        for pid in (s.get("parentIds") or []):
            if pid not in all_ids:
                log.warn(f"WARN: step {s['module']['name']} (id={s['id'][-6:]}) references "
                         f"unknown parentId {pid[-6:]} — will be treated as root!")
            elif pid not in enabled_ids:
                log.warn(f"WARN: step {s['module']['name']} (id={s['id'][-6:]}) references "
                         f"DISABLED parent {pid[-6:]} — will skip that dependency.")

    abort_event = threading.Event()
    outputs: dict = {}   # step_id → [str]

    for wi, wave in enumerate(waves):
        if abort_event.is_set():
            break

        names = [s["module"]["name"] for s in wave]
        log.info(f"▶ Wave {wi+1}/{len(waves)}: [{', '.join(names)}]  "
                 f"({'parallel' if len(wave) > 1 else 'sequential'})")

        if len(wave) == 1:
            run_step(wave[0], outputs, initial_targets, enabled_ids,
                     safe_name, config, log, status, abort_event, enabled_steps)
        else:
            # Run siblings in parallel threads
            errors: list = []

            def _run(s):
                try:
                    run_step(s, outputs, initial_targets, enabled_ids,
                             safe_name, config, log, status, abort_event, enabled_steps)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=_run, args=(s,), daemon=True) for s in wave]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            if errors:
                log.warn(f"  {len(errors)} step(s) in wave {wi+1} reported errors (continuing)")

        log.info(f"  Wave {wi+1} complete\n")

    log.sep()
    log.info("ALL WAVES COMPLETE")
    log.sep()


# ─── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="GUI-AX Workflow Runner")
    parser.add_argument("--run-id",        required=True, help="Unique run identifier")
    parser.add_argument("--workflow-file", required=True, help="Path to workflow JSON file")
    args = parser.parse_args()

    log    = Logger(args.run_id)
    status = StatusTracker(args.run_id)

    log.info(f"workflow-runner.py starting  run-id={args.run_id}")
    log.info(f"workflow file: {args.workflow_file}")
    log.info(f"bridge URL:    {BRIDGE_URL}")
    log.info(f"log dir:       {LOG_DIR}")

    try:
        with open(args.workflow_file) as f:
            workflow = json.load(f)
    except Exception as e:
        log.error(f"Failed to load workflow file: {e}")
        status.finish("failed")
        sys.exit(1)

    try:
        run_workflow(args.run_id, workflow, log, status)
        status.finish("completed")
        log.info("workflow-runner.py DONE — status: completed")
    except Exception as e:
        log.error(f"Workflow runner crashed: {e}")
        traceback.print_exc()
        status.finish("failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
