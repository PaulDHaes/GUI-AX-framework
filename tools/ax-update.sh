#!/usr/bin/env bash
# ax-update.sh — Update the Ax framework using its built-in 'ax update' command
#
# Usage:
#   bash tools/ax-update.sh              # run ax update
#   bash tools/ax-update.sh --restart    # also restart the bridge after update
#   bash tools/ax-update.sh --help
#
# The dashboard also calls this via GET /api/axiom/update (streaming response).

set -euo pipefail

# ─── colours ──────────────────────────────────────────────────────────────────
Color_Off='\033[0m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
BRed='\033[1;31m'
BCyan='\033[1;36m'
BWhite='\033[1;37m'

info()    { echo -e "${BGreen}[+]${Color_Off} $*"; }
warn()    { echo -e "${BYellow}[!]${Color_Off} $*"; }
error()   { echo -e "${BRed}[✗]${Color_Off} $*" >&2; }
success() { echo -e "${BCyan}[✓]${Color_Off} $*"; }

# ─── constants ────────────────────────────────────────────────────────────────
AXIOM_PATH="${HOME}/.axiom"
RESTART_BRIDGE=false

# ─── argument parsing ─────────────────────────────────────────────────────────
usage() {
    echo -e "${BWhite}Usage:${Color_Off} ax-update.sh [--restart] [--help]"
    echo ""
    echo -e "  ${BCyan}--restart${Color_Off}   Restart the gui-ax-bridge process after updating"
    echo -e "  ${BCyan}--help${Color_Off}      Show this help"
    echo ""
    echo -e "This script pulls the latest Ax framework from GitHub to ${AXIOM_PATH}."
    echo -e "Run it periodically to stay on the latest modules, payloads, and templates."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --restart) RESTART_BRIDGE=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) error "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

# ─── main logic ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BWhite}╔══════════════════════════════════════════════════════════════╗${Color_Off}"
echo -e "${BWhite}║              Ax Framework Updater                           ║${Color_Off}"
echo -e "${BWhite}╚══════════════════════════════════════════════════════════════╝${Color_Off}"
echo ""

# ── 1. Make sure Ax is installed ──────────────────────────────────────────────
if [[ ! -d "${AXIOM_PATH}" ]]; then
    error "Ax not found at ${AXIOM_PATH} — run the installer first."
    exit 1
fi

# Ensure interact/ is on PATH for this session
if [[ ":${PATH}:" != *":${AXIOM_PATH}/interact:"* ]]; then
    export PATH="${PATH}:${AXIOM_PATH}/interact"
fi

if ! command -v ax &>/dev/null && ! command -v axiom-update &>/dev/null; then
    error "'ax' command not found. Make sure ${AXIOM_PATH}/interact is on your PATH."
    exit 1
fi

# Show current commit before update
CURRENT_COMMIT="$(git -C "${AXIOM_PATH}" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
info "Current commit: ${CURRENT_COMMIT}"

# ── 2. Run ax update ──────────────────────────────────────────────────────────
echo ""
info "Running: ax update"
ax update

NEW_COMMIT="$(git -C "${AXIOM_PATH}" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
if [[ "${NEW_COMMIT}" != "${CURRENT_COMMIT}" ]]; then
    success "Updated: ${CURRENT_COMMIT} → ${NEW_COMMIT}"
else
    success "Already up to date."
fi

# ── 3. Optionally restart the bridge ──────────────────────────────────────────
if [[ "${RESTART_BRIDGE}" == true ]]; then
    echo ""
    info "Restarting gui-ax-bridge..."
    # Find and kill existing bridge process
    BRIDGE_PID="$(pgrep -f "axiom-bridge.py" 2>/dev/null | head -1 || true)"
    if [[ -n "${BRIDGE_PID}" ]]; then
        kill "${BRIDGE_PID}"
        info "Killed existing bridge (PID ${BRIDGE_PID})"
        sleep 1
    fi

    # Re-launch from the repo root (two directories up from this script)
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    nohup python3 "${REPO_ROOT}/tools/axiom-bridge.py" \
        > "${REPO_ROOT}/bridge.log" 2>&1 &
    success "Bridge restarted (PID $!) — logs: ${REPO_ROOT}/bridge.log"
fi

# ── 4. Summary ────────────────────────────────────────────────────────────────
echo ""
success "Ax is up to date."
echo -e "  Modules: ${BCyan}$(ls "${AXIOM_PATH}/modules/" 2>/dev/null | wc -l | tr -d ' ')${Color_Off} installed"
echo ""
