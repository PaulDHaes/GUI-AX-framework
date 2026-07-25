#!/usr/bin/env bash
# =============================================================================
#  GUI-AX Framework — Install Script
#  Dashboard repo : https://github.com/PaulDHaes/GUI-AX-framework
#  Ax framework   : https://github.com/attacksurge/ax
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
Color_Off='\033[0m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
BBlue='\033[1;34m'
BCyan='\033[1;36m'
BWhite='\033[1;37m'
Green='\033[0;32m'
Yellow='\033[0;33m'
Red='\033[0;31m'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_URL="https://github.com/PaulDHaes/GUI-AX-framework"
AX_REPO="https://github.com/attacksurge/ax"
AXIOM_PATH="${HOME}/.axiom"

INSTALL_DIR="${GUI_AX_PATH:-$HOME/gui-ax-framework}"
BRIDGE_PORT="${PORT:-5000}"
UI_PORT="${UI_PORT:-3000}"
MIN_NODE_MAJOR=18
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=9

PYTHON_CMD=""   # resolved in check_python

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
print_banner() {
cat << 'EOF'

 ██████╗ ██╗   ██╗██╗      █████╗ ██╗  ██╗
██╔════╝ ██║   ██║██║     ██╔══██╗╚██╗██╔╝
██║  ███╗██║   ██║██║     ███████║ ╚███╔╝ 
██║   ██║██║   ██║██║     ██╔══██║ ██╔██╗ 
╚██████╔╝╚██████╔╝██║     ██║  ██║██╔╝ ██╗
 ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝

 ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
 ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
 █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
 ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
 ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

  A React + Flask dashboard for the Ax distributed recon framework
  Dashboard : https://github.com/PaulDHaes/GUI-AX-framework
  Ax        : https://github.com/attacksurge/ax

EOF
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo -e "${BGreen}[+]${Color_Off} $*"; }
warn()    { echo -e "${BYellow}[!]${Color_Off} $*"; }
error()   { echo -e "${BRed}[✗]${Color_Off} $*" >&2; }
success() { echo -e "${BCyan}[✓]${Color_Off} $*"; }
step()    { echo -e "\n${BBlue}══>${Color_Off} ${BWhite}$*${Color_Off}"; }
hr()      { echo -e "${BBlue}──────────────────────────────────────────────────────────────${Color_Off}"; }

ask_yn() {
    local prompt="$1" default="${2:-y}" answer
    while true; do
        echo -e -n "${BYellow}${prompt} [y/n]: ${Color_Off}"
        read -r answer
        answer="${answer:-$default}"
        case "${answer,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) warn "Please enter 'y' or 'n'" ;;
        esac
    done
}

command_exists() { command -v "$1" &>/dev/null; }

require_cmd() {
    if ! command_exists "$1"; then
        error "Required command '$1' not found. Please install it and re-run."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
detect_os() {
    BASEOS="$(uname)"
    case "$BASEOS" in
        Linux)
            if command_exists lsb_release; then
                OS="$(lsb_release -si 2>/dev/null)"
            elif [[ -f /etc/os-release ]]; then
                OS="$(. /etc/os-release && echo "$ID")"
            else
                OS="unknown-linux"
            fi
            ;;
        Darwin)
            OS="macOS"
            ;;
        *)
            OS="unknown"
            ;;
    esac
    info "Detected OS: ${OS} (${BASEOS})"
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
check_git() {
    step "Checking git"
    if command_exists git; then
        success "git found: $(git --version)"
    else
        error "git is required but not installed."
        case "$BASEOS" in
            Linux)  info "Run: sudo apt-get install git  (or equivalent for your distro)" ;;
            Darwin) info "Run: brew install git" ;;
        esac
        exit 1
    fi
}

check_node() {
    step "Checking Node.js (>= ${MIN_NODE_MAJOR})"
    if command_exists node; then
        NODE_VER="$(node --version | sed 's/v//')"
        NODE_MAJOR="$(echo "$NODE_VER" | cut -d. -f1)"
        if (( NODE_MAJOR >= MIN_NODE_MAJOR )); then
            success "Node.js ${NODE_VER} found"
            return 0
        else
            warn "Node.js ${NODE_VER} is below the minimum ${MIN_NODE_MAJOR}. Upgrading..."
        fi
    else
        warn "Node.js not found. Installing..."
    fi

    if [[ "$BASEOS" == "Darwin" ]]; then
        require_cmd brew
        brew install node
    elif [[ "$BASEOS" == "Linux" ]]; then
        # Use NodeSource for a modern version
        info "Installing Node.js ${MIN_NODE_MAJOR}.x via NodeSource..."
        curl -fsSL "https://deb.nodesource.com/setup_${MIN_NODE_MAJOR}.x" | sudo -E bash -
        sudo apt-get install -y nodejs
    fi

    success "Node.js installed: $(node --version)"
}

check_npm() {
    step "Checking npm"
    if command_exists npm; then
        success "npm found: $(npm --version)"
    else
        error "npm is required but not found (usually bundled with Node.js)."
        exit 1
    fi
}

check_python() {
    step "Checking Python (>= ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR})"

    PYTHON_CMD=""
    for cmd in python3 python; do
        if command_exists "$cmd"; then
            PY_VER="$($cmd --version 2>&1 | awk '{print $2}')"
            PY_MAJOR="$(echo "$PY_VER" | cut -d. -f1)"
            PY_MINOR="$(echo "$PY_VER" | cut -d. -f2)"
            if (( PY_MAJOR >= MIN_PYTHON_MAJOR && PY_MINOR >= MIN_PYTHON_MINOR )); then
                PYTHON_CMD="$cmd"
                success "Python ${PY_VER} found at $(command -v $cmd)"
                break
            fi
        fi
    done

    if [[ -z "$PYTHON_CMD" ]]; then
        warn "Python >= ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR} not found. Installing..."
        if [[ "$BASEOS" == "Darwin" ]]; then
            require_cmd brew
            brew install python3
        elif [[ "$BASEOS" == "Linux" ]]; then
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip python3-venv
        fi
        PYTHON_CMD="python3"
        success "Python installed: $($PYTHON_CMD --version)"
    fi
}

check_pip() {
    step "Checking pip"
    if "$PYTHON_CMD" -m pip --version &>/dev/null; then
        success "pip found"
    else
        warn "pip not found — attempting to install..."
        if [[ "$BASEOS" == "Darwin" ]]; then
            brew install python3
        else
            sudo apt-get install -y python3-pip
        fi
    fi
}

install_python_deps() {
    step "Installing Python bridge dependencies (Flask, flask-cors, geoip2, mcp)"
    # geoip2 enables the optional offline IP-geolocation source for the Geo Map;
    # mcp + httpx power the optional MCP server (tools/mcp-server.py). All optional.
    "$PYTHON_CMD" -m pip install --user flask flask-cors geoip2 mcp httpx 2>&1 | tail -5
    success "Python dependencies installed"
}

# ---------------------------------------------------------------------------
# ── AX FRAMEWORK ────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

ax_is_installed() {
    [[ -d "${AXIOM_PATH}" ]] && \
        ( command_exists axiom-scan 2>/dev/null || [[ -f "${AXIOM_PATH}/interact/axiom-scan" ]] )
}

install_ax() {
    step "Ax framework setup"

    if ax_is_installed; then
        success "Ax is already installed at ${AXIOM_PATH}"
        if ask_yn "Pull latest Ax updates?" "y"; then
            cd "${AXIOM_PATH}" && git pull --ff-only 2>/dev/null \
                && success "Ax updated" \
                || warn "Could not auto-pull Ax (local changes?)"
        fi
        return
    fi

    hr
    echo -e "${BWhite}Ax${Color_Off} is the distributed recon framework this dashboard connects to."
    echo -e "It provisions cloud VPS fleets for parallel scanning."
    echo -e "Source: ${BCyan}${AX_REPO}${Color_Off}"
    hr
    echo ""
    echo -e "  ${BGreen}1)${Color_Off} Full install  — clone Ax and run axiom-configure (set up cloud credentials)"
    echo -e "  ${BGreen}2)${Color_Off} Clone only   — download Ax scripts now, configure later"
    echo -e "  ${BGreen}3)${Color_Off} Skip         — I already have Ax or don't need it right now"
    echo ""
    echo -e -n "${BYellow}Choose [1/2/3]: ${Color_Off}"
    read -r ax_choice

    case "${ax_choice:-3}" in
        1)  _ax_full_install ;;
        2)  _ax_clone_only ;;
        3)  warn "Skipping Ax. Run later:"
            echo -e "  ${BCyan}bash <(curl -fsSL https://raw.githubusercontent.com/attacksurge/ax/master/interact/axiom-configure) --run${Color_Off}"
            ;;
        *)  warn "Invalid choice — skipping Ax." ;;
    esac
}

_ax_clone_only() {
    info "Cloning Ax → ${AXIOM_PATH}"
    if [[ -d "${AXIOM_PATH}/.git" ]]; then
        warn "${AXIOM_PATH} already exists — skipping clone"
    else
        git clone "${AX_REPO}" "${AXIOM_PATH}"
    fi
    _ax_add_to_path
    success "Ax cloned. Run ${BCyan}axiom-configure --run${Color_Off} to set up cloud credentials."
}

_ax_full_install() {
    _ax_clone_only

    # Install Ax system dependencies
    if [[ "$BASEOS" == "Linux" ]]; then
        step "Installing Ax system dependencies"
        if command_exists apt-get; then
            info "Installing: jq curl git wget unzip rsync bc python3-pip"
            DEBIAN_FRONTEND=noninteractive sudo apt-get update -qq
            DEBIAN_FRONTEND=noninteractive sudo apt-get install -y \
                jq curl git wget unzip rsync bc python3-pip net-tools xsltproc \
                openssh-client 2>&1 | tail -5
        elif command_exists pacman; then
            sudo pacman -Syu --noconfirm jq curl git wget unzip rsync bc python-pip
        elif command_exists dnf; then
            sudo dnf install -y jq curl git wget unzip rsync bc python3-pip
        fi
        success "System dependencies installed"
    elif [[ "$BASEOS" == "Darwin" ]]; then
        step "Installing Ax macOS dependencies"
        if command_exists brew; then
            brew install jq wget coreutils gnu-sed 2>&1 | tail -5
            success "macOS dependencies installed"
        else
            warn "Homebrew not found — skipping macOS dependency install"
        fi
    fi

    # Run axiom-configure for cloud account setup
    step "Running Ax cloud configuration"
    info "axiom-configure will ask for your cloud provider credentials."
    if ask_yn "Run axiom-configure now to set up your cloud account?" "y"; then
        if [[ -f "${AXIOM_PATH}/interact/axiom-configure" ]]; then
            bash "${AXIOM_PATH}/interact/axiom-configure" --run
        else
            warn "axiom-configure not found locally — running from URL"
            bash <(curl -fsSL "https://raw.githubusercontent.com/attacksurge/ax/master/interact/axiom-configure") --run
        fi
    else
        warn "Skipped cloud setup. Run ${BCyan}axiom-configure --run${Color_Off} when ready."
    fi
}

_ax_add_to_path() {
    # Detect shell RC file and add ~/.axiom/interact to PATH if not already there
    local rc_file
    case "${SHELL##*/}" in
        zsh)  rc_file="${HOME}/.zshrc" ;;
        bash) rc_file="${HOME}/.bashrc" ;;
        *)    rc_file="${HOME}/.profile" ;;
    esac

    local export_line='export PATH="$PATH:$HOME/.axiom/interact"'
    if ! grep -qF ".axiom/interact" "${rc_file}" 2>/dev/null; then
        { echo ""; echo "# Ax framework"; echo "${export_line}"; } >> "${rc_file}"
        info "Added Ax to PATH in ${rc_file}"
    fi
    # Apply for current session
    export PATH="${PATH}:${AXIOM_PATH}/interact"
}

# ---------------------------------------------------------------------------
# Clone / update the repository
# ---------------------------------------------------------------------------
clone_or_update_repo() {
    step "Setting up repository at ${INSTALL_DIR}"

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Repository already exists — pulling latest changes..."
        cd "$INSTALL_DIR"
        git pull --ff-only origin main 2>/dev/null \
            || git pull --ff-only origin master 2>/dev/null \
            || warn "Could not auto-pull. You may be on a detached HEAD or have local changes."
        success "Repository updated"
    else
        info "Cloning ${REPO_URL} → ${INSTALL_DIR}"
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        success "Repository cloned"
    fi
}

# ---------------------------------------------------------------------------
# Install Node dependencies
# ---------------------------------------------------------------------------
install_node_deps() {
    step "Installing Node.js dependencies"
    cd "$INSTALL_DIR"
    npm install 2>&1 | tail -10
    success "Node.js dependencies installed"
}

# ---------------------------------------------------------------------------
# Environment / config setup
# ---------------------------------------------------------------------------
setup_env() {
    step "Configuring environment"
    cd "$INSTALL_DIR"

    ENV_FILE="${INSTALL_DIR}/.env"

    if [[ -f "$ENV_FILE" ]]; then
        warn ".env already exists — skipping (delete it to reconfigure)"
        return
    fi

    # Gemini API key (optional)
    GEMINI_KEY=""
    if ask_yn "Do you want to configure a Gemini API key? (enables AI panel)" "n"; then
        echo -e -n "${BYellow}Enter your Gemini API key: ${Color_Off}"
        read -r GEMINI_KEY
    fi

    # Ports
    echo -e -n "${BYellow}Bridge API port [${BRIDGE_PORT}]: ${Color_Off}"
    read -r input_port
    BRIDGE_PORT="${input_port:-$BRIDGE_PORT}"

    echo -e -n "${BYellow}UI dev-server port [${UI_PORT}]: ${Color_Off}"
    read -r input_ui_port
    UI_PORT="${input_ui_port:-$UI_PORT}"

    cat > "$ENV_FILE" << EOF
# GUI-AX Framework — environment configuration
# Generated by gui-ax-install.sh on $(date)

# Gemini AI key (leave blank to disable AI panel)
GEMINI_API_KEY=${GEMINI_KEY}

# Flask bridge port
PORT=${BRIDGE_PORT}

# Path overrides (optional — defaults are relative to the repo root)
# STORE_PATH=./data/axiom_bridge_store.json
# IMPORTS_PATH=./imports
EOF

    success ".env written to ${ENV_FILE}"
}

# ---------------------------------------------------------------------------
# Create systemd service (Linux only, optional)
# ---------------------------------------------------------------------------
setup_systemd() {
    [[ "$BASEOS" != "Linux" ]] && return
    command_exists systemctl || return

    ask_yn "Create a systemd service so the bridge auto-starts on boot?" "n" || return

    SERVICE_FILE="/etc/systemd/system/gui-ax-bridge.service"
    PYTHON_BIN="$(command -v "$PYTHON_CMD")"

    info "Writing ${SERVICE_FILE}"
    sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=GUI-AX Framework — Flask bridge
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PORT=${BRIDGE_PORT}"
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/tools/axiom-bridge.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable gui-ax-bridge.service
    sudo systemctl start  gui-ax-bridge.service
    success "systemd service installed and started (sudo systemctl status gui-ax-bridge)"
}

# ---------------------------------------------------------------------------
# Print usage summary
# ---------------------------------------------------------------------------
print_next_steps() {
    echo ""
    echo -e "${BGreen}╔══════════════════════════════════════════════════════════════╗${Color_Off}"
    echo -e "${BGreen}║           GUI-AX Framework installed successfully!           ║${Color_Off}"
    echo -e "${BGreen}╚══════════════════════════════════════════════════════════════╝${Color_Off}"
    echo ""
    if ax_is_installed; then
        echo -e "  ${BCyan}Ax framework${Color_Off}   ${AXIOM_PATH}"
    else
        echo -e "  ${Yellow}Ax framework${Color_Off}   not configured yet"
        echo -e "                 → ${BCyan}axiom-configure --run${Color_Off} when ready"
    fi
    echo -e "  ${BCyan}Dashboard${Color_Off}      ${INSTALL_DIR}"
    echo ""
    echo -e "${BWhite}Location:${Color_Off} ${INSTALL_DIR}"
    echo ""
    echo -e "${BWhite}To start the bridge (Flask API + file watcher):${Color_Off}"
    echo -e "  ${BCyan}cd ${INSTALL_DIR}${Color_Off}"
    echo -e "  ${BCyan}python3 tools/axiom-bridge.py${Color_Off}"
    echo ""
    echo -e "${BWhite}To start the UI (development server):${Color_Off}"
    echo -e "  ${BCyan}cd ${INSTALL_DIR}${Color_Off}"
    echo -e "  ${BCyan}npm run dev${Color_Off}"
    echo ""
    echo -e "${BWhite}Or start both at once:${Color_Off}"
    echo -e "  ${BCyan}cd ${INSTALL_DIR} && bash tools/start-dev.sh${Color_Off}"
    echo ""
    echo -e "${BWhite}Drop axiom scan output into:${Color_Off}"
    echo -e "  ${BCyan}${INSTALL_DIR}/imports/${Color_Off}"
    echo -e "  (or copy .dir folders from axiom output directly)"
    echo ""
    echo -e "${BWhite}Dashboard URL:${Color_Off} ${BCyan}http://localhost:${UI_PORT}${Color_Off}"
    echo -e "${BWhite}Bridge API URL:${Color_Off} ${BCyan}http://localhost:${BRIDGE_PORT}${Color_Off}"
    echo ""
    echo -e "${Yellow}Tip:${Color_Off} Edit ${INSTALL_DIR}/.env to change ports or add your Gemini API key."
    echo ""
}

# ---------------------------------------------------------------------------
# Usage / help
# ---------------------------------------------------------------------------
usage() {
    echo -e "${BWhite}Usage:${Color_Off} gui-ax-install.sh [OPTIONS]"
    echo ""
    echo -e "${BWhite}Options:${Color_Off}"
    echo -e "  --dir <path>       Install directory (default: ~/gui-ax-framework)"
    echo -e "  --port <port>      Bridge API port (default: 5000)"
    echo -e "  --ui-port <port>   UI dev-server port (default: 3000)"
    echo -e "  --skip-ax          Skip Ax framework installation"
    echo -e "  --skip-node        Skip Node.js dependency install"
    echo -e "  --skip-python      Skip Python dependency install"
    echo -e "  --unattended       Non-interactive install (clone-only for Ax)"
    echo -e "  --update           Pull latest changes and reinstall deps only"
    echo -e "  --help             Show this help"
    echo ""
    echo -e "${BWhite}Examples:${Color_Off}"
    echo -e "  ${BGreen}bash gui-ax-install.sh${Color_Off}                       # Interactive full install"
    echo -e "  ${BGreen}bash gui-ax-install.sh --unattended${Color_Off}           # Silent install (clones Ax)"
    echo -e "  ${BGreen}bash gui-ax-install.sh --skip-ax${Color_Off}              # Dashboard only"
    echo -e "  ${BGreen}bash gui-ax-install.sh --dir /opt/gui-ax${Color_Off}      # Custom path"
    echo -e "  ${BGreen}bash gui-ax-install.sh --update${Color_Off}               # Update existing install"
    echo ""
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
UNATTENDED=false
SKIP_AX=false
SKIP_NODE=false
SKIP_PYTHON=false
UPDATE_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)         INSTALL_DIR="$2"; shift 2 ;;
        --port)        BRIDGE_PORT="$2"; shift 2 ;;
        --ui-port)     UI_PORT="$2"; shift 2 ;;
        --skip-ax)     SKIP_AX=true; shift ;;
        --skip-node)   SKIP_NODE=true; shift ;;
        --skip-python) SKIP_PYTHON=true; shift ;;
        --unattended)  UNATTENDED=true; shift ;;
        --update)      UPDATE_ONLY=true; shift ;;
        --help|-h)     usage; exit 0 ;;
        *)
            error "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

# In unattended mode: auto-answer yes & skip interactive Ax cloud setup
if [[ "$UNATTENDED" == true ]]; then
    ask_yn() { return 0; }
    install_ax() {
        step "Ax framework setup (unattended — clone only)"
        if ax_is_installed; then success "Ax already installed"; return; fi
        _ax_clone_only
    }
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    print_banner

    if [[ "$UPDATE_ONLY" == true ]]; then
        step "Update mode — pulling latest changes"
        clone_or_update_repo
        install_node_deps
        "$SKIP_PYTHON" || install_python_deps
        success "Update complete!"
        print_next_steps
        exit 0
    fi

    echo -e "${BWhite}This script will:${Color_Off}"
    echo -e "  1. Check system dependencies  (git, Node.js ≥ ${MIN_NODE_MAJOR}, Python ≥ ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR})"
    echo -e "  2. Ax framework               (${AX_REPO})"
    echo -e "  3. GUI-AX dashboard            (${REPO_URL})"
    echo -e "  4. npm + pip dependencies"
    echo -e "  5. .env config                 (ports, Gemini API key)"
    echo -e "  6. systemd service             (Linux, optional)"
    echo ""

    if [[ "$UNATTENDED" != true ]]; then
        echo -e -n "${BYellow}Press ENTER to continue, or Ctrl+C to abort...${Color_Off}"
        read -r
    fi

    detect_os

    step "Checking dependencies"
    check_git
    "$SKIP_NODE"   || check_node
    "$SKIP_NODE"   || check_npm
    "$SKIP_PYTHON" || check_python
    "$SKIP_PYTHON" || check_pip

    # Ax framework (before dashboard clone so PATH is set)
    "$SKIP_AX" || install_ax

    clone_or_update_repo

    "$SKIP_NODE"   || install_node_deps
    "$SKIP_PYTHON" || install_python_deps

    setup_env
    setup_systemd

    print_next_steps
}

main "$@"
