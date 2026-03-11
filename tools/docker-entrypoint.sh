#!/usr/bin/env bash
# =============================================================================
#  GUI-AX Framework — Docker entrypoint (All-in-One)
#  • Ax framework is pre-installed at /root/.axiom (cloned during build)
#  • Dashboard (bridge + Vite) runs in a tmux session called "dashboard"
#  • When user opens a shell, .zshrc auto-prompts axiom-configure if needed
#  • Matches the official Ax Docker experience (zsh + interactive configure)
# =============================================================================
set -e

APP_DIR="/app"

# ── Ensure required directories exist ──
mkdir -p "$APP_DIR/data" "$APP_DIR/imports/processed"

# ── Ax is on PATH ──
export PATH="/root/.axiom/interact:${PATH}"

# ── If user passes an explicit command, just run it ──
if [[ $# -gt 0 ]]; then
    exec "$@"
fi

# ── Install .zshrc hook for interactive shells ──
# Fires every time someone opens a shell in the container
# (docker exec -it, Docker Desktop terminal, etc.)
cat > /root/.zshrc << 'ZSHRC'
export PATH="/root/.axiom/interact:${PATH}"

# ── Check if Ax is configured (real .json accounts, not .example templates) ──
if [[ -z "$(find /root/.axiom/accounts/ -maxdepth 1 -name '*.json' ! -name '*.example' 2>/dev/null)" ]]; then
    echo ""
    echo "════════════════════════════════════════════════════════════════════"
    echo "  ⚠️  Ax framework is not yet configured!"
    echo ""
    echo "  The dashboard is running, but fleet & scan features need a"
    echo "  cloud provider to be set up first."
    echo "════════════════════════════════════════════════════════════════════"
    echo ""
    read "answer?  Run axiom-configure now? [Y/n] "
    case "${answer:-Y}" in
        [Yy]*|"")
            echo ""
            /root/.axiom/interact/axiom-configure --run
            echo ""
            echo "✅ Ax configuration complete!"
            echo "   Dashboard: http://localhost:3000"
            echo ""
            ;;
        *)
            echo ""
            echo "  Skipped. Run it later with:  axiom-configure --run"
            echo ""
            ;;
    esac
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ✅ Ax is configured — cloud provider ready"
    echo "  📊 Dashboard:  http://localhost:3000"
    echo "  🔧 Bridge API: http://localhost:${PORT:-5000}"
    echo ""
    echo "  💡 tmux attach -t dashboard  — view bridge/Vite logs"
    echo "  💡 tmux ls                   — list all sessions"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
fi
ZSHRC

# ── Also install .bashrc (same content) as fallback ──
cp /root/.zshrc /root/.bashrc
# Fix bash read syntax (zsh uses read "var?prompt", bash uses read -p)
sed -i 's/read "answer?  Run/read -p "  Run/' /root/.bashrc

# ── Start the dashboard in a tmux session (bridge + Vite) ──
tmux kill-session -t dashboard 2>/dev/null || true

tmux new-session -d -s dashboard -n bridge \
    "echo '🚀 Starting axiom-bridge on port ${PORT:-5000}...' && python3 $APP_DIR/tools/axiom-bridge.py; zsh"

tmux new-window -t dashboard -n vite \
    "echo '🖥️  Starting Vite dev server on port 3000...' && cd $APP_DIR && npm run dev; zsh"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ Dashboard started in tmux session 'dashboard'"
echo "   • Dashboard UI:  http://localhost:3000"
echo "   • Bridge API:    http://localhost:${PORT:-5000}"
echo "═══════════════════════════════════════════════════════════════"

if [[ -z "$(find /root/.axiom/accounts/ -maxdepth 1 -name '*.json' ! -name '*.example' 2>/dev/null)" ]]; then
    echo ""
    echo "  ⚠️  Ax not configured yet. Open a shell to get started:"
    echo "    docker exec -it gui-ax-dashboard zsh"
fi
echo ""

# ── Keep the container alive (works in detached -d mode) ──
exec tail -f /dev/null
