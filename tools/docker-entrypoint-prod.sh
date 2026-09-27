#!/usr/bin/env bash
# =============================================================================
#  GUI-AX Framework — Production entrypoint
#  nginx serves the pre-built frontend; Flask bridge runs as a tmux session.
#  No Vite dev server. No bind mounts. Code is baked into the image.
# =============================================================================
set -e

APP_DIR="/app"

mkdir -p "$APP_DIR/data" "$APP_DIR/imports/processed"

export PATH="/root/.axiom/interact:${PATH}"

if [[ $# -gt 0 ]]; then
    exec "$@"
fi

# ── AWS hardening ──
aws configure set cli_connect_timeout 5 2>/dev/null || true
aws configure set cli_read_timeout 15 2>/dev/null || true

if [[ -f "$APP_DIR/tools/setup-aws-region-filter.sh" ]]; then
    bash "$APP_DIR/tools/setup-aws-region-filter.sh" || true
fi

# ── Start Flask bridge in tmux ──
tmux kill-session -t dashboard 2>/dev/null || true

tmux new-session -d -s dashboard -n bridge \
    "echo '🚀 Starting axiom-bridge on port ${PORT:-5000}...' && python3 $APP_DIR/tools/axiom-bridge.py; bash"

# ── Start nginx ──
nginx -g "daemon off;" &
NGINX_PID=$!

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ GUI-AX Production started"
echo "   • Dashboard UI:  http://localhost:80   (nginx → dist/)"
echo "   • Bridge API:    http://localhost:5000 (Flask, internal)"
echo "   • tmux attach -t dashboard  — view bridge logs"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Keep container alive; exit if nginx exits
wait $NGINX_PID
