#!/bin/bash
# Local development startup script
# Starts: Axiom bridge (port 5000) and Vite dev server (port 3000)
# The bridge handles import watching natively — no separate watcher needed.
#
# 🐳 For Docker, use instead:
#   docker compose up --build
#   (exposes the same ports: 3000 for UI, 5000 for bridge)

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Starting Axiom bridge on port 5000..."
python3 "$APP_DIR/tools/axiom-bridge.py" &
BRIDGE_PID=$!

echo "Waiting for bridge to start..."
sleep 2

echo "Starting Vite dev server..."
cd "$APP_DIR" && npm run dev &
VITE_PID=$!

echo ""
echo "✓ All services started:"
echo "  - Bridge API:  http://localhost:5000"
echo "  - Frontend UI: http://localhost:3000"
echo ""
echo "Drop scan output files into $APP_DIR/imports/ to import them."
echo ""
echo "Press Ctrl+C to stop all services"

trap "kill $BRIDGE_PID $VITE_PID 2>/dev/null" EXIT
wait
