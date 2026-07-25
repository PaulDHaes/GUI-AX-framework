#!/bin/bash
# Local development startup script
# Starts: Axiom bridge (port 5000) and Vite dev server (port 3000)
# The bridge handles import watching natively — no separate watcher needed.

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Stopping any running bridge/vite processes..."
pkill -f "axiom-bridge.py"   2>/dev/null
pkill -f "workflow-runner.py" 2>/dev/null
# Kill the full npm-run-dev tree (npm → bash → esbuild/vite child processes)
pkill -f "npm run dev"       2>/dev/null
pkill -f "vite"              2>/dev/null
pkill -f "esbuild"           2>/dev/null
sleep 1

# Bound how long any single `aws` call can hang on an unreachable/degraded
# region (e.g. me-south-1) before failing. AWS_MAX_ATTEMPTS/AWS_RETRY_MODE
# (set in docker-compose.yml) control retry *count*; these two control the
# per-attempt socket timeouts, which have no env var equivalent — they only
# exist as ~/.aws/config keys. Only touches these two keys, so it doesn't
# interfere with axiom's own account/region switching (which lives in the
# same file's region/profile keys).
echo "Configuring AWS CLI connect/read timeouts..."
aws configure set cli_connect_timeout 5 2>/dev/null
aws configure set cli_read_timeout 10 2>/dev/null

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
