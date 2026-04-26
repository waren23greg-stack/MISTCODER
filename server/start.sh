#!/usr/bin/env bash
# EDEN×MISTCODER — Local dev server
# Run from inside your MISTCODER repo root:
#   bash server/start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "[EDEN] Starting server from $REPO_ROOT"

# Install deps if not present
pip install -q fastapi uvicorn apscheduler python-multipart 2>/dev/null || true

# Set env so server.py finds your real reports
export REPORTS_DIR="$REPO_ROOT/reports"
export SCAN_INTERVAL_MINUTES="${SCAN_INTERVAL_MINUTES:-5}"

cd "$SCRIPT_DIR"

# Copy latest dashboard into server dir so FastAPI can serve it
cp dashboard.html "$SCRIPT_DIR/dashboard.html" 2>/dev/null || true

echo "[EDEN] Reports dir : $REPORTS_DIR"
echo "[EDEN] Scan interval: ${SCAN_INTERVAL_MINUTES} minutes"
echo "[EDEN] Dashboard    : http://localhost:8000"
echo ""

uvicorn server:app --host 0.0.0.0 --port 8000 --reload
