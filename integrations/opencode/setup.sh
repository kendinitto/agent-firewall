#!/usr/bin/env bash
# Setup and start Agent Firewall server
# Run this to start the firewall alongside opencode

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Stop existing server
pkill -f "uvicorn.*8080" 2>/dev/null || true
sleep 1

# Start firewall server
cd "$PROJECT_DIR"
nohup .venv/bin/python -m src.proxy.server --port 8080 > ~/.opencode/firewall.log 2>&1 &
echo "Firewall PID: $!"
sleep 2

# Verify
if curl -s http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "Firewall is running on port 8080"
    curl -s http://127.0.0.1:8080/health
else
    echo "Failed to start. Check ~/.opencode/firewall.log"
    cat ~/.opencode/firewall.log
    exit 1
fi
